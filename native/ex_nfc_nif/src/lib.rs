//! The kernel `nfc` generic-netlink family through `neli`, and NDEF
//! record framing through `ndef-rs`.

use std::collections::HashMap;
use std::iter::once;
use std::sync::atomic::{AtomicU64, Ordering};

use ndef_rs::payload::ExternalPayload;
use ndef_rs::{NdefMessage, NdefRecord, RecordFlags, TNF};
use neli::consts::nl::NlmF;
use neli::consts::socket::NlFamily;
use neli::err::RouterError;
use neli::genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder, NoUserHeader};
use neli::nl::NlPayload;
use neli::router::synchronous::{NlRouter, NlRouterReceiverHandle};
use neli::types::{Buffer, GenlBuffer};
use neli::utils::Groups;
use rustler::types::atom::{nil, ok};
use rustler::{
    Atom, Binary, Encoder, Env, Error, LocalPid, NifResult, OwnedBinary, OwnedEnv, Resource,
    ResourceArc, Term,
};

mod atoms {
    rustler::atoms! {
        ex_nfc_event, closed, targets_found, target_lost, device_added, device_removed,
        index, name, protocols, powered, target_index, sens_res, sel_res, nfcid1,
        sensb_res, sensf_res, ats, iso15693_uid, iso15693_dsfid,
        eperm, enoent, eio, eagain, enomem, eacces, ebusy, eexist, enodev, einval,
        epipe, eproto, emsgsize, eopnotsupp, eafnosupport, enobufs, eisconn,
        enotconn, etimedout, econnrefused, ealready, eremoteio, erfkill,
        no_events_group, malformed_ndef, chunked_record_unsupported, bad_record,
    }
}

// include/uapi/linux/nfc.h
const NFC_GENL_VERSION: u8 = 1;

const CMD_GET_DEVICE: u8 = 1;
const CMD_DEV_UP: u8 = 2;
const CMD_DEV_DOWN: u8 = 3;
const CMD_START_POLL: u8 = 6;
const CMD_STOP_POLL: u8 = 7;
const CMD_GET_TARGET: u8 = 8;
const EVENT_TARGETS_FOUND: u8 = 9;
const EVENT_DEVICE_ADDED: u8 = 10;
const EVENT_DEVICE_REMOVED: u8 = 11;
const EVENT_TARGET_LOST: u8 = 12;
const CMD_DEACTIVATE_TARGET: u8 = 30;

const ATTR_DEVICE_INDEX: u16 = 1;
const ATTR_DEVICE_NAME: u16 = 2;
const ATTR_PROTOCOLS: u16 = 3;
const ATTR_TARGET_INDEX: u16 = 4;
const ATTR_TARGET_SENS_RES: u16 = 5;
const ATTR_TARGET_SEL_RES: u16 = 6;
const ATTR_TARGET_NFCID1: u16 = 7;
const ATTR_TARGET_SENSB_RES: u16 = 8;
const ATTR_TARGET_SENSF_RES: u16 = 9;
const ATTR_DEVICE_POWERED: u16 = 12;
const ATTR_IM_PROTOCOLS: u16 = 13;
const ATTR_TM_PROTOCOLS: u16 = 14;
const ATTR_TARGET_ISO15693_DSFID: u16 = 26;
const ATTR_TARGET_ISO15693_UID: u16 = 27;
const ATTR_TARGET_ATS: u16 = 32;

type Msg = Genlmsghdr<u8, u16, NoUserHeader>;

/// An open connection to the `nfc` family. Replies are matched to their
/// request by neli's router; events arrive on a thread of their own.
pub struct Nfc {
    router: NlRouter,
    family_id: u16,
}

#[rustler::resource_impl]
impl Resource for Nfc {}

fn errno_atom(errno: i32) -> Option<Atom> {
    Some(match errno {
        1 => atoms::eperm(),
        2 => atoms::enoent(),
        5 => atoms::eio(),
        11 => atoms::eagain(),
        12 => atoms::enomem(),
        13 => atoms::eacces(),
        16 => atoms::ebusy(),
        17 => atoms::eexist(),
        19 => atoms::enodev(),
        22 => atoms::einval(),
        32 => atoms::epipe(),
        71 => atoms::eproto(),
        90 => atoms::emsgsize(),
        95 => atoms::eopnotsupp(),
        97 => atoms::eafnosupport(),
        105 => atoms::enobufs(),
        106 => atoms::eisconn(),
        107 => atoms::enotconn(),
        110 => atoms::etimedout(),
        111 => atoms::econnrefused(),
        114 => atoms::ealready(),
        121 => atoms::eremoteio(),
        132 => atoms::erfkill(),
        _ => return None,
    })
}

/// `{:error, :ebusy}` for a kernel errno, `{:error, "message"}` otherwise.
fn router_err<T: std::fmt::Debug, P: std::fmt::Debug>(e: RouterError<T, P>) -> Error {
    if let RouterError::Nlmsgerr(ref m) = e {
        let errno = -*m.error();
        return match errno_atom(errno) {
            Some(a) => Error::Term(Box::new(a)),
            None => Error::Term(Box::new(errno)),
        };
    }
    Error::Term(Box::new(e.to_string()))
}

fn build_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Term(Box::new(e.to_string()))
}

impl Nfc {
    /// Sends one command and returns the payload of every reply: one for a
    /// plain request (acked), several for a dump.
    fn call(&self, cmd: u8, attrs: &[(u16, u32)], dump: bool) -> NifResult<Vec<Msg>> {
        let attrs = attrs
            .iter()
            .map(|&(t, v)| {
                let nla_type = AttrTypeBuilder::default().nla_type(t).build().map_err(build_err)?;
                NlattrBuilder::default()
                    .nla_type(nla_type)
                    .nla_payload(v)
                    .build()
                    .map_err(build_err)
            })
            .collect::<NifResult<GenlBuffer<u16, Buffer>>>()?;
        let msg = GenlmsghdrBuilder::<u8, u16, NoUserHeader>::default()
            .cmd(cmd)
            .version(NFC_GENL_VERSION)
            .attrs(attrs)
            .build()
            .map_err(build_err)?;
        let flags = if dump { NlmF::DUMP } else { NlmF::ACK };
        let replies: NlRouterReceiverHandle<u16, Msg> = self
            .router
            .send(self.family_id, flags, NlPayload::Payload(msg))
            .map_err(router_err)?;

        let mut out = Vec::new();
        for reply in replies {
            if let NlPayload::Payload(p) = reply.map_err(router_err)?.nl_payload() {
                out.push(p.clone());
            }
        }
        Ok(out)
    }

    fn request(&self, cmd: u8, attrs: &[(u16, u32)]) -> NifResult<Atom> {
        self.call(cmd, attrs, false).map(|_| ok())
    }
}

fn attr<'a>(m: &'a Msg, t: u16) -> Option<&'a [u8]> {
    m.attrs()
        .iter()
        .find(|a| *a.nla_type().nla_type() == t)
        .map(|a| a.nla_payload().as_ref())
}

fn attr_uint(m: &Msg, t: u16) -> Option<u32> {
    match attr(m, t)? {
        [a] => Some(*a as u32),
        [a, b] => Some(u16::from_ne_bytes([*a, *b]) as u32),
        [a, b, c, d] => Some(u32::from_ne_bytes([*a, *b, *c, *d])),
        _ => None,
    }
}

fn attr_string(m: &Msg, t: u16) -> Option<String> {
    let bytes = attr(m, t)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn bin<'a>(env: Env<'a>, bytes: &[u8]) -> Term<'a> {
    let mut b = OwnedBinary::new(bytes.len()).expect("binary allocation");
    b.as_mut_slice().copy_from_slice(bytes);
    b.release(env).encode(env)
}

fn opt_bin<'a>(env: Env<'a>, bytes: Option<&[u8]>) -> Term<'a> {
    bytes.map_or(nil().encode(env), |b| bin(env, b))
}

fn map<'a>(env: Env<'a>, pairs: Vec<(Atom, Term<'a>)>) -> Term<'a> {
    let (keys, values): (Vec<_>, Vec<_>) = pairs.into_iter().map(|(k, v)| (k.encode(env), v)).unzip();
    Term::map_from_term_arrays(env, &keys, &values).expect("unique keys")
}

/// `%{index, name, protocols, powered}`
fn device<'a>(env: Env<'a>, m: &Msg) -> Term<'a> {
    map(
        env,
        vec![
            (atoms::index(), attr_uint(m, ATTR_DEVICE_INDEX).encode(env)),
            (atoms::name(), attr_string(m, ATTR_DEVICE_NAME).encode(env)),
            (atoms::protocols(), attr_uint(m, ATTR_PROTOCOLS).encode(env)),
            (atoms::powered(), (attr_uint(m, ATTR_DEVICE_POWERED) == Some(1)).encode(env)),
        ],
    )
}

/// The target's attributes as the kernel reports them; absent ones are nil.
fn target<'a>(env: Env<'a>, m: &Msg) -> Term<'a> {
    map(
        env,
        vec![
            (atoms::target_index(), attr_uint(m, ATTR_TARGET_INDEX).encode(env)),
            (atoms::protocols(), attr_uint(m, ATTR_PROTOCOLS).encode(env)),
            (atoms::sens_res(), attr_uint(m, ATTR_TARGET_SENS_RES).encode(env)),
            (atoms::sel_res(), attr_uint(m, ATTR_TARGET_SEL_RES).encode(env)),
            (atoms::nfcid1(), opt_bin(env, attr(m, ATTR_TARGET_NFCID1))),
            (atoms::sensb_res(), opt_bin(env, attr(m, ATTR_TARGET_SENSB_RES))),
            (atoms::sensf_res(), opt_bin(env, attr(m, ATTR_TARGET_SENSF_RES))),
            (atoms::ats(), opt_bin(env, attr(m, ATTR_TARGET_ATS))),
            (atoms::iso15693_uid(), opt_bin(env, attr(m, ATTR_TARGET_ISO15693_UID))),
            (atoms::iso15693_dsfid(), attr_uint(m, ATTR_TARGET_ISO15693_DSFID).encode(env)),
        ],
    )
}

fn event<'a>(env: Env<'a>, m: &Msg) -> Option<Term<'a>> {
    let idx = || attr_uint(m, ATTR_DEVICE_INDEX).encode(env);
    Some(match *m.cmd() {
        EVENT_TARGETS_FOUND => (atoms::targets_found(), idx()).encode(env),
        EVENT_TARGET_LOST => {
            (atoms::target_lost(), idx(), attr_uint(m, ATTR_TARGET_INDEX)).encode(env)
        }
        EVENT_DEVICE_ADDED => (atoms::device_added(), device(env, m)).encode(env),
        EVENT_DEVICE_REMOVED => (atoms::device_removed(), idx()).encode(env),
        _ => return None,
    })
}

const EVENTS: [u8; 4] =
    [EVENT_TARGETS_FOUND, EVENT_TARGET_LOST, EVENT_DEVICE_ADDED, EVENT_DEVICE_REMOVED];

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Connects to `family` and joins its `events` group. Events are sent to
/// `pid` as `{:ex_nfc_event, id, event}`, and `{:ex_nfc_event, id, :closed}`
/// once the connection is gone; `id` tells connections apart.
#[rustler::nif(schedule = "DirtyIo")]
fn open(env: Env, family: String, pid: LocalPid) -> NifResult<Term> {
    let (router, events) =
        NlRouter::connect(NlFamily::Generic, None, Groups::empty()).map_err(router_err)?;
    let family_id = router.resolve_genl_family(&family).map_err(router_err)?;
    let group = router
        .resolve_nl_mcast_group(&family, "events")
        .map_err(|_| Error::Term(Box::new(atoms::no_events_group())))?;
    router
        .add_mcast_membership(Groups::new_groups(&[group]))
        .map_err(router_err)?;

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::thread::spawn(move || forward_events(events, pid, id));
    let nfc = ResourceArc::new(Nfc { router, family_id });
    Ok((ok(), nfc, id).encode(env))
}

fn forward_events(mut events: NlRouterReceiverHandle<u16, Msg>, pid: LocalPid, id: u64) {
    let mut env = OwnedEnv::new();
    while let Some(Ok(m)) = events.next_typed::<u16, Msg>() {
        let NlPayload::Payload(p) = m.nl_payload() else { continue };
        if !EVENTS.contains(p.cmd()) {
            continue;
        }
        let sent = env.send_and_clear(&pid, |env| {
            (atoms::ex_nfc_event(), id, event(env, p).expect("known event")).encode(env)
        });
        if sent.is_err() {
            return;
        }
    }
    let _ = env.send_and_clear(&pid, |env| (atoms::ex_nfc_event(), id, atoms::closed()).encode(env));
}

#[rustler::nif(schedule = "DirtyIo")]
fn get_devices(env: Env, nfc: ResourceArc<Nfc>) -> NifResult<(Atom, Vec<Term>)> {
    let replies = nfc.call(CMD_GET_DEVICE, &[], true)?;
    Ok((ok(), replies.iter().map(|m| device(env, m)).collect()))
}

#[rustler::nif(schedule = "DirtyIo")]
fn get_targets(env: Env, nfc: ResourceArc<Nfc>, dev: u32) -> NifResult<(Atom, Vec<Term>)> {
    let replies = nfc.call(CMD_GET_TARGET, &[(ATTR_DEVICE_INDEX, dev)], true)?;
    Ok((ok(), replies.iter().map(|m| target(env, m)).collect()))
}

#[rustler::nif(schedule = "DirtyIo")]
fn dev_up(nfc: ResourceArc<Nfc>, dev: u32) -> NifResult<Atom> {
    nfc.request(CMD_DEV_UP, &[(ATTR_DEVICE_INDEX, dev)])
}

#[rustler::nif(schedule = "DirtyIo")]
fn dev_down(nfc: ResourceArc<Nfc>, dev: u32) -> NifResult<Atom> {
    nfc.request(CMD_DEV_DOWN, &[(ATTR_DEVICE_INDEX, dev)])
}

#[rustler::nif(schedule = "DirtyIo")]
fn start_poll(nfc: ResourceArc<Nfc>, dev: u32, im: u32, tm: u32) -> NifResult<Atom> {
    let attrs = [(ATTR_DEVICE_INDEX, dev), (ATTR_IM_PROTOCOLS, im), (ATTR_TM_PROTOCOLS, tm)];
    nfc.request(CMD_START_POLL, &attrs)
}

#[rustler::nif(schedule = "DirtyIo")]
fn stop_poll(nfc: ResourceArc<Nfc>, dev: u32) -> NifResult<Atom> {
    nfc.request(CMD_STOP_POLL, &[(ATTR_DEVICE_INDEX, dev)])
}

#[rustler::nif(schedule = "DirtyIo")]
fn deactivate_target(nfc: ResourceArc<Nfc>, dev: u32, target: u32) -> NifResult<Atom> {
    nfc.request(CMD_DEACTIVATE_TARGET, &[(ATTR_DEVICE_INDEX, dev), (ATTR_TARGET_INDEX, target)])
}

// ---- NDEF ---------------------------------------------------------------

type RawRecord<'a> = (u8, Binary<'a>, Option<Binary<'a>>, Binary<'a>);

/// Splits an NDEF message into `{tnf, type, id | nil, payload}` records.
#[rustler::nif]
fn ndef_decode<'a>(env: Env<'a>, data: Binary<'a>) -> NifResult<(Atom, Vec<Term<'a>>)> {
    if data.is_empty() {
        return Ok((ok(), vec![]));
    }
    let chunked = || Error::Term(Box::new(atoms::chunked_record_unsupported()));
    let message = NdefMessage::decode(data.as_slice()).map_err(|_| {
        if data[0] & RecordFlags::CF.bits() != 0 {
            chunked()
        } else {
            Error::Term(Box::new(atoms::malformed_ndef()))
        }
    })?;
    let mut out = Vec::new();
    for r in message.records() {
        if r.flags().contains(RecordFlags::CF) {
            return Err(chunked());
        }
        out.push(
            (r.tnf() as u8, bin(env, r.record_type()), opt_bin(env, r.id()), bin(env, r.payload()))
                .encode(env),
        );
    }
    Ok((ok(), out))
}

/// Joins `{tnf, type, id | nil, payload}` records into an NDEF message.
#[rustler::nif]
fn ndef_encode<'a>(env: Env<'a>, records: Vec<RawRecord<'a>>) -> NifResult<(Atom, Term<'a>)> {
    if records.is_empty() {
        return Ok((ok(), bin(env, &[])));
    }
    let bad = || Error::Term(Box::new(atoms::bad_record()));
    let records = records
        .into_iter()
        .map(|(tnf, ty, id, payload)| {
            let tnf = TNF::from_repr(tnf).ok_or_else(bad)?;
            let body = ExternalPayload::from_raw(ty.as_slice().to_vec(), payload.as_slice().to_vec());
            NdefRecord::builder()
                .tnf(tnf)
                .payload(&body)
                .id(id.map(|i| i.as_slice().to_vec()).unwrap_or_default())
                .build()
                .map_err(|_| bad())
        })
        .collect::<NifResult<Vec<_>>>()?;
    let bytes = NdefMessage::from(records).to_buffer().map_err(|_| bad())?;
    Ok((ok(), bin(env, &bytes)))
}

/// The NFC Forum URI identifier codes: `%{code => prefix}`.
#[rustler::nif]
fn uri_prefixes() -> HashMap<u8, &'static str> {
    ndef_rs::URI_ABBREVIATIONS
        .iter()
        .map(|a| (a.as_byte(), a.as_uri()))
        .chain(once((0, "")))
        .collect()
}

rustler::init!("Elixir.ExNfc.Native");

