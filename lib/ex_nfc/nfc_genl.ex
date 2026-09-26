# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.NfcGenl do
  @moduledoc false
  # Encoders / decoders for the kernel `nfc` generic-netlink family
  # (include/uapi/linux/nfc.h, net/nfc/netlink.c). Pure functions only —
  # the socket handling lives in `ExNfc.Controller`.

  import Bitwise

  alias ExNfc.Netlink

  # ---- Commands / events (enum nfc_commands) ------------------------------

  @cmd_get_device 1
  @cmd_dev_up 2
  @cmd_dev_down 3
  @cmd_start_poll 6
  @cmd_stop_poll 7
  @cmd_get_target 8
  @event_targets_found 9
  @event_device_added 10
  @event_device_removed 11
  @event_target_lost 12
  @cmd_deactivate_target 30

  def cmd_get_device, do: @cmd_get_device
  def cmd_dev_up, do: @cmd_dev_up
  def cmd_dev_down, do: @cmd_dev_down
  def cmd_start_poll, do: @cmd_start_poll
  def cmd_stop_poll, do: @cmd_stop_poll
  def cmd_get_target, do: @cmd_get_target
  def cmd_deactivate_target, do: @cmd_deactivate_target

  # ---- Attributes (enum nfc_attrs) ----------------------------------------

  @attr_device_index 1
  @attr_device_name 2
  @attr_protocols 3
  @attr_target_index 4
  @attr_target_sens_res 5
  @attr_target_sel_res 6
  @attr_target_nfcid1 7
  @attr_target_sensb_res 8
  @attr_target_sensf_res 9
  @attr_device_powered 12
  @attr_im_protocols 13
  @attr_tm_protocols 14
  @attr_target_iso15693_dsfid 26
  @attr_target_iso15693_uid 27
  @attr_target_ats 32

  # ---- Protocols (NFC_PROTO_*, 1-indexed shift values) ---------------------

  @proto_jewel 1
  @proto_mifare 2
  @proto_felica 3
  @proto_iso14443 4
  @proto_nfc_dep 5
  @proto_iso14443_b 6
  @proto_iso15693 7

  @protocols [
    {@proto_jewel, :jewel},
    {@proto_mifare, :mifare},
    {@proto_felica, :felica},
    {@proto_iso14443, :iso14443_a},
    {@proto_iso14443_b, :iso14443_b},
    {@proto_iso15693, :iso15693},
    {@proto_nfc_dep, :nfc_dep}
  ]

  @doc "Bitmask of every tag (non peer-to-peer) protocol."
  def tag_protocols_mask do
    Enum.reduce(@protocols, 0, fn
      {@proto_nfc_dep, _}, acc -> acc
      {shift, _}, acc -> acc ||| bsl(1, shift)
    end)
  end

  @doc "Bit for NFC-DEP (peer-to-peer)."
  def nfc_dep_mask, do: bsl(1, @proto_nfc_dep)

  @doc "Translate a protocol atom (or raw `NFC_PROTO_*` value) to the raw value."
  @spec protocol_value(atom() | non_neg_integer()) :: {:ok, non_neg_integer()} | :error
  def protocol_value(n) when is_integer(n) and n >= 0, do: {:ok, n}
  def protocol_value(:iso14443), do: {:ok, @proto_iso14443}

  def protocol_value(atom) when is_atom(atom) do
    case List.keyfind(@protocols, atom, 1) do
      {n, ^atom} -> {:ok, n}
      nil -> :error
    end
  end

  def protocol_value(_), do: :error

  @doc "Pick the first protocol set in a `NFC_ATTR_PROTOCOLS` bitmask."
  @spec decode_first_protocol(non_neg_integer() | nil) :: atom() | non_neg_integer() | nil
  def decode_first_protocol(nil), do: nil

  def decode_first_protocol(mask) when is_integer(mask) do
    Enum.find_value(@protocols, mask, fn {shift, name} ->
      if (mask &&& bsl(1, shift)) != 0, do: name
    end)
  end

  # ---- Request attribute builders ------------------------------------------

  def device_attrs(idx), do: Netlink.nla_u32(@attr_device_index, idx)

  def start_poll_attrs(idx, im_protocols, tm_protocols \\ 0) do
    IO.iodata_to_binary([
      Netlink.nla_u32(@attr_device_index, idx),
      Netlink.nla_u32(@attr_im_protocols, im_protocols),
      Netlink.nla_u32(@attr_tm_protocols, tm_protocols)
    ])
  end

  def target_attrs(idx, target_idx) do
    IO.iodata_to_binary([
      Netlink.nla_u32(@attr_device_index, idx),
      Netlink.nla_u32(@attr_target_index, target_idx)
    ])
  end

  # ---- Reply / event decoders ----------------------------------------------

  @doc """
  Decode a `CTRL_CMD_GETFAMILY` reply body (genl header included).
  """
  def parse_family_reply(<<_cmd::8, _ver::8, _rsvd::16, attrs::binary>>) do
    parsed = Netlink.parse_attrs(attrs)

    case Netlink.find_attr(parsed, Netlink.ctrl_attr_family_id()) do
      <<fid::little-16, _::binary>> ->
        {:ok, %{family_id: fid, events_group: find_mcast_group(parsed, "events")}}

      _ ->
        {:error, :family_not_found}
    end
  end

  def parse_family_reply(_), do: {:error, :family_not_found}

  defp find_mcast_group(attrs, name) do
    case Netlink.find_attr(attrs, Netlink.ctrl_attr_mcast_groups()) do
      nil ->
        nil

      groups_bin ->
        groups_bin
        |> Netlink.parse_attrs()
        |> Enum.find_value(fn {_idx, body} ->
          inner = Netlink.parse_attrs(body)

          with name_bin when is_binary(name_bin) <-
                 Netlink.find_attr(inner, Netlink.ctrl_attr_mcast_grp_name()),
               ^name <- cstring(name_bin),
               <<gid::little-32>> <- Netlink.find_attr(inner, Netlink.ctrl_attr_mcast_grp_id()) do
            gid
          else
            _ -> nil
          end
        end)
    end
  end

  @doc "Decode a `NFC_CMD_GET_DEVICE` reply / `NFC_EVENT_DEVICE_ADDED` body."
  def parse_device(<<_cmd::8, _ver::8, _rsvd::16, attrs::binary>>) do
    parsed = Netlink.parse_attrs(attrs)

    %{
      index: u32(parsed, @attr_device_index),
      name: string(parsed, @attr_device_name),
      protocols: u32(parsed, @attr_protocols),
      powered: u8(parsed, @attr_device_powered) == 1
    }
  end

  @doc """
  Decode a `NFC_CMD_GET_TARGET` dump part into the target map broadcast
  with `:tag_arrived`. `device_index` / `device_name` identify the
  controller the target was found on (the dump itself doesn't carry them).
  """
  def parse_target(<<_cmd::8, _ver::8, _rsvd::16, attrs::binary>>, device_index, device_name) do
    parsed = Netlink.parse_attrs(attrs)
    nfcid1 = Netlink.find_attr(parsed, @attr_target_nfcid1)
    iso15693_uid = Netlink.find_attr(parsed, @attr_target_iso15693_uid)
    protocols = u32(parsed, @attr_protocols)

    %{
      device_index: device_index,
      device: device_name,
      target_index: u32(parsed, @attr_target_index),
      protocol: decode_first_protocol(protocols),
      protocols: protocols,
      nfcid1: nfcid1,
      uid_hex: (nfcid1 && hex(nfcid1)) || (iso15693_uid && hex(iso15693_uid)),
      sens_res: u16(parsed, @attr_target_sens_res),
      sel_res: u8(parsed, @attr_target_sel_res),
      sensb_res: Netlink.find_attr(parsed, @attr_target_sensb_res),
      sensf_res: Netlink.find_attr(parsed, @attr_target_sensf_res),
      ats: Netlink.find_attr(parsed, @attr_target_ats),
      iso15693_uid: iso15693_uid,
      iso15693_dsfid: u8(parsed, @attr_target_iso15693_dsfid)
    }
  end

  @doc """
  Classify a multicast event body from the `events` group.
  """
  def parse_event(<<cmd::8, _ver::8, _rsvd::16, attrs::binary>> = body) do
    parsed = Netlink.parse_attrs(attrs)

    case cmd do
      @event_targets_found ->
        {:targets_found, u32(parsed, @attr_device_index)}

      @event_target_lost ->
        {:target_lost, u32(parsed, @attr_device_index), u32(parsed, @attr_target_index)}

      @event_device_added ->
        {:device_added, parse_device(body)}

      @event_device_removed ->
        {:device_removed, u32(parsed, @attr_device_index)}

      _ ->
        :ignore
    end
  end

  def parse_event(_), do: :ignore

  # ---- errno --------------------------------------------------------------

  @errno %{
    1 => :eperm,
    2 => :enoent,
    5 => :eio,
    11 => :eagain,
    12 => :enomem,
    13 => :eacces,
    16 => :ebusy,
    17 => :eexist,
    19 => :enodev,
    22 => :einval,
    32 => :epipe,
    71 => :eproto,
    90 => :emsgsize,
    95 => :eopnotsupp,
    97 => :eafnosupport,
    105 => :enobufs,
    106 => :eisconn,
    107 => :enotconn,
    110 => :etimedout,
    111 => :econnrefused,
    114 => :ealready,
    121 => :eremoteio,
    132 => :erfkill
  }

  @doc "Map a positive errno to an atom; unknown values pass through."
  def errno_to_atom(n) when is_integer(n), do: Map.get(@errno, n, n)

  # ---- Small decoders -----------------------------------------------------

  defp u32(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      <<n::little-32>> -> n
      _ -> nil
    end
  end

  defp u16(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      <<n::little-16>> -> n
      _ -> nil
    end
  end

  defp u8(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      <<n::8>> -> n
      _ -> nil
    end
  end

  defp string(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      nil -> nil
      bin -> cstring(bin)
    end
  end

  defp cstring(bin) do
    case :binary.split(bin, <<0>>) do
      [s | _] -> s
    end
  end

  defp hex(bin), do: Base.encode16(bin)
end
