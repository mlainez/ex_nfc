# ex_nfc

> ### ⚠️ Very early work — built for a workshop, not for production
>
> Written for the **Goatmire Elixir workshop** on running Nerves on Fairphone 3 hardware. There are no stability guarantees and APIs will change without notice.

Elixir client for the Linux kernel NFC subsystem.

Speaks `NETLINK_GENERIC` directly to the kernel's `nfc` family and uses
`AF_NFC` sockets for data exchange — pure Elixir on OTP `:socket`, no C
shim, no vendor daemon. Works with in-kernel NCI controllers
(`nxp-nci-i2c`, `s3fwrn5`, `st21nfca`, …) that expose an `nfcN` device
under `/sys/class/nfc/`.

## Status

* Tag detection (polling, `:tag_arrived` / `:tag_departed` events) was
  used on the Fairphone 3 (NXP NCI controller). The controller has since
  been reworked (separate request/event sockets, tag release via
  `NFC_CMD_DEACTIVATE_TARGET`, graceful degradation without NFC); the
  netlink plumbing is exercised against a real host kernel in the test
  suite, but the new version **has not yet been re-verified on the device**.
* Raw data exchange (`ExNfc.connect/1`, `ExNfc.transceive/3`) and NDEF
  read/write (`ExNfc.read_ndef/2`, `ExNfc.write_ndef/3`) were fixed after
  a review against the kernel sources (`AF_NFC` socket type, `sockaddr_nfc`
  layout, tag release) and are covered by host tests against a simulated
  tag, but **tag read/write has not been verified on the device since
  those fixes**.

## Requirements

* Linux kernel with `CONFIG_NFC` and `CONFIG_NFC_NCI`, plus the driver for
  your controller (e.g. `CONFIG_NFC_NXP_NCI` + `CONFIG_NFC_NXP_NCI_I2C` on
  the Fairphone 3). The modules auto-load: the `nfc` module when the
  generic-netlink family is first requested, the driver from the device
  tree / ACPI match.
* `CAP_NET_ADMIN` for the NFC commands (power, polling); on Nerves the
  application runs as root.

On a machine without NFC support the controller stays in the
`:unavailable` state and every call returns `{:error, :nfc_unavailable}`;
it keeps retrying in the background and never takes the application down.

## Toolchain

Built and tested with Erlang/OTP 29.1.1 and Elixir 1.20.4, matching the official Nerves systems (see `.tool-versions`).

## Install

```elixir
defp deps do
  [{:ex_nfc, github: "mlainez/ex_nfc"}]
end
```

## Usage

### Subscribe to tag events

```elixir
ExNfc.subscribe()

# When a tag enters the field:
# {ExNfc, :tag_arrived, %{uid_hex: "04A2B3…", protocol: :mifare,
#                         target_index: 1, device_index: 0, device: "nfc0", …}}
# {ExNfc, :tag_departed, %{target_index: 1, device_index: 0, device: "nfc0"}}
```

Controller hotplug arrives as
`{ExNfc, :device_added, %{index: i, name: "nfc0", protocols: mask}}` and
`{ExNfc, :device_removed, %{index: i}}`.

`ExNfc.state/0` returns `:unavailable | :no_device | :down | :idle |
:polling | :tag_active`. `ExNfc.list_devices/0` returns `{:ok, devices}`.

### Tag handling modes

Set with `config :ex_nfc, controller: [resume_after_tap: mode]`:

* `:auto` (default) — right after `:tag_arrived` the controller releases
  the tag and restarts polling, so every tap produces `:tag_arrived`
  followed by `:tag_departed`. You cannot talk to the tag in this mode.
* `:manual` — the controller stays in `:tag_active` until you call
  `ExNfc.deactivate/0` (or `ExNfc.start_polling/0`). Use this to read,
  write or exchange frames with the tag.

In both modes polling resumes by itself when the kernel reports that the
active tag left the field. Other controller options: `autostart: false`
(don't power up / poll at boot), `device_index: n`, `poll_protocols: mask`.
Set `config :ex_nfc, log_events: false` to silence the built-in event
logger.

### Read and write NDEF (`:manual` mode)

```elixir
receive do
  {ExNfc, :tag_arrived, target} ->
    {:ok, records} = ExNfc.read_ndef(target)
    Enum.map(records, &ExNfc.NDEF.uri_value/1)

    :ok = ExNfc.write_ndef(target, [
      ExNfc.NDEF.uri("https://elixir-lang.org"),
      ExNfc.NDEF.text("hello from Nerves")
    ])

    ExNfc.deactivate()
end
```

Type 2 tags (NTAG / MIFARE Ultralight, protocol `:mifare`) and Type 4
tags (ISO-DEP, `:iso14443_a` / `:iso14443_b`) are supported.

### Raw frame exchange (`:manual` mode)

```elixir
{:ok, conn} = ExNfc.connect(target)
{:ok, response} = ExNfc.transceive(conn, apdu, 2_000)
ExNfc.Connection.close(conn)
ExNfc.deactivate()
```

## Development

```sh
mix test   # no NFC hardware needed
```

## License

Apache-2.0
