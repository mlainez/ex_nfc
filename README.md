# ex_nfc

> ### ⚠️ Very early work — built for a workshop, not for production
>
> Written for the **Goatmire Elixir workshop** on running Nerves on
> Fairphone 3 hardware. It exists for tinkering and teaching.
>
> **Not an actively maintained project** (yet) — no stability
> guarantees, no test coverage, APIs will change without notice.

Elixir client for the Linux kernel NFC subsystem.

Speaks `NETLINK_GENERIC` directly to the kernel's `nfc` family — no C
shim, no vendor daemon. Works with any in-kernel NCI controller
(`nxp-nci-i2c`, `s3fwrn5`, `st21nfca`, …) that exposes an `nfcN` device
under `/sys/class/nfc/`.

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

# Then, when a tag enters the field:
# {ExNfc, :tag_arrived, %{uid_hex: "04A2B3…", protocol: :iso14443_a, …}}
# {ExNfc, :tag_departed, %{idx: 1, device: "nfc0"}}
```

Controller hotplug arrives as `{ExNfc, :device_added | :device_removed,
%{index: i}}`.

### Read and write NDEF

```elixir
{:ok, records} = ExNfc.read_ndef(target)

ExNfc.write_ndef(target, [
  %{type: :text, text: "hello from Nerves"}
])
```

### Raw APDU exchange

```elixir
{:ok, conn} = ExNfc.open(target)
{:ok, response} = ExNfc.transceive(conn, payload, 2_000)
ExNfc.close(conn)
```

## Tag handling modes

In `:auto` mode the chip resumes polling after a tag leaves. In
`:manual` mode you call `deactivate/0` yourself — use this when you want
to hold a connection open across several `transceive/3` calls without the
controller re-polling underneath you.

## License

Apache-2.0
