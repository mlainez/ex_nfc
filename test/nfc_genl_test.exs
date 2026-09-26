defmodule ExNfc.NfcGenlTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias ExNfc.{Netlink, NfcGenl}

  defp genl(cmd, attrs), do: IO.iodata_to_binary([<<cmd, 1, 0, 0>>, attrs])

  test "command ids match include/uapi/linux/nfc.h" do
    assert NfcGenl.cmd_get_device() == 1
    assert NfcGenl.cmd_dev_up() == 2
    assert NfcGenl.cmd_dev_down() == 3
    assert NfcGenl.cmd_start_poll() == 6
    assert NfcGenl.cmd_stop_poll() == 7
    assert NfcGenl.cmd_get_target() == 8
    assert NfcGenl.cmd_deactivate_target() == 30
  end

  test "parse_family_reply extracts family id and the events group" do
    group = fn idx, name, id ->
      Netlink.nla(
        idx ||| 0x8000,
        [Netlink.nla_u32(2, id), Netlink.nla_string(1, name)]
      )
    end

    attrs = [
      Netlink.nla_string(2, "nfc"),
      Netlink.nla(1, <<31::little-16>>),
      Netlink.nla(7 ||| 0x8000, [group.(1, "other", 3), group.(2, "events", 9)])
    ]

    assert {:ok, %{family_id: 31, events_group: 9}} =
             NfcGenl.parse_family_reply(genl(1, attrs))

    assert {:ok, %{family_id: 31, events_group: nil}} =
             NfcGenl.parse_family_reply(genl(1, Netlink.nla(1, <<31::little-16>>)))

    assert {:error, :family_not_found} = NfcGenl.parse_family_reply(genl(1, []))
  end

  test "parse_device" do
    body =
      genl(1, [
        Netlink.nla_string(2, "nfc0"),
        Netlink.nla_u32(1, 0),
        Netlink.nla_u32(3, 0xDE),
        Netlink.nla(12, <<1>>),
        Netlink.nla(11, <<0>>)
      ])

    assert NfcGenl.parse_device(body) == %{index: 0, name: "nfc0", protocols: 0xDE, powered: true}
  end

  test "parse_target decodes a GET_TARGET dump part and carries the device" do
    body =
      genl(8, [
        Netlink.nla_u32(4, 3),
        Netlink.nla_u32(3, 1 <<< 4),
        Netlink.nla(5, <<0x0344::little-16>>),
        Netlink.nla(6, <<0x20>>),
        Netlink.nla(7, <<0x04, 0x52, 0x89, 0x22>>),
        Netlink.nla(32, <<0x05, 0x78>>)
      ])

    t = NfcGenl.parse_target(body, 0, "nfc0")
    assert t.device_index == 0
    assert t.device == "nfc0"
    assert t.target_index == 3
    assert t.protocol == :iso14443_a
    assert t.protocols == 16
    assert t.uid_hex == "04528922"
    assert t.sens_res == 0x0344
    assert t.sel_res == 0x20
    assert t.ats == <<0x05, 0x78>>
    assert t.sensb_res == nil
  end

  test "parse_target with an ISO 15693 target uses its UID" do
    uid = <<0xE0, 1, 2, 3, 4, 5, 6, 7>>
    body = genl(8, [Netlink.nla_u32(4, 1), Netlink.nla_u32(3, 1 <<< 7), Netlink.nla(27, uid)])
    t = NfcGenl.parse_target(body, 1, "nfc1")
    assert t.protocol == :iso15693
    assert t.uid_hex == "E001020304050607"
  end

  test "parse_event classifies multicast events" do
    assert {:targets_found, 0} = NfcGenl.parse_event(genl(9, Netlink.nla_u32(1, 0)))

    assert {:target_lost, 0, 2} =
             NfcGenl.parse_event(genl(12, [Netlink.nla_u32(1, 0), Netlink.nla_u32(4, 2)]))

    assert {:device_added, %{index: 1, name: "nfc1"}} =
             NfcGenl.parse_event(genl(10, [Netlink.nla_u32(1, 1), Netlink.nla_string(2, "nfc1")]))

    assert {:device_removed, 1} = NfcGenl.parse_event(genl(11, Netlink.nla_u32(1, 1)))
    assert :ignore = NfcGenl.parse_event(genl(13, []))
    assert :ignore = NfcGenl.parse_event(<<1>>)
  end

  test "protocol helpers" do
    assert {:ok, 2} = NfcGenl.protocol_value(:mifare)
    assert {:ok, 4} = NfcGenl.protocol_value(:iso14443_a)
    assert {:ok, 4} = NfcGenl.protocol_value(:iso14443)
    assert {:ok, 6} = NfcGenl.protocol_value(:iso14443_b)
    assert {:ok, 9} = NfcGenl.protocol_value(9)
    assert :error = NfcGenl.protocol_value(:bogus)

    assert NfcGenl.decode_first_protocol(1 <<< 2) == :mifare
    assert NfcGenl.decode_first_protocol(nil) == nil
    assert NfcGenl.decode_first_protocol(1) == 1

    # Jewel, MIFARE, FeliCa, ISO14443, ISO14443-B, ISO15693 — no NFC-DEP
    assert NfcGenl.tag_protocols_mask() == 0b11011110
    assert NfcGenl.nfc_dep_mask() == 0b100000
  end

  test "request attribute builders" do
    assert [{1, <<0::little-32>>}, {13, <<6::little-32>>}, {14, <<0::little-32>>}] =
             Netlink.parse_attrs(NfcGenl.start_poll_attrs(0, 6))

    assert [{1, <<1::little-32>>}, {4, <<5::little-32>>}] =
             Netlink.parse_attrs(NfcGenl.target_attrs(1, 5))
  end

  test "errno mapping" do
    assert NfcGenl.errno_to_atom(16) == :ebusy
    assert NfcGenl.errno_to_atom(107) == :enotconn
    assert NfcGenl.errno_to_atom(9999) == 9999
  end
end
