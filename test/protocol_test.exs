defmodule ExNfc.ProtocolTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias ExNfc.Protocol

  # A GET_TARGET dump part as ExNfc.Native.get_targets/2 returns it.
  defp attrs(overrides) do
    Map.merge(
      %{
        target_index: 1,
        protocols: nil,
        sens_res: nil,
        sel_res: nil,
        nfcid1: nil,
        sensb_res: nil,
        sensf_res: nil,
        ats: nil,
        iso15693_uid: nil,
        iso15693_dsfid: nil
      },
      overrides
    )
  end

  test "target/3 builds the :tag_arrived map" do
    t =
      attrs(%{
        target_index: 3,
        protocols: 1 <<< 4,
        sens_res: 0x0344,
        sel_res: 0x20,
        nfcid1: <<0x04, 0x52, 0x89, 0x22>>,
        ats: <<0x05, 0x78>>
      })
      |> Protocol.target(0, "nfc0")

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

  test "target/3 with an ISO 15693 target uses its UID" do
    uid = <<0xE0, 1, 2, 3, 4, 5, 6, 7>>
    t = Protocol.target(attrs(%{protocols: 1 <<< 7, iso15693_uid: uid}), 1, "nfc1")
    assert t.protocol == :iso15693
    assert t.uid_hex == "E001020304050607"
  end

  test "protocol helpers" do
    assert {:ok, 2} = Protocol.value(:mifare)
    assert {:ok, 4} = Protocol.value(:iso14443_a)
    assert {:ok, 4} = Protocol.value(:iso14443)
    assert {:ok, 6} = Protocol.value(:iso14443_b)
    assert {:ok, 9} = Protocol.value(9)
    assert :error = Protocol.value(:bogus)

    assert Protocol.first(1 <<< 2) == :mifare
    assert Protocol.first(nil) == nil
    assert Protocol.first(1) == 1

    # Jewel, MIFARE, FeliCa, ISO14443, ISO14443-B, ISO15693 — no NFC-DEP
    assert Protocol.tag_mask() == 0b11011110
    assert Protocol.nfc_dep_mask() == 0b100000
  end
end
