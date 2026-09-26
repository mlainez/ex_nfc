defmodule ExNfc.NDEF.Type2Test do
  use ExUnit.Case, async: true

  alias ExNfc.{FakeTag, NDEF}
  alias ExNfc.NDEF.Type2

  # NTAG213-like memory: 45 pages; CC = E1 10 12 00 (144-byte data area).
  defp blank_tag(cc \\ <<0xE1, 0x10, 0x12, 0x00>>, data \\ <<0x03, 0x00, 0xFE>>) do
    header = :binary.copy(<<0>>, 12) <> cc
    data = data <> :binary.copy(<<0>>, 144 - byte_size(data))
    header <> data <> :binary.copy(<<0>>, 45 * 4 - 16 - 144)
  end

  defp handler(<<0x30, page>>, %{mem: mem} = s) do
    mem2 = mem <> mem
    {binary_part(mem2, page * 4, 16), s}
  end

  defp handler(<<0xA2, page, data::binary-size(4)>>, %{mem: mem, log: log} = s) do
    <<pre::binary-size(^page * 4), _::binary-size(4), post::binary>> = mem
    {<<0x0A>>, %{s | mem: pre <> data <> post, log: [{page, data} | log]}}
  end

  defp start(mem), do: FakeTag.start(&handler/2, %{mem: mem, log: []})

  test "parse_cc" do
    assert {:ok, 144} = Type2.parse_cc(<<0xE1, 0x10, 0x12, 0x00>>)
    assert {:ok, 48} = Type2.parse_cc(<<0xE1, 0x10, 0x06, 0x00, 1, 2, 3>>)
    assert {:error, :not_ndef_formatted} = Type2.parse_cc(<<0, 0, 0, 0>>)
    assert {:error, :not_ndef_formatted} = Type2.parse_cc(<<0xE1>>)
  end

  test "extract_ndef_tlv skips NULL and control TLVs" do
    assert {:ok, "abc"} = Type2.extract_ndef_tlv(<<0x03, 3, "abc", 0xFE>>)
    assert {:ok, "abc"} = Type2.extract_ndef_tlv(<<0, 0, 0x03, 3, "abc">>)

    assert {:ok, "ab"} =
             Type2.extract_ndef_tlv(
               <<0x01, 3, 0xA0, 0x0C, 0x34, 0x02, 3, 1, 2, 3, 0x03, 2, "ab">>
             )

    long = :binary.copy("x", 300)
    assert {:ok, ^long} = Type2.extract_ndef_tlv(<<0x03, 0xFF, 300::16, long::binary, 0xFE>>)
    assert {:ok, ""} = Type2.extract_ndef_tlv(<<0x03, 0, 0xFE>>)
  end

  test "extract_ndef_tlv errors" do
    assert {:error, :no_ndef_tlv} = Type2.extract_ndef_tlv(<<0xFE, 0x03, 1, 0>>)
    assert {:error, :no_ndef_tlv} = Type2.extract_ndef_tlv(<<0, 0>>)
    assert {:error, :malformed_tlv} = Type2.extract_ndef_tlv(<<0x03, 10, "abc">>)
  end

  test "wrap_tlv uses 1- or 3-byte lengths" do
    assert Type2.wrap_tlv("ab") == <<0x03, 2, "ab", 0xFE>>
    ndef = :binary.copy("y", 254)
    assert <<0x03, 254, _::binary-size(254), 0xFE>> = Type2.wrap_tlv(ndef)
    ndef = :binary.copy("y", 255)
    assert <<0x03, 0xFF, 255::16, _::binary-size(255), 0xFE>> = Type2.wrap_tlv(ndef)
  end

  test "write then read round trip on a fake tag" do
    {conn, tag} = start(blank_tag())
    records = [NDEF.uri("https://elixir-lang.org"), NDEF.text("hello")]

    assert :ok = Type2.write(conn, records)
    assert {:ok, ^records} = Type2.read(conn)

    # First page written with zero length, rewritten with the real one last.
    log = FakeTag.get_state(tag).log |> Enum.reverse()
    assert [{4, <<0x03, 0x00, _, _>>} | _] = log
    assert {4, <<0x03, len, _, _>>} = List.last(log)
    assert len == byte_size(NDEF.encode(records))
  end

  test "long NDEF message uses the 3-byte TLV length" do
    {conn, _tag} = FakeTag.start(&handler/2, %{mem: big_tag(), log: []})
    records = [NDEF.mime("text/plain", :binary.copy("q", 400))]
    assert :ok = Type2.write(conn, records)
    assert {:ok, ^records} = Type2.read(conn)
  end

  defp big_tag do
    # NTAG216-like: 888-byte data area (CC size byte 0x6F), 231 pages.
    header = :binary.copy(<<0>>, 12) <> <<0xE1, 0x10, 0x6F, 0x00>>
    header <> <<0x03, 0, 0xFE>> <> :binary.copy(<<0>>, 231 * 4 - 16 - 3)
  end

  test "read an empty NDEF message" do
    {conn, _} = start(blank_tag())
    assert {:ok, []} = Type2.read(conn)
  end

  test "refuses writes that don't fit, to read-only or unformatted tags" do
    {conn, _} = start(blank_tag(<<0xE1, 0x10, 0x02, 0x00>>))

    assert {:error, {:tag_full, needed: _, capacity: 16}} =
             Type2.write(conn, [NDEF.text("too long for this")])

    {conn, _} = start(blank_tag(<<0xE1, 0x10, 0x12, 0x0F>>))
    assert {:error, :read_only} = Type2.write(conn, [NDEF.text("x")])

    {conn, _} = start(blank_tag(<<0, 0, 0, 0>>))
    assert {:error, :not_ndef_formatted} = Type2.read(conn)
  end

  test "NAKs are reported" do
    nak = fn _frame, s -> {<<0x00>>, s} end
    {conn, _} = FakeTag.start(nak, nil)
    assert {:error, {:read_failed, 3, <<0>>}} = Type2.read(conn)
  end
end
