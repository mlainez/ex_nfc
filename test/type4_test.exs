defmodule ExNfc.NDEF.Type4Test do
  use ExUnit.Case, async: true

  alias ExNfc.{FakeTag, NDEF}
  alias ExNfc.NDEF.Type4

  @aid <<0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01>>
  @ok <<0x90, 0x00>>

  defp cc(opts) do
    mle = Keyword.get(opts, :mle, 0x3B)
    mlc = Keyword.get(opts, :mlc, 0x34)
    max = Keyword.get(opts, :max, 0x0800)
    w = Keyword.get(opts, :write, 0x00)
    <<0x000F::16, 0x20, mle::16, mlc::16, 0x04, 0x06, 0xE1, 0x04, max::16, 0x00, w>>
  end

  defp tag_state(opts \\ []) do
    max = Keyword.get(opts, :max, 0x0800)

    %{
      app: false,
      file: nil,
      files: %{
        <<0xE1, 0x03>> => cc(opts),
        <<0xE1, 0x04>> => <<0, 0>> <> :binary.copy(<<0>>, max - 2)
      },
      log: []
    }
  end

  defp handler(apdu, s) do
    s = %{s | log: [apdu | s.log]}
    respond(apdu, s)
  end

  defp respond(<<0x00, 0xA4, 0x04, 0x00, 7, @aid::binary, 0x00>>, s), do: {@ok, %{s | app: true}}

  defp respond(<<0x00, 0xA4, 0x00, 0x0C, 2, fid::binary-size(2)>>, %{app: true} = s) do
    if Map.has_key?(s.files, fid), do: {@ok, %{s | file: fid}}, else: {<<0x6A, 0x82>>, s}
  end

  defp respond(<<0x00, 0xB0, off::16, le>>, %{file: f} = s) when f != nil do
    data = s.files[f]

    if off + le <= byte_size(data),
      do: {binary_part(data, off, le) <> @ok, s},
      else: {<<0x6B, 0x00>>, s}
  end

  defp respond(<<0x00, 0xD6, off::16, lc, chunk::binary-size(lc)>>, %{file: f} = s)
       when f != nil do
    data = s.files[f]
    <<pre::binary-size(^off), _::binary-size(^lc), post::binary>> = data
    {@ok, put_in(s.files[f], pre <> chunk <> post)}
  end

  defp respond(_apdu, s), do: {<<0x6D, 0x00>>, s}

  test "parse_cc" do
    assert {:ok,
            %Type4.CC{max_le: 0x3B, max_lc: 0x34, ndef_fid: <<0xE1, 0x04>>, max_ndef_size: 0x800}} =
             Type4.parse_cc(cc([]))

    assert {:error, :malformed_cc} = Type4.parse_cc(<<0x000F::16, 0x30, 0::32, 0x06, 0x08>>)
    assert {:error, :malformed_cc} = Type4.parse_cc(<<>>)
  end

  test "split_sw" do
    assert {:ok, "ab", @ok} = Type4.split_sw("ab" <> @ok)
    assert {:ok, "", <<0x6A, 0x82>>} = Type4.split_sw(<<0x6A, 0x82>>)
    assert {:error, :short_apdu_response} = Type4.split_sw(<<0x90>>)
    assert {:error, :short_apdu_response} = Type4.split_sw(<<>>)
  end

  test "write then read round trip, chunked to MLc / MLe" do
    {conn, tag} = FakeTag.start(&handler/2, tag_state(mle: 0x10, mlc: 0x0D))
    records = [NDEF.uri("https://elixir-lang.org"), NDEF.text(:binary.copy("abc", 30))]

    assert :ok = Type4.write(conn, records)
    assert {:ok, ^records} = Type4.read(conn)

    apdus = FakeTag.get_state(tag).log |> Enum.reverse()
    updates = for <<0x00, 0xD6, off::16, lc, data::binary-size(lc)>> <- apdus, do: {off, lc, data}

    # NLEN zeroed first, payload from offset 2, NLEN written last.
    assert {0, 2, <<0, 0>>} = hd(updates)
    nlen = byte_size(NDEF.encode(records))
    assert {0, 2, <<^nlen::16>>} = List.last(updates)
    assert Enum.all?(updates, fn {_, lc, _} -> lc <= 0x0D end)

    reads = for <<0x00, 0xB0, _off::16, le>> <- apdus, do: le
    assert Enum.all?(reads, &(&1 <= 0x10))
  end

  test "capacity check accounts for the 2-byte NLEN" do
    records = [NDEF.mime("a/b", :binary.copy("z", 20))]
    nlen = byte_size(NDEF.encode(records))

    {conn, _} = FakeTag.start(&handler/2, tag_state(max: nlen + 2))
    assert :ok = Type4.write(conn, records)
    assert {:ok, ^records} = Type4.read(conn)

    {conn, _} = FakeTag.start(&handler/2, tag_state(max: nlen + 1))
    assert {:error, {:tag_full, needed: needed, capacity: cap}} = Type4.write(conn, records)
    assert needed == nlen + 2 and cap == nlen + 1
  end

  test "read-only tag" do
    {conn, _} = FakeTag.start(&handler/2, tag_state(write: 0xFF))
    assert {:error, {:read_only, 0xFF}} = Type4.write(conn, [NDEF.text("x")])
  end

  test "empty tag reads as no records" do
    {conn, _} = FakeTag.start(&handler/2, tag_state())
    assert {:ok, []} = Type4.read(conn)
  end

  test "APDU errors and short responses are returned, not raised" do
    {conn, _} = FakeTag.start(fn _apdu, s -> {<<0x6A, 0x82>>, s} end, nil)
    assert {:error, {:apdu_status, 0x6A, 0x82}} = Type4.read(conn)

    {conn, _} = FakeTag.start(fn _apdu, s -> {<<0x90>>, s} end, nil)
    assert {:error, :short_apdu_response} = Type4.read(conn)

    {conn, _} = FakeTag.start(fn _apdu, s -> {<<>>, s} end, nil)
    assert {:error, :short_apdu_response} = Type4.write(conn, [NDEF.text("x")])
  end
end
