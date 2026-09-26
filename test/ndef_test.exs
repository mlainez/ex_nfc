defmodule ExNfc.NDEFTest do
  use ExUnit.Case, async: true

  alias ExNfc.NDEF
  alias ExNfc.NDEF.Record

  doctest ExNfc.NDEF

  defp roundtrip(records) do
    assert {:ok, decoded} = records |> NDEF.encode() |> NDEF.decode()
    decoded
  end

  test "empty message" do
    assert NDEF.encode([]) == <<>>
    assert {:ok, []} = NDEF.decode(<<>>)
  end

  test "URI round trip with prefix abbreviation" do
    for url <- ["https://elixir-lang.org", "http://www.x.y", "tel:+3212345", "custom:thing"] do
      assert [rec] = roundtrip([NDEF.uri(url)])
      assert NDEF.uri_value(rec) == url
    end

    assert NDEF.uri("custom:thing").payload == <<0x00, "custom:thing">>
  end

  test "text round trip keeps language and UTF-8" do
    assert [rec] = roundtrip([NDEF.text("héllo wörld", lang: "de")])
    assert NDEF.text_value(rec) == {"de", "héllo wörld"}
    assert NDEF.uri_value(rec) == nil
  end

  test "MIME record round trip" do
    rec = NDEF.mime("application/json", ~s({"a":1}))
    assert [^rec] = roundtrip([rec])
    assert NDEF.text_value(rec) == nil
  end

  test "multiple records get MB on the first and ME on the last" do
    records = [NDEF.uri("https://a.b"), NDEF.text("x"), NDEF.mime("a/b", "c")]
    bin = NDEF.encode(records)
    assert <<1::1, 0::1, _::6, _::binary>> = bin
    assert roundtrip(records) == records

    [_, second | _] = split_headers(bin)
    assert <<0::1, 0::1, _::6>> = second
  end

  test "single record has MB and ME, SR set for short payloads" do
    assert <<0xD1, 1, 2, "T", _::binary>> = NDEF.encode([NDEF.text("", lang: "a")])
  end

  test "long record (>= 256 byte payload) uses a 4-byte length" do
    rec = NDEF.mime("a/b", :binary.copy("z", 300))
    bin = NDEF.encode([rec])
    assert <<0xC2, 3, 300::big-32, "a/b", _::binary-size(300)>> = bin
    assert [^rec] = roundtrip([rec])
  end

  test "record id is encoded with the IL flag" do
    rec = %Record{tnf: :external, type: "example.com:t", id: "id1", payload: "p"}
    assert <<0xDC, 13, 1, 3, "example.com:t", "id1", "p">> = NDEF.encode([rec])
    assert [^rec] = roundtrip([rec])
  end

  test "malformed and chunked input" do
    assert {:error, :malformed_ndef} = NDEF.decode(<<0xD1, 0x01, 0x10, "U", 0x04, "short">>)
    assert {:error, :malformed_ndef} = NDEF.decode(<<0xD1>>)
    assert {:error, :chunked_record_unsupported} = NDEF.decode(<<0xB1, 1, 1, "T", 0>>)
  end

  # Returns the header byte of each record in a message of short records
  # without IDs.
  defp split_headers(<<>>), do: []

  defp split_headers(<<h::binary-size(1), tl, pl, rest::binary>>) do
    <<_::binary-size(^tl + ^pl), rest::binary>> = rest
    [h | split_headers(rest)]
  end
end
