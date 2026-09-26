# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.NDEF do
  @moduledoc """
  NFC Data Exchange Format — pure-binary parser/serializer.

  NDEF is a tag-agnostic record container defined by the NFC Forum.
  This module operates on the raw byte stream: parse it after reading
  the payload off a tag (`ExNfc.NDEF.Type2.read/1`, `Type4.read/1`),
  serialize it before writing one back.

  ## Records

  Each record is represented as a struct:

      %ExNfc.NDEF.Record{
        tnf: :well_known | :mime | :uri | :external | :empty | :unknown | :unchanged,
        type: binary(),
        id: binary() | nil,
        payload: binary()
      }

  Helpers are provided for the most common shapes:

    * `uri/1`  → a single Well-Known URI record (`"U"`)
    * `text/2` → a single Well-Known Text record (`"T"`)
    * `mime/2` → a MIME-typed record

  Build a full message with `encode/1`:

      iex> ExNfc.NDEF.encode([ExNfc.NDEF.uri("https://elixir-lang.org")])
      <<0xD1, 0x01, 0x10, "U", 0x04, "elixir-lang.org">>

  Parse with `decode/1`:

      iex> ExNfc.NDEF.decode(<<0xD1, 0x01, 0x10, "U", 0x04, "elixir-lang.org">>)
      {:ok, [%ExNfc.NDEF.Record{tnf: :well_known, type: "U", id: nil, payload: <<0x04, "elixir-lang.org">>}]}

  and read the values back:

      iex> {:ok, [record]} = ExNfc.NDEF.decode(<<0xD1, 0x01, 0x10, "U", 0x04, "elixir-lang.org">>)
      iex> ExNfc.NDEF.uri_value(record)
      "https://elixir-lang.org"

  Chunked records (`CF` flag) are not supported and decode to
  `{:error, :chunked_record_unsupported}`.
  """

  import Bitwise
  alias ExNfc.NDEF.Record

  @tnf %{
    0x00 => :empty,
    0x01 => :well_known,
    0x02 => :mime,
    0x03 => :uri,
    0x04 => :external,
    0x05 => :unknown,
    0x06 => :unchanged
  }
  @tnf_inv Map.new(@tnf, fn {k, v} -> {v, k} end)

  # NFC Forum URI prefix table (NFC Forum URI RTD 1.0, table 3).
  @uri_prefixes %{
    0x00 => "",
    0x01 => "http://www.",
    0x02 => "https://www.",
    0x03 => "http://",
    0x04 => "https://",
    0x05 => "tel:",
    0x06 => "mailto:",
    0x07 => "ftp://anonymous:anonymous@",
    0x08 => "ftp://ftp.",
    0x09 => "ftps://",
    0x0A => "sftp://",
    0x0B => "smb://",
    0x0C => "nfs://",
    0x0D => "ftp://",
    0x0E => "dav://",
    0x0F => "news:",
    0x10 => "telnet://",
    0x11 => "imap:",
    0x12 => "rtsp://",
    0x13 => "urn:",
    0x14 => "pop:",
    0x15 => "sip:",
    0x16 => "sips:",
    0x17 => "tftp:",
    0x18 => "btspp://",
    0x19 => "btl2cap://",
    0x1A => "btgoep://",
    0x1B => "tcpobex://",
    0x1C => "irdaobex://",
    0x1D => "file://",
    0x1E => "urn:epc:id:",
    0x1F => "urn:epc:tag:",
    0x20 => "urn:epc:pat:",
    0x21 => "urn:epc:raw:",
    0x22 => "urn:epc:",
    0x23 => "urn:nfc:"
  }

  defmodule Record do
    @moduledoc "A single NDEF record. See `ExNfc.NDEF`."

    @type tnf ::
            :empty | :well_known | :mime | :uri | :external | :unknown | :unchanged

    @type t :: %__MODULE__{
            tnf: tnf(),
            type: binary(),
            id: binary() | nil,
            payload: binary()
          }

    defstruct tnf: :well_known, type: "", id: nil, payload: ""
  end

  # ---- Convenience constructors ------------------------------------------

  @doc """
  Build a Well-Known URI record. The longest matching prefix from the
  NFC Forum table is encoded as a 1-byte abbreviation so the record
  is as compact as possible.

      iex> ExNfc.NDEF.uri("https://www.example.com")
      %ExNfc.NDEF.Record{tnf: :well_known, type: "U", id: nil, payload: <<0x02, "example.com">>}
  """
  @spec uri(String.t()) :: Record.t()
  def uri(url) when is_binary(url) do
    {prefix_byte, rest} = pick_uri_prefix(url)
    %Record{tnf: :well_known, type: "U", payload: <<prefix_byte::8, rest::binary>>}
  end

  @doc """
  Build a Well-Known Text record (UTF-8). The language tag defaults to
  `"en"`; pass `lang: "fr"` to change it.

      iex> ExNfc.NDEF.text("hi", lang: "fr")
      %ExNfc.NDEF.Record{tnf: :well_known, type: "T", id: nil, payload: <<2, "fr", "hi">>}
  """
  @spec text(String.t(), keyword()) :: Record.t()
  def text(text, opts \\ []) when is_binary(text) do
    lang = Keyword.get(opts, :lang, "en")
    status = byte_size(lang) &&& 0x3F

    %Record{
      tnf: :well_known,
      type: "T",
      payload: <<status::8, lang::binary, text::binary>>
    }
  end

  @doc "Build a MIME-typed record."
  @spec mime(String.t(), binary()) :: Record.t()
  def mime(mime_type, payload) when is_binary(mime_type) and is_binary(payload) do
    %Record{tnf: :mime, type: mime_type, payload: payload}
  end

  # ---- Encode / decode ---------------------------------------------------

  @doc """
  Encode a list of records into the NDEF binary form. The first record
  gets `MB=1`, the last gets `ME=1`. Records with `byte_size(payload) <
  256` use the short-record header.
  """
  @spec encode([Record.t()]) :: binary()
  def encode([]), do: <<>>

  def encode(records) when is_list(records) do
    last = length(records) - 1

    records
    |> Enum.with_index()
    |> Enum.map(fn {rec, i} -> encode_record(rec, mb: i == 0, me: i == last) end)
    |> IO.iodata_to_binary()
  end

  @doc "Decode an NDEF binary into a list of records."
  @spec decode(binary()) :: {:ok, [Record.t()]} | {:error, term()}
  def decode(bin) when is_binary(bin) do
    case decode_records(bin, []) do
      {:ok, records} -> {:ok, Enum.reverse(records)}
      err -> err
    end
  end

  defp decode_records(<<>>, acc), do: {:ok, acc}

  defp decode_records(<<_mb::1, _me::1, 1::1, _::5, _::binary>>, _acc) do
    {:error, :chunked_record_unsupported}
  end

  defp decode_records(
         <<_mb::1, _me::1, 0::1, sr::1, il::1, tnf::3, type_len::8, rest::binary>>,
         acc
       ) do
    with {:ok, payload_len, rest} <- read_payload_len(sr, rest),
         {:ok, id_len, rest} <- read_id_len(il, rest),
         <<type::binary-size(^type_len), rest::binary>> <- rest,
         {:ok, id, rest} <- read_id(id_len, rest),
         <<payload::binary-size(^payload_len), rest::binary>> <- rest do
      record = %Record{tnf: Map.get(@tnf, tnf, :unknown), type: type, id: id, payload: payload}
      decode_records(rest, [record | acc])
    else
      _ -> {:error, :malformed_ndef}
    end
  end

  defp decode_records(_, _), do: {:error, :malformed_ndef}

  defp read_payload_len(1, <<len::8, rest::binary>>), do: {:ok, len, rest}
  defp read_payload_len(0, <<len::big-32, rest::binary>>), do: {:ok, len, rest}
  defp read_payload_len(_, _), do: {:error, :short}

  defp read_id_len(1, <<len::8, rest::binary>>), do: {:ok, len, rest}
  defp read_id_len(0, rest), do: {:ok, 0, rest}

  defp read_id(0, rest), do: {:ok, nil, rest}

  defp read_id(n, bin) do
    case bin do
      <<id::binary-size(^n), rest::binary>> -> {:ok, id, rest}
      _ -> {:error, :short}
    end
  end

  defp encode_record(%Record{} = r, opts) do
    mb = if Keyword.get(opts, :mb, false), do: 1, else: 0
    me = if Keyword.get(opts, :me, false), do: 1, else: 0
    cf = 0
    il = if r.id && byte_size(r.id) > 0, do: 1, else: 0
    type_len = byte_size(r.type)
    payload_len = byte_size(r.payload)
    sr = if payload_len < 256, do: 1, else: 0
    tnf = Map.fetch!(@tnf_inv, r.tnf)

    header = <<mb::1, me::1, cf::1, sr::1, il::1, tnf::3, type_len::8>>
    plen = if sr == 1, do: <<payload_len::8>>, else: <<payload_len::big-32>>
    id_len_bytes = if il == 1, do: <<byte_size(r.id)::8>>, else: <<>>
    id_bytes = if il == 1, do: r.id, else: <<>>

    [header, plen, id_len_bytes, r.type, id_bytes, r.payload]
  end

  # ---- URI helpers -------------------------------------------------------

  @doc """
  Decode a Well-Known URI record's payload back to a string. Returns
  `nil` for any non-URI record.
  """
  @spec uri_value(Record.t()) :: String.t() | nil
  def uri_value(%Record{tnf: :well_known, type: "U", payload: <<code::8, rest::binary>>}) do
    Map.get(@uri_prefixes, code, "") <> rest
  end

  def uri_value(_), do: nil

  @doc """
  Decode a Well-Known Text record's payload to `{lang, text}`. Returns
  `nil` for any non-text record. UTF-16 text is returned undecoded.

      iex> ExNfc.NDEF.text_value(ExNfc.NDEF.text("hello"))
      {"en", "hello"}
  """
  @spec text_value(Record.t()) :: {String.t(), String.t()} | nil
  def text_value(%Record{tnf: :well_known, type: "T", payload: <<status::8, rest::binary>>}) do
    lang_len = status &&& 0x3F

    case rest do
      <<lang::binary-size(^lang_len), text::binary>> -> {lang, text}
      _ -> nil
    end
  end

  def text_value(_), do: nil

  defp pick_uri_prefixes() do
    # Longest prefix first so e.g. "https://www." wins over "https://".
    @uri_prefixes
    |> Enum.reject(fn {_code, p} -> p == "" end)
    |> Enum.sort_by(fn {_code, p} -> -byte_size(p) end)
  end

  defp pick_uri_prefix(url) do
    Enum.find_value(pick_uri_prefixes(), {0x00, url}, fn {code, prefix} ->
      if String.starts_with?(url, prefix) do
        {code, binary_part(url, byte_size(prefix), byte_size(url) - byte_size(prefix))}
      end
    end)
  end
end
