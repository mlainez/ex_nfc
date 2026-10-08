# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.NDEF do
  @moduledoc """
  NFC Data Exchange Format records.

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

  Record framing and the URI identifier codes come from the `ndef-rs`
  crate (through `ExNfc.Native`). Chunked records (`CF` flag) are not
  supported and decode to `{:error, :chunked_record_unsupported}`.
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
  NFC Forum table is encoded as its 1-byte identifier code.

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
  def encode(records) when is_list(records) do
    raw = for r <- records, do: {Map.fetch!(@tnf_inv, r.tnf), r.type, r.id, r.payload}
    {:ok, bin} = ExNfc.Native.ndef_encode(raw)
    bin
  end

  @doc "Decode an NDEF binary into a list of records."
  @spec decode(binary()) :: {:ok, [Record.t()]} | {:error, term()}
  def decode(bin) when is_binary(bin) do
    with {:ok, raw} <- ExNfc.Native.ndef_decode(bin) do
      {:ok,
       for {tnf, type, id, payload} <- raw do
         %Record{tnf: Map.get(@tnf, tnf, :unknown), type: type, id: id, payload: payload}
       end}
    end
  end

  # ---- URI helpers -------------------------------------------------------

  @doc """
  Decode a Well-Known URI record's payload back to a string. Returns
  `nil` for any non-URI record.
  """
  @spec uri_value(Record.t()) :: String.t() | nil
  def uri_value(%Record{tnf: :well_known, type: "U", payload: <<code::8, rest::binary>>}) do
    Map.get(uri_prefixes(), code, "") <> rest
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

  defp uri_prefixes, do: ExNfc.Native.uri_prefixes()

  defp pick_uri_prefix(url) do
    uri_prefixes()
    |> Enum.reject(fn {_code, prefix} -> prefix == "" end)
    |> Enum.sort_by(fn {_code, prefix} -> -byte_size(prefix) end)
    |> Enum.find_value({0x00, url}, fn {code, prefix} ->
      if String.starts_with?(url, prefix) do
        {code, binary_part(url, byte_size(prefix), byte_size(url) - byte_size(prefix))}
      end
    end)
  end
end
