# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.NDEF.Type4 do
  @moduledoc """
  NDEF read/write for NFC Forum **Type 4** tags — ISO-DEP file-based
  storage. Used by DESFire-based NDEF tags, phones in Host Card
  Emulation, some payment-like cards.

  Talks ISO 7816-4 APDUs over the connection's ISO-DEP transport:

    1. `SELECT NDEF Tag Application` (AID `D2760000850101`)
    2. `SELECT CC File` (FID `E103`), `READ BINARY` it
    3. `SELECT NDEF File` (FID from CC), `READ BINARY` length + payload
    4. For writes: zero NLEN, write the payload at offset 2, write NLEN

  The CC carries the per-tag maximum R-APDU data size (`MLe`) and
  C-APDU data size (`MLc`); both are respected so large payloads are
  split into legal-size chunks. Only the mapping version 2 CC layout
  (NDEF File Control TLV `04 06 …`) is supported.

  The connection must use protocol `:iso14443_a` or `:iso14443_b`
  (ISO-DEP).
  """

  alias ExNfc.Connection
  alias ExNfc.NDEF

  @ndef_aid <<0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01>>
  @cc_fid <<0xE1, 0x03>>

  @sw_ok <<0x90, 0x00>>

  defmodule CC do
    @moduledoc false
    # max_ndef_size is the NDEF file size, which includes the 2-byte NLEN.
    defstruct [:max_le, :max_lc, :ndef_fid, :max_ndef_size, :read_access, :write_access]
  end

  @doc """
  Read every NDEF record from the connected Type 4 tag.
  """
  @spec read(Connection.t()) :: {:ok, [NDEF.Record.t()]} | {:error, term()}
  def read(%Connection{} = conn) do
    with :ok <- select_ndef_app(conn),
         {:ok, cc} <- read_cc(conn),
         :ok <- check_readable(cc),
         :ok <- select_file(conn, cc.ndef_fid),
         {:ok, nlen} <- read_ndef_length(conn, cc),
         {:ok, ndef_bytes} <- read_ndef_payload(conn, nlen, cc.max_le),
         {:ok, records} <- NDEF.decode(ndef_bytes) do
      {:ok, records}
    end
  end

  @doc """
  Write a list of NDEF records to the connected Type 4 tag.

  The write sequence zeroes the NLEN first so a partial write can't be
  misread as a truncated NDEF; then writes the payload at offset 2
  (chunked to the CC's MLc); then writes the final NLEN.
  """
  @spec write(Connection.t(), [NDEF.Record.t()]) :: :ok | {:error, term()}
  def write(%Connection{} = conn, records) when is_list(records) do
    payload = NDEF.encode(records)
    nlen = byte_size(payload)

    with :ok <- select_ndef_app(conn),
         {:ok, cc} <- read_cc(conn),
         :ok <- check_writable(cc),
         :ok <- check_capacity(nlen + 2, cc.max_ndef_size),
         :ok <- select_file(conn, cc.ndef_fid),
         :ok <- update_binary(conn, 0, <<0x00, 0x00>>, cc.max_lc),
         :ok <- update_binary(conn, 2, payload, cc.max_lc),
         :ok <- update_binary(conn, 0, <<nlen::big-16>>, cc.max_lc) do
      :ok
    end
  end

  # ---- APDU helpers ------------------------------------------------------

  defp select_ndef_app(conn) do
    apdu = <<0x00, 0xA4, 0x04, 0x00, byte_size(@ndef_aid)::8, @ndef_aid::binary, 0x00>>
    expect_ok(Connection.transceive(conn, apdu))
  end

  defp select_file(conn, <<_::binary-size(2)>> = fid) do
    apdu = <<0x00, 0xA4, 0x00, 0x0C, 0x02, fid::binary>>
    expect_ok(Connection.transceive(conn, apdu))
  end

  defp read_cc(conn) do
    with :ok <- select_file(conn, @cc_fid),
         {:ok, bin} <- read_binary(conn, 0, 15) do
      parse_cc(bin)
    end
  end

  @doc false
  # CC file (T4T v2): CCLEN, mapping version, MLe, MLc, then the NDEF File
  # Control TLV (T=04, L=06): file id, max NDEF file size, read / write
  # access. The extended v3 TLV (T=06) is not supported.
  def parse_cc(
        <<_cclen::big-16, _ver::8, max_le::big-16, max_lc::big-16, 0x04, 0x06, fid_hi::8,
          fid_lo::8, max_ndef::big-16, read_acc::8, write_acc::8, _rest::binary>>
      ) do
    {:ok,
     %CC{
       max_le: max_le,
       max_lc: max_lc,
       ndef_fid: <<fid_hi::8, fid_lo::8>>,
       max_ndef_size: max_ndef,
       read_access: read_acc,
       write_access: write_acc
     }}
  end

  def parse_cc(_), do: {:error, :malformed_cc}

  defp check_readable(%CC{read_access: 0x00}), do: :ok
  defp check_readable(%CC{read_access: code}), do: {:error, {:read_protected, code}}

  defp check_writable(%CC{write_access: 0x00}), do: :ok
  defp check_writable(%CC{write_access: code}), do: {:error, {:read_only, code}}

  defp check_capacity(needed, cap) when needed <= cap, do: :ok
  defp check_capacity(needed, cap), do: {:error, {:tag_full, needed: needed, capacity: cap}}

  defp read_ndef_length(conn, %CC{max_ndef_size: max}) do
    case read_binary(conn, 0, 2) do
      {:ok, <<nlen::big-16>>} when nlen + 2 <= max -> {:ok, nlen}
      {:ok, <<nlen::big-16>>} -> {:error, {:invalid_nlen, nlen}}
      err -> err
    end
  end

  defp read_ndef_payload(_conn, 0, _max_le), do: {:ok, <<>>}

  defp read_ndef_payload(conn, total, max_le) do
    chunk_size = min(max_le, 0xFF)
    read_loop(conn, 2, total, chunk_size, <<>>)
  end

  defp read_loop(_conn, _off, 0, _chunk, acc), do: {:ok, acc}

  defp read_loop(conn, offset, remaining, chunk_size, acc) do
    want = min(remaining, chunk_size)

    case read_binary(conn, offset, want) do
      {:ok, bytes} -> read_loop(conn, offset + want, remaining - want, chunk_size, acc <> bytes)
      err -> err
    end
  end

  defp read_binary(conn, offset, len) do
    apdu = <<0x00, 0xB0, offset::big-16, len::8>>

    with {:ok, full} <- Connection.transceive(conn, apdu),
         {:ok, data, sw} <- split_sw(full) do
      case sw do
        @sw_ok when byte_size(data) == len -> {:ok, data}
        @sw_ok -> {:error, {:short_read, expected: len, got: byte_size(data)}}
        <<sw1, sw2>> -> {:error, {:apdu_status, sw1, sw2}}
      end
    end
  end

  defp update_binary(_conn, _offset, <<>>, _max_lc), do: :ok

  defp update_binary(conn, offset, payload, max_lc) do
    chunk_size = min(max_lc, 0xFF)
    write_loop(conn, offset, payload, chunk_size)
  end

  defp write_loop(_conn, _off, <<>>, _chunk), do: :ok

  defp write_loop(conn, offset, payload, chunk_size) do
    {chunk, rest} =
      case payload do
        <<c::binary-size(^chunk_size), r::binary>> -> {c, r}
        _ -> {payload, <<>>}
      end

    apdu = <<0x00, 0xD6, offset::big-16, byte_size(chunk)::8, chunk::binary>>

    case expect_ok(Connection.transceive(conn, apdu)) do
      :ok -> write_loop(conn, offset + byte_size(chunk), rest, chunk_size)
      err -> err
    end
  end

  # ---- Generic helpers ---------------------------------------------------

  defp expect_ok({:ok, bin}) do
    case split_sw(bin) do
      {:ok, _data, @sw_ok} -> :ok
      {:ok, _data, <<sw1, sw2>>} -> {:error, {:apdu_status, sw1, sw2}}
      err -> err
    end
  end

  defp expect_ok({:error, _} = err), do: err

  @doc false
  # Split an R-APDU into data and the trailing SW1 SW2.
  @spec split_sw(binary()) :: {:ok, binary(), <<_::16>>} | {:error, :short_apdu_response}
  def split_sw(bin) when byte_size(bin) >= 2 do
    data_len = byte_size(bin) - 2
    <<data::binary-size(^data_len), sw::binary-size(2)>> = bin
    {:ok, data, sw}
  end

  def split_sw(_bin), do: {:error, :short_apdu_response}
end
