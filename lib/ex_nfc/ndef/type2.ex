# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.NDEF.Type2 do
  @moduledoc """
  NDEF read/write for NFC Forum **Type 2** tags (NTAG21x, MIFARE
  Ultralight family — the cheap programmable stickers).

  Type 2 tags are page-organised. Each page is 4 bytes. The host
  speaks the raw NFC-A command set:

    * `READ pageN`  — `0x30 NN` returns 16 bytes (4 pages starting at NN).
    * `WRITE pageN` — `0xA2 NN B0 B1 B2 B3` writes 4 bytes to page NN.

  Pages 0–3 carry the tag serial / lock bits / Capability Container,
  pages 4+ carry user data as a TLV stream: `03 LEN <NDEF bytes> FE`.

  This module wraps that in `read/1` and `write/2`, taking an open
  `ExNfc.Connection` and a list of `ExNfc.NDEF.Record`s.
  """

  alias ExNfc.Connection
  alias ExNfc.NDEF

  @read_cmd 0x30
  @write_cmd 0xA2

  @cc_page 3
  @data_start_page 4
  @ndef_magic 0xE1

  @doc """
  Read every NDEF record from the connected Type 2 tag.

  Returns `{:ok, [%ExNfc.NDEF.Record{}]}` on success, or `{:error,
  reason}` if the tag isn't NDEF-formatted, the read transport fails,
  or the TLV stream is malformed.
  """
  @spec read(Connection.t()) :: {:ok, [NDEF.Record.t()]} | {:error, term()}
  def read(%Connection{} = conn) do
    with {:ok, cc_block} <- read_pages(conn, @cc_page),
         {:ok, data_size} <- parse_cc(cc_block),
         {:ok, raw} <- read_user_area(conn, data_size),
         {:ok, ndef_bytes} <- extract_ndef_tlv(raw),
         {:ok, records} <- NDEF.decode(ndef_bytes) do
      {:ok, records}
    end
  end

  @doc """
  Write a list of NDEF records to the connected Type 2 tag.

  Reads the CC first to bound the write to the tag's data size, then
  writes 4 bytes at a time. Pages are sent strictly in order; a single
  failed write returns `{:error, {page, reason}}` without retrying.
  """
  @spec write(Connection.t(), [NDEF.Record.t()]) :: :ok | {:error, term()}
  def write(%Connection{} = conn, records) when is_list(records) do
    ndef = NDEF.encode(records)
    tlv = wrap_tlv(ndef)

    with {:ok, cc_block} <- read_pages(conn, @cc_page),
         {:ok, capacity} <- parse_cc(cc_block),
         :ok <- check_capacity(byte_size(tlv), capacity) do
      write_pages(conn, @data_start_page, pad_to_pages(tlv))
    end
  end

  # ---- READ helpers ------------------------------------------------------

  defp read_pages(%Connection{} = conn, page) when page in 0..255 do
    case Connection.transceive(conn, <<@read_cmd, page::8>>) do
      {:ok, <<bytes::binary-size(16)>>} -> {:ok, bytes}
      {:ok, short} when byte_size(short) > 0 -> {:ok, short}
      {:ok, <<>>} -> {:error, :read_returned_empty}
      {:error, _} = err -> err
    end
  end

  defp parse_cc(<<@ndef_magic, _version::8, size_div_8::8, _rw::8, _rest::binary>>) do
    {:ok, size_div_8 * 8}
  end

  defp parse_cc(_), do: {:error, :not_ndef_formatted}

  defp read_user_area(conn, byte_count) do
    pages_needed = div(byte_count + 3, 4)
    last_page = @data_start_page + pages_needed - 1
    do_read_loop(conn, @data_start_page, last_page, <<>>)
  end

  defp do_read_loop(_conn, page, last, acc) when page > last, do: {:ok, acc}

  defp do_read_loop(conn, page, last, acc) do
    case read_pages(conn, page) do
      {:ok, bytes} -> do_read_loop(conn, page + 4, last, acc <> bytes)
      err -> err
    end
  end

  # NDEF TLV stream: walk until we hit `03 LL …`. Skip any `00`
  # padding TLVs and stop on `FE` terminator.
  defp extract_ndef_tlv(<<>>), do: {:error, :no_ndef_tlv}
  defp extract_ndef_tlv(<<0x00, rest::binary>>), do: extract_ndef_tlv(rest)
  defp extract_ndef_tlv(<<0xFE, _::binary>>), do: {:error, :no_ndef_tlv}

  defp extract_ndef_tlv(<<0x03, 0xFF, len::big-16, payload::binary-size(len), _rest::binary>>) do
    {:ok, payload}
  end

  defp extract_ndef_tlv(<<0x03, len::8, payload::binary-size(len), _rest::binary>>) do
    {:ok, payload}
  end

  # Lock-control / memory-control TLVs: tag=0x01/0x02, 1-byte length,
  # value — skip them and continue.
  defp extract_ndef_tlv(<<t, len::8, _val::binary-size(len), rest::binary>>) when t in [0x01, 0x02] do
    extract_ndef_tlv(rest)
  end

  defp extract_ndef_tlv(_), do: {:error, :malformed_tlv}

  # ---- WRITE helpers -----------------------------------------------------

  defp wrap_tlv(ndef) do
    len = byte_size(ndef)

    cond do
      len < 0xFF -> <<0x03, len::8>> <> ndef <> <<0xFE>>
      true -> <<0x03, 0xFF, len::big-16>> <> ndef <> <<0xFE>>
    end
  end

  defp check_capacity(needed, cap) when needed <= cap, do: :ok
  defp check_capacity(needed, cap), do: {:error, {:tag_full, needed: needed, capacity: cap}}

  defp pad_to_pages(bin) do
    case rem(byte_size(bin), 4) do
      0 -> bin
      n -> bin <> :binary.copy(<<0>>, 4 - n)
    end
  end

  defp write_pages(_conn, _page, <<>>), do: :ok

  defp write_pages(conn, page, <<chunk::binary-size(4), rest::binary>>) do
    case Connection.transceive(conn, <<@write_cmd, page::8, chunk::binary>>, 1_500) do
      {:ok, <<ack::8>>} when ack in [0x0A, 0x00] -> write_pages(conn, page + 1, rest)
      {:ok, other} -> {:error, {:write_nack, page: page, reply: other}}
      {:error, reason} -> {:error, {page, reason}}
    end
  end
end
