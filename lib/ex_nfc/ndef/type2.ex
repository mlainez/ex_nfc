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
  The connection must use protocol `:mifare` (what the kernel reports
  for Type 2 tags).

  This module wraps that in `read/1` and `write/2`, taking an open
  `ExNfc.Connection` and a list of `ExNfc.NDEF.Record`s.
  """

  import Bitwise

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

  Reads the CC first to check the tag is NDEF-formatted, writable and
  large enough, then writes the NDEF TLV 4 bytes (one page) at a time
  starting at page 4. The first page is written with a zero TLV length
  and rewritten with the real length last, so an interrupted write
  leaves an empty NDEF message rather than a truncated one. A failed
  write returns `{:error, {:write_failed, page, reason}}` without
  retrying.
  """
  @spec write(Connection.t(), [NDEF.Record.t()]) :: :ok | {:error, term()}
  def write(%Connection{} = conn, records) when is_list(records) do
    tlv = records |> NDEF.encode() |> wrap_tlv()

    with {:ok, cc_block} <- read_pages(conn, @cc_page),
         {:ok, capacity} <- parse_cc(cc_block),
         :ok <- check_writable(cc_block),
         :ok <- check_capacity(byte_size(tlv), capacity) do
      <<first::binary-size(4), rest::binary>> = pad_to_pages(tlv)

      with :ok <- write_pages(conn, @data_start_page, [zero_length(first)]),
           :ok <- write_pages(conn, @data_start_page + 1, chunk_pages(rest)) do
        write_pages(conn, @data_start_page, [first])
      end
    end
  end

  # ---- READ helpers ------------------------------------------------------

  # READ returns 16 bytes (4 pages); anything else is a NAK (a 4-bit
  # code delivered as one byte) or a transport problem.
  defp read_pages(%Connection{} = conn, page) when page in 0..255 do
    case Connection.transceive(conn, <<@read_cmd, page::8>>) do
      {:ok, <<bytes::binary-size(16)>>} -> {:ok, bytes}
      {:ok, other} -> {:error, {:read_failed, page, other}}
      {:error, reason} -> {:error, {:read_failed, page, reason}}
    end
  end

  @doc false
  # Capability Container (page 3): magic 0xE1, version, data area size / 8,
  # access byte. Returns the data area size in bytes.
  @spec parse_cc(binary()) :: {:ok, non_neg_integer()} | {:error, :not_ndef_formatted}
  def parse_cc(<<@ndef_magic, _version::8, size_div_8::8, _access::8, _rest::binary>>) do
    {:ok, size_div_8 * 8}
  end

  def parse_cc(_), do: {:error, :not_ndef_formatted}

  # Write access nibble (low 4 bits of CC byte 3): 0x0 = writable.
  defp check_writable(<<_::binary-size(3), access::8, _::binary>>) do
    case access &&& 0x0F do
      0 -> :ok
      _ -> {:error, :read_only}
    end
  end

  defp read_user_area(conn, byte_count) do
    pages_needed = div(byte_count + 3, 4)
    last_page = @data_start_page + pages_needed - 1
    do_read_loop(conn, @data_start_page, last_page, [])
  end

  defp do_read_loop(_conn, page, last, acc) when page > last,
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp do_read_loop(conn, page, last, acc) do
    case read_pages(conn, page) do
      {:ok, bytes} -> do_read_loop(conn, page + 4, last, [bytes | acc])
      err -> err
    end
  end

  @doc false
  # Walk the TLV stream in the data area until the NDEF Message TLV
  # (0x03). NULL TLVs (0x00) are skipped, other TLVs (lock / memory
  # control, proprietary) are skipped using their length, and the
  # terminator (0xFE) ends the search.
  @spec extract_ndef_tlv(binary()) :: {:ok, binary()} | {:error, term()}
  def extract_ndef_tlv(<<>>), do: {:error, :no_ndef_tlv}
  def extract_ndef_tlv(<<0x00, rest::binary>>), do: extract_ndef_tlv(rest)
  def extract_ndef_tlv(<<0xFE, _::binary>>), do: {:error, :no_ndef_tlv}

  def extract_ndef_tlv(<<tag, rest::binary>>) do
    with {:ok, len, rest} <- tlv_length(rest),
         <<value::binary-size(^len), rest::binary>> <- rest do
      if tag == 0x03, do: {:ok, value}, else: extract_ndef_tlv(rest)
    else
      _ -> {:error, :malformed_tlv}
    end
  end

  defp tlv_length(<<0xFF, len::big-16, rest::binary>>), do: {:ok, len, rest}
  defp tlv_length(<<len::8, rest::binary>>) when len != 0xFF, do: {:ok, len, rest}
  defp tlv_length(_), do: :error

  # ---- WRITE helpers -----------------------------------------------------

  @doc false
  # NDEF Message TLV + Terminator TLV. Lengths up to 254 use one byte,
  # longer ones the 3-byte `FF hi lo` form.
  @spec wrap_tlv(binary()) :: binary()
  def wrap_tlv(ndef) when byte_size(ndef) < 0xFF do
    <<0x03, byte_size(ndef)::8, ndef::binary, 0xFE>>
  end

  def wrap_tlv(ndef), do: <<0x03, 0xFF, byte_size(ndef)::big-16, ndef::binary, 0xFE>>

  defp zero_length(<<0x03, 0xFF, _len::16, _::binary>>), do: <<0x03, 0xFF, 0, 0>>
  defp zero_length(<<0x03, _len::8, rest::binary>>), do: <<0x03, 0x00, rest::binary>>

  defp check_capacity(needed, cap) when needed <= cap, do: :ok
  defp check_capacity(needed, cap), do: {:error, {:tag_full, needed: needed, capacity: cap}}

  defp pad_to_pages(bin) do
    case rem(byte_size(bin), 4) do
      0 -> bin
      n -> bin <> :binary.copy(<<0>>, 4 - n)
    end
  end

  defp chunk_pages(bin), do: for(<<page::binary-size(4) <- bin>>, do: page)

  defp write_pages(_conn, _page, []), do: :ok

  # WRITE is acknowledged with the 4-bit ACK 0xA (one byte on the wire).
  defp write_pages(conn, page, [chunk | rest]) do
    case Connection.transceive(conn, <<@write_cmd, page::8, chunk::binary>>) do
      {:ok, <<0x0A>>} -> write_pages(conn, page + 1, rest)
      {:ok, other} -> {:error, {:write_failed, page, {:nack, other}}}
      {:error, reason} -> {:error, {:write_failed, page, reason}}
    end
  end
end
