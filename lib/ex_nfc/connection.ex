# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Connection do
  @moduledoc """
  Raw data exchange with an activated NFC tag.

  Wraps a Linux `AF_NFC / SOCK_SEQPACKET / NFC_SOCKPROTO_RAW` socket.
  Connecting it to `(device_index, target_index, nfc_protocol)` makes the
  kernel activate the target (`nfc_activate_target`); after that each
  `transceive/3` sends one application-layer frame and returns the tag's
  answer — ISO 7816-4 APDUs for Type 4 (ISO-DEP) tags, raw NFC-A commands
  for Type 2 (NTAG/Ultralight) tags. Closing the socket makes the kernel
  deactivate the target again.

  ## Lifecycle

  Configure the controller with `resume_after_tap: :manual` so the chip
  stays in `:tag_active` while you talk to the tag:

      config :ex_nfc, controller: [resume_after_tap: :manual]

  Then on `:tag_arrived`:

      receive do
        {ExNfc, :tag_arrived, target} ->
          {:ok, conn} = ExNfc.Connection.open(target)
          # ISO-DEP: SELECT the NDEF application
          {:ok, resp} =
            ExNfc.Connection.transceive(conn, <<0x00, 0xA4, 0x04, 0x00, 0x07,
              0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00>>)
          ExNfc.Connection.close(conn)
          ExNfc.deactivate()
      end

  In `:auto` mode the controller restarts polling right after the
  `:tag_arrived` broadcast, which releases the tag, so `open/1` will
  fail — use `:manual` whenever you intend to talk to the tag.
  """

  require Logger

  alias ExNfc.NfcGenl

  @af_nfc 39
  @nfc_sockproto_raw 0
  # NFC_HEADER_SIZE: the kernel prepends one byte to every received frame.
  @nfc_header_size 1

  @typedoc "A connection handle. Treat as opaque."
  @type t :: %__MODULE__{
          sock: :socket.socket(),
          device_index: non_neg_integer(),
          target_index: non_neg_integer(),
          nfc_protocol: non_neg_integer()
        }

  defstruct [:sock, :device_index, :target_index, :nfc_protocol]

  @doc """
  Open a raw connection to a tag.

  `target` is either:

    * a target map as received in `{ExNfc, :tag_arrived, target}` (uses
      its `:device_index`, `:target_index` and `:protocol`), or
    * a keyword list `[device_index: …, target_index: …, protocol: …]`
      where `protocol` is one of `:jewel | :mifare | :felica | :iso14443_a
      | :iso14443_b | :iso15693` or a raw `NFC_PROTO_*` value.
  """
  @spec open(map() | keyword()) :: {:ok, t()} | {:error, term()}
  def open(target_or_opts)

  def open(%{device_index: dev, target_index: tidx, protocol: proto})
      when is_integer(dev) and is_integer(tidx) do
    do_open(dev, tidx, proto)
  end

  def open(opts) when is_list(opts) do
    with {:ok, dev} <- fetch_int(opts, :device_index),
         {:ok, tidx} <- fetch_int(opts, :target_index),
         {:ok, proto} <- Keyword.fetch(opts, :protocol) do
      do_open(dev, tidx, proto)
    else
      :error -> {:error, :invalid_target}
    end
  end

  def open(_other), do: {:error, :invalid_target}

  @doc """
  Send a frame to the tag and wait up to `timeout` ms for the response.

  `payload` is the application-layer bytes (e.g. an APDU) without any
  header. The one-byte header the kernel prepends to received frames is
  stripped. After a timeout the connection should be closed: a late
  answer would otherwise be returned by the next call.
  """
  @spec transceive(t(), iodata(), timeout()) :: {:ok, binary()} | {:error, term()}
  def transceive(%__MODULE__{sock: sock}, payload, timeout \\ 2_000) do
    with :ok <- :socket.send(sock, IO.iodata_to_binary(payload)),
         {:ok, <<_header::binary-size(@nfc_header_size), data::binary>>} <-
           :socket.recv(sock, 0, timeout) do
      {:ok, data}
    else
      {:ok, _short} -> {:error, :empty_response}
      {:error, _} = err -> err
    end
  end

  @doc "Close the connection (the kernel deactivates the target)."
  @spec close(t()) :: :ok
  def close(%__MODULE__{sock: sock}) do
    _ = :socket.close(sock)
    :ok
  end

  @doc false
  # struct sockaddr_nfc (uapi/linux/nfc.h):
  #   __kernel_sa_family_t sa_family;   // offset 0, 2 bytes
  #   /* 2 bytes padding */
  #   __u32 dev_idx;                    // offset 4
  #   __u32 target_idx;                 // offset 8
  #   __u32 nfc_protocol;               // offset 12  -> sizeof == 16
  # OTP `:socket` copies `addr` right after sa_family (to offset 2), so
  # the padding must be included. The kernel rejects anything shorter
  # than 16 bytes with EINVAL.
  @spec sockaddr_nfc(non_neg_integer(), non_neg_integer(), non_neg_integer()) :: map()
  def sockaddr_nfc(dev_idx, target_idx, nfc_protocol) do
    %{
      family: @af_nfc,
      addr: <<0::16, dev_idx::native-32, target_idx::native-32, nfc_protocol::native-32>>
    }
  end

  # ---- Internals ----------------------------------------------------------

  defp fetch_int(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, n} when is_integer(n) -> {:ok, n}
      _ -> :error
    end
  end

  defp do_open(dev_idx, target_idx, proto) do
    with {:ok, nfc_protocol} <- protocol(proto),
         {:ok, sock} <- :socket.open(@af_nfc, :seqpacket, @nfc_sockproto_raw) do
      with :ok <- :socket.setopt(sock, {:otp, :rcvbuf}, 65_536),
           :ok <- :socket.connect(sock, sockaddr_nfc(dev_idx, target_idx, nfc_protocol)) do
        {:ok,
         %__MODULE__{
           sock: sock,
           device_index: dev_idx,
           target_index: target_idx,
           nfc_protocol: nfc_protocol
         }}
      else
        {:error, reason} = err ->
          :socket.close(sock)
          Logger.warning("[ExNfc.Connection] connect failed: #{inspect(reason)}")
          err
      end
    end
  end

  defp protocol(proto) do
    case NfcGenl.protocol_value(proto) do
      {:ok, n} -> {:ok, n}
      :error -> {:error, {:unknown_protocol, proto}}
    end
  end
end
