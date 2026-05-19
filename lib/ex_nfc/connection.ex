# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Connection do
  @moduledoc """
  Raw data exchange with an activated NFC tag.

  Wraps a Linux `AF_NFC / SOCK_RAW / NFC_SOCKPROTO_RAW` socket.
  Connected to a specific `(device_index, target_index, nfc_protocol)`
  it sends and receives application-layer frames — ISO-DEP I-PDUs for
  Type 4 (DESFire, contactless EMV), or raw NFC-A commands for Type 2
  (NTAG/Ultralight).

  ## Lifecycle

  Configure the controller with `resume_after_tap: :manual` so the chip
  stays in `:tag_active` while you talk to the tag:

      config :ex_nfc, controller: [resume_after_tap: :manual]

  Then on `:tag_arrived`:

      receive do
        {ExNfc, :tag_arrived, target} ->
          {:ok, conn} = ExNfc.Connection.open(target)
          {:ok, resp} = ExNfc.Connection.transceive(conn, <<0x00, 0xA4, 0x04, 0x00, ...>>)
          ExNfc.Connection.close(conn)
          ExNfc.deactivate()
      end

  In `:auto` mode the chip is deactivated immediately after the
  arrived event, so any `connect()` will race the deactivation —
  use `:manual` whenever you intend to talk to the tag.
  """

  require Logger

  # ---- Socket constants ---------------------------------------------------

  @af_nfc 39
  @nfc_sockproto_raw 0

  # NFC protocol shift values — must match `ExNfc.Controller`.
  @nfc_proto_jewel 1
  @nfc_proto_mifare 2
  @nfc_proto_felica 3
  @nfc_proto_iso14443 4
  @nfc_proto_iso14443_b 6
  @nfc_proto_iso15693 7

  @typedoc """
  A connection handle — opaque to callers. Internally an OTP `:socket`
  reference.
  """
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

    * a target map as received from `{ExNfc, :tag_arrived, target}`
      (uses `:target_index` and `:protocol`), or
    * a keyword list `[device_index: …, target_index: …, protocol: …]`
      where `protocol` is a `:jewel | :mifare | :felica | :iso14443_a
      | :iso14443_b | :iso15693` atom or the raw `NFC_PROTO_*` shift.
  """
  @spec open(map() | keyword()) :: {:ok, t()} | {:error, term()}
  def open(target_or_opts)

  def open(%{target_index: tidx, protocol: proto} = m) when is_integer(tidx) do
    dev_idx = Map.get(m, :device_index, 0)
    do_open(dev_idx, tidx, protocol_value(proto))
  end

  def open(opts) when is_list(opts) do
    dev_idx = Keyword.get(opts, :device_index, 0)
    tidx = Keyword.fetch!(opts, :target_index)
    proto = Keyword.fetch!(opts, :protocol)
    do_open(dev_idx, tidx, protocol_value(proto))
  end

  @doc """
  Send a frame to the tag and wait for the response.

  `payload` is the application-layer bytes — e.g. an ISO-DEP APDU
  body — without any pseudo-header. The 1-byte adapter prefix the
  kernel adds on receive is stripped automatically.
  """
  @spec transceive(t(), iodata(), pos_integer()) :: {:ok, binary()} | {:error, term()}
  def transceive(%__MODULE__{sock: sock}, payload, timeout \\ 2_000) do
    with :ok <- :socket.send(sock, IO.iodata_to_binary(payload)),
         {:ok, <<_adapter::8, data::binary>>} <- :socket.recv(sock, 0, timeout) do
      {:ok, data}
    else
      {:ok, <<>>} -> {:error, :empty_response}
      {:error, _} = err -> err
    end
  end

  @doc "Close the connection."
  @spec close(t()) :: :ok
  def close(%__MODULE__{sock: sock}) do
    _ = :socket.close(sock)
    :ok
  end

  # ---- Internals ----------------------------------------------------------

  defp do_open(dev_idx, target_idx, nfc_protocol) when is_integer(nfc_protocol) do
    with {:ok, sock} <- :socket.open(@af_nfc, :raw, @nfc_sockproto_raw),
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
        Logger.warning("[ExNfc.Connection] open failed: #{inspect(reason)}")
        err
    end
  end

  # struct sockaddr_nfc {
  #   __kernel_sa_family_t sa_family; // u16 on Linux
  #   __u32 dev_idx;
  #   __u32 target_idx;
  #   __u32 nfc_protocol;
  # }
  # `:socket.connect/2` wants %{family: int, addr: bytes} where bytes
  # follow the family field — i.e. everything from dev_idx on.
  defp sockaddr_nfc(dev_idx, target_idx, nfc_protocol) do
    %{
      family: @af_nfc,
      addr: <<
        dev_idx::little-32,
        target_idx::little-32,
        nfc_protocol::little-32
      >>
    }
  end

  # Translate an atom / integer protocol selector into the raw shift
  # value expected by the kernel in `sockaddr_nfc.nfc_protocol`.
  defp protocol_value(:jewel), do: @nfc_proto_jewel
  defp protocol_value(:mifare), do: @nfc_proto_mifare
  defp protocol_value(:felica), do: @nfc_proto_felica
  defp protocol_value(:iso14443_a), do: @nfc_proto_iso14443
  defp protocol_value(:iso14443), do: @nfc_proto_iso14443
  defp protocol_value(:iso14443_b), do: @nfc_proto_iso14443_b
  defp protocol_value(:iso15693), do: @nfc_proto_iso15693
  defp protocol_value(n) when is_integer(n), do: n
end
