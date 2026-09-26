# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc do
  @moduledoc """
  Elixir client for the Linux kernel NFC subsystem.

  Speaks `NETLINK_GENERIC` directly to the kernel's `nfc` family and uses
  `AF_NFC` sockets for data exchange. Works with in-kernel NCI controllers
  (`nxp-nci-i2c`, `s3fwrn5`, `st21nfca`, …) that show up as an `nfcN`
  device under `/sys/class/nfc/`.

  ## Events

  Subscribers (see `subscribe/0`) receive `{ExNfc, kind, payload}` tuples:

    * `{ExNfc, :tag_arrived, target}` — a tag was found. `target` is a map
      with `:device_index`, `:device`, `:target_index`, `:protocol`
      (`:jewel | :mifare | :felica | :iso14443_a | :iso14443_b | :iso15693`),
      `:protocols` (raw bitmask), `:uid_hex`, `:nfcid1`, `:sens_res`,
      `:sel_res`, `:sensb_res`, `:sensf_res`, `:ats`, `:iso15693_uid` and
      `:iso15693_dsfid` (absent values are `nil`).
    * `{ExNfc, :tag_departed, %{target_index: i, device_index: d, device: "nfc0"}}` —
      the tag was released (automatically in `:auto` mode, by
      `deactivate/0` in `:manual` mode) or left the field.
    * `{ExNfc, :device_added, %{index: i, name: "nfc0", protocols: mask}}`
      and `{ExNfc, :device_removed, %{index: i}}` — controller hotplug.

  ## Quick start

      ExNfc.subscribe()
      # tap a tag on the antenna...
      flush()
      # {ExNfc, :tag_arrived, %{uid_hex: "04528922F82A80", protocol: :mifare,
      #   target_index: 1, device_index: 0, device: "nfc0", ...}}
      # {ExNfc, :tag_departed, %{target_index: 1, device_index: 0, device: "nfc0"}}

  At boot the controller binds the first NFC controller, powers it up
  and polls for every tag protocol it supports. If the kernel has no NFC
  support the controller stays `:unavailable` (calls return
  `{:error, :nfc_unavailable}`) instead of crashing the application.

  Configuration:

      # Defaults shown; every key is optional.
      config :ex_nfc,
        log_events: true,           # log every event via ExNfc.Logger
        controller: [
          autostart: true,          # power up + poll when a controller is bound
          resume_after_tap: :auto   # or :manual
          # device_index: 0,        # default: first controller found
          # poll_protocols: mask    # default: all tag protocols, see ExNfc.Controller
        ]

  ### Resume-after-tap policies

    * `:auto` (default) — release the tag and restart polling right after
      broadcasting `:tag_arrived`; each tap yields `:tag_arrived` followed
      by `:tag_departed`. You cannot talk to the tag in this mode.
    * `:manual` — stay in `:tag_active` until `deactivate/0` (or
      `start_polling/0`) is called. Use it to read/write the tag.

  In both modes polling resumes automatically when the kernel reports
  that an active tag left the field.
  """

  @doc """
  Subscribe the calling process to NFC events (see the module doc).

  Idempotent: calling it several times from the same process registers
  it once, so each event is delivered once per subscribed process.
  """
  @spec subscribe() :: :ok
  def subscribe() do
    if :tag_events in Registry.keys(ExNfc.Registry, self()) do
      :ok
    else
      {:ok, _} = Registry.register(ExNfc.Registry, :tag_events, [])
      :ok
    end
  end

  @doc "Unsubscribe the calling process."
  @spec unsubscribe() :: :ok
  def unsubscribe() do
    Registry.unregister(ExNfc.Registry, :tag_events)
    :ok
  end

  @doc "List the NFC controllers known to the kernel."
  @spec list_devices() :: {:ok, [map()]} | {:error, term()}
  def list_devices(), do: ExNfc.Controller.list_devices()

  @doc "Start polling on the bound controller (powering it up if needed)."
  @spec start_polling() :: :ok | {:error, term()}
  def start_polling(), do: ExNfc.Controller.start_polling()

  @doc "Stop polling on the bound controller."
  @spec stop_polling() :: :ok | {:error, term()}
  def stop_polling(), do: ExNfc.Controller.stop_polling()

  @doc """
  Release the active tag and resume polling.

  Use this with `resume_after_tap: :manual` once you are done with the
  tag. No-op when no tag is active.
  """
  @spec deactivate() :: :ok | {:error, term()}
  def deactivate(), do: ExNfc.Controller.deactivate()

  @doc """
  Current controller state:
  `:unavailable | :no_device | :down | :idle | :polling | :tag_active`.
  """
  @spec state() :: ExNfc.Controller.fsm()
  def state(), do: ExNfc.Controller.state()

  @doc "Power the bound controller down (radio off)."
  @spec dev_down() :: :ok | {:error, term()}
  def dev_down(), do: ExNfc.Controller.dev_down()

  @doc """
  Open a raw `AF_NFC` connection to a found tag for data exchange.

  Requires `resume_after_tap: :manual` so the tag stays active. See
  `ExNfc.Connection` for details.

      receive do
        {ExNfc, :tag_arrived, target} ->
          {:ok, conn} = ExNfc.connect(target)
          {:ok, response} = ExNfc.transceive(conn, apdu)
          ExNfc.Connection.close(conn)
          ExNfc.deactivate()
      end
  """
  @spec connect(map() | keyword()) :: {:ok, ExNfc.Connection.t()} | {:error, term()}
  defdelegate connect(target_or_opts), to: ExNfc.Connection, as: :open

  @doc """
  Send a frame to the connected tag and wait for the response.

  See `ExNfc.Connection.transceive/3`.
  """
  @spec transceive(ExNfc.Connection.t(), iodata(), pos_integer()) ::
          {:ok, binary()} | {:error, term()}
  defdelegate transceive(conn, payload, timeout \\ 2_000), to: ExNfc.Connection

  @doc """
  Read all NDEF records from an activated tag.

  Picks Type 2 (`:mifare` protocol — NTAG/Ultralight, page-based) or
  Type 4 (`:iso14443_a` / `:iso14443_b` — ISO-DEP, file-based) from the
  target's protocol. Pass `tag_type: :type2 | :type4` in `opts` to
  override.

  Requires `resume_after_tap: :manual`. Connects, reads and closes in one
  call; call `deactivate/0` afterwards to resume polling.
  """
  @spec read_ndef(map() | keyword(), keyword()) ::
          {:ok, [ExNfc.NDEF.Record.t()]} | {:error, term()}
  def read_ndef(target, opts \\ []) do
    with {:ok, conn} <- connect(target) do
      result = do_read_ndef(conn, target, opts)
      ExNfc.Connection.close(conn)
      result
    end
  end

  @doc """
  Write NDEF records (built with `ExNfc.NDEF.uri/1`, `ExNfc.NDEF.text/2`,
  `ExNfc.NDEF.mime/2` or `%ExNfc.NDEF.Record{}`) to a found tag. See
  `read_ndef/2` for tag-type dispatch and lifecycle notes.

      ExNfc.write_ndef(target, [ExNfc.NDEF.uri("https://elixir-lang.org")])
  """
  @spec write_ndef(map() | keyword(), [ExNfc.NDEF.Record.t()], keyword()) ::
          :ok | {:error, term()}
  def write_ndef(target, records, opts \\ []) do
    with {:ok, conn} <- connect(target) do
      result = do_write_ndef(conn, target, records, opts)
      ExNfc.Connection.close(conn)
      result
    end
  end

  defp do_read_ndef(conn, target, opts) do
    case tag_type(target, opts) do
      :type2 -> ExNfc.NDEF.Type2.read(conn)
      :type4 -> ExNfc.NDEF.Type4.read(conn)
      other -> {:error, {:unsupported_tag_type, other}}
    end
  end

  defp do_write_ndef(conn, target, records, opts) do
    case tag_type(target, opts) do
      :type2 -> ExNfc.NDEF.Type2.write(conn, records)
      :type4 -> ExNfc.NDEF.Type4.write(conn, records)
      other -> {:error, {:unsupported_tag_type, other}}
    end
  end

  defp tag_type(target, opts) do
    case Keyword.get(opts, :tag_type, :auto) do
      :auto -> auto_tag_type(target)
      other -> other
    end
  end

  defp auto_tag_type(target) do
    case protocol_of(target) do
      p when p in [:iso14443_a, :iso14443, :iso14443_b] -> :type4
      :mifare -> :type2
      other -> other
    end
  end

  defp protocol_of(%{protocol: p}), do: p
  defp protocol_of(opts) when is_list(opts), do: Keyword.get(opts, :protocol)
  defp protocol_of(_), do: nil
end
