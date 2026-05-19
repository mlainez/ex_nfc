# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc do
  @moduledoc """
  Elixir client for the Linux kernel NFC subsystem.

  Speaks `NETLINK_GENERIC` directly to the kernel's `nfc` family. Works
  with any in-kernel NCI controller (`nxp-nci-i2c`, `s3fwrn5`,
  `st21nfca`, etc.) that surfaces an `nfcN` device under
  `/sys/class/nfc/`.

  ## Events

  Subscribers receive `{ExNfc, kind, payload}` tuples:

    * `{ExNfc, :tag_arrived, %{uid_hex: "…", protocol: :iso14443_a, …}}` —
      a tag has been activated by the chip.
    * `{ExNfc, :tag_departed, %{idx: target_index, device: "nfc0"}}` —
      the active tag has been deactivated (auto-resume in `:auto` mode,
      explicit `deactivate/0` in `:manual` mode, or the tag left the
      field).
    * `{ExNfc, :device_added | :device_removed, %{index: i}}` — an
      `nfcN` controller appeared / disappeared.

  ## Quick start

      iex> ExNfc.subscribe()
      :ok
      # tap a tag on the antenna...
      flush()
      # {ExNfc, :tag_arrived, %{
      #   uid_hex: "04528922F82A80",
      #   protocol: :iso14443_a,
      #   nfcid1: <<0x04, 0x52, 0x89, ...>>,
      #   target_index: 1,
      #   ...
      # }}
      # {ExNfc, :tag_departed, %{idx: 1, device: "nfc0"}}

  By default the supervisor brings the first discovered NFC controller
  up at boot and starts polling for every tag type the chip advertises
  (Jewel / MIFARE / Felica / ISO 14443-A/B / ISO 15693). Disable the
  logger sink via `config :ex_nfc, log_events: false`, or change
  controller behaviour with:

      config :ex_nfc, controller: [
        autostart: false,
        resume_after_tap: :manual
      ]

  ### Resume-after-tap policies

  After a tag is activated the chip is in `NCI_POLL_ACTIVE` and stops
  discovering. The controller's `resume_after_tap` option decides what
  happens next:

    * `:auto` (default) — drop the tag immediately and restart polling.
      Each tap yields a `:tag_arrived` followed by `:tag_departed`.
    * `:manual` — keep the chip in tag-active state until the caller
      calls `ExNfc.deactivate/0`. Useful when you want to do data
      exchange (read NDEF, etc.) before letting the next tag in.
    * `:one_shot` — drop the tag but do not restart polling. Stays
      idle until `ExNfc.start_polling/0` is called.

  Inspect the current state with `ExNfc.state/0` (`:idle | :polling |
  :tag_active`).
  """

  @doc """
  Subscribe the calling process to NFC events.

  Idempotent: calling this multiple times from the same process does
  not register multiple times, so each tap will produce exactly one
  `{ExNfc, :tag_found, _}` message per subscribed process.
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

  @doc "List all NFC controllers known to the kernel."
  @spec list_devices() :: [map()]
  defdelegate list_devices(), to: ExNfc.Controller

  @doc "Start polling on the bound device. Returns `:ok` or `{:error, reason}`."
  @spec start_polling() :: :ok | {:error, term()}
  defdelegate start_polling(), to: ExNfc.Controller

  @doc "Stop polling on the bound device."
  @spec stop_polling() :: :ok | {:error, term()}
  defdelegate stop_polling(), to: ExNfc.Controller

  @doc """
  Deactivate the currently active tag and resume polling.

  Use this when `resume_after_tap: :manual` is set, after you've finished
  doing whatever you wanted with the tag.
  """
  @spec deactivate() :: :ok | {:error, term()}
  defdelegate deactivate(), to: ExNfc.Controller

  @doc "Current controller state: `:idle | :polling | :tag_active`."
  @spec state() :: :idle | :polling | :tag_active
  defdelegate state(), to: ExNfc.Controller

  @doc "Bring the bound device down (turn the radio off)."
  @spec dev_down() :: :ok | {:error, term()}
  defdelegate dev_down(), to: ExNfc.Controller

  @doc """
  Open a raw `AF_NFC` connection to an activated tag for data exchange.

  Set `resume_after_tap: :manual` in config so the chip stays in
  `:tag_active` long enough to talk to the tag. See `ExNfc.Connection`
  for the full API.

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
end
