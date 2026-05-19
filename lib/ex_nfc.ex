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

  ## Quick start

      iex> ExNfc.subscribe()
      :ok
      # tap a tag on the antenna...
      flush()
      # {ExNfc, :tag_found, %{
      #   uid_hex: "0432af1a2b5c80",
      #   protocol: :iso14443_a,
      #   nfcid1: <<0x04, 0x32, 0xAF, ...>>,
      #   ...
      # }}

  By default the supervisor brings the first discovered NFC controller
  up at boot and starts polling for every tag type the kernel
  advertises (Jewel / Mifare / Felica / ISO 14443-A/B / ISO 15693). Set

      config :ex_nfc, controller: [autostart: false]

  to manage the lifecycle manually with `start_polling/0` and
  `stop_polling/0`.
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

  @doc "Bring the bound device down (turn the radio off)."
  @spec dev_down() :: :ok | {:error, term()}
  defdelegate dev_down(), to: ExNfc.Controller
end
