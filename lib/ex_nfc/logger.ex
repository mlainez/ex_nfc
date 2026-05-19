# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Logger do
  @moduledoc """
  Optional subscriber that emits a `Logger.info` line for every NFC
  event ExNfc broadcasts. Useful as a default sink so taps show up in
  the console without having to write your own subscriber.

  Started automatically by `ExNfc.Application` unless disabled via:

      config :ex_nfc, log_events: false

  Application code that wants programmatic access to the same events
  should call `ExNfc.subscribe/0` directly — both will receive the
  message, the logger doesn't consume it.
  """

  use GenServer
  require Logger

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @impl GenServer
  def init([]) do
    :ok = ExNfc.subscribe()
    {:ok, %{}}
  end

  @impl GenServer
  def handle_info({ExNfc, :tag_arrived, target}, state) do
    Logger.info("[ExNfc] tag arrived " <> format_tag(target))
    {:noreply, state}
  end

  def handle_info({ExNfc, :tag_departed, %{idx: idx}}, state) do
    Logger.info("[ExNfc] tag departed idx=#{inspect(idx)}")
    {:noreply, state}
  end

  def handle_info({ExNfc, _other, _payload}, state), do: {:noreply, state}
  def handle_info(_other, state), do: {:noreply, state}

  defp format_tag(target) do
    [
      "uid=#{target[:uid_hex] || "?"}",
      "protocol=#{inspect(target[:protocol])}",
      target[:sens_res] && "sens_res=0x#{Integer.to_string(target.sens_res, 16)}",
      target[:sel_res] && "sel_res=0x#{Integer.to_string(target.sel_res, 16)}"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end
end
