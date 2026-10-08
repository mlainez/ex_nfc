# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Controller do
  @moduledoc """
  GenServer that talks to the kernel NFC subsystem over `NETLINK_GENERIC`
  and drives one NFC controller.

  The netlink side is `ExNfc.Native`, a Rust NIF over `neli`: commands
  (`DEV_UP`, `START_POLL`, dumps, …) return the kernel's answer, and the
  `nfc` family's `events` multicast group is read on a thread of its own
  that sends each event to this process.

  Lifecycle:

    1. Resolve the `"nfc"` family and join its `"events"` multicast group
       (resolving the family also makes the kernel auto-load the `nfc`
       module). If that fails — e.g. a host without NFC support —
       the controller stays in the `:unavailable` state, answers calls
       with `{:error, :nfc_unavailable}` and retries with exponential
       backoff (1 s up to 30 s). It never crashes the application.
    2. Dump the NFC controllers (`NFC_CMD_GET_DEVICE`) and bind to the
       configured one, or the first one. If none exists yet the state is
       `:no_device` until the kernel announces one (`NFC_EVENT_DEVICE_ADDED`).
    3. With `autostart: true`, power it up (`NFC_CMD_DEV_UP`) and start
       polling (`NFC_CMD_START_POLL`).
    4. On `NFC_EVENT_TARGETS_FOUND`, dump the targets (`NFC_CMD_GET_TARGET`),
       broadcast `{ExNfc, :tag_arrived, target}` and apply the
       `resume_after_tap` policy.

  States (`ExNfc.state/0`):

    * `:unavailable` — the kernel `nfc` generic-netlink family isn't there.
    * `:no_device` — NFC is available but no controller is bound.
    * `:down` — controller bound, radio off.
    * `:idle` — radio on, not polling.
    * `:polling` — discovering tags.
    * `:tag_active` — a tag was found; polling is paused until it is
      released (`ExNfc.deactivate/0`, or automatically in `:auto` mode).
  """

  use GenServer
  require Logger
  import Bitwise

  alias ExNfc.{Native, Protocol}

  @call_timeout 30_000
  @retry_initial_ms 1_000
  @retry_max_ms 30_000

  @type fsm :: :unavailable | :no_device | :down | :idle | :polling | :tag_active

  @doc """
  Start the NFC controller GenServer.

  Options:

    * `:device_index` — bind to a specific kernel NFC controller index.
      Defaults to the first one discovered.
    * `:poll_protocols` — bitmask of `1 <<< NFC_PROTO_*` bits to poll for.
      Defaults to every tag protocol (Jewel, MIFARE, FeliCa, ISO 14443-A/B,
      ISO 15693); it is always clamped to what the controller supports
      and NFC-DEP (peer-to-peer) is always removed.
    * `:autostart` — when `true` (default), power the controller up and
      start polling as soon as it is bound.
    * `:resume_after_tap` — what to do once a tag has been found:
      * `:auto` (default) — release the tag and restart polling right
        away, so every tap yields `:tag_arrived` then `:tag_departed`.
      * `:manual` — stay in `:tag_active` until `ExNfc.deactivate/0`
        (or `ExNfc.start_polling/0`) is called. Required to talk to the tag.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "List the NFC controllers known to the kernel."
  @spec list_devices(GenServer.server()) :: {:ok, [map()]} | {:error, term()}
  def list_devices(server \\ __MODULE__), do: call(server, :list_devices)

  @doc """
  Start polling on the bound controller, powering it up first if needed.
  Returns `:ok` if polling is running afterwards.
  """
  @spec start_polling(GenServer.server()) :: :ok | {:error, term()}
  def start_polling(server \\ __MODULE__), do: call(server, :start_polling)

  @doc "Stop polling (the radio stays powered, state becomes `:idle`)."
  @spec stop_polling(GenServer.server()) :: :ok | {:error, term()}
  def stop_polling(server \\ __MODULE__), do: call(server, :stop_polling)

  @doc """
  Release the active tag and resume polling. No-op unless the state is
  `:tag_active`.
  """
  @spec deactivate(GenServer.server()) :: :ok | {:error, term()}
  def deactivate(server \\ __MODULE__), do: call(server, :deactivate)

  @doc "Return the current state (see the module doc)."
  @spec state(GenServer.server()) :: fsm()
  def state(server \\ __MODULE__), do: call(server, :state)

  @doc "Stop polling if needed and power the controller down (radio off)."
  @spec dev_down(GenServer.server()) :: :ok | {:error, term()}
  def dev_down(server \\ __MODULE__), do: call(server, :dev_down)

  defp call(server, msg), do: GenServer.call(server, msg, @call_timeout)

  # ---- GenServer ---------------------------------------------------------

  @impl GenServer
  def init(opts) do
    state = %{
      family: Keyword.get(opts, :family, "nfc"),
      nfc: nil,
      nfc_id: nil,
      wanted_index: Keyword.get(opts, :device_index),
      device_index: nil,
      device_name: nil,
      requested_protocols: Keyword.get(opts, :poll_protocols) || Protocol.tag_mask(),
      poll_protocols: 0,
      autostart: Keyword.get(opts, :autostart, true),
      resume_after_tap: resume_policy(Keyword.get(opts, :resume_after_tap, :auto)),
      fsm: :unavailable,
      active_targets: [],
      retry_ms: @retry_initial_ms,
      failures: 0
    }

    {:ok, state, {:continue, :setup}}
  end

  defp resume_policy(policy) when policy in [:auto, :manual], do: policy

  defp resume_policy(other) do
    Logger.error("[ExNfc] invalid resume_after_tap #{inspect(other)}, using :auto")
    :auto
  end

  @impl GenServer
  def handle_continue(:setup, state), do: {:noreply, setup(state)}

  @impl GenServer
  def handle_info(:setup, state), do: {:noreply, setup(state)}

  def handle_info({:ex_nfc_event, id, :closed}, %{nfc_id: id} = state) do
    Logger.error("[ExNfc] netlink connection closed")
    {:noreply, reset(state)}
  end

  def handle_info({:ex_nfc_event, id, event}, %{nfc_id: id} = state) do
    {:noreply, handle_event(event, state)}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl GenServer
  def handle_call(:state, _from, state), do: {:reply, state.fsm, state}

  def handle_call(_msg, _from, %{fsm: :unavailable} = state) do
    {:reply, {:error, :nfc_unavailable}, state}
  end

  def handle_call(:list_devices, _from, state) do
    {:reply, dump_devices(state), state}
  end

  def handle_call(_msg, _from, %{fsm: :no_device} = state) do
    {:reply, {:error, :no_device}, state}
  end

  def handle_call(:start_polling, _from, %{fsm: :polling} = state), do: {:reply, :ok, state}

  def handle_call(:start_polling, _from, %{fsm: :tag_active} = state) do
    {reply, state} = release_and_repoll(state)
    {:reply, reply, state}
  end

  def handle_call(:start_polling, _from, state) do
    case bring_up_and_poll(state) do
      :ok -> {:reply, :ok, %{state | fsm: :polling}}
      err -> {:reply, err, state}
    end
  end

  def handle_call(:stop_polling, _from, %{fsm: :polling} = state) do
    case Native.stop_poll(state.nfc, state.device_index) do
      :ok -> {:reply, :ok, %{state | fsm: :idle}}
      err -> {:reply, err, state}
    end
  end

  def handle_call(:stop_polling, _from, %{fsm: :tag_active} = state) do
    # The kernel is no longer "polling" once a target was found, so
    # STOP_POLL would be rejected. Restart discovery (which puts the chip
    # back in a known RF state) and stop it again.
    case release_and_repoll(state) do
      {:ok, state} -> handle_call(:stop_polling, nil, state)
      {err, state} -> {:reply, err, state}
    end
  end

  def handle_call(:stop_polling, _from, state), do: {:reply, :ok, state}

  def handle_call(:deactivate, _from, %{fsm: :tag_active} = state) do
    {reply, state} = release_and_repoll(state)
    {:reply, reply, state}
  end

  def handle_call(:deactivate, _from, state), do: {:reply, :ok, state}

  def handle_call(:dev_down, _from, %{fsm: :down} = state), do: {:reply, :ok, state}

  def handle_call(:dev_down, _from, state) do
    idx = state.device_index

    case state.fsm do
      :polling -> _ = Native.stop_poll(state.nfc, idx)
      :tag_active -> deactivate_targets(state)
      _ -> :ok
    end

    state = drop_targets(state)

    case Native.dev_down(state.nfc, idx) do
      ok when ok in [:ok, {:error, :ealready}] ->
        {:reply, :ok, %{state | fsm: :down}}

      err ->
        {:reply, err, %{state | fsm: if(state.fsm == :tag_active, do: :idle, else: state.fsm)}}
    end
  end

  # ---- Setup / teardown --------------------------------------------------

  defp setup(state) do
    case open_nfc(state.family) do
      {:ok, nfc, id} ->
        if state.failures > 0, do: Logger.info("[ExNfc] kernel NFC subsystem now available")

        %{state | nfc: nfc, nfc_id: id, fsm: :no_device, retry_ms: @retry_initial_ms, failures: 0}
        |> discover()

      {:error, reason} ->

        if state.failures == 0 do
          Logger.warning(
            "[ExNfc] kernel NFC subsystem unavailable (#{inspect(reason)}), " <>
              "retrying in the background"
          )
        else
          Logger.debug("[ExNfc] NFC still unavailable: #{inspect(reason)}")
        end

        Process.send_after(self(), :setup, state.retry_ms)

        %{
          state
          | fsm: :unavailable,
            failures: state.failures + 1,
            retry_ms: min(state.retry_ms * 2, @retry_max_ms)
        }
    end
  end

  defp open_nfc(family) do
    Native.open(family, self())
  rescue
    ErlangError -> {:error, :nif_not_loaded}
  end

  # The connection closes once nothing references it any more.
  defp reset(state) do
    state = %{state | nfc: nil, nfc_id: nil}
    Process.send_after(self(), :setup, state.retry_ms)

    %{
      state
      | fsm: :unavailable,
        device_index: nil,
        device_name: nil,
        active_targets: [],
        failures: state.failures + 1
    }
  end

  # ---- Device discovery --------------------------------------------------

  defp dump_devices(state) do
    Native.get_devices(state.nfc)
  end

  defp discover(state) do
    case dump_devices(state) do
      {:ok, devices} ->
        case pick_device(devices, state.wanted_index) do
          nil ->
            Logger.info("[ExNfc] no NFC controller yet, waiting for one to appear")
            state

          dev ->
            bind_device(state, dev)
        end

      {:error, reason} ->
        Logger.error("[ExNfc] listing NFC controllers failed: #{inspect(reason)}")
        state
    end
  end

  defp pick_device(devices, nil), do: List.first(devices)
  defp pick_device(devices, idx), do: Enum.find(devices, &(&1.index == idx))

  defp bind_device(state, dev) do
    # Clamp to what the controller supports: an unsupported bit makes
    # START_POLL fail. Never poll for NFC-DEP (peer-to-peer).
    poll = state.requested_protocols &&& (dev.protocols || 0) &&& bnot(Protocol.nfc_dep_mask())

    state = %{
      state
      | device_index: dev.index,
        device_name: dev.name,
        poll_protocols: poll,
        fsm: if(dev.powered, do: :idle, else: :down)
    }

    Logger.info("[ExNfc] bound to #{dev.name} (index #{dev.index})")

    if state.autostart do
      case bring_up_and_poll(state) do
        :ok ->
          Logger.info(
            "[ExNfc] polling started on #{dev.name} (im_protocols=0x#{Integer.to_string(poll, 16)})"
          )

          %{state | fsm: :polling}

        {:error, reason} ->
          Logger.error("[ExNfc] autostart failed: #{inspect(reason)}")
          state
      end
    else
      state
    end
  end

  # ---- NFC commands ------------------------------------------------------

  defp bring_up_and_poll(state) do
    with :ok <- dev_up(state) do
      start_poll(state)
    end
  end

  defp dev_up(state) do
    case Native.dev_up(state.nfc, state.device_index) do
      {:error, :ealready} -> :ok
      other -> other
    end
  end

  defp start_poll(%{poll_protocols: 0}), do: {:error, :no_supported_protocols}

  defp start_poll(state) do
    case poll(state) do
      # From :idle/:down, EBUSY from nfc_start_poll means already polling.
      {:error, :ebusy} -> :ok
      other -> other
    end
  end

  # After NFC_EVENT_TARGETS_FOUND the kernel clears dev->polling, so
  # STOP_POLL is rejected with EINVAL. The way back to discovery is:
  #
  #   1. NFC_CMD_DEACTIVATE_TARGET for targets activated through an
  #      AF_NFC socket (ENOTCONN when none was — that's fine).
  #   2. NFC_CMD_START_POLL — NCI implicitly deactivates the RF interface
  #      (RF_DEACTIVATE idle) before starting discovery.
  #
  # If START_POLL still answers EBUSY the NCI core believes a target is
  # active (it happens when a connected tag was lost), and only a
  # DEV_DOWN / DEV_UP cycle clears it.
  defp repoll(state) do
    deactivate_targets(state)

    case poll(state) do
      {:error, :ebusy} ->
        Logger.warning("[ExNfc] controller busy after tag release, power-cycling it")

        with :ok <- dev_down_ok(state),
             :ok <- dev_up(state) do
          poll(state)
        end

      other ->
        other
    end
  end

  defp poll(state), do: Native.start_poll(state.nfc, state.device_index, state.poll_protocols, 0)

  defp dev_down_ok(state) do
    case Native.dev_down(state.nfc, state.device_index) do
      {:error, :ealready} -> :ok
      other -> other
    end
  end

  defp deactivate_targets(state) do
    for %{target_index: tidx} <- state.active_targets, is_integer(tidx) do
      case Native.deactivate_target(state.nfc, state.device_index, tidx) do
        :ok -> :ok
        {:error, :enotconn} -> :ok
        {:error, reason} -> Logger.debug("[ExNfc] deactivate target #{tidx}: #{inspect(reason)}")
      end
    end

    :ok
  end

  # Release the active targets, broadcast :tag_departed and resume polling.
  defp release_and_repoll(state) do
    result = repoll(state)
    state = drop_targets(state)

    case result do
      :ok ->
        {:ok, %{state | fsm: :polling}}

      {:error, reason} = err ->
        Logger.error("[ExNfc] could not resume polling: #{inspect(reason)}")
        {err, %{state | fsm: :idle}}
    end
  end

  defp drop_targets(state) do
    Enum.each(state.active_targets, &broadcast_departed(state, &1.target_index))
    %{state | active_targets: []}
  end

  # ---- Events -------------------------------------------------------------

  defp handle_event({:targets_found, idx}, %{device_index: idx} = state) when idx != nil do
    case get_targets(state) do
      {:ok, []} ->
        Logger.debug("[ExNfc] targets found event but no targets in dump")
        state

      {:ok, targets} ->
        Enum.each(targets, &broadcast({:tag_arrived, &1}))
        apply_resume_policy(%{state | fsm: :tag_active, active_targets: targets})

      {:error, reason} ->
        Logger.error("[ExNfc] reading found targets failed: #{inspect(reason)}")
        %{state | fsm: :tag_active}
    end
  end

  defp handle_event({:target_lost, idx, tidx}, %{device_index: idx} = state) when idx != nil do
    {lost, kept} = Enum.split_with(state.active_targets, &(&1.target_index == tidx))
    Enum.each(lost, fn _ -> broadcast_departed(state, tidx) end)
    state = %{state | active_targets: kept}

    if state.fsm == :tag_active and kept == [] do
      # The tag left the field: resume polling so the next one is seen.
      {_, state} = release_and_repoll(state)
      state
    else
      state
    end
  end

  defp handle_event({:device_added, dev}, state) do
    broadcast({:device_added, Map.take(dev, [:index, :name, :protocols])})

    if state.device_index == nil and state.wanted_index in [nil, dev.index] do
      bind_device(state, dev)
    else
      state
    end
  end

  defp handle_event({:device_removed, idx}, state) do
    broadcast({:device_removed, %{index: idx}})

    if idx != nil and idx == state.device_index do
      Logger.warning("[ExNfc] NFC controller #{state.device_name} removed")
      state = drop_targets(state)
      %{state | fsm: :no_device, device_index: nil, device_name: nil}
    else
      state
    end
  end

  defp handle_event(_event, state), do: state

  defp get_targets(state) do
    with {:ok, targets} <- Native.get_targets(state.nfc, state.device_index) do
      {:ok, Enum.map(targets, &Protocol.target(&1, state.device_index, state.device_name))}
    end
  end

  defp apply_resume_policy(%{resume_after_tap: :manual} = state), do: state

  defp apply_resume_policy(%{resume_after_tap: :auto} = state) do
    {_, state} = release_and_repoll(state)
    state
  end

  defp broadcast_departed(state, target_index) do
    broadcast(
      {:tag_departed,
       %{target_index: target_index, device_index: state.device_index, device: state.device_name}}
    )
  end

  defp broadcast({kind, payload}) do
    Registry.dispatch(ExNfc.Registry, :tag_events, fn subs ->
      for {pid, _} <- subs, do: send(pid, {ExNfc, kind, payload})
    end)
  end
end
