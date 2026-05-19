# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Controller do
  @moduledoc """
  GenServer that owns a `NETLINK_GENERIC` socket and drives the kernel
  NFC subsystem.

  Lifecycle:

    1. Open `AF_NETLINK / NETLINK_GENERIC` raw socket.
    2. Resolve the `"nfc"` family id and the `"events"` multicast group
       id via `CTRL_CMD_GETFAMILY`.
    3. Join the events multicast group so the kernel pushes
       `NFC_EVENT_TARGETS_FOUND` and friends to us.
    4. List the NFC controllers (`NFC_CMD_GET_DEVICE` dump) and pick
       the first one (typically `nfc0`).
    5. Bring it up (`NFC_CMD_DEV_UP`) and start polling
       (`NFC_CMD_START_POLL`).

  When the kernel reports a target it fans the event out via
  `Registry.dispatch/3` so application code can subscribe with
  `ExNfc.subscribe/0`.
  """

  use GenServer
  require Logger
  import Bitwise

  alias ExNfc.Netlink

  # ---- Socket constants ---------------------------------------------------

  @af_netlink 16
  @netlink_generic 16

  # SOL_NETLINK / NETLINK_ADD_MEMBERSHIP — used to join the NFC events
  # multicast group via `setsockopt`.
  @sol_netlink 270
  @netlink_add_membership 1

  # ---- NFC genetlink commands (uapi/linux/nfc.h:nfc_commands) ------------

  @nfc_cmd_get_device 1
  @nfc_cmd_dev_up 2
  @nfc_cmd_dev_down 3
  @nfc_cmd_start_poll 6
  @nfc_cmd_stop_poll 7
  @nfc_cmd_get_target 8
  @nfc_event_targets_found 9
  @nfc_event_device_added 10
  @nfc_event_device_removed 11
  @nfc_event_target_lost 12

  # ---- NFC attributes (uapi/linux/nfc.h:nfc_attrs) -----------------------

  @nfc_attr_device_index 1
  @nfc_attr_device_name 2
  @nfc_attr_protocols 3
  @nfc_attr_target_index 4
  @nfc_attr_target_sens_res 5
  @nfc_attr_target_sel_res 6
  @nfc_attr_target_nfcid1 7
  @nfc_attr_target_sensb_res 8
  @nfc_attr_target_sensf_res 9
  @nfc_attr_comm_mode 10
  @nfc_attr_im_protocols 13
  @nfc_attr_tm_protocols 14

  # ---- NFC protocol bitmask (uapi/linux/nfc.h) ---------------------------
  # `NFC_PROTO_*` shift values. These are **1-indexed** in the kernel
  # uAPI (`include/uapi/linux/nfc.h`), not 0-indexed — getting this
  # wrong is what produced "the target found does not have the desired
  # protocol" rejections in the kernel for every ISO-DEP card. Stay
  # in sync with uapi/linux/nfc.h.

  @nfc_proto_jewel 1
  @nfc_proto_mifare 2
  @nfc_proto_felica 3
  @nfc_proto_iso14443 4
  @nfc_proto_nfc_dep 5
  @nfc_proto_iso14443_b 6
  @nfc_proto_iso15693 7

  @poll_protocols_default bsl(1, @nfc_proto_jewel) |||
                            bsl(1, @nfc_proto_mifare) |||
                            bsl(1, @nfc_proto_felica) |||
                            bsl(1, @nfc_proto_iso14443) |||
                            bsl(1, @nfc_proto_iso14443_b) |||
                            bsl(1, @nfc_proto_iso15693)

  # NFC_COMM_MODE — 0 = active, 1 = passive (what tags are read in).
  @nfc_comm_passive 1

  # ------------------------------------------------------------------------

  @doc """
  Start the NFC controller GenServer.

  Options:

    * `:device_index` — bind to a specific kernel NFC controller
      index. Defaults to the first one discovered.
    * `:poll_protocols` — bitmask of `NFC_PROTO_*` shifts to poll for.
      Defaults to "everything except NFC-DEP" (i.e. tags, no peer-to-peer).
    * `:autostart` — when `true` (default), automatically bring the
      controller up and start polling. Set `false` for manual control.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Return all known NFC controllers as `[%{index, name, protocols}]`."
  @spec list_devices() :: [map()]
  def list_devices(), do: GenServer.call(__MODULE__, :list_devices)

  @doc "Start polling on the bound device."
  @spec start_polling() :: :ok | {:error, term()}
  def start_polling(), do: GenServer.call(__MODULE__, :start_polling)

  @doc "Stop polling on the bound device."
  @spec stop_polling() :: :ok | {:error, term()}
  def stop_polling(), do: GenServer.call(__MODULE__, :stop_polling)

  @doc "Bring the bound device down (radio off)."
  @spec dev_down() :: :ok | {:error, term()}
  def dev_down(), do: GenServer.call(__MODULE__, :dev_down)

  # ---- GenServer ---------------------------------------------------------

  @impl GenServer
  def init(opts) do
    state = %{
      sock: nil,
      family_id: nil,
      events_group: nil,
      device_index: Keyword.get(opts, :device_index),
      device_name: nil,
      poll_protocols: Keyword.get(opts, :poll_protocols, @poll_protocols_default),
      autostart: Keyword.get(opts, :autostart, true),
      buf: <<>>
    }

    case open_socket() do
      {:ok, sock} ->
        send(self(), :resolve_family)
        {:ok, %{state | sock: sock}}

      {:error, reason} ->
        Logger.error("[ExNfc] could not open NETLINK_GENERIC socket: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl GenServer
  def handle_info(:resolve_family, state) do
    case resolve_nfc_family(state.sock) do
      {:ok, %{family_id: fid, events_group: grp}} ->
        :ok = join_mcast(state.sock, grp)
        state = %{state | family_id: fid, events_group: grp}
        send(self(), :discover_devices)
        {:noreply, state}

      {:error, reason} ->
        Logger.error("[ExNfc] could not resolve 'nfc' generic-netlink family: #{inspect(reason)}")
        {:stop, reason, state}
    end
  end

  @discover_retry_ms 2_000
  @discover_max_attempts 15

  def handle_info(:discover_devices, %{family_id: fid, sock: sock} = state) do
    state = Map.put_new(state, :discover_attempts, 0)
    devices = dump_devices(sock, fid)

    idx =
      state.device_index ||
        case devices do
          [%{index: i} | _] -> i
          _ -> nil
        end

    cond do
      idx == nil and state.discover_attempts < @discover_max_attempts ->
        # Kernel hasn't registered the NCI controller yet (the i2c
        # driver probes asynchronously after we boot). Try again
        # shortly — but don't loop forever.
        Process.send_after(self(), :discover_devices, @discover_retry_ms)
        {:noreply, %{state | discover_attempts: state.discover_attempts + 1}}

      idx == nil ->
        Logger.warning("[ExNfc] no NFC controllers found after #{state.discover_attempts} tries — staying idle")
        install_recv(state.sock)
        {:noreply, state}

      true ->
        Logger.info("[ExNfc] discovered NFC devices: #{inspect(devices)}")
        device_protos = device_protocols(devices, idx) || 0
        # Clamp poll protocols to what the controller actually
        # supports — sending the kernel any unsupported bit makes
        # `START_POLL` fail with EOPNOTSUPP. Always strip NFC-DEP
        # (peer-to-peer) since we're only polling for tags.
        poll = state.poll_protocols &&& device_protos &&& bnot(bsl(1, @nfc_proto_nfc_dep))

        state = %{
          state
          | device_index: idx,
            device_name: device_name(devices, idx),
            poll_protocols: poll
        }

        if state.autostart do
          case bring_up_and_poll(state) do
            :ok ->
              Logger.info(
                "[ExNfc] polling started on #{state.device_name} (im_protocols=0x#{Integer.to_string(poll, 16)})"
              )

            {:error, reason} ->
              Logger.error("[ExNfc] autostart failed: #{inspect(reason)}")
          end
        end

        install_recv(state.sock)
        {:noreply, state}
    end
  end

  def handle_info({:"$socket", sock, :select, _}, %{sock: sock} = state) do
    {:noreply, drain_socket(state)}
  end

  def handle_info({:"$socket", sock, :abort, _}, %{sock: sock} = state) do
    Logger.error("[ExNfc] netlink socket aborted")
    {:stop, :socket_aborted, state}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl GenServer
  def handle_call(:list_devices, _from, %{sock: sock, family_id: fid} = state) do
    {:reply, dump_devices(sock, fid), state}
  end

  def handle_call(:start_polling, _from, state) do
    {:reply, start_poll_cmd(state), state}
  end

  def handle_call(:stop_polling, _from, %{family_id: fid, sock: sock, device_index: idx} = state)
      when not is_nil(idx) do
    attrs = Netlink.nla_u32(@nfc_attr_device_index, idx)
    msg = Netlink.pack(fid, @nfc_cmd_stop_poll, Netlink.request_flags(), attrs)
    {:reply, send_and_wait_ack(sock, msg), state}
  end

  def handle_call(:stop_polling, _from, state), do: {:reply, {:error, :no_device}, state}

  def handle_call(:dev_down, _from, %{family_id: fid, sock: sock, device_index: idx} = state)
      when not is_nil(idx) do
    attrs = Netlink.nla_u32(@nfc_attr_device_index, idx)
    msg = Netlink.pack(fid, @nfc_cmd_dev_down, Netlink.request_flags(), attrs)
    {:reply, send_and_wait_ack(sock, msg), state}
  end

  def handle_call(:dev_down, _from, state), do: {:reply, {:error, :no_device}, state}

  # ---- Socket helpers ----------------------------------------------------

  defp open_socket() do
    # OTP `:socket` doesn't expose a typed `sockaddr_nl`, so we hand it
    # the raw bytes that follow the family field: 2-byte pad, 4-byte
    # pid (0 = kernel auto-assigns), 4-byte groups bitmask. We add the
    # NFC events mcast group later via `NETLINK_ADD_MEMBERSHIP`.
    with {:ok, sock} <- :socket.open(@af_netlink, :raw, @netlink_generic),
         :ok <-
           :socket.bind(sock, %{
             family: @af_netlink,
             addr: <<0::16, 0::little-32, 0::little-32>>
           }) do
      {:ok, sock}
    end
  end

  # Install a non-blocking receive so the kernel will send us a
  # `{:"$socket", sock, :select, _}` message when data is ready. We
  # then call `:socket.recv/3` with timeout 0 to drain.
  defp install_recv(sock) do
    case :socket.recv(sock, 0, :nowait) do
      {:select, _info} -> :ok
      {:ok, data} -> send(self(), {:initial_data, data})
      {:error, _} -> :ok
    end
  end

  defp drain_socket(state) do
    case :socket.recv(state.sock, 0, :nowait) do
      {:ok, data} ->
        state = handle_data(state.buf <> data, state)
        drain_socket(state)

      {:select, _info} ->
        state

      {:error, :timeout} ->
        state

      {:error, reason} ->
        Logger.error("[ExNfc] netlink recv error: #{inspect(reason)}")
        state
    end
  end

  # OTP `:socket.setopt_native/3` lets us pass arbitrary `{level, opt}`
  # integer pairs — needed because `SOL_NETLINK (270)` has no atom
  # alias in `:socket`.
  defp join_mcast(_sock, nil), do: :ok

  defp join_mcast(sock, group_id) do
    :socket.setopt_native(
      sock,
      {@sol_netlink, @netlink_add_membership},
      <<group_id::little-32>>
    )
  rescue
    e ->
      Logger.warning("[ExNfc] join_mcast(#{group_id}) failed: #{Exception.message(e)}")
      :ok
  end

  # Generic helper: send + receive responses until we see an NLMSG_ERROR
  # (ack == 0) or NLMSG_DONE for this seq. Asynchronous events that
  # arrive before then are buffered into state.buf for `drain_socket/1`
  # to handle later — except here we don't have GenServer state, so we
  # let them be lost. That's OK for control commands (kernel never
  # multiplexes events with synchronous responses on the same fd
  # before we've joined the mcast group during init).
  defp send_and_wait_ack(sock, msg) do
    case :socket.send(sock, msg) do
      :ok ->
        wait_ack(sock)

      {:error, reason} ->
        {:error, {:send, reason}}
    end
  end

  defp wait_ack(sock) do
    case :socket.recv(sock, 0, 2_000) do
      {:ok, data} ->
        Enum.find_value(Netlink.parse_nlmsgs(data), {:error, :no_ack}, fn
          {type, _flags, _seq, _pid, body} ->
            if type == Netlink.nlmsg_error() do
              <<errno::little-signed-32, _orig::binary>> = body
              if errno == 0, do: :ok, else: {:error, errno_to_atom(-errno)}
            else
              nil
            end
        end)

      {:error, reason} ->
        {:error, {:recv, reason}}
    end
  end

  defp wait_response(sock, timeout \\ 2_000) do
    case :socket.recv(sock, 0, timeout) do
      {:ok, data} -> {:ok, Netlink.parse_nlmsgs(data)}
      {:error, reason} -> {:error, reason}
    end
  end

  # Minimal errno-to-atom mapping — covers the codes the kernel NFC
  # subsystem actually returns. Unknown values pass through as integers
  # so the call site still gets something matchable.
  @errno %{
    1 => :eperm,
    2 => :enoent,
    11 => :eagain,
    12 => :enomem,
    13 => :eacces,
    16 => :ebusy,
    17 => :eexist,
    19 => :enodev,
    22 => :einval,
    25 => :enotty,
    32 => :epipe,
    97 => :eafnosupport,
    105 => :enobufs,
    107 => :enotconn,
    110 => :etimedout,
    111 => :econnrefused,
    113 => :ehostunreach,
    114 => :ealready
  }

  defp errno_to_atom(n) when is_integer(n) and n > 0, do: Map.get(@errno, n, n)
  defp errno_to_atom(other), do: other

  # ---- NFC family resolution --------------------------------------------

  defp resolve_nfc_family(sock) do
    attrs = Netlink.nla_string(Netlink.ctrl_attr_family_name(), "nfc")

    msg =
      Netlink.pack(
        Netlink.genl_id_ctrl(),
        Netlink.ctrl_cmd_getfamily(),
        Netlink.request_flags(),
        attrs
      )

    with :ok <- :socket.send(sock, msg),
         {:ok, msgs} <- wait_response(sock) do
      case Enum.find(msgs, fn {type, _, _, _, _} -> type == Netlink.genl_id_ctrl() end) do
        nil ->
          {:error, :no_genl_reply}

        {_type, _flags, _seq, _pid, body} ->
          parse_family_reply(body)
      end
    end
  end

  defp parse_family_reply(<<_cmd::8, _ver::8, _rsvd::16, attrs::binary>>) do
    parsed = Netlink.parse_attrs(attrs)

    with fid_bin when is_binary(fid_bin) <-
           Netlink.find_attr(parsed, Netlink.ctrl_attr_family_id()),
         <<fid::little-16, _::binary>> <- fid_bin do
      grp = find_events_group(parsed)
      {:ok, %{family_id: fid, events_group: grp}}
    else
      _ -> {:error, :family_not_found}
    end
  end

  defp find_events_group(attrs) do
    case Netlink.find_attr(attrs, Netlink.ctrl_attr_mcast_groups()) do
      nil ->
        nil

      groups_bin ->
        groups_bin
        |> Netlink.parse_attrs()
        |> Enum.find_value(fn {_idx, body} ->
          inner = Netlink.parse_attrs(body)

          case Netlink.find_attr(inner, Netlink.ctrl_attr_mcast_grp_name()) do
            "events" <> _ ->
              case Netlink.find_attr(inner, Netlink.ctrl_attr_mcast_grp_id()) do
                <<gid::little-32>> -> gid
                _ -> nil
              end

            _ ->
              nil
          end
        end)
    end
  end

  # ---- NFC device discovery ---------------------------------------------

  defp dump_devices(sock, fid) do
    msg = Netlink.pack(fid, @nfc_cmd_get_device, Netlink.dump_flags(), [])

    with :ok <- :socket.send(sock, msg) do
      collect_dump(sock, fid, [])
    else
      _ -> []
    end
  end

  defp collect_dump(sock, fid, acc) do
    case wait_response(sock, 1_000) do
      {:ok, msgs} ->
        {new_acc, done?} =
          Enum.reduce(msgs, {acc, false}, fn {type, _f, _s, _p, body}, {accum, done?} ->
            cond do
              type == Netlink.nlmsg_done() -> {accum, true}
              type == fid -> {[parse_device(body) | accum], done?}
              true -> {accum, done?}
            end
          end)

        if done?, do: Enum.reverse(new_acc), else: collect_dump(sock, fid, new_acc)

      _ ->
        Enum.reverse(acc)
    end
  end

  defp parse_device(<<_cmd::8, _ver::8, _rsvd::16, attrs::binary>>) do
    parsed = Netlink.parse_attrs(attrs)

    %{
      index: u32(parsed, @nfc_attr_device_index),
      name: string(parsed, @nfc_attr_device_name),
      protocols: u32(parsed, @nfc_attr_protocols)
    }
  end

  defp device_name(devices, idx) do
    case Enum.find(devices, &(&1.index == idx)) do
      %{name: name} -> name
      _ -> nil
    end
  end

  defp device_protocols(devices, idx) do
    case Enum.find(devices, &(&1.index == idx)) do
      %{protocols: p} -> p
      _ -> nil
    end
  end

  # ---- Bring-up + poll --------------------------------------------------

  defp bring_up_and_poll(state) do
    with :ok <- dev_up_cmd(state),
         :ok <- start_poll_cmd(state) do
      :ok
    end
  end

  defp dev_up_cmd(%{family_id: fid, sock: sock, device_index: idx}) do
    attrs = Netlink.nla_u32(@nfc_attr_device_index, idx)
    msg = Netlink.pack(fid, @nfc_cmd_dev_up, Netlink.request_flags(), attrs)

    case send_and_wait_ack(sock, msg) do
      :ok ->
        :ok

      {:error, :ealready} ->
        # already up — fine
        :ok

      err ->
        err
    end
  end

  defp start_poll_cmd(%{family_id: fid, sock: sock, device_index: idx, poll_protocols: protos}) do
    attrs =
      [
        Netlink.nla_u32(@nfc_attr_device_index, idx),
        Netlink.nla_u32(@nfc_attr_im_protocols, protos),
        Netlink.nla_u32(@nfc_attr_tm_protocols, 0)
      ]
      |> IO.iodata_to_binary()

    msg = Netlink.pack(fid, @nfc_cmd_start_poll, Netlink.request_flags(), attrs)

    case send_and_wait_ack(sock, msg) do
      # `:ebusy` from `NFC_CMD_START_POLL` means polling is already
      # running on this controller — treat as success.
      {:error, :ebusy} -> :ok
      other -> other
    end
  end

  # ---- Event dispatch ----------------------------------------------------

  defp handle_data(buf, state) do
    msgs = Netlink.parse_nlmsgs(buf)
    Enum.each(msgs, fn m -> dispatch(m, state) end)
    %{state | buf: <<>>}
  end

  defp dispatch({type, _flags, _seq, _pid, body}, state) do
    cond do
      type == state.family_id -> handle_nfc_event(body, state)
      type == Netlink.nlmsg_error() -> :ok
      type == Netlink.nlmsg_done() -> :ok
      true -> :ok
    end
  end

  defp handle_nfc_event(<<cmd::8, _ver::8, _rsvd::16, attrs::binary>>, state) do
    parsed = Netlink.parse_attrs(attrs)

    case cmd do
      # NFC_EVENT_TARGETS_FOUND only carries NFC_ATTR_DEVICE_INDEX; per-target
      # details (UID, SENS_RES, etc.) are fetched via a separate
      # NFC_CMD_GET_TARGET dump. Issue that dump now — responses come back
      # async on this same socket as cmd = NFC_CMD_GET_TARGET messages.
      @nfc_event_targets_found ->
        request_targets(state, u32(parsed, @nfc_attr_device_index))

      @nfc_cmd_get_target ->
        target = parse_target(parsed)
        broadcast({:tag_found, Map.put(target, :device, state.device_name)})

      @nfc_event_target_lost ->
        broadcast({:tag_lost, %{device: state.device_name}})

      @nfc_event_device_added ->
        broadcast({:device_added, %{index: u32(parsed, @nfc_attr_device_index)}})

      @nfc_event_device_removed ->
        broadcast({:device_removed, %{index: u32(parsed, @nfc_attr_device_index)}})

      _ ->
        :ok
    end
  end

  # Send a NFC_CMD_GET_TARGET dump request for the given device. We don't wait
  # — the kernel's reply (one message per target, cmd = NFC_CMD_GET_TARGET) is
  # delivered through the normal `:"$socket"` event flow and dispatched back
  # through handle_nfc_event above.
  defp request_targets(%{sock: sock, family_id: fid}, idx) when is_integer(idx) do
    attrs = Netlink.nla_u32(@nfc_attr_device_index, idx)
    msg = Netlink.pack(fid, @nfc_cmd_get_target, Netlink.dump_flags(), attrs)
    _ = :socket.send(sock, msg)
    :ok
  end

  defp request_targets(_state, _idx), do: :ok

  defp parse_target(parsed) do
    nfcid1 = Netlink.find_attr(parsed, @nfc_attr_target_nfcid1)

    %{
      target_index: u32(parsed, @nfc_attr_target_index),
      protocol: u32(parsed, @nfc_attr_protocols) |> decode_first_protocol(),
      nfcid1: nfcid1,
      uid_hex: nfcid1 && hex(nfcid1),
      sens_res: u16(parsed, @nfc_attr_target_sens_res),
      sel_res: u8(parsed, @nfc_attr_target_sel_res),
      sensb_res: Netlink.find_attr(parsed, @nfc_attr_target_sensb_res),
      sensf_res: Netlink.find_attr(parsed, @nfc_attr_target_sensf_res),
      comm_mode: u32(parsed, @nfc_attr_comm_mode) || @nfc_comm_passive
    }
  end

  defp broadcast(event) do
    Registry.dispatch(ExNfc.Registry, :tag_events, fn subs ->
      for {pid, _} <- subs, do: send(pid, {ExNfc, elem(event, 0), elem(event, 1)})
    end)
  end

  # ---- Small decoders ---------------------------------------------------

  defp u32(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      <<n::little-32>> -> n
      _ -> nil
    end
  end

  defp u16(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      <<n::little-16>> -> n
      <<n::8>> -> n
      _ -> nil
    end
  end

  defp u8(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      <<n::8>> -> n
      _ -> nil
    end
  end

  defp string(parsed, type) do
    case Netlink.find_attr(parsed, type) do
      nil -> nil
      bin -> bin |> :binary.bin_to_list() |> Enum.take_while(&(&1 != 0)) |> List.to_string()
    end
  end

  defp decode_first_protocol(nil), do: nil

  defp decode_first_protocol(mask) when is_integer(mask) do
    cond do
      (mask &&& Bitwise.bsl(1, @nfc_proto_jewel)) != 0 -> :jewel
      (mask &&& Bitwise.bsl(1, @nfc_proto_mifare)) != 0 -> :mifare
      (mask &&& Bitwise.bsl(1, @nfc_proto_felica)) != 0 -> :felica
      (mask &&& Bitwise.bsl(1, @nfc_proto_iso14443)) != 0 -> :iso14443_a
      (mask &&& Bitwise.bsl(1, @nfc_proto_iso14443_b)) != 0 -> :iso14443_b
      (mask &&& Bitwise.bsl(1, @nfc_proto_iso15693)) != 0 -> :iso15693
      (mask &&& Bitwise.bsl(1, @nfc_proto_nfc_dep)) != 0 -> :nfc_dep
      true -> mask
    end
  end

  defp hex(bin) do
    for <<b <- bin>>, into: "", do: Integer.to_string(b, 16) |> String.pad_leading(2, "0")
  end
end
