defmodule ExNfc.FakeTag do
  @moduledoc false
  # A stand-in for an AF_NFC socket: a connected AF_UNIX SOCK_SEQPACKET
  # pair. The "tag" side runs `handler.(frame, tag_state)` for every frame
  # and answers with the kernel's 1-byte NFC header prepended, exactly like
  # net/nfc/rawsock.c does.

  def start(handler, tag_state) do
    path = Path.join(System.tmp_dir!(), "ex_nfc_fake_#{System.unique_integer([:positive])}")
    File.rm(path)
    {:ok, lsock} = :socket.open(:local, :seqpacket, :default)
    :ok = :socket.bind(lsock, %{family: :local, path: path})
    :ok = :socket.listen(lsock)
    parent = self()

    tag =
      spawn_link(fn ->
        {:ok, sock} = :socket.accept(lsock)
        send(parent, {:accepted, self()})
        loop(sock, handler, tag_state)
      end)

    {:ok, csock} = :socket.open(:local, :seqpacket, :default)
    :ok = :socket.connect(csock, %{family: :local, path: path})

    receive do
      {:accepted, ^tag} -> :ok
    after
      1_000 -> raise "fake tag did not accept"
    end

    File.rm(path)
    conn = %ExNfc.Connection{sock: csock, device_index: 0, target_index: 1, nfc_protocol: 0}
    {conn, tag}
  end

  @doc "Fetch the tag's current state (e.g. its memory)."
  def get_state(tag) do
    send(tag, {:get_state, self()})

    receive do
      {:tag_state, s} -> s
    after
      1_000 -> raise "no state"
    end
  end

  defp loop(sock, handler, tag_state) do
    case :socket.recv(sock, 0, 50) do
      {:ok, frame} ->
        {reply, tag_state} = handler.(frame, tag_state)
        :ok = :socket.send(sock, <<0, reply::binary>>)
        loop(sock, handler, tag_state)

      {:error, :timeout} ->
        receive do
          {:get_state, from} -> send(from, {:tag_state, tag_state})
        after
          0 -> :ok
        end

        loop(sock, handler, tag_state)

      {:error, _closed} ->
        :ok
    end
  end
end
