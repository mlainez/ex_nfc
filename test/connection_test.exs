defmodule ExNfc.ConnectionTest do
  use ExUnit.Case, async: true

  alias ExNfc.{Connection, FakeTag}

  test "sockaddr_nfc includes the padding after sa_family (16-byte struct)" do
    assert %{family: 39, addr: addr} = Connection.sockaddr_nfc(1, 2, 4)
    assert byte_size(addr) + 2 == 16
    assert addr == <<0, 0, 1::native-32, 2::native-32, 4::native-32>>
  end

  test "open validates its argument" do
    assert {:error, :invalid_target} = Connection.open(target_index: 1, protocol: :mifare)
    assert {:error, :invalid_target} = Connection.open(%{target_index: 1, protocol: :mifare})
    assert {:error, :invalid_target} = Connection.open(:nope)

    assert {:error, {:unknown_protocol, :bogus}} =
             Connection.open(device_index: 0, target_index: 1, protocol: :bogus)
  end

  test "open without NFC hardware returns an error tuple" do
    # ENODEV when the kernel has NFC support but no controller,
    # EAFNOSUPPORT when it has none at all.
    assert {:error, _} = Connection.open(device_index: 250, target_index: 1, protocol: :mifare)
  end

  test "transceive strips the kernel's 1-byte header" do
    {conn, _} = FakeTag.start(fn frame, s -> {"echo:" <> frame, s} end, nil)
    assert {:ok, "echo:hi"} = Connection.transceive(conn, ["h", "i"])
    assert :ok = Connection.close(conn)
  end

  test "transceive times out" do
    {conn, _} = FakeTag.start(fn frame, s -> Process.sleep(200) && {frame, s} end, nil)
    assert {:error, :timeout} = Connection.transceive(conn, "x", 20)
  end
end
