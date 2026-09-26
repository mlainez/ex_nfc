defmodule ExNfc.ControllerTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias ExNfc.Controller

  @states [:unavailable, :no_device, :down, :idle, :polling, :tag_active]

  test "the application's controller is up whatever the host supports" do
    assert Process.whereis(Controller) |> Process.alive?()
    state = ExNfc.state()
    assert state in @states

    case state do
      :unavailable ->
        assert {:error, :nfc_unavailable} = ExNfc.list_devices()

      _ ->
        assert {:ok, devices} = ExNfc.list_devices()
        assert is_list(devices)
    end
  end

  test "a missing generic-netlink family leaves the controller :unavailable, not crashed" do
    log =
      capture_log(fn ->
        {:ok, pid} =
          Controller.start_link(name: :ex_nfc_test_controller, family: "ex_nfc_no_such_family")

        assert Controller.state(pid) == :unavailable
        assert {:error, :nfc_unavailable} = Controller.list_devices(pid)
        assert {:error, :nfc_unavailable} = Controller.start_polling(pid)
        assert {:error, :nfc_unavailable} = Controller.stop_polling(pid)
        assert {:error, :nfc_unavailable} = Controller.deactivate(pid)
        assert {:error, :nfc_unavailable} = Controller.dev_down(pid)
        assert Process.alive?(pid)
        GenServer.stop(pid)
      end)

    assert log =~ "unavailable"
  end

  test "commands without a bound controller return :no_device" do
    if ExNfc.state() == :no_device do
      assert {:error, :no_device} = ExNfc.start_polling()
      assert {:error, :no_device} = ExNfc.deactivate()
      assert {:error, :no_device} = ExNfc.dev_down()
    end
  end

  test "subscribe is idempotent" do
    assert :ok = ExNfc.subscribe()
    assert :ok = ExNfc.subscribe()
    assert Registry.keys(ExNfc.Registry, self()) == [:tag_events]
    assert :ok = ExNfc.unsubscribe()
    assert Registry.keys(ExNfc.Registry, self()) == []
  end
end
