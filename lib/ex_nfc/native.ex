# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Native do
  @moduledoc false
  # Rust NIF: the kernel `nfc` generic-netlink family through `neli`, and
  # NDEF record framing through `ndef-rs`. See native/ex_nfc_nif.

  use Rustler, otp_app: :ex_nfc, crate: "ex_nfc_nif"

  def open(_family, _pid), do: :erlang.nif_error(:nif_not_loaded)
  def get_devices(_nfc), do: :erlang.nif_error(:nif_not_loaded)
  def get_targets(_nfc, _dev), do: :erlang.nif_error(:nif_not_loaded)
  def dev_up(_nfc, _dev), do: :erlang.nif_error(:nif_not_loaded)
  def dev_down(_nfc, _dev), do: :erlang.nif_error(:nif_not_loaded)
  def start_poll(_nfc, _dev, _im, _tm), do: :erlang.nif_error(:nif_not_loaded)
  def stop_poll(_nfc, _dev), do: :erlang.nif_error(:nif_not_loaded)
  def deactivate_target(_nfc, _dev, _target), do: :erlang.nif_error(:nif_not_loaded)
  def ndef_decode(_data), do: :erlang.nif_error(:nif_not_loaded)
  def ndef_encode(_records), do: :erlang.nif_error(:nif_not_loaded)
  def uri_prefixes, do: :erlang.nif_error(:nif_not_loaded)
end
