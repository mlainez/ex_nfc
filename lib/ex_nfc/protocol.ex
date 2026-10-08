# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Protocol do
  @moduledoc false
  # NFC_PROTO_* values (include/uapi/linux/nfc.h) and the target map
  # broadcast with `:tag_arrived`.

  import Bitwise

  @proto_nfc_dep 5

  @protocols [
    {1, :jewel},
    {2, :mifare},
    {3, :felica},
    {4, :iso14443_a},
    {6, :iso14443_b},
    {7, :iso15693},
    {@proto_nfc_dep, :nfc_dep}
  ]

  @doc "Bitmask of every tag (non peer-to-peer) protocol."
  def tag_mask do
    for {shift, _} <- @protocols, shift != @proto_nfc_dep, reduce: 0 do
      acc -> acc ||| bsl(1, shift)
    end
  end

  @doc "Bit for NFC-DEP (peer-to-peer)."
  def nfc_dep_mask, do: bsl(1, @proto_nfc_dep)

  @doc "Translate a protocol atom (or raw `NFC_PROTO_*` value) to the raw value."
  @spec value(atom() | non_neg_integer()) :: {:ok, non_neg_integer()} | :error
  def value(n) when is_integer(n) and n >= 0, do: {:ok, n}
  def value(:iso14443), do: value(:iso14443_a)

  def value(atom) when is_atom(atom) do
    case List.keyfind(@protocols, atom, 1) do
      {n, ^atom} -> {:ok, n}
      nil -> :error
    end
  end

  def value(_), do: :error

  @doc "The first protocol set in a `NFC_ATTR_PROTOCOLS` bitmask."
  @spec first(non_neg_integer() | nil) :: atom() | non_neg_integer() | nil
  def first(nil), do: nil

  def first(mask) when is_integer(mask) do
    Enum.find_value(@protocols, mask, fn {shift, name} ->
      if (mask &&& bsl(1, shift)) != 0, do: name
    end)
  end

  @doc """
  The `:tag_arrived` target map, from the attributes the kernel reports
  for a target and the controller it was found on.
  """
  def target(attrs, device_index, device_name) do
    uid = attrs.nfcid1 || attrs.iso15693_uid

    Map.merge(attrs, %{
      device_index: device_index,
      device: device_name,
      protocol: first(attrs.protocols),
      uid_hex: uid && Base.encode16(uid)
    })
  end
end
