# SPDX-FileCopyrightText: 2026 Marc Lainez
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ExNfc.Netlink do
  @moduledoc """
  Low-level encoders / decoders for `NETLINK_GENERIC` messages targeting
  the Linux kernel `nfc` family.

  Two layers are at play here:

    * **Netlink header** (16 bytes) — `nlmsg_len` / `nlmsg_type` /
      `nlmsg_flags` / `nlmsg_seq` / `nlmsg_pid`.
    * **Generic-netlink header** (4 bytes) — `cmd` / `version` /
      `reserved`.

  After both headers come zero or more NLAs (Netlink attributes),
  each TLV-encoded as `<<u16 len, u16 type, payload, padding to 4>>`.

  This module exposes:

    * `pack/4` — assemble a complete netlink message.
    * `parse_nlmsgs/1` — split a recv buffer into individual messages.
    * `parse_attrs/1` — decode the NLA TLVs in a message body.

  Constants for the NFC family itself live in `ExNfc.Controller`; this
  module is intentionally protocol-agnostic so it can be reused for any
  generic-netlink family.
  """

  import Bitwise

  # nlmsghdr flags (uapi/linux/netlink.h)
  @nlm_f_request 0x0001
  @nlm_f_ack 0x0004
  @nlm_f_root 0x0100
  @nlm_f_match 0x0200
  @nlm_f_dump @nlm_f_root ||| @nlm_f_match

  # nlmsghdr "well-known" types
  @nlmsg_error 0x0002
  @nlmsg_done 0x0003

  # GENL control family — used to resolve other family ids by name.
  @genl_id_ctrl 0x10
  @ctrl_cmd_getfamily 3
  @ctrl_attr_family_id 1
  @ctrl_attr_family_name 2
  @ctrl_attr_mcast_groups 7
  @ctrl_attr_mcast_grp_name 1
  @ctrl_attr_mcast_grp_id 2

  @doc "Flags that say request + want-ack (the common case)."
  @spec request_flags() :: non_neg_integer()
  def request_flags(), do: @nlm_f_request ||| @nlm_f_ack

  @doc "Flags for a dump-style request (returns multiple messages + DONE)."
  @spec dump_flags() :: non_neg_integer()
  def dump_flags(), do: @nlm_f_request ||| @nlm_f_dump

  @doc "Well-known `NLMSG_ERROR` type id."
  @spec nlmsg_error() :: non_neg_integer()
  def nlmsg_error(), do: @nlmsg_error

  @doc "Well-known `NLMSG_DONE` type id."
  @spec nlmsg_done() :: non_neg_integer()
  def nlmsg_done(), do: @nlmsg_done

  @doc "Generic-netlink CTRL family id (16, fixed by the kernel)."
  @spec genl_id_ctrl() :: non_neg_integer()
  def genl_id_ctrl(), do: @genl_id_ctrl

  @doc "CTRL_CMD_GETFAMILY command id."
  @spec ctrl_cmd_getfamily() :: non_neg_integer()
  def ctrl_cmd_getfamily(), do: @ctrl_cmd_getfamily

  @doc "Attribute id `CTRL_ATTR_FAMILY_NAME`."
  @spec ctrl_attr_family_name() :: non_neg_integer()
  def ctrl_attr_family_name(), do: @ctrl_attr_family_name

  @doc "Attribute id `CTRL_ATTR_FAMILY_ID`."
  @spec ctrl_attr_family_id() :: non_neg_integer()
  def ctrl_attr_family_id(), do: @ctrl_attr_family_id

  @doc "Attribute id `CTRL_ATTR_MCAST_GROUPS`."
  @spec ctrl_attr_mcast_groups() :: non_neg_integer()
  def ctrl_attr_mcast_groups(), do: @ctrl_attr_mcast_groups

  @doc "Inside a mcast-group block: name attribute id."
  @spec ctrl_attr_mcast_grp_name() :: non_neg_integer()
  def ctrl_attr_mcast_grp_name(), do: @ctrl_attr_mcast_grp_name

  @doc "Inside a mcast-group block: numeric id attribute id."
  @spec ctrl_attr_mcast_grp_id() :: non_neg_integer()
  def ctrl_attr_mcast_grp_id(), do: @ctrl_attr_mcast_grp_id

  @doc """
  Build a complete generic-netlink message for transmission.

  `family_id` is the resolved id of the target family (use
  `genl_id_ctrl/0` to talk to the GENL control family itself).
  `cmd` is the family-specific command id.
  `flags` should usually be `request_flags/0` or `dump_flags/0`.
  `attrs` is an iolist of already-packed NLAs (see `nla/2`).
  """
  @spec pack(non_neg_integer(), non_neg_integer(), non_neg_integer(), iodata()) :: binary()
  def pack(family_id, cmd, flags, attrs) do
    seq = unique_seq()
    body = IO.iodata_to_binary([<<cmd::8, 1::8, 0::16>>, attrs])
    total = 16 + byte_size(body)

    <<total::little-32, family_id::little-16, flags::little-16, seq::little-32, 0::little-32>> <>
      body
  end

  @doc "Pack one Netlink attribute (TLV with 4-byte alignment padding)."
  @spec nla(non_neg_integer(), iodata()) :: binary()
  def nla(type, value) do
    value_bin = IO.iodata_to_binary([value])
    len = 4 + byte_size(value_bin)
    pad = padding(len)
    <<len::little-16, type::little-16>> <> value_bin <> :binary.copy(<<0>>, pad)
  end

  @doc "Pack a NUL-terminated string NLA."
  @spec nla_string(non_neg_integer(), String.t()) :: binary()
  def nla_string(type, str), do: nla(type, str <> <<0>>)

  @doc "Pack a u32 NLA."
  @spec nla_u32(non_neg_integer(), non_neg_integer()) :: binary()
  def nla_u32(type, value), do: nla(type, <<value::little-32>>)

  @doc """
  Split a netlink receive buffer into individual messages.

  Each entry is `{nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid, body}`
  where `body` is everything past the 16-byte netlink header (so it
  includes the genlmsghdr for genetlink messages).
  """
  @spec parse_nlmsgs(binary()) :: [
          {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), binary()}
        ]
  def parse_nlmsgs(buf), do: parse_nlmsgs(buf, [])

  defp parse_nlmsgs(<<>>, acc), do: Enum.reverse(acc)

  defp parse_nlmsgs(
         <<len::little-32, type::little-16, flags::little-16, seq::little-32, pid::little-32,
           rest::binary>> = full,
         acc
       )
       when len >= 16 and byte_size(full) >= len do
    payload_len = len - 16
    aligned = aligned_size(len)
    <<body::binary-size(payload_len), tail::binary>> = rest
    tail_skip = aligned - len
    tail = drop_padding(tail, tail_skip)
    parse_nlmsgs(tail, [{type, flags, seq, pid, body} | acc])
  end

  defp parse_nlmsgs(_truncated, acc), do: Enum.reverse(acc)

  defp drop_padding(bin, n) when n <= 0, do: bin

  defp drop_padding(bin, n) when byte_size(bin) >= n do
    <<_::binary-size(n), rest::binary>> = bin
    rest
  end

  defp drop_padding(_bin, _n), do: <<>>

  @doc """
  Decode the NLA TLVs that follow a generic-netlink header.

  Pass the message `body` *minus* the 4-byte `genlmsghdr`. Returns a
  list of `{type, value}` pairs in the order they appear. Values are
  raw binaries; nested NLAs can be re-parsed by passing them back
  through `parse_attrs/1`.
  """
  @spec parse_attrs(binary()) :: [{non_neg_integer(), binary()}]
  def parse_attrs(body), do: parse_attrs(body, [])

  defp parse_attrs(<<>>, acc), do: Enum.reverse(acc)

  defp parse_attrs(
         <<len::little-16, type::little-16, rest::binary>>,
         acc
       )
       when len >= 4 do
    val_len = len - 4
    aligned = aligned_size(len)

    case rest do
      <<value::binary-size(val_len), tail::binary>> ->
        tail = drop_padding(tail, aligned - len)
        parse_attrs(tail, [{type, value} | acc])

      _ ->
        Enum.reverse(acc)
    end
  end

  defp parse_attrs(_truncated, acc), do: Enum.reverse(acc)

  @doc """
  Find an attribute by id in a list returned from `parse_attrs/1`.
  Returns the raw binary value or `nil`.
  """
  @spec find_attr([{non_neg_integer(), binary()}], non_neg_integer()) :: binary() | nil
  def find_attr(attrs, type) do
    case List.keyfind(attrs, type, 0) do
      {^type, value} -> value
      nil -> nil
    end
  end

  defp padding(len), do: rem(4 - rem(len, 4), 4)
  defp aligned_size(len), do: len + padding(len)

  defp unique_seq do
    :erlang.unique_integer([:positive]) |> rem(0xFFFFFFFF)
  end
end
