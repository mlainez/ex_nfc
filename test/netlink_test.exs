defmodule ExNfc.NetlinkTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias ExNfc.Netlink

  doctest ExNfc.Netlink

  describe "pack/5" do
    test "builds nlmsghdr + genlmsghdr + attrs with correct total length" do
      attrs = Netlink.nla_u32(1, 7)
      msg = Netlink.pack(28, 6, Netlink.request_flags(), attrs, 42)

      assert <<len::little-32, 28::little-16, 0x0005::little-16, 42::little-32, 0::32, 6, 1, 0, 0,
               rest::binary>> = msg

      assert len == byte_size(msg)
      assert len == 16 + 4 + 8
      assert rest == attrs
    end

    test "dump flags are REQUEST | ROOT | MATCH" do
      assert Netlink.dump_flags() == 0x0301
    end

    test "generates distinct non-zero sequence numbers when none is given" do
      <<_::64, s1::little-32, _::binary>> = Netlink.pack(16, 3, 0, [])
      <<_::64, s2::little-32, _::binary>> = Netlink.pack(16, 3, 0, [])
      assert s1 != s2
      assert s1 > 0 and s2 > 0
    end
  end

  describe "nla" do
    test "pads values to 4 bytes but reports the unpadded length" do
      assert Netlink.nla(2, "abc") == <<7::little-16, 2::little-16, "abc", 0>>
      assert Netlink.nla(2, "abcd") == <<8::little-16, 2::little-16, "abcd">>
      assert Netlink.nla(2, "") == <<4::little-16, 2::little-16>>
    end

    test "nla_string NUL-terminates" do
      assert Netlink.nla_string(2, "nfc") == <<8::little-16, 2::little-16, "nfc", 0>>
    end

    test "nla_u32 is little-endian" do
      assert Netlink.nla_u32(1, 0x01020304) == <<8, 0, 1, 0, 4, 3, 2, 1>>
    end
  end

  describe "parse_nlmsgs/1" do
    test "splits several messages and drops alignment padding" do
      m1 = Netlink.pack(28, 1, 0, Netlink.nla(1, "abc"), 5)
      m2 = Netlink.pack(28, 2, 0, [], 6)
      # m1 is 16 + 4 + 8 = 28 bytes, already aligned; add an odd one
      odd = <<17::little-32, 3::little-16, 0::16, 7::little-32, 0::32, 0xAA, 0, 0, 0>>

      assert [
               {28, 0, 5, 0, <<1, 1, 0, 0, _::binary>>},
               {3, 0, 7, 0, <<0xAA>>},
               {28, 0, 6, 0, <<2, 1, 0, 0>>}
             ] = Netlink.parse_nlmsgs(m1 <> odd <> m2)
    end

    test "stops at a truncated message" do
      m = Netlink.pack(28, 1, 0, [], 5)
      assert [{28, 0, 5, 0, _}] = Netlink.parse_nlmsgs(m <> binary_part(m, 0, 10))
      assert [] = Netlink.parse_nlmsgs(<<100::little-32, 0::96>>)
    end
  end

  describe "parse_attrs/1" do
    test "decodes TLVs in order, skipping padding" do
      bin = Netlink.nla(1, "a") <> Netlink.nla_u32(2, 9) <> Netlink.nla(3, "hello")
      assert [{1, "a"}, {2, <<9::little-32>>}, {3, "hello"}] = Netlink.parse_attrs(bin)
    end

    test "masks NLA_F_NESTED and NLA_F_NET_BYTEORDER from the type" do
      inner = Netlink.nla_u32(2, 5)
      nested = Netlink.nla(7 ||| 0x8000, inner)
      netorder = Netlink.nla(4 ||| 0x4000, <<1, 2>>)

      assert [{7, ^inner}, {4, <<1, 2>>}] = Netlink.parse_attrs(nested <> netorder)
      assert [{2, <<5::little-32>>}] = Netlink.parse_attrs(inner)
    end

    test "stops on truncated or invalid attributes" do
      good = Netlink.nla(1, "abcd")
      assert [{1, "abcd"}] = Netlink.parse_attrs(good <> <<20::little-16, 2::little-16, "x">>)
      assert [] = Netlink.parse_attrs(<<2::little-16, 1::little-16>>)
    end

    test "find_attr returns the value or nil" do
      attrs = [{1, "a"}, {2, "b"}]
      assert Netlink.find_attr(attrs, 2) == "b"
      assert Netlink.find_attr(attrs, 3) == nil
    end
  end
end
