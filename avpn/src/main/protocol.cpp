//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/protocol.hpp"
#include "utils/io.hpp"

namespace avpn {
	using stream_endian::bitstream;

	vpn_packet make_common_header(
		bool enc, bool has_src, uint8_t type, uint32_t src)
	{
		vpn_packet pkt;
		bitstream writer(pkt.data(), 1450);

		writer.WriteBits(enc, 1);
		writer.WriteBits(has_src, 1);
		writer.WriteBits(type, 6);

		if (has_src)
			writer.WriteUInt32(src);

		auto bytes = writer.ByteOffset();
		pkt.resize(bytes);

		return pkt;
	}

	int unwrap_common_header(vpn_packet& pkt,
		bool& enc, bool& has_src, uint8_t& type, uint32_t& src)
	{
		bitstream reader(pkt.data(), pkt.size());
		uint32_t t = 0;
		reader.ReadBits(&t, 1);
		enc = !!t;
		reader.ReadBits(&t, 1);
		has_src = !!t;
		reader.ReadBits(&t, 6);
		type = (uint8_t)t;
		src = 0;

		if (has_src)
		{
			reader.ReadUInt32(&t);
			src = t;
		}

		return (int)reader.ByteOffset();
	}

	vpn_packet make_auth_request(
		uint32_t src, std::string_view id, std::string_view pubkey)
	{
		auto has_src = src == 0 ? false : true;
		auto pkt = make_common_header(false, has_src, vpt_auth_request, src);

		bitstream writer(pkt.data() + pkt.size(), 1450 - pkt.size());
		writer.WriteUInt16((uint16_t)id.size());
		writer.WriteString(id.data(), id.size());
		writer.WriteUInt16((uint16_t)pubkey.size());
		writer.WriteString(pubkey.data(), pubkey.size());

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_auth_request(vpn_packet& pkt,
		uint32_t& src, std::string& id, std::string& pubkey)
	{
		bool enc;
		bool has_src;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, has_src, type, src);

		bitstream reader(pkt.data() + bytes, pkt.size() - bytes);
		uint16_t length = 0;

		reader.ReadUInt16(&length);
		id.resize(length);
		BOOST_ASSERT(length <= 32);
		reader.ReadString((char*)id.data(), length);

		reader.ReadUInt16(&length);
		BOOST_ASSERT(length == 32);
		pubkey.resize(length);
		reader.ReadString((char*)pubkey.data(), length);

		bytes += (int)reader.ByteOffset();

		return bytes;
	}

}
