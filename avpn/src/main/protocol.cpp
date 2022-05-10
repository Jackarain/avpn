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

		bool ret = reader.ReadBits(&t, 1);
		if (!ret) return -1;
		enc = !!t;
		ret = reader.ReadBits(&t, 1);
		if (!ret) return -1;
		has_src = !!t;
		ret = reader.ReadBits(&t, 6);
		if (!ret) return -1;
		type = (uint8_t)t;
		src = 0;

		if (has_src)
		{
			ret = reader.ReadUInt32(&t);
			if (!ret) return -1;

			src = t;
		}

		return (int)reader.ByteOffset();
	}

	vpn_packet make_handshake(uint32_t src,
		std::string_view id, std::string_view pubkey,
		std::string_view additional/* = {}*/)
	{
		auto has_src = src == 0 ? false : true;
		auto pkt = make_common_header(false, has_src, vpt_handshake, src);

		bitstream writer(pkt.data() + pkt.size(), 1450 - pkt.size());
		writer.WriteUInt8((uint8_t)id.size());
		writer.WriteString(id.data(), id.size());
		writer.WriteUInt8((uint8_t)pubkey.size());
		writer.WriteString(pubkey.data(), pubkey.size());
		writer.WriteUInt16((uint8_t)additional.size());
		if (additional.size() > 0)
			writer.WriteString(additional.data(), additional.size());

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_handshake(vpn_packet& pkt,
		uint32_t& src, std::string& id, std::string& pubkey,
		std::string& additional)
	{
		bool enc;
		bool has_src;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, has_src, type, src);

		bitstream reader(pkt.data() + bytes, pkt.size() - bytes);
		uint8_t length = 0;

		bool ret = reader.ReadUInt8(&length);
		if (!ret) return -1;
		id.resize(length);
		BOOST_ASSERT(length <= 32);
		ret = reader.ReadString((char*)id.data(), length);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&length);
		if (!ret) return -1;
		BOOST_ASSERT(length == 32);
		pubkey.resize(length);
		ret = reader.ReadString((char*)pubkey.data(), length);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&length);
		if (!ret) return -1;
		if (length > 0)
		{
			additional.resize(length);
			reader.ReadString(additional.data(), length);
		}

		bytes += (int)reader.ByteOffset();

		return bytes;
	}

	avpn::vpn_packet make_handshake_reply(std::string_view id, uint32_t addr,
		uint8_t prefix_length, bool passbyvpn, uint32_t pushdns,
		std::vector<std::string> routes)
	{
		auto has_src = addr == 0 ? false : true;
		auto pkt = make_common_header(
			false, has_src, vpt_handshake_reply, addr);

		bitstream writer(pkt.data() + pkt.size(), 1450 - pkt.size());

		writer.WriteUInt8((uint8_t)id.size());
		writer.WriteString(id.data(), id.size());

		writer.WriteUInt32(addr);
		writer.WriteUInt8(prefix_length);
		writer.WriteUInt8((uint8_t)passbyvpn);
		writer.WriteUInt32(pushdns);
		writer.WriteUInt8((uint8_t)routes.size());
		for (auto& r : routes)
		{
			writer.WriteUInt8((uint8_t)r.size());
			writer.WriteString(r.data(), r.size());
		}

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_handshake_reply(vpn_packet& pkt,
		std::string& id, uint32_t& addr, uint8_t& prefix_length,
		bool& passbyvpn, uint32_t& pushdns,
		std::vector<std::string>& routes)
	{
		bool enc;
		bool has_src;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, has_src, type, addr);

		bitstream reader(pkt.data() + bytes, pkt.size() - bytes);
		uint8_t v8 = 0;

		bool ret = reader.ReadUInt8(&v8);
		if (!ret) return -1;
		id.resize(v8);
		BOOST_ASSERT(v8 <= 32);
		ret = reader.ReadString((char*)id.data(), v8);
		if (!ret) return -1;

		ret = reader.ReadUInt32(&addr);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&prefix_length);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&v8);
		if (!ret) return -1;
		passbyvpn = !!v8;

		ret = reader.ReadUInt32(&pushdns);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&v8);
		if (!ret) return -1;

		for (auto i = 0; i < v8; i++)
		{
			uint8_t len = 0;
			ret = reader.ReadUInt8(&len);
			if (!ret) return -1;

			std::string route(len, 0);
			reader.ReadString(route.data(), len);

			routes.push_back(route);
		}

		bytes += (int)reader.ByteOffset();

		return bytes;
	}

	vpn_packet make_transfer(uint32_t src, std::string_view data)
	{
		auto has_src = src == 0 ? false : true;
		auto pkt = make_common_header(false, has_src, vpt_transfer, src);

		bitstream writer(pkt.data() + pkt.size(), 1450 - pkt.size());
		writer.WriteUInt16((uint16_t)data.size());
		writer.WriteString(data.data(), data.size());

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_transfer(vpn_packet& pkt, uint32_t& src, std::string& data)
	{
		bool enc;
		bool has_src;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, has_src, type, src);

		bitstream reader(pkt.data() + bytes, pkt.size() - bytes);
		uint16_t length = 0;

		auto ret = reader.ReadUInt16(&length);
		if (!ret) return -1;

		data.resize(length);
		reader.ReadString(data.data(), length);

		bytes += (int)reader.ByteOffset();

		return bytes;
	}

	vpn_packet make_transfer_compress(uint32_t src, std::string_view data)
	{
		auto has_src = src == 0 ? false : true;
		auto pkt = make_common_header(
			false, has_src, vpt_transfer_compress, src);

		bitstream writer(pkt.data() + pkt.size(), 1450 - pkt.size());

		writer.WriteUInt8(0);
		writer.WriteUInt16((uint16_t)data.size());
		writer.WriteString(data.data(), data.size());

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_transfer_compress(
		vpn_packet& pkt, uint32_t& src, std::string& data)
	{
		bool enc;
		bool has_src;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, has_src, type, src);

		bitstream reader(pkt.data() + bytes, pkt.size() - bytes);
		uint16_t length = 0;

		uint8_t compress_type = 0;
		auto ret = reader.ReadUInt8(&compress_type);
		if (!ret) return -1;

		ret = reader.ReadUInt16(&length);
		if (!ret) return -1;

		data.resize(length);
		reader.ReadString(data.data(), length);

		bytes += (int)reader.ByteOffset();

		return bytes;
	}

}
