//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/protocol.hpp"
#include "utils/io.hpp"
#include "zstd.h"

#include <algorithm>

namespace avpn {
	using stream_endian::bitstream;

	vpn_packet make_common_header(
		bool enc, uint8_t type, uint32_t src)
	{
		vpn_packet pkt;
		bitstream writer(pkt.data(), avpn_packet_size);

		writer.WriteBits(enc, 1);
		writer.WriteBits(0, 1);
		writer.WriteBits(type, 6);
		writer.WriteUInt32(src);

		auto bytes = writer.ByteOffset();
		pkt.resize(bytes);

		return pkt;
	}

	void make_common_header(vpn_packet& pkt,
		bool enc, uint8_t type, uint32_t src)
	{
		bitstream writer(pkt.data(), avpn_packet_size);

		writer.WriteBits(enc, 1);
		writer.WriteBits(0, 1);
		writer.WriteBits(type, 6);
		writer.WriteUInt32(src);
	}

	int unwrap_common_header(vpn_packet& pkt,
		bool& enc, uint8_t& type, uint32_t& src)
	{
		bitstream reader(pkt.data(), pkt.size());
		uint32_t t = 0;

		bool ret = reader.ReadBits(&t, 1);
		if (!ret) return -1;
		enc = !!t;
		t = 0;
		ret = reader.ReadBits(&t, 1);
		if (!ret) return -1;
		t = 0;
		ret = reader.ReadBits(&t, 6);
		if (!ret) return -1;
		type = (uint8_t)t;
		src = 0;
		ret = reader.ReadUInt32(&src);
		if (!ret) return -1;

		return (int)reader.ByteOffset();
	}

	vpn_packet make_handshake(uint32_t src,
		std::string_view id, std::string_view pubkey,
		uint8_t ds, uint8_t ps)
	{
		auto pkt = make_common_header(false, vpt_handshake, src);

		bitstream writer(pkt.data() + pkt.size(), avpn_packet_size - pkt.size());
		writer.WriteUInt8((uint8_t)id.size());
		writer.WriteString(id.data(), id.size());
		writer.WriteUInt8((uint8_t)pubkey.size());
		writer.WriteString(pubkey.data(), pubkey.size());
		writer.WriteUInt8(ds);
		writer.WriteUInt8(ps);
		writer.WriteUInt16(avpn_protocol_version);

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_handshake(vpn_packet& pkt,
		uint32_t& src, std::string& id, std::string& pubkey,
		uint8_t& ds, uint8_t& ps)
	{
		bool enc;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, type, src);
		if (bytes == -1)
			return -1;
		if (type != vpt_handshake)
			return -1;
		auto surplus = pkt.size() - bytes;
		bitstream reader(pkt.data() + bytes, surplus);
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

		ret = reader.ReadUInt8(&ds);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&ps);
		if (!ret) return -1;

		uint16_t protocol_version = 0;
		ret = reader.ReadUInt16(&protocol_version);
		if (!ret) return -1;
		if (protocol_version != avpn_protocol_version)
		{
			LOG_WARN << "Version not match"
				<< ", expect: " << avpn_protocol_version
				<< ", got: " << protocol_version;
			return -1;
		}

		bytes += (int)reader.ByteOffset();

		return bytes;
	}

	avpn::vpn_packet make_handshake_reply(std::string_view id,
		uint8_t ds, uint8_t ps,
		uint32_t addr, uint8_t prefix_length,
		bool passbyvpn, uint32_t pushdns,
		std::vector<std::string> routes)
	{
		auto pkt = make_common_header(
			false, vpt_handshake_reply, addr);

		bitstream writer(pkt.data() + pkt.size(), avpn_packet_size - pkt.size());

		writer.WriteUInt8((uint8_t)id.size());
		writer.WriteString(id.data(), id.size());

		writer.WriteUInt8(ds);
		writer.WriteUInt8(ps);

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
		std::string& id, uint8_t& ds, uint8_t& ps,
		uint32_t& addr, uint8_t& prefix_length,
		bool& passbyvpn, uint32_t& pushdns,
		std::vector<std::string>& routes)
	{
		bool enc;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, type, addr);
		if (bytes == -1)
			return -1;
		if (type != vpt_handshake_reply)
			return -1;
		auto surplus = pkt.size() - bytes;
		bitstream reader(pkt.data() + bytes, surplus);
		uint8_t v8 = 0;

		bool ret = reader.ReadUInt8(&v8);
		if (!ret) return -1;
		id.resize(v8);
		BOOST_ASSERT(v8 <= 32);
		ret = reader.ReadString((char*)id.data(), v8);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&ds);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&ps);
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

	vpn_packet make_keepalive(uint32_t src,
		std::string_view id,
		uint32_t rx, uint32_t tx,
		uint64_t timestamp/* = 0 */)
	{
		auto pkt = make_common_header(false, vpt_keepalive, src);
		auto w = pkt.data() + pkt.size();
		const auto base = w;

		stream_endian::write_uint8((uint8_t)id.size(), w);
		stream_endian::write_string(id, w);

		stream_endian::write_uint32(rx, w);
		stream_endian::write_uint32(tx, w);

		stream_endian::write_uint64(timestamp, w);

		auto bytes = w - base;
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_keepalive(vpn_packet& pkt,
		uint32_t& src,
		std::string& id,
		uint32_t& rx, uint32_t& tx,
		uint64_t& timestamp)
	{
		bool enc;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, type, src);
		if (bytes == -1)
			return -1;
		if (type != vpt_keepalive)
			return -1;

		auto surplus = pkt.size() - bytes;
		auto r = pkt.data() + bytes;
		const auto base = r;

		uint8_t length = stream_endian::read_uint8(r);
		if (--surplus < 0)
			return -1;
		BOOST_ASSERT(length <= 32);
		if (length > 32)
			return -1;

		id.assign((const char*)r, length);
		r += length;
		surplus -= length;
		if (surplus < 0)
			return -1;

		rx = stream_endian::read_uint32(r);
		surplus -= sizeof(uint32_t);
		if (surplus < 0) return -1;

		tx = stream_endian::read_uint32(r);
		surplus -= sizeof(uint32_t);
		if (surplus < 0) return -1;

		timestamp = stream_endian::read_uint64(r);
		surplus -= sizeof(uint64_t);
		if (surplus < 0) return -1;

		bytes = static_cast<int>(r - base);
		return bytes;
	}

	vpn_packet make_keepalive_reply(uint32_t src,
		std::string_view id,
		uint32_t rx, uint32_t tx,
		uint64_t timestamp/* = 0 */)
	{
		auto pkt = make_common_header(false, vpt_keepalive_reply, src);

		auto w = pkt.data() + pkt.size();
		const auto base = w;

		stream_endian::write_uint8((uint8_t)id.size(), w);
		stream_endian::write_string(id, w);

		stream_endian::write_uint32(rx, w);
		stream_endian::write_uint32(tx, w);

		stream_endian::write_uint64(timestamp, w);

		auto bytes = w - base;
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	int unwrap_keepalive_reply(vpn_packet& pkt,
		uint32_t& src,
		std::string& id,
		uint32_t& rx, uint32_t& tx,
		uint64_t& timestamp)
	{
		bool enc;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, type, src);
		if (bytes == -1)
			return -1;
		if (type != vpt_keepalive_reply)
			return -1;

		auto surplus = pkt.size() - bytes;
		auto r = pkt.data() + bytes;
		const auto base = r;

		uint8_t length = stream_endian::read_uint8(r);
		if (--surplus < 0)
			return -1;
		BOOST_ASSERT(length <= 32);
		if (length > 32)
			return -1;

		id.assign((const char*)r, length);
		r += length;
		surplus -= length;
		if (surplus < 0)
			return -1;

		rx = stream_endian::read_uint32(r);
		surplus -= sizeof(uint32_t);
		if (surplus < 0) return -1;

		tx = stream_endian::read_uint32(r);
		surplus -= sizeof(uint32_t);
		if (surplus < 0) return -1;

		timestamp = stream_endian::read_uint64(r);
		surplus -= sizeof(uint64_t);
		if (surplus < 0) return -1;

		bytes = static_cast<int>(r - base);
		return bytes;
	}

	vpn_packet make_transfer(uint32_t src,
		uint32_t gid, uint8_t pid, std::string_view data)
	{
		auto pkt = make_common_header(false, vpt_transfer, src);
		bitstream writer(pkt.data() + pkt.size(), avpn_packet_size - pkt.size());

		pkt.gid_ = gid;
		pkt.pid_ = pid;

		writer.WriteUInt32(gid);
		writer.WriteUInt8(pid);
		writer.WriteUInt8(0);
		writer.WriteUInt8(0);

		writer.WriteUInt16((uint16_t)data.size());
		writer.WriteString(data.data(), data.size());

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	void make_transfer(vpn_packet& pkt, uint32_t src,
		uint32_t gid, uint8_t pid, std::string_view data)
	{
		make_common_header(pkt, false, vpt_transfer, src);
		bitstream writer(pkt.data() + avpn_pkt_header_size,
			avpn_packet_size - avpn_pkt_header_size);

		pkt.gid_ = gid;
		pkt.pid_ = pid;

		writer.WriteUInt32(gid);
		writer.WriteUInt8(pid);
		writer.WriteUInt8(0);
		writer.WriteUInt8(0);

		writer.WriteUInt16((uint16_t)data.size());

		auto bytes = writer.ByteOffset() + data.size();
		pkt.resize(avpn_pkt_header_size + bytes);
	}

	int unwrap_transfer(vpn_packet& pkt,
		uint32_t& src, uint32_t& gid, uint8_t& pid)
	{
		bool enc;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, type, src);
		if (bytes == -1)
			return -1;
		if (type != vpt_transfer)
			return -1;

		auto surplus = pkt.size() - bytes;
		bitstream reader(pkt.data() + bytes, surplus);

		auto ret = reader.ReadUInt32(&gid);
		if (!ret) return -1;

		ret = reader.ReadUInt8(&pid);
		if (!ret) return -1;

		uint8_t rsv = 0;
		ret = reader.ReadUInt8(&rsv);
		if (!ret) return -1;
		ret = reader.ReadUInt8(&rsv);
		if (!ret) return -1;

		pkt.gid_ = gid;
		pkt.pid_ = pid;

		uint16_t length = 0;
		ret = reader.ReadUInt16(&length);
		if (!ret) return -1;

		BOOST_ASSERT(length <= surplus);
		length = std::min<uint16_t>(length, (uint16_t)surplus);

		pkt.payload_size(length);

		bytes += (int)reader.ByteOffset() + length;

		return bytes;
	}

	vpn_packet make_transfer_compress(uint32_t src,
		uint32_t gid, uint8_t pid,
		uint8_t ctype, std::string_view data)
	{
		auto pkt = make_common_header(
			false, vpt_transfer_compress, src);

		bitstream writer(pkt.data() + pkt.size(),
			avpn_packet_size - pkt.size());

		bool fallback = false;
		auto dst_size = ZSTD_compressBound(data.size());
		std::vector<uint8_t> dst(dst_size, 0);
		auto ret = ZSTD_compress(dst.data(), dst_size,
			data.data(), data.size(), ZSTD_CLEVEL_DEFAULT);
		if (ZSTD_isError(ret) || dst_size >= data.size())
			fallback = true;

		writer.WriteUInt32(gid);
		writer.WriteUInt8(pid);
		if (fallback)
			writer.WriteUInt8(0);
		else
			writer.WriteUInt8(ctype);

		writer.WriteUInt8(0);

		if (fallback)
		{
			writer.WriteUInt16((uint16_t)data.size());
			writer.WriteString(data.data(), data.size());
		}
		else
		{
			writer.WriteUInt16((uint16_t)ret);
			writer.WriteString((char*)dst.data(), ret);
		}

		auto bytes = writer.ByteOffset();
		pkt.resize(pkt.size() + bytes);

		return pkt;
	}

	void make_transfer_compress(vpn_packet& pkt, uint32_t src,
		uint32_t gid, uint8_t pid, uint8_t ctype, std::string_view data)
	{
		make_common_header(pkt, false, vpt_transfer_compress, src);
		bitstream writer(pkt.data() + avpn_pkt_header_size,
			avpn_packet_size - avpn_pkt_header_size);

		bool fallback = false;
		auto dst_size = ZSTD_compressBound(data.size());
		dst_size = std::max<size_t>(avpn_static_mtu, dst_size);
		std::vector<uint8_t> dst(dst_size, 0);
		dst_size = ZSTD_compress(dst.data(), dst_size,
			data.data(), data.size(), ZSTD_CLEVEL_DEFAULT);
		if (ZSTD_isError(dst_size) || dst_size >= data.size())
			fallback = true;

		pkt.gid_ = gid;
		pkt.pid_ = pid;

		writer.WriteUInt32(gid);
		writer.WriteUInt8(pid);

		if (fallback)
			writer.WriteUInt8(0);
		else
			writer.WriteUInt8(ctype);

		writer.WriteUInt8(0);

		if (fallback)
		{
			writer.WriteUInt16((uint16_t)data.size());
			dst_size = data.size();
		}
		else
		{
			writer.WriteUInt16((uint16_t)dst_size);
			std::memcpy(pkt.payload(), dst.data(), dst_size);
			std::memset(pkt.payload() + dst_size,
				0, avpn_payload_size - dst_size);
		}

		auto bytes = writer.ByteOffset() + dst_size;
		pkt.resize(avpn_pkt_header_size + bytes);
	}

	vpn_packet_ptr unwrap_transfer_compress(vpn_packet& pkt, uint32_t& src,
		uint32_t& gid, uint8_t& pid, uint8_t& ctype)
	{
		bool enc;
		uint8_t type;

		auto bytes = unwrap_common_header(pkt, enc, type, src);
		if (bytes == -1)
			return {};
		if (type != vpt_transfer_compress)
			return {};
		auto surplus = pkt.size() - bytes;
		bitstream reader(pkt.data() + bytes, surplus);

		auto ret = reader.ReadUInt32(&gid);
		if (!ret) return {};

		ret = reader.ReadUInt8(&pid);
		if (!ret) return {};

		pkt.gid_ = gid;
		pkt.pid_ = pid;

		ret = reader.ReadUInt8(&ctype);
		if (!ret) return {};
		uint8_t rsv = 0;
		ret = reader.ReadUInt8(&rsv);
		if (!ret) return {};

		uint16_t length = 0;
		ret = reader.ReadUInt16(&length);
		if (!ret) return {};

		BOOST_ASSERT(length <= surplus);
		length = std::min<uint16_t>(length, (uint16_t)surplus);
		size_t rawsize = length;

		if (ctype != 0)
		{
			auto tmp = std::make_shared<vpn_packet>();
			rawsize = ZSTD_decompress(tmp->payload(),
				avpn_static_mtu, pkt.payload(), length);
			if (ZSTD_isError(rawsize))
				return {};
			tmp->payload_size(rawsize);
			return tmp;
		}
		pkt.payload_size(rawsize);
		return dup_vpn_packet(pkt);
	}
}
