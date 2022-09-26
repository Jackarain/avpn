//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_packet.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/protocol.hpp"

namespace avpn {

	//////////////////////////////////////////////////////////////////////////
	void packet_free::operator()(void* p)
	{
		static_packet_allocator()->free_packet((uint8_t*)p);
	}

	vpn_packet::vpn_packet()
		: data_(static_packet_allocator()->alloc_packet())
	{}

	vpn_packet::vpn_packet(vpn_packet&& p)
		: data_(std::move(p.data_))
		, size_(p.size_)
		, payload_size_(p.payload_size_)
		, index_(p.index_)
		, type_(p.type_)
		, pkt_flag_(p.pkt_flag_)
	{
		p.size_ = 0;
		p.payload_size_ = 0;
		p.pkt_flag_ = 0;
	}

	vpn_packet& vpn_packet::operator=(vpn_packet&& p)
	{
		data_ = std::move(p.data_);
		size_ = p.size_;
		payload_size_ = p.payload_size_;
		index_ = p.index_;
		type_ = p.type_;
		pkt_flag_ = p.pkt_flag_;

		p.size_ = 0;
		p.payload_size_ = 0;
		p.index_ = 0;
		p.pkt_flag_ = 0;

		return *this;
	}

	vpn_packet::~vpn_packet()
	{

	}

	uint8_t* vpn_packet::data()
	{
		BOOST_ASSERT(data_);
		return data_.get();
	}

	const uint8_t* vpn_packet::data() const
	{
		BOOST_ASSERT(data_);
		return data_.get();
	}

	uint16_t vpn_packet::size()
	{
		return size_;
	}

	void vpn_packet::resize(size_t count)
	{
		size_ = (uint16_t)count;
	}

	uint8_t* vpn_packet::payload()
	{
		return data_.get() + avpn_payload_header_size;
	}

	uint16_t vpn_packet::payload_size()
	{
		return (uint16_t)payload_size_;
	}

	void vpn_packet::payload_size(size_t count)
	{
		payload_size_ = (uint16_t)count;
	}

	vpn_packet_t vpn_packet::type() const
	{
		return type_;
	}

	void vpn_packet::type(vpn_packet_t t)
	{
		type_ = t;
	}

	void* vpn_packet::release()
	{
		return data_.release();
	}

	vpn_packet_ptr dup_vpn_packet_ptr(const vpn_packet_ptr& p)
	{
		auto ret = std::make_shared<vpn_packet>();

		std::memcpy(ret->data(), p->data(), avpn_packet_size);
		ret->index_ = p->index_;
		ret->payload_size_ = p->payload_size_;
		ret->size_ = p->size_;
		ret->type_ = p->type_;
		ret->pkt_flag_ = p->pkt_flag_;

		return ret;
	}

	vpn_packet_ptr dup_vpn_packet_ptr(const vpn_packet& p)
	{
		auto ret = std::make_shared<vpn_packet>();

		std::memcpy(ret->data(), p.data(), avpn_packet_size);
		ret->index_ = p.index_;
		ret->payload_size_ = p.payload_size_;
		ret->size_ = p.size_;
		ret->type_ = p.type_;
		ret->pkt_flag_ = p.pkt_flag_;

		return ret;
	}

	vpn_packet dup_vpn_packet(const vpn_packet_ptr& p)
	{
		vpn_packet ret;

		std::memcpy(ret.data(), p->data(), avpn_packet_size);
		ret.index_ = p->index_;
		ret.payload_size_ = p->payload_size_;
		ret.size_ = p->size_;
		ret.type_ = p->type_;
		ret.pkt_flag_ = p->pkt_flag_;

		return static_cast<vpn_packet&&>(ret);
	}

	vpn_packet dup_vpn_packet(const vpn_packet& p)
	{
		vpn_packet ret;

		std::memcpy(ret.data(), p.data(), avpn_packet_size);
		ret.index_ = p.index_;
		ret.payload_size_ = p.payload_size_;
		ret.size_ = p.size_;
		ret.type_ = p.type_;
		ret.pkt_flag_ = p.pkt_flag_;

		return static_cast<vpn_packet&&>(ret);
	}

	//////////////////////////////////////////////////////////////////////////

	vpn_tun_packet::vpn_tun_packet(vpn_tun_packet&& p)
		: pkt_(std::move(p.pkt_))
		, endp_(std::move(p.endp_))
	{
	}

	vpn_tun_packet::vpn_tun_packet(vpn_packet pkt, endpoint_pair endp)
		: pkt_(std::move(pkt))
		, endp_(std::move(endp))
	{}

	vpn_tun_packet& vpn_tun_packet::operator=(vpn_tun_packet&& p)
	{
		pkt_ = std::move(p.pkt_);
		endp_ = std::move(p.endp_);

		return *this;
	}

}
