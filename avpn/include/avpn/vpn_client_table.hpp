//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/misc.hpp"

#include <boost/thread/lockable_adapter.hpp>


namespace avpn
{
	using namespace util;

	class vpn_tunnel;

	using vpn_tunnel_ptr = std::shared_ptr<vpn_tunnel>;
	using vpn_tunnel_weak_ptr = std::weak_ptr<vpn_tunnel>;

	// 定义vpn client结构, 用于辅助存储vpn tunnel对象
	// 这样, 就可以通过client id及vnet addr分别索引到
	// tunnel.
	struct vpn_client
	{
		std::string id_;
		uint32_t vnet_addr_ = 0;
		vpn_tunnel_weak_ptr tunnel_;
	};

	struct cid {};
	struct caddr {};

	// 定义client表结构, 可根据vnet addr和 client id分别索引.
	// 这是一个内存数据库结构, 并且client id和vnet addr均不允
	// 许重复出现.
	using client_table = boost::multi_index::multi_index_container<
		vpn_client,
		boost::multi_index::indexed_by<
			boost::multi_index::ordered_unique<
				boost::multi_index::tag<cid>,
					BOOST_MULTI_INDEX_MEMBER(vpn_client, std::string, id_)>,
			boost::multi_index::ordered_unique<
				boost::multi_index::tag<caddr>,
					BOOST_MULTI_INDEX_MEMBER(vpn_client, uint32_t, vnet_addr_)>
		>
	>;

	class vpn_client_table
		: public boost::lockable_adapter<std::mutex>
	{
		// c++11 noncopyable.
		vpn_client_table(const vpn_client_table&) = delete;
		vpn_client_table& operator=(const vpn_client_table&) = delete;

	public:
		vpn_client_table();
		~vpn_client_table() = default;

	public:
		// 根据不同key分别查询.
		vpn_client lookup_by_id(const std::string& id) const;
		vpn_client lookup_by_addr(uint32_t vaddr) const;

		// 返回所有tunnel指针.
		std::vector<vpn_tunnel_weak_ptr> all() const;

		// 创建vpn_client.
		bool make(const vpn_client& client);
		// 删除vpn_client.
		bool remove(const std::string& id);
		bool remove(uint32_t vaddr);

		// 返回client_table引用, 用于直接操作client_table.
		client_table& table();

	private:
		std::thread::id m_thread_id;
		client_table m_clients;
	};
}
