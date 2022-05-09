//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_client_table.hpp"

namespace avpn {

	vpn_client
	vpn_client_table::lookup_by_id(const std::string& id) const
	{
		using cid_type = typename
			boost::multi_index::index<client_table, cid>::type;

		const cid_type& it =
			boost::multi_index::get<cid>(m_clients);

		auto f = it.find(id);
		if (f == it.end())
			return {};

		return *f;
	}

	vpn_client
	vpn_client_table::lookup_by_addr(uint32_t vaddr) const
	{
		using caddr_type = typename
			boost::multi_index::index<client_table, caddr>::type;

		const caddr_type& it =
			boost::multi_index::get<caddr>(m_clients);

		auto f = it.find(vaddr);
		if (f == it.end())
			return {};

		return *f;
	}

	std::vector<vpn_tunnel_weak_ptr> vpn_client_table::all() const
	{
		std::vector<vpn_tunnel_weak_ptr> result;

		for (auto& it : m_clients)
			result.push_back(it.tunnel_);

		return result;
	}

	bool vpn_client_table::make(const vpn_client& client)
	{
		auto ret = m_clients.insert(client);
		return ret.second;
	}

	bool vpn_client_table::remove(const std::string& id)
	{
		auto ret = m_clients.erase(id);
		return !!ret;
	}

	bool vpn_client_table::remove(uint32_t vaddr)
	{
		using caddr_type = typename
			boost::multi_index::index<client_table, caddr>::type;

		const caddr_type& it =
			boost::multi_index::get<caddr>(m_clients);

		auto f = it.find(vaddr);
		if (f != it.end())
		{
			auto ret = m_clients.erase(f->id_);
			return !!ret;
		}

		return false;
	}

	client_table& vpn_client_table::table()
	{
		return m_clients;
	}

}
