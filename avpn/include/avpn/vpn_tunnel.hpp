//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/io_context_pool.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/bitfield.hpp"
#include "utils/url_parser.hpp"
#include "utils/async_connect.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/crypto.hpp"
#include "utils/uawaitable.hpp"

#include "avpn/endpoint_pair.hpp"

#include "avpn/reedsolomon.hpp"
#include "avpn/fec_cache.hpp"


namespace avpn {

	class vpn_tunnel : public std::enable_shared_from_this<vpn_tunnel>
	{
	public:
		vpn_tunnel();
		~vpn_tunnel();
	private:
	};

	using vpn_tunnel_ptr = std::shared_ptr<vpn_tunnel>;
	using vpn_tunnel_weak_ptr = std::weak_ptr<vpn_tunnel>;
}
