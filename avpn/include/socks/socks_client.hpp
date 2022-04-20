//
// socks_client.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <string>

namespace socks {

	struct socks_params
	{
		std::string host;
		std::string port;
		std::string username;
		std::string password;
		int version;
	};

}
