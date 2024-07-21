//
// asio_transfer_at_least.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef INCLUDE__2024_07_18__ASIO_TRANSFER_AT_LEAST_HPP
#define INCLUDE__2024_07_18__ASIO_TRANSFER_AT_LEAST_HPP


#include <cstdint>

namespace asio_util {

	//////////////////////////////////////////////////////////////////////////

	inline size_t default_max_transfer_size = 1024 * 1024;

	class transfer_at_least_t
	{
	public:
		typedef std::size_t result_type;

		explicit transfer_at_least_t(std::size_t minimum)
			: minimum_(minimum)
		{
		}

		template <typename Error>
		std::size_t operator()(const Error& err, std::size_t bytes_transferred)
		{
			return (!!err || bytes_transferred >= minimum_)
				? 0 : default_max_transfer_size;
		}

	private:
		std::size_t minimum_;
	};

	inline transfer_at_least_t transfer_at_least(std::size_t minimum)
	{
		return transfer_at_least_t(minimum);
	}
}

#endif // INCLUDE__2024_07_18__ASIO_TRANSFER_AT_LEAST_HPP
