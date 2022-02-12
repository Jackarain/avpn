//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/internal.hpp"


namespace avpn {

	/// A pool of io_context objects.
	class io_context_pool
	{
		// c++11 noncopyable.
		io_context_pool(const io_context_pool&) = delete;
		io_context_pool& operator=(const io_context_pool&) = delete;

	public:
		/// Construct the io_context pool.
		explicit io_context_pool(std::size_t pool_size);

		/// Run all io_context objects in the pool.
		void run(std::size_t db_threads = 1);

		/// Stop all io_context objects in the pool.
		void stop();

		/// Get an io_context to use.
		boost::asio::io_context& get_io_context();

		/// Get an server io_context to use.
		boost::asio::io_context& server_io_context();

		/// Get an schedule io_context to use.
		boost::asio::io_context& schedule_io_context();

		/// Get an database io_context to use.
		boost::asio::io_context& database_io_context();

		/// Get pool size.
		std::size_t pool_size() const;

	private:
		using io_context_ptr = std::shared_ptr<boost::asio::io_context>;
		using work_ptr = std::shared_ptr<boost::asio::io_context::work>;

		/// The pool of io_contexts.
		std::vector<io_context_ptr> io_contexts_;

		/// The work that keeps the io_contexts running.
		std::vector<work_ptr> work_;

		/// The next io_context to use for a connection.
		std::size_t next_io_context_;
	};
}
