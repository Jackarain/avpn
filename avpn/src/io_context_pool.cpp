//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/internal.hpp"
#include "avpn/io_context_pool.hpp"

namespace avpn {

	io_context_pool::io_context_pool(std::size_t pool_size)
		: next_io_context_(0)
	{
		if (pool_size == 0)
			throw std::runtime_error("io_context_pool size is 0");

		// Give all the io_contexts work to do so that their run() functions will not
		// exit until they are explicitly stopped.
		for (std::size_t i = 0; i < pool_size + 3; ++i)
		{
			io_context_ptr io_context(new boost::asio::io_context);
			work_ptr work(new boost::asio::io_context::work(*io_context));
			io_contexts_.push_back(io_context);
			work_.push_back(work);
		}
	}

	void io_context_pool::run(std::size_t db_threads/* = 1*/)
	{
		// Create a pool of threads to run all of the io_contexts.
		std::vector<std::shared_ptr<boost::thread>> threads;
		for (std::size_t i = 0; i < io_contexts_.size(); ++i)
		{
			std::shared_ptr<boost::thread> thread(new boost::thread(
				[this, i]() mutable { io_contexts_[i]->run();  }));
			if (i == 0)
				set_thread_name(thread.get(), "server");
			else if (i == 1)
				set_thread_name(thread.get(), "schedule");
			else if (i == 2)
				set_thread_name(thread.get(), "database");
			else
				set_thread_name(thread.get(), "io_context_pool");
			threads.push_back(thread);
		}

		// Create more threads for database.
		for (std::size_t i = 1; i < db_threads; ++i)
		{
			std::shared_ptr<boost::thread> thread(new boost::thread(
				[this]() mutable { io_contexts_[2]->run();  }));
			set_thread_name(thread.get(), "database");
			threads.push_back(thread);
		}

		// Wait for all threads in the pool to exit.
		for (auto& thread : threads)
			thread->join();
	}

	void io_context_pool::stop()
	{
		// Explicitly stop all io_contexts.
		for (auto& io : work_)
			io.reset();
	}

	boost::asio::io_context& io_context_pool::get_io_context()
	{
		// Use a round-robin scheme to choose the next io_context to use.
		if (next_io_context_ == 0) next_io_context_++;
		if (next_io_context_ == 1) next_io_context_++;
		if (next_io_context_ == 2) next_io_context_++;
		boost::asio::io_context& io_context = *io_contexts_[next_io_context_];
		next_io_context_ = (next_io_context_ + 1) % io_contexts_.size();
		return io_context;
	}

	boost::asio::io_context& io_context_pool::server_io_context()
	{
		boost::asio::io_context& io_context = *io_contexts_[0];
		return io_context;
	}

	boost::asio::io_context& io_context_pool::schedule_io_context()
	{
		boost::asio::io_context& io_context = *io_contexts_[1];
		return io_context;
	}

	boost::asio::io_context& io_context_pool::database_io_context()
	{
		boost::asio::io_context& io_context = *io_contexts_[2];
		return io_context;
	}

	std::size_t io_context_pool::pool_size() const
	{
		return io_contexts_.size();
	}

}
