//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/internal.hpp"
#include "utils/io_context_pool.hpp"
#include "utils/misc.hpp"

namespace util {

io_context_pool::io_context_pool(std::size_t pool_size)
	: next_io_context_(0)
{
	if (pool_size == 0)
		throw std::runtime_error("io_context_pool size is 0");

	// Give all the io_contexts work to do so that their run() functions will not
	// exit until they are explicitly stopped.
	for (std::size_t i = 0; i < pool_size; ++i)
	{
		io_context_ptr io_context(new boost::asio::io_context(BOOST_ASIO_CONCURRENCY_HINT_UNSAFE_IO));
		work_ptr work(new boost::asio::io_context::work(*io_context));
		io_contexts_.push_back(io_context);
		work_.push_back(work);
	}

	// main_io_context_ do not have a worker on it, so main thread run() will exit
	// if no more work left
}

void io_context_pool::run()
{
	// Create a pool of threads to run all of the io_contexts.
    std::vector<std::shared_ptr<std::thread>> threads;
	for (std::size_t i = 0; i < io_contexts_.size(); ++i)
	{
        std::shared_ptr<std::thread> thread(new std::thread(
			[this, i]() mutable { io_contexts_[i]->run();  }));
			set_thread_name(thread.get(), "round-robin io runner");
		threads.push_back(thread);
	}

	// main_io_context_ have no worker, so will exit if no more pending IO left.
	main_io_context_.run();

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
	boost::asio::io_context& io_context = *io_contexts_[next_io_context_];
	next_io_context_ = (next_io_context_ + 1) % io_contexts_.size();
	return io_context;
}

boost::asio::io_context& io_context_pool::server_io_context()
{
	return main_io_context_;
}

std::size_t io_context_pool::pool_size() const
{
	return io_contexts_.size();
}

}
