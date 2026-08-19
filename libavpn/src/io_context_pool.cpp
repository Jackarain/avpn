#include "libavpn/io_context_pool.hpp"

#include <stdexcept>
#include <thread>

namespace libavpn {

    io_context_pool::io_context_pool(std::size_t pool_size)
        : next_io_context_(0)
    {
        if (pool_size == 0)
            throw std::runtime_error("io_context_pool size is 0");

        // 创建指定数量的 io_context 对象.
        for (std::size_t i = 0; i < pool_size; ++i)
        {
            auto io_ctx = std::make_shared<net::io_context>();
            io_contexts_.push_back(io_ctx);
            work_.emplace_back(net::make_work_guard(*io_ctx));
        }
    }

    io_context_pool::~io_context_pool()
    {}

    void io_context_pool::run()
    {
        // 创建线程池来运行 io_context 对象.
        std::vector<std::thread> threads;
        for (auto& io_ctx : io_contexts_)
        {
            threads.emplace_back([io_ctx]()
            {
                io_ctx->run();
            });
        }

        main_io_context_.run();

        // 等待所有线程完成.
        for (auto& thread : threads)
        {
            if (thread.joinable())
                thread.join();
        }
    }

    void io_context_pool::stop()
    {
        // 停止所有 io_context 对象, 在这里只是重置 work 对象, 使其不再
        // 保持 io_context 始终处理运行状态, 这样 io_context.run() 会
        // 自然返回，从而停止 io_context 的运行.
        for (auto& work : work_)
            work.reset();
    }

    net::io_context& io_context_pool::get_io_context()
    {
        // 使用轮询方式获取下一个 io_context 对象.
        auto& io_ctx = *io_contexts_[next_io_context_];
        ++next_io_context_;
        if (next_io_context_ == io_contexts_.size())
            next_io_context_ = 0;
        return io_ctx;
    }

    net::io_context& io_context_pool::main_io_context()
    {
        return main_io_context_;
    }

    std::size_t io_context_pool::size() const
    {
        return io_contexts_.size();
    }

} // namespace libavpn
