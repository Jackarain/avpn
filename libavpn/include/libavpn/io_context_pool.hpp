//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__IOVPN_CONTEXT_POOL_HPP
#define INCLUDE__2025_11_20__IOVPN_CONTEXT_POOL_HPP

#include <boost/asio/io_context.hpp>

#include <vector>
#include <memory>

namespace libavpn {

    namespace net = boost::asio;


    // io_context 池.
    class io_context_pool
    {
        io_context_pool(const io_context_pool&) = delete;
        io_context_pool& operator=(const io_context_pool&) = delete;

    public:
        explicit io_context_pool(std::size_t pool_size);
        ~io_context_pool();

        // 启动 io_context 池.
        void run();

        // 停止 io_context 池.
        void stop();

        // 获取下一个 io_context.
        net::io_context& get_io_context();

        // 获取 main io_context.
        net::io_context& main_io_context();

        // 获取 io_context 数量.
        std::size_t size() const;

    private:
        using io_context_ptr = std::shared_ptr<net::io_context>;
        using io_context_work = net::executor_work_guard<net::io_context::executor_type>;

        // main_io_context_ 用于处理业务调度的任务.
        net::io_context main_io_context_;

        // io_context 池, 用于处理具体的异步 I/O 任务.
        std::vector<io_context_ptr> io_contexts_;

        // 保持 io_context 运行的 work 对象集合.
        std::vector<io_context_work> work_;

        // 下一个 io_context 索引.
        std::size_t next_io_context_;
    };
}

#endif // INCLUDE__2025_11_20__IOVPN_CONTEXT_POOL_HPP
