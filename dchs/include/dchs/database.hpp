//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <odb/database.hxx>
#include <odb/transaction.hxx>
#include <odb/schema-catalog.hxx>

#include <odb/pgsql/database.hxx>
#include <odb/pgsql/traits.hxx>

#include "dchs/db-odb.hxx"

#include "dchs/db.hpp"
#include "dchs/internal.hpp"

namespace dchs {

	struct db_config
	{
		std::string user_{ "postgres" };
		std::string password_{ "postgres" };
		std::string dbname_{ "postgres" };
		std::string host_{ "127.0.0.1" };
		unsigned int port_{ 5432 };
		int pool_{ 20 };
	};

	using db_result = std::variant<bool, std::exception_ptr>;

	class dchs_database
	{
		// c++11 noncopyable.
		dchs_database(const dchs_database&) = delete;
		dchs_database& operator=(const dchs_database&) = delete;

		// initiate_do_load_xpay_config 实现异步加载 xpay_config.
		struct initiate_do_load_xpay_config
		{
			template<typename Handler>
			void operator()(Handler&& handler, dchs_database* db, dchs_config* config)
			{
				auto mdb = db->m_db;
				if (!mdb)
				{
					auto ec = boost::asio::error::make_error_code(boost::asio::error::no_recovery);
					handler(ec, false);
					return;
				}

				db->m_io_context.post([this, db, mdb, handler = std::move(handler), config]() mutable {
					boost::system::error_code ec;
					bool result = false;

					auto ret = db->load_config(*config);
					std::visit([&handler, &ec, &result](auto&& arg) mutable {
						using T = std::decay_t<decltype(arg)>;
						if constexpr (std::is_same_v<T, bool>) {
							result = arg;
						}
						else if constexpr (std::is_same_v<T, std::exception_ptr>) {
							try {
								std::rethrow_exception(arg);
							}
							catch (const std::exception& e) {
								LOG_WARN << "initiate_do_load_xpay_config: exception: " << e.what();
							}
							ec = boost::asio::error::make_error_code(boost::asio::error::no_recovery);
						}
						else {
							static_assert(always_false<T>, "initiate_do_load_xpay_config, non-exhaustive visitor!");
						}

						auto executor = boost::asio::get_associated_executor(handler);
						boost::asio::post(executor, [ec, handler, result]() mutable {
								handler(ec, result);
							});
						}, ret);
				});
			}
		};

		// initiate_do_add_xpay_config 实现异步添加xpay_config.
		struct initiate_do_add_xpay_config
		{
			template<typename Handler>
			void operator()(Handler&& handler, dchs_database* db, dchs_config* config)
			{
				auto mdb = db->m_db;
				if (!db->m_db)
				{
					auto ec = boost::asio::error::make_error_code(boost::asio::error::no_recovery);
					handler(ec, false);
					return;
				}

				db->m_io_context.post([this, db, mdb, handler = std::move(handler), config]() mutable {
					boost::system::error_code ec;
					bool result = false;

					auto ret = db->add_config(*config);

					std::visit([&handler, &ec, &result](auto&& arg) mutable {
						using T = std::decay_t<decltype(arg)>;
						if constexpr (std::is_same_v<T, bool>) {
							result = arg;
						}
						else if constexpr (std::is_same_v<T, std::exception_ptr>) {
							try {
								std::rethrow_exception(arg);
							}
							catch (const std::exception& e) {
								LOG_WARN << "initiate_do_add_xpay_config: exception: " << e.what();
							}
							ec = boost::asio::error::make_error_code(boost::asio::error::no_recovery);
						}
						else {
							static_assert(always_false<T>, "initiate_do_add_xpay_config, non-exhaustive visitor!");
						}

						auto executor = boost::asio::get_associated_executor(handler);
						boost::asio::post(executor, [ec, handler, result]() mutable {
								handler(ec, result);
							});
						}, ret);
				});
			}
		};

		// initiate_do_update_xpay_config 实现异步更新 xpay_config.
		struct initiate_do_update_xpay_config
		{
			template<typename Handler>
			void operator()(Handler&& handler, dchs_database* db, const dchs_config& config)
			{
				auto mdb = db->m_db;
				if (!db->m_db)
				{
					auto ec = boost::asio::error::make_error_code(boost::asio::error::no_recovery);
					handler(ec, false);
					return;
				}

				db->m_io_context.post([this, db, mdb, handler = std::move(handler), config]() mutable {
					boost::system::error_code ec;
					bool result = false;

					auto ret = db->update_config(config);

					std::visit([&handler, &ec, &result](auto&& arg) mutable {
						using T = std::decay_t<decltype(arg)>;
						if constexpr (std::is_same_v<T, bool>) {
							result = arg;
						}
						else if constexpr (std::is_same_v<T, std::exception_ptr>) {
							try {
								std::rethrow_exception(arg);
							}
							catch (const std::exception& e) {
								LOG_WARN << "initiate_do_update_xpay_config: exception: " << e.what();
							}
							ec = boost::asio::error::make_error_code(boost::asio::error::no_recovery);
						}
						else {
							static_assert(always_false<T>, "initiate_do_update_xpay_config, non-exhaustive visitor!");
						}

						auto executor = boost::asio::get_associated_executor(handler);
						boost::asio::post(executor, [ec, handler, result]() mutable {
								handler(ec, result);
							});
						}, ret);
				});
			}
		};

	public:
		dchs_database(const db_config& cfg, boost::asio::io_context& ioc);
		~dchs_database() = default;

	public:
		void shutdown();

		db_result load_config(dchs_config& config);
		db_result add_config(dchs_config& config);
		db_result update_config(const dchs_config& config);

	public:
		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, bool))
		async_load_config(dchs_config& config, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			return boost::asio::async_initiate<Handler, void(boost::system::error_code, bool)>
				(initiate_do_load_xpay_config{}, handler, this, &config);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, bool))
		async_add_config(dchs_config& config, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			return boost::asio::async_initiate<Handler, void(boost::system::error_code, bool)>
				(initiate_do_add_xpay_config{}, handler, this, &config);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, bool))
		async_update_config(const dchs_config& config, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			return boost::asio::async_initiate<Handler, void(boost::system::error_code, bool)>
				(initiate_do_update_xpay_config{}, handler, this, config);
		}

	private:
		template<typename T>
		db_result retry_database_op(T&& t) noexcept
		{
			if (!m_db)
			{
				try
				{
					throw std::bad_function_call();
				}
				catch (const std::exception&)
				{
					return std::current_exception();
				}
			}

			using namespace std::chrono_literals;
			std::exception_ptr eptr;
			for (int retry_count(0); retry_count < db_max_retries; retry_count++)
			{
				try
				{
					return t();
				}
				catch (const odb::recoverable&)
				{
					eptr = std::current_exception();
					std::this_thread::sleep_for(5s);
					continue;
				}
				catch (const std::exception&)
				{
					return std::current_exception();
				}
			}

			return eptr;
		}

	private:
		enum { db_max_retries = 25 };
		db_config m_config;
		boost::asio::io_context& m_io_context;
		boost::shared_ptr<odb::core::database> m_db;
	};
}
