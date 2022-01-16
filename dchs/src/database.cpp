#include "dchs/database.hpp"
#include "dchs/logging.hpp"

namespace dchs {
	dchs_database::dchs_database(const db_config& cfg, boost::asio::io_context& ioc)
		: m_config(cfg)
		, m_io_context(ioc)
	{
		if (m_config.host_.empty() ||
			m_config.dbname_.empty() ||
			m_config.user_.empty())
		{
			LOG_WARN << "Warning, Database not config!";
			return;
		}

		std::unique_ptr<odb::pgsql::connection_factory>
			pool(new odb::pgsql::connection_pool_factory(cfg.pool_, cfg.pool_ / 2));

		m_db = boost::make_shared<odb::pgsql::database>(m_config.user_,
			m_config.password_, m_config.dbname_, m_config.host_, m_config.port_,
			"application_name=dchs", std::move(pool));

		odb::transaction t(m_db->begin());
		if (m_db->schema_version() == 0)
		{
			t.commit();
			t.reset(m_db->begin());
			odb::schema_catalog::create_schema(*m_db, "", true);
			t.commit();
		}
		else
		{
			t.commit();
			t.reset(m_db->begin());
			odb::schema_catalog::migrate(*m_db);
			t.commit();
		}
	}

	void dchs_database::shutdown()
	{
		m_db.reset();
	}

	db_result dchs_database::load_config(dchs_config& config)
	{
		return retry_database_op([&, this]() mutable
		{
			odb::transaction t(m_db->begin());
			auto r(m_db->query<dchs_config>());
			if (r.empty())
			{
				t.commit();
				return false;
			}

			config = *r.begin();
			t.commit();

			return true;
		});
	}

	db_result dchs_database::add_config(dchs_config& config)
	{
		if (!m_db)
			return false;

		return retry_database_op([&, this]() mutable
		{
			odb::transaction t(m_db->begin());
			m_db->persist(config);
			t.commit();
			return true;
		});
	}

	db_result dchs_database::update_config(const dchs_config& config)
	{
		return retry_database_op([&, this]() mutable
		{
			odb::transaction t(m_db->begin());
			m_db->update(config);
			t.commit();
			return true;
		});
	}

}
