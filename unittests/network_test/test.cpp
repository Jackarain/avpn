#define BOOST_TEST_MAIN

#ifdef USE_MIMALLOC

#ifdef MI_OVERRIDE
#	include <mimalloc.h>
#else
#	include <mimalloc-new-delete.h>
#endif

#ifdef _WIN32
#	include <mimalloc-new-delete.h>
#endif

#endif // USE_MIMALLOC

#include <boost/test/included/unit_test.hpp>
#include <cstdlib>
#include <ctime>

#include "utils/misc.hpp"

class sender {
public:
	sender(net::io_context& ioc)
		: ioc_(ioc)
		, socket_(ioc, udp::endpoint(udp::v4(), 0))
		, timer_(ioc, net::chrono::seconds(1))
	{
		net::socket_base::receive_buffer_size rbo(16 * 1024 * 1024);
		net::socket_base::send_buffer_size sbo(16 * 1024 * 1024);

		socket_.set_option(rbo);
		socket_.set_option(sbo);

		udp::resolver resolver(ioc_);
		auto endpoints =
			resolver.resolve(udp::v4(), "192.168.1.148", "5005");
		remote_ = *endpoints.begin();
	}

	~sender() = default;

public:
	void run()
	{
		timer_.async_wait([this](auto) mutable {
			on_timer({});
		});
		do_udp_write();
	}

	void do_udp_write()
	{
		average_++;

		if (total_ > 5592) {
			int ret = socket_.send_to(net::buffer(data_, 1422), remote_);
			if (ret != 1422)
				fail_++;
			return;
		}

		total_++;
		socket_.async_send_to(
			net::buffer(data_, 1422),
			remote_,
				[this](auto, auto bytes) mutable {
					if (bytes != 1422)
						fail_++;
					total_--;
					for (int i = 0; i < 2; i++)
						do_udp_write();
				});
	}

	void on_timer(const boost::system::error_code& /*e*/)
	{
		timer_.expires_from_now(net::chrono::seconds(1));
		timer_.async_wait(std::bind(&sender::on_timer,
			this, std::placeholders::_1));

		std::cerr	<< "Total: " << total_
					<< ", average: " << average_
					<< ", fail: " << fail_
					<< "/s\n";
		average_ = 0;
	}


private:
	net::io_context& ioc_;
	udp::socket socket_;
	net::steady_timer timer_;
	udp::endpoint remote_;
	int64_t total_{ 0 };
	int64_t average_{ 0 };
	int64_t fail_{ 0 };
	enum { max_length = 1422 };
	char data_[max_length];
};

BOOST_AUTO_TEST_CASE(udp_test)
{
	net::io_context ioc;

	sender s(ioc);
	s.run();

	ioc.run();
}

#if 0
BOOST_AUTO_TEST_CASE(fec_cache2_test1)
{
	avpn::vpn_packet pkt1;
	pkt1.size_ = 100;

	avpn::vpn_packet pkt2 = std::move(pkt1);

	BOOST_TEST(pkt1.size_ == 0);
	BOOST_TEST(pkt2.size_ == 100);

	for (int i = 0; i < 100; i++)
	{
		avpn::vpn_packet p;
		p.size_ = 100;
	}

	avpn::vpn_packet pkt3;
	avpn::vpn_packet pkt4;
}

BOOST_AUTO_TEST_CASE(fec_cache2_test2)
{
	avpn::fec_decode_group gop(8, 4);
	avpn::vpn_packet pkt;

	avpn::vpn_packet_ptr ptr =
		std::make_shared<avpn::vpn_packet>(std::move(pkt));

	gop.update(1, 0, ptr);

	BOOST_TEST(ptr->size() == avpn::avpn_packet_size);
	BOOST_TEST(gop.total_ == avpn::avpn_packet_size);
}
#endif
