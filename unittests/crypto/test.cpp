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
#include <vector>
#include <string>
#include <string_view>

#include <boost/asio.hpp>

#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/crypto.hpp"

namespace net = boost::asio;

net::io_context ioc;
net::io_context::work* work2;
net::io_context ioc2;

struct params
{
	params() {
		LOG_DBG << "params(): " << this;
	}
	~params() {
		LOG_DBG << "~params(): " << this;
	}
	params(params&) {
		LOG_DBG << "params(params&): " << this;
	}
	params(params&&) {
		LOG_DBG << "params(params&&): " << this;
	}

	void print() {
		LOG_DBG << "print: " << this;
	}
};


net::awaitable<void>
test3(params p)
{
	LOG_DBG << "##############1: " << std::this_thread::get_id();
	co_await net::this_coro::executor;
	LOG_DBG << "##############2: " << std::this_thread::get_id();

	p.print();

	co_return;
}

net::awaitable<void>
test2(params p)
{
	LOG_DBG << "*************1: " << std::this_thread::get_id();
	co_await net::this_coro::executor;
	LOG_DBG << "*************2: " << std::this_thread::get_id();
	net::co_spawn(ioc2, test3(std::move(p)), net::detached);
	LOG_DBG << "*************3: " << std::this_thread::get_id();
	co_return;
}

net::awaitable<void>
test(params p)
{
	p.print();
	LOG_DBG << ".............1: " << std::this_thread::get_id();
	co_await test2(std::move(p));
	LOG_DBG << ".............2: " << std::this_thread::get_id();
	// net::co_spawn(ioc, test2(std::move(p)), net::detached);

	co_return;
}

using intptr = std::shared_ptr<int>;
net::awaitable<intptr>
async_make_tunnel(int i)
{
	auto ptr = std::make_shared<int>(i);
	LOG_DBG << i;
	co_return ptr;
}

BOOST_AUTO_TEST_CASE(asio_coroutine_test)
{
	params p;
	net::co_spawn(ioc, test(std::move(p)), net::detached);

// 	for (int i = 0; i < 100; i++)
// 	{
// 		net::co_spawn(ioc, [i]() -> net::awaitable<void> {
// 			co_await async_make_tunnel(i);
// 			}, net::detached);
// 	}

	std::thread t([]() {
		work2 = new net::io_context::work(ioc2);
		ioc2.run();
		});

	ioc.run();
	if (work2)
		delete work2;
	t.join();
}

BOOST_AUTO_TEST_CASE(ecdh_keyexchange_test)
{
	std::string privateKey1 = "ICBmoiZBqo7pyHZVK+vM2I3LF9PePa18DVjkcbLl/XM=";
	std::string publicKey1;

	std::string privateKey2;
	std::string publicKey2;

	crypto_util::keyexchange server(privateKey1);
	publicKey1 = server.StaticPublicKey();
	auto pubkey = base64_encode(publicKey1);
	BOOST_TEST("lLgKbd/K9p5EIwrAFxXC5EJN6RQXIX4WQO34o1N7N30=" == pubkey);

	crypto_util::keyexchange client;
	publicKey2 = client.StaticPublicKey();

	auto shared1 = server.GenerateSharedKey(publicKey2);
	auto shared2 = client.GenerateSharedKey(publicKey1);

	BOOST_TEST(shared2 == shared1);
}

BOOST_AUTO_TEST_CASE(dh2_keyexchange_test)
{
	std::vector<uint8_t> privateKey1;
	from_hexstring("0x6046c7a0f56f6beea5779f8c9c908ecd83a7ab3b", privateKey1);
	std::vector<uint8_t> publicKey1;
	from_hexstring("0xad92905b6bd21661900c611e1af501102343d8fa"
		"9352dd80a1c7e4215be23e266ea353613e37df0a"
		"7abfbd0e5bbf5f3197c3b04d7c3c0370c3d471bf"
		"2b8ca1d045bbb8bf171c391bdc5db7babbeb708a"
		"f84751b312ebc39222078485eab1bdfb2b1cefb7"
		"18d15791ab20df1ce70d8c37acbcbce92bd11887"
		"0ceaab5ec8e717ea", publicKey1);

	crypto_util::keyexchange dh1
	(
		{ (char*)privateKey1.data(), privateKey1.size() },
		{ (char*)publicKey1.data(), publicKey1.size() },
		false
	)
		;

	std::vector<uint8_t> privateKey2;
	from_hexstring("0x60bc9d4c1651479b1ffd25eedf3e7a3c2dd1179c", privateKey2);
	std::vector<uint8_t> publicKey2;
	from_hexstring("0x26698d46188640bb6a9c1fdd79b859deb3c58e86"
		"df86c049a8d36d8a84968c8af5fa4baeec139a20"
		"0f0d66d813c394934760e475f469ae9fb90bd1b9"
		"0e442707c89c7a0c7aed38cd6be4ca5ca55bf255"
		"eabcd6e4e5255ecfd0081022d672bba80ad48ce0"
		"d3dd49d990d4c86040bb042eda1e3ca0a3cbaa78"
		"c76b5adaacd8af6c", publicKey2);

	crypto_util::keyexchange dh2
	(
		{ (char*)privateKey2.data(), privateKey2.size() },
		{ (char*)publicKey2.data(), publicKey2.size() },
		false
	)
		;

	auto dspk1 = dh1.StaticPublicKey();
	auto depk1 = dh1.EphemeralPublicKey();

	auto dspk2 = dh2.StaticPublicKey();
	auto depk2 = dh2.EphemeralPublicKey();

	{
		auto shkey1 = dh1.GenerateSharedKey(depk2);
		auto shkey2 = dh2.GenerateSharedKey(depk1);

		BOOST_TEST(shkey2 == shkey1);

		auto s1 = to_hex_prefixed(shkey1);
		auto s2 = to_hex_prefixed(shkey2);

		LOG_DBG << "unauth: " << s1;
		LOG_DBG << "unauth: " << s2;
	}

	{
		auto shkey1 = dh1.GenerateSharedKey(dspk2, depk2);
		auto shkey2 = dh2.GenerateSharedKey(dspk1, depk1);

		BOOST_TEST(shkey2 == shkey1);

		auto s1 = to_hex_prefixed(shkey1);
		auto s2 = to_hex_prefixed(shkey2);

		LOG_DBG << "authed: " << s1;
		LOG_DBG << "authed: " << s2;
	}
}

#if 0
BOOST_AUTO_TEST_CASE(stream_crypto_test1)
{
	std::string origin = "The quick brown fox jumps over the lazy dog";
	std::string content = origin;

	crypto_util::stream_crypto enc1("aa1122!@#0a");
	enc1.perform(std::as_writable_bytes(std::span{ content }));
	std::string encoded = content;

	crypto_util::stream_crypto dec1("aa1122!@#0a");
	dec1.perform(std::as_writable_bytes(std::span{ content }));
	BOOST_TEST(origin == content);

	crypto_util::stream_crypto dec2("11111111111");
	dec2.perform(std::as_writable_bytes(std::span{ encoded }));
	BOOST_TEST(origin != encoded);

	crypto_util::stream_crypto enc2("aa1122!@#0a");
	auto h = enc2.aead_encrypt(std::as_writable_bytes(std::span{ content }));
	encoded = content;

	crypto_util::stream_crypto dec3("aa1122!@#0a");
	auto r1 = dec3.aead_decrypt(std::as_writable_bytes(std::span{ content }), h);
	BOOST_TEST(r1 == true);
	BOOST_TEST(content == origin);

	crypto_util::stream_crypto dec4("11111111111");
	auto r2 = dec3.aead_decrypt(std::as_writable_bytes(std::span{ encoded }), h);
	BOOST_TEST(r2 == false);
}
#endif

BOOST_AUTO_TEST_CASE(stream_crypto_test2)
{
	std::string origin = "The quick brown fox jumps over the lazy dog";
	std::string content = origin;

	crypto_util::stream_crypto enc1("aa1122!@#0a");
	enc1.perform(std::as_writable_bytes(std::span{ content }));
	auto b64enc = base64_encode(content);
	BOOST_TEST(b64enc == "jW1ivz7biGw31qOU7uhbb/hN58xvSGLuFZhv/lfUMLmfwiyWFzLM7IkCPw==");

	content = origin;
	crypto_util::stream_crypto enc2("11111111111");
	enc2.perform(std::as_writable_bytes(std::span{ content }));
	b64enc = base64_encode(content);
	BOOST_TEST(b64enc == "nzkh1NDCO/g3kbiG0ck2Jr7x8mEDJ32adGChSy6/aL6mGql45opKMOoF0g==");

}
