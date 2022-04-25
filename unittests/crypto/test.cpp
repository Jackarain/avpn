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

#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/crypto.hpp"

BOOST_AUTO_TEST_CASE(dh_keyexchange_test)
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

	crypto_util::dh_keyexchange dh1
	(
		{ (char*)privateKey1.data(), privateKey1.size() },
		{ (char*)publicKey1.data(), publicKey1.size() }
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

	crypto_util::dh_keyexchange dh2
	(
		{ (char*)privateKey2.data(), privateKey2.size() },
		{ (char*)publicKey2.data(), publicKey2.size() }
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

BOOST_AUTO_TEST_CASE(stream_crypto_test)
{
	crypto_util::stream_crypto encrypto("aa1122!@#0a");

	std::string origin = "The quick brown fox jumps over the lazy dog";
	std::string content = origin;

	encrypto.perform(std::as_writable_bytes(std::span{ content }));

	crypto_util::stream_crypto decrypto("aa1122!@#0a");
	decrypto.perform(std::as_writable_bytes(std::span{ content }));

	BOOST_TEST(origin == content);
}
