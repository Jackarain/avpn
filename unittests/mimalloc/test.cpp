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
#include "avpn/fec_cache.hpp"
#include "avpn/reedsolomon.hpp"

BOOST_AUTO_TEST_CASE(mimalloc_test)
{
	char* p = (char*)malloc(1024);
	memset(p, 0, 1024);
	free(p);

	fec::reedsolomon* rs = new fec::reedsolomon(8, 2);
	delete rs;

	std::string test = gen_unique_string(1450);
	BOOST_TEST_MESSAGE(test);
}
