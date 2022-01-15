/*
	This file is part of cpp-ethereum.

	cpp-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	cpp-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file Common.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include "Common.h"
#include <libdevcore/Base64.h>
#include <libdevcore/Terminal.h>
#include <libdevcore/CommonIO.h>
#include <libdevcore/Log.h>
#include <libdevcore/SHA3.h>
#include "Exceptions.h"

using namespace std;
using namespace dev;
using namespace dev::eth;

namespace dev
{
namespace eth
{

const unsigned c_protocolVersion = 63;
#if ETH_FATDB
const unsigned c_minorProtocolVersion = 3;
const unsigned c_databaseBaseVersion = 9;
const unsigned c_databaseVersionModifier = 1;
#else
const unsigned c_minorProtocolVersion = 2;
const unsigned c_databaseBaseVersion = 9;
const unsigned c_databaseVersionModifier = 0;
#endif

const unsigned c_databaseVersion = c_databaseBaseVersion + (c_databaseVersionModifier << 8) + (23 << 9);

const Address c_blockhashContractAddress(0xf0);
const bytes c_blockhashContractCode(fromHex("0x600073fffffffffffffffffffffffffffffffffffffffe33141561005957600143035b60011561005357600035610100820683015561010081061561004057005b6101008104905061010082019150610022565b506100e0565b4360003512156100d4576000356001814303035b61010081121515610085576000610100830614610088565b60005b156100a75761010083019250610100820491506101008104905061006d565b610100811215156100bd57600060a052602060a0f35b610100820683015460c052602060c0f350506100df565b600060e052602060e0f35b5b50"));

Address toAddress(std::string const& _s)
{
	try
	{
		auto b = fromHex(_s.substr(0, 2) == "0x" ? _s.substr(2) : _s, WhenError::Throw);
		if (b.size() == 20)
			return Address(b);
	}
	catch (BadHexCharacter&) {}
	BOOST_THROW_EXCEPTION(InvalidAddress());
}

vector<pair<u256, string>> const& units()
{
	static const vector<pair<u256, string>> s_units =
	{
		{exp10<54>(), "Uether"},
		{exp10<51>(), "Vether"},
		{exp10<48>(), "Dether"},
		{exp10<45>(), "Nether"},
		{exp10<42>(), "Yether"},
		{exp10<39>(), "Zether"},
		{exp10<36>(), "Eether"},
		{exp10<33>(), "Pether"},
		{exp10<30>(), "Tether"},
		{exp10<27>(), "Gether"},
		{exp10<24>(), "Mether"},
		{exp10<21>(), "grand"},
		{exp10<18>(), "ether"},
		{exp10<15>(), "finney"},
		{exp10<12>(), "szabo"},
		{exp10<9>(), "Gwei"},
		{exp10<6>(), "Mwei"},
		{exp10<3>(), "Kwei"},
		{exp10<0>(), "wei"}
	};

	return s_units;
}

std::string formatBalance(bigint const& _b)
{
	ostringstream ret;
	u256 b;
	if (_b < 0)
	{
		ret << "-";
		b = (u256)-_b;
	}
	else
		b = (u256)_b;

	if (b > units()[0].first * 1000)
	{
		ret << (b / units()[0].first) << " " << units()[0].second;
		return ret.str();
	}
	ret << setprecision(5);
	for (auto const& i: units())
		if (i.first != 1 && b >= i.first)
		{
			ret << (double(b / (i.first / 1000)) / 1000.0) << " " << i.second;
			return ret.str();
		}
	ret << b << " wei";
	return ret.str();
}

}
}
