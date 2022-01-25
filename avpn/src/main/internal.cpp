//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include <iostream>
#include <iterator>
#include <algorithm>
#include <random>

#ifdef __linux__

#  include <sys/prctl.h>

#  include <sys/resource.h>
//#  include <systemd/sd-daemon.h>

#  include <sys/types.h>
#  include <pwd.h>

#elif __APPLE__

#  include <sys/types.h>
#  include <unistd.h>
#  include <sys/types.h>
#  include <pwd.h>

#elif _WIN32

#  include <fcntl.h>
#  include <io.h>

#endif

#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/format.hpp>

#include <boost/date_time/c_local_time_adjustor.hpp>

#include "avpn/internal.hpp"
#include "utils/scoped_exit.hpp"

#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"
#include "cryptopp/base64.h"


#ifdef _MSC_VER
const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

void SetThreadName(uint32_t dwThreadID, const char* threadName)
{
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName;
	info.dwThreadID = dwThreadID;
	info.dwFlags = 0;

	__try
	{
		RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{}
}

void set_thread_name(const char* name)
{
	SetThreadName(GetCurrentThreadId(), name);
}

void set_thread_name(boost::thread* thread, const char* name)
{
	DWORD threadId = ::GetThreadId(static_cast<HANDLE>(thread->native_handle()));
	SetThreadName(threadId, name);
}

#elif __linux__

void set_thread_name(boost::thread* thread, const char* name)
{
	auto handle = thread->native_handle();
	pthread_setname_np(handle, name);
}

void set_thread_name(const char* name)
{
	prctl(PR_SET_NAME, name, 0, 0, 0);
}

#else

void set_thread_name(boost::thread*, const char*)
{
}

void set_thread_name(const char* name)
{
}

#endif


inline std::string uuid_to_string(boost::uuids::uuid const& u)
{
	std::string result;
	result.reserve(36);

	std::size_t i = 0;
	boost::uuids::uuid::const_iterator it_data = u.begin();
	for (; it_data != u.end(); ++it_data, ++i)
	{
		const size_t hi = ((*it_data) >> 4) & 0x0F;
		result += boost::uuids::detail::to_char(hi);

		const size_t lo = (*it_data) & 0x0F;
		result += boost::uuids::detail::to_char(lo);
	}
	return result;
}

std::string gen_uuid()
{
	boost::uuids::uuid guid = boost::uuids::random_generator()();
	return uuid_to_string(guid);
}


//////////////////////////////////////////////////////////////////////////

std::string google_code_to_string(int google_code)
{
	boost::format f("%06d");
	f% google_code;
	return f.str();
}

int google_auth_code(const std::string& secret, unsigned long tm /*= 0*/, unsigned long duration/* = 30*/)
{
	int lookup[256];
	const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	CryptoPP::Base32Decoder::InitializeDecodingLookupArray(lookup, ALPHABET, 32, true /*insensitive*/);
	CryptoPP::Base32Decoder decoder;
	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::DecodingLookupArray(), (const int*)lookup);
	decoder.IsolatedInitialize(params);

	std::string key;

	decoder.Put((CryptoPP::byte*)secret.data(), secret.size());
	decoder.MessageEnd();
	auto size = decoder.MaxRetrievable();
	if (size && size <= std::numeric_limits<decltype(size)>::max())
	{
		key.resize(size);
		decoder.Get((CryptoPP::byte*)&key[0], key.size());
	}
	else
	{
		return -1;
	}

	if (tm == 0)
		tm = static_cast<unsigned long>(std::time(nullptr) / duration);
	else
		tm = tm / duration;

	uint8_t challenge[8];
	for (int i = 8; i--; tm >>= 8)
		challenge[i] = static_cast<uint8_t>(tm);

	std::string output(EVP_MAX_MD_SIZE, '\0');
	unsigned int output_length = 0;

	CryptoPP::HMAC<CryptoPP::SHA1> hmac((const CryptoPP::byte*)key.data(), key.size());
	hmac.Update((const CryptoPP::byte*)challenge, 8);
	hmac.Final((CryptoPP::byte*)output.data());
	output_length = hmac.DigestSize();

	output.resize(output_length);
	const int offset = output[output_length - 1] & 0x0F;

	uint8_t* u8parts = (uint8_t*)&output[offset];
	u8parts[0] = u8parts[0] & 0x7F;

	uint32_t number = (uint32_t(u8parts[0]) << 24) + (uint32_t(u8parts[1]) << 16) +
		(uint32_t(u8parts[2]) << 8) + uint32_t(u8parts[3]);

	return number % 1000000;
}

std::string google_generate_secret()
{
	const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::EncodingLookupArray(), (const CryptoPP::byte*)ALPHABET);
	CryptoPP::Base32Encoder encoder;
	encoder.IsolatedInitialize(params);

	static thread_local std::default_random_engine g =
		std::default_random_engine(std::random_device()());
	std::uniform_int_distribution<int> uid(0, 255);

	const int GOOGLE_SECRET_BITS = 128;
	const int buf_size = GOOGLE_SECRET_BITS / 8;
	std::vector<CryptoPP::byte> buf(buf_size, 0);
	for (int i = 0; i < buf_size; i++)
		buf[i] = static_cast<CryptoPP::byte>(uid(g));

	encoder.Put(buf.data(), GOOGLE_SECRET_BITS / 8);
	encoder.MessageEnd();

	std::string result;
	auto size = encoder.MaxRetrievable();
	if (size)
	{
		result.resize(size);
		encoder.Get((CryptoPP::byte*)&result[0], result.size());
	}

	return result;
}

//////////////////////////////////////////////////////////////////////////


bool parse_endpoint_string(const std::string& str, std::string& host, std::string& port, bool& ipv6only)
{
	ipv6only = false;

	auto address_string = boost::trim_copy(str);
	auto it = address_string.begin();
	bool is_ipv6_address = *it == '[';
	if (is_ipv6_address)
	{
		auto tmp_it = std::find(it, address_string.end(), ']');
		if (tmp_it == address_string.end())
			return false;

		it++;
		for (auto first = it; first != tmp_it; first++)
			host.push_back(*first);

		std::advance(it, tmp_it - it);
		it++;
	}
	else
	{
		auto tmp_it = std::find(it, address_string.end(), ':');
		if (tmp_it == address_string.end())
			return false;

		for (auto first = it; first != tmp_it; first++)
			host.push_back(*first);

		// Skip host.
		std::advance(it, tmp_it - it);
	}

	if (*it != ':')
		return false;

	it++;
	for (; it != address_string.end(); it++)
	{
		if (*it >= '0' && *it <= '9')
		{
			port.push_back(*it);
			continue;
		}

		break;
	}

	if (it != address_string.end())
	{
		if (std::string(it, address_string.end()) == "ipv6only" ||
			std::string(it, address_string.end()) == "-ipv6only")
			ipv6only = true;
	}

	return true;
}

// 解析下列用于listen格式的endpoint
// [::]:443
// [::1]:443
// [::0]:443
// 0.0.0.0:443
bool make_listen_endpoint(const std::string& address, tcp::endpoint& endp, boost::system::error_code& ec)
{
	std::string host, port;
	bool ipv6only = false;
	if (!parse_endpoint_string(address, host, port, ipv6only))
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	if (host.empty() || port.empty())
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	endp.address(boost::asio::ip::address::from_string(host, ec));
	endp.port(static_cast<unsigned short>(std::atoi(port.data())));

	return ipv6only;
}

bool make_listen_endpoint(const std::string& address, udp::endpoint& endp, boost::system::error_code& ec)
{
	std::string host, port;
	bool ipv6only = false;
	if (!parse_endpoint_string(address, host, port, ipv6only))
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	if (host.empty() || port.empty())
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	endp.address(boost::asio::ip::address::from_string(host, ec));
	endp.port(static_cast<unsigned short>(std::atoi(port.data())));

	return ipv6only;
}

char from_hex_char(char c) noexcept
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

bool from_hexstring(std::string const& src, std::vector<uint8_t>& result)
{
	unsigned s = (src.size() >= 2 && src[0] == '0' && src[1] == 'x') ? 2 : 0;
	result.reserve((src.size() - s + 1) / 2);

	if (src.size() % 2)
	{
		auto h = from_hex_char(src[s++]);
		if (h != static_cast<char>(-1))
			result.push_back(h);
		else
			return false;
	}
	for (unsigned i = s; i < src.size(); i += 2)
	{
		int h = from_hex_char(src[i]);
		int l = from_hex_char(src[i + 1]);

		if (h != -1 && l != -1)
		{
			result.push_back((uint8_t)(h * 16 + l));
			continue;
		}
		return false;
	}

	return true;
}

bool is_hexstring(std::string const& src) noexcept
{
	auto it = src.begin();
	if (src.compare(0, 2, "0x") == 0)
		it += 2;
	return std::all_of(it, src.end(),
		[](char c) { return from_hex_char(c) != static_cast<char>(-1); });
}

std::string to_string(std::vector<uint8_t> const& data)
{
	return std::string((char const*)data.data(), (char const*)(data.data() + data.size()));
}

std::string to_string(const boost::posix_time::ptime& t)
{
	if (t.is_not_a_date_time())
		return "";

	return boost::posix_time::to_iso_extended_string(t);
}

//////////////////////////////////////////////////////////////////////////

fs::path config_home_path()
{
	char* homedir = nullptr;

#ifdef WIN32
	homedir = getenv("USERPROFILE");
#elif(__linux__)
	if (!(homedir = getenv("HOME")))
		homedir = getpwuid(getuid())->pw_dir;
#elif(__APPLE__)
	int bufsize;
	if ((bufsize = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1)
		return {};
	char buffer[bufsize];
	struct passwd pwd, *result = NULL;
	if (getpwuid_r(getuid(), &pwd, buffer, bufsize, &result) != 0 || !result)
		return {};
	homedir = pwd.pw_dir;
#endif

	if (!homedir)
		return {};

	static fs::path config_path = fs::path(homedir) / ("." APP_NAME);

	boost::system::error_code ec;
	if (!fs::exists(config_path, ec))
	{
		if (!fs::create_directories(config_path, ec))
			return {};
		if (ec)
			return {};
	}

	return config_path;
}

std::string read_file(const std::string& path)
{
	std::ifstream f(path);
	f.exceptions(f.failbit);
	return std::string((std::istreambuf_iterator<char>(f)),
		std::istreambuf_iterator<char>());
}

std::string app_config(const std::string& cfg)
{
	std::string file = (config_home_path() / cfg).string();

	try
	{
		return read_file(file);
	}
	catch (const std::exception&)
	{
		return {};
	}
}

//////////////////////////////////////////////////////////////////////////

std::string base64_encode(std::string_view input)
{
	std::string result;

	CryptoPP::Base64Decoder decoder;
	decoder.Put((CryptoPP::byte*)input.data(), input.size());
	decoder.MessageEnd();

	auto size = decoder.MaxRetrievable();
	if (size && size <= SIZE_MAX)
	{
		result.resize(size);
		decoder.Get((CryptoPP::byte*)&result[0], result.size());
	}

	return result;
}

std::string base64_decode(std::string_view input)
{
	std::string result;

	CryptoPP::Base64Encoder encoder;
	encoder.Put((CryptoPP::byte*)input.data(), input.size());
	encoder.MessageEnd();

	auto size = encoder.MaxRetrievable();
	if (size)
	{
		result.resize(size);
		encoder.Get((CryptoPP::byte*)&result[0], result.size());
	}

	return result;
}

//////////////////////////////////////////////////////////////////////////
bool unescape_path(const std::string& in, std::string& out)
{
	out.clear();
	out.reserve(in.size());
	for (std::size_t i = 0; i < in.size(); ++i)
	{
		switch (in[i])
		{
		case '%':
			if (i + 3 <= in.size())
			{
				unsigned int value = 0;
				for (std::size_t j = i + 1; j < i + 3; ++j)
				{
					switch (in[j])
					{
					case '0': case '1': case '2': case '3': case '4':
					case '5': case '6': case '7': case '8': case '9':
						value += in[j] - '0';
						break;
					case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
						value += in[j] - 'a' + 10;
						break;
					case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
						value += in[j] - 'A' + 10;
						break;
					default:
						return false;
					}
					if (j == i + 1)
						value <<= 4;
				}
				out += static_cast<char>(value);
				i += 2;
			}
			else
				return false;
			break;
		case '+':
			out += ' ';
			break;
		case '-': case '_': case '.': case '!': case '~': case '*':
		case '\'': case '(': case ')': case ':': case '@': case '&':
		case '=': case '$': case ',': case '/': case ';':
			out += in[i];
			break;
		default:
			if (!std::isalnum((unsigned char)in[i]))
				return false;
			out += in[i];
			break;
		}
	}
	return true;
}

//////////////////////////////////////////////////////////////////////////

boost::posix_time::ptime make_localtime(std::string_view time) noexcept
{
	auto base = (time.size() >= 2 && time[0] == '0' && time[1] == 'x') ? 16 : 10;
	base = (time.size() >= 2 && time[0] == '0' && time[1] != 'x') ? 8 : base;
	auto timestamp = std::stoll(time.data(), nullptr, base);
	struct tm ts;
	if (!time_clock::localtime(timestamp, ts))
		return {};
	try {
		return boost::posix_time::ptime_from_tm(ts);
	}
	catch (...) {}
	return {};
}


