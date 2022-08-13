//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/misc.hpp"
#include "utils/logging.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/fileop.hpp"

#include <iostream>
#include <iterator>
#include <algorithm>
#include <random>

#ifdef __linux__

#	include <unistd.h>
#	include <sys/prctl.h>
#	include <sys/resource.h>

#	include <sys/types.h>
#	include <pwd.h>

#elif __APPLE__

#	include <sys/types.h>
#	include <unistd.h>
#	include <sys/types.h>
#	include <pwd.h>

#elif _WIN32

#	include <fcntl.h>
#	include <io.h>

#	include <Windows.h>
#	include <Shlwapi.h>
#	include <NTSecAPI.h>

#	include <ws2tcpip.h>
#	include <iphlpapi.h>
#	include <SetupAPI.h>
// #	include <winternl.h>

#	include <cfgmgr32.h>
#	include <devguid.h>
#	include <ndisguid.h>
#	include <shellapi.h>
#	include <ipexport.h>
#	include <sddl.h>
#	include <winefs.h>

#	pragma comment(lib, "Ws2_32.lib")
#	pragma comment(lib, "Iphlpapi.lib")
#	pragma comment(lib, "Shlwapi.lib")
#	pragma comment(lib, "Setupapi.lib")


#endif

#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string/regex.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <boost/date_time/c_local_time_adjustor.hpp>

#ifndef _MSC_VER
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wdeprecated-declarations"
#	pragma clang diagnostic ignored "-Wunused-variable"
#endif // _MSC_VER

#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"
#include "cryptopp/base32.h"
#include "cryptopp/base64.h"

#ifndef _MSC_VER
#	pragma GCC diagnostic pop
#	pragma clang diagnostic pop
#endif // _MSC_VER

#ifdef _MSC_VER
#	pragma warning(disable: 4191)
#endif // _MSC_VER

namespace fs = std::filesystem;

//////////////////////////////////////////////////////////////////////////

template <class Iterator>
std::string to_hex(Iterator it, Iterator end, std::string const& prefix)
{
	using traits = std::iterator_traits<Iterator>;
	static_assert(sizeof(typename traits::value_type) == 1, "to_hex needs byte-sized element type");

	static char const* hexdigits = "0123456789abcdef";
	size_t off = prefix.size();
	std::string hex(std::distance(it, end) * 2 + off, '0');
	hex.replace(0, off, prefix);
	for (; it != end; it++)
	{
		hex[off++] = hexdigits[(*it >> 4) & 0x0f];
		hex[off++] = hexdigits[*it & 0x0f];
	}
	return hex;
}

// template <class T> std::string to_hex(T const& data)
// {
// 	return to_hex(data.begin(), data.end(), "");
// }

std::string to_hex(std::string_view data)
{
	return to_hex(data.begin(), data.end(), "");
}

std::string to_hex_prefixed(std::string_view data)
{
	return to_hex(data.begin(), data.end(), "0x");
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

bool from_hexstring(std::string_view src, std::vector<uint8_t>& result)
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

std::string to_string(float v, int width, int precision /*= 3*/)
{
	char buf[20] = { 0 };
	std::sprintf(buf, "%*.*f", width, precision, v);
	return std::string(buf);
}

bool valid_utf(unsigned char* string, int length)
{
	static const unsigned char utf8_table[] =
	{
	  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	  3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
	};

	unsigned char* p;

	if (length < 0)
	{
		for (p = string; *p != 0; p++);
		length = (int)(p - string);
	}

	for (p = string; length-- > 0; p++)
	{
		unsigned char ab, c, d;

		c = *p;
		if (c < 128) continue;                /* ASCII character */

		if (c < 0xc0)                         /* Isolated 10xx xxxx byte */
			return false;

		if (c >= 0xfe)                        /* Invalid 0xfe or 0xff bytes */
			return false;

		ab = utf8_table[c & 0x3f];            /* Number of additional bytes */
		if (length < ab)
			return false;
		length -= ab;                         /* Length remaining */

		/* Check top bits in the second byte */
		if (((d = *(++p)) & 0xc0) != 0x80)
			return false;

		/* For each length, check that the remaining bytes start with the 0x80 bit
		   set and not the 0x40 bit. Then check for an overlong sequence, and for the
		   excluded range 0xd800 to 0xdfff. */
		switch (ab)
		{
			/* 2-byte character. No further bytes to check for 0x80. Check first byte
			   for for xx00 000x (overlong sequence). */
		case 1:
			if ((c & 0x3e) == 0)
				return false;
			break;
		case 2:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if (c == 0xe0 && (d & 0x20) == 0)
				return false;
			if (c == 0xed && d >= 0xa0)
				return false;
			break;

			/* 4-byte character. Check 3rd and 4th bytes for 0x80. Then check first 2
			   bytes for for 1111 0000, xx00 xxxx (overlong sequence), then check for a
			   character greater than 0x0010ffff (f4 8f bf bf) */
		case 3:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fourth byte */
				return false;
			if (c == 0xf0 && (d & 0x30) == 0)
				return false;
			if (c > 0xf4 || (c == 0xf4 && d > 0x8f))
				return false;
			break;

			/* 5-byte and 6-byte characters are not allowed by RFC 3629, and will be
			   rejected by the length test below. However, we do the appropriate tests
			   here so that overlong sequences get diagnosed, and also in case there is
			   ever an option for handling these larger code points. */

			   /* 5-byte character. Check 3rd, 4th, and 5th bytes for 0x80. Then check for
				  1111 1000, xx00 0xxx */
		case 4:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fourth byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fifth byte */
				return false;
			if (c == 0xf8 && (d & 0x38) == 0)
				return false;
			break;

			/* 6-byte character. Check 3rd-6th bytes for 0x80. Then check for
			   1111 1100, xx00 00xx. */
		case 5:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fourth byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fifth byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Sixth byte */
				return false;
			if (c == 0xfc && (d & 0x3c) == 0)
				return false;
			break;
		}

		/* Character is valid under RFC 2279, but 4-byte and 5-byte characters are
		   excluded by RFC 3629. The pointer p is currently at the last byte of the
		   character. */
		if (ab > 3)
			return false;
	}

	return true;
}


//////////////////////////////////////////////////////////////////////////

std::string base64_encode(std::string_view input)
{
	std::string result;

	CryptoPP::Base64Encoder encoder(nullptr, false);
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

std::string base64_decode(std::string_view input)
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

//////////////////////////////////////////////////////////////////////////
static const char* base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t base58_map[256] =
{
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

std::string base58_decode(std::string_view input)
{
	auto psz = input.data();
	// Skip leading spaces.
	while (*psz && *psz == ' ')
		psz++;
	// Skip and count leading '1's.
	int zeroes = 0;
	int length = 0;
	while (*psz == '1') {
		zeroes++;
		psz++;
	}
	// Allocate enough space in big-endian base256 representation.
	auto size = strlen(psz) * 733 / 1000 + 1; // log(58) / log(256), rounded up.
	std::vector<uint8_t> bin256(size, 0);
	// Process the characters.
	static_assert(sizeof(base58_map) / sizeof(base58_map[0]) == 256,
		"mapBase58.size() should be 256"); // guarantee not out of range
	while (*psz && !(*psz == ' ')) {
		// Decode base58 character
		int carry = base58_map[(uint8_t)*psz];
		if (carry == -1)  // Invalid b58 character
			return {};
		int i = 0;
		for (std::vector<unsigned char>::reverse_iterator it =
			bin256.rbegin(); (carry != 0 || i < length) && (it != bin256.rend());
			++it, ++i) {
			carry += 58 * (*it);
			*it = carry % 256;
			carry /= 256;
		}
		assert(carry == 0);
		length = i;
		psz++;
	}
	// Skip trailing spaces.
	while ((*psz == ' '))
		psz++;
	if (*psz != 0)
		return {};

	return to_hex({ (char*)bin256.data(), bin256.size() });
}

std::string base58_encode(std::string_view input)
{
	// Skip & count leading zeroes.
	int zeroes = 0;
	int length = 0;
	while (input.size() > 0 && input[0] == 0) {
		input = input.substr(1);
		zeroes++;
	}
	// Allocate enough space in big-endian base58 representation.
	auto size = input.size() * 138 / 100 + 1; // log(256) / log(58), rounded up.
	std::vector<unsigned char> b58(size);
	// Process the bytes.
	while (input.size() > 0) {
		int carry = (unsigned char)input[0];
		int i = 0;
		// Apply "b58 = b58 * 256 + ch".
		for (auto it = b58.rbegin();
			(carry != 0 || i < length) && (it != b58.rend());
			it++, i++)
		{
			carry += 256 * (*it);
			*it = carry % 58;
			carry /= 58;
		}
		assert(carry == 0);
		length = i;
		input = input.substr(1);
	}
	// Skip leading zeroes in base58 result.
	auto it = b58.begin() + (size - length);
	while (it != b58.end() && *it == 0)
		it++;
	// Translate the result into a string.
	std::string str;
	str.reserve(zeroes + (b58.end() - it));
	str.assign(zeroes, '1');
	while (it != b58.end())
		str += base58_chars[*(it++)];
	return str;
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

std::string add_suffix(float val, char const* suffix /*= nullptr*/)
{
	std::string ret;

	const char* prefix[] = { "kB", "MB", "GB", "TB" };
	for (auto& i : prefix)
	{
		val /= 1024.f;
		if (std::fabs(val) < 1024.f)
		{
			ret = to_string(val, 4);
			ret += i;
			if (suffix) ret += suffix;
			return ret;
		}
	}
	ret = to_string(val, 4);
	ret += "PB";
	if (suffix) ret += suffix;
	return ret;
}


//////////////////////////////////////////////////////////////////////////

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

int gen_random_int(int start, int end)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(start, end);

	return dis(gen);
}

std::string gen_unique_string(const unsigned int len)
{
	static const char acsii_table[] = {
		'a', 'b', 'c', 'd', 'e',
		'f', 'g', 'h', 'i', 'j',
		'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y',
		'z', '1', '2', '3', '4',
		'5', '6', '7', '8', '9',
		'0'
	};
	static const int table_len = sizeof(acsii_table) / sizeof(char);

	std::string str;
	for (unsigned int i = 0; i < len; i++) {

		int index = gen_random_int(0, table_len - 1);
		str.append(1, acsii_table[index]);
	}

	return str;
}

uint32_t gen_unique_number()
{
	static std::atomic_uint32_t base = static_cast<uint32_t>(
		std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::system_clock::now().time_since_epoch()).count());
	return base++;
}

std::string gen_uuid()
{
	boost::uuids::uuid guid = boost::uuids::random_generator()();
	return uuid_to_string(guid);
}


//////////////////////////////////////////////////////////////////////////

#ifdef WIN32

inline void utf8_utf16(const std::string& utf8, std::wstring& utf16)
{
	auto len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
	if (len > 0)
	{
		wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len);
		MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, tmp, len);
		utf16.assign(tmp);
		free(tmp);
	}
}

inline void utf16_utf8(const std::wstring& utf16, std::string& utf8)
{
	auto len = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, 0, 0);
	if (len > 0)
	{
		char* tmp = (char*)malloc(sizeof(char) * len);
		WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, tmp, len, 0, 0);
		utf8.assign(tmp);
		free(tmp);
	}
}

std::string utf8_from_astring(const std::string& str)
{
	wchar_t* wstring;
	int char_count;

	// convert "ANSI code page" string to UTF-16.
	char_count = MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), NULL, 0);
	std::string result(char_count * sizeof(wchar_t) * 10, 0);
	wstring = (wchar_t*)(result.data() + (char_count * sizeof(wchar_t) * 5));
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), wstring, char_count);

	// convert UTF-16 to MAME string (UTF-8).
	char_count = WideCharToMultiByte(CP_UTF8, 0, wstring, char_count, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, wstring, char_count, (char*)result.data(), char_count, NULL, NULL);
	result.resize(char_count);

	return result;
}

inline std::string error_format(DWORD err)
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process.
	std::string error_msg;
#ifdef UNICODE
	std::wstring tmp((LPTSTR)lpMsgBuf);
	utf16_utf8(tmp, error_msg);
#else
	error_msg.assign((char*)lpMsgBuf);
#endif // UNICODE

	LocalFree(lpMsgBuf);
	boost::trim(error_msg);

	return error_msg;
}

uint64_t get_process_id()
{
	return GetCurrentProcessId();
}


//////////////////////////////////////////////////////////////////////////


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

void set_thread_name(std::thread* thread, const char* name)
{
	DWORD threadId = ::GetThreadId(static_cast<HANDLE>(thread->native_handle()));
	SetThreadName(threadId, name);
}

std::tuple<std::string, bool> run_command(const std::string& cmd) noexcept
{
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hread, hwrite;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&hread, &hwrite, &sa, 0))
		return { {}, false };

	std::wstring command = L"cmd.exe /C " + boost::nowide::widen(cmd);

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfoW(&si);
	si.hStdError = hwrite;
	si.hStdOutput = hwrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	if (!CreateProcessW(NULL, (LPWSTR)command.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		CloseHandle(hwrite);
		CloseHandle(hread);

		return { {}, false };
	}

	CloseHandle(hwrite);

	char buffer[4096] = { 0 };
	DWORD nbytes;
	std::ostringstream oss;

	while (true)
	{
		if (ReadFile(hread, buffer, 4096, &nbytes, NULL) == NULL)
			break;

		oss.write(buffer, nbytes);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	DWORD exit_code;
	GetExitCodeProcess(pi.hProcess, &exit_code);

	CloseHandle(hread);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return { utf8_from_astring(oss.str()), exit_code == EXIT_SUCCESS ? true : false };
}

bool set_dns(const std::string& dns, std::string local_ip/* = ""*/)
{
	std::string register_dns_key = "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters";
	int i = 0;

	for (; i < 10 && !local_ip.empty(); i++)
	{
		ULONG size = 0;
		DWORD status;

		auto pip_free = [](PIP_ADAPTER_INFO p) { free(p); };
		using ip_adapter_info_ptr = std::unique_ptr < IP_ADAPTER_INFO, decltype(pip_free)>;

		if ((status = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
		{
			LOG_WARN << "Set dns, GetAdaptersInfo, code: " << status << ", message: " << error_format(status);
			return false;
		}

		auto pi = (PIP_ADAPTER_INFO)::malloc(size);
		ip_adapter_info_ptr spi(pi, pip_free);

		if ((status = GetAdaptersInfo(pi, &size)) != NO_ERROR)
		{
			LOG_WARN << "Set dns, GetAdaptersInfo, code: " << status << ", message: " << error_format(status);
			return false;
		}

		PIP_ADAPTER_INFO it = pi;
		for (; it != NULL; it = it->Next)
		{
			std::string ip(it->IpAddressList.IpAddress.String);
			if (ip == local_ip)
			{
				register_dns_key = register_dns_key
					+ "\\Interfaces\\" + boost::to_lower_copy(std::string(it->AdapterName));
				break;
			}
		}

		if (it)
			break;

		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	if (i == 10)
	{
		LOG_WARN << "Set dns, Not found local ip: " << local_ip;
		return false;
	}

	HKEY dns_key = NULL;
	DWORD dwDisposition = REG_OPENED_EXISTING_KEY;

	auto status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, register_dns_key.data(),
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &dns_key, &dwDisposition);
	if (status != ERROR_SUCCESS)
	{
		LOG_WARN << "Set dns, RegCreateKeyExA, code: " << status << ", message: " << error_format(status);
		return false;
	}

	typedef std::unique_ptr<std::remove_pointer<HKEY>::type,
		decltype(&RegCloseKey)> register_closer;
	register_closer adapter_key_close(dns_key, &RegCloseKey);

	status = RegSetValueExA(dns_key, "NameServer", 0,
		REG_SZ, (const BYTE*)dns.c_str(), (DWORD)dns.size());
	if (status != ERROR_SUCCESS)
	{
		LOG_WARN << "Set dns, RegSetValueExA, code: " << status << ", message: " << error_format(status);
		return false;
	}

	HMODULE dnsapi = LoadLibraryA("dnsapi.dll");
	if (dnsapi == NULL)
	{
		LOG_WARN << "Set dns, LoadLibraryA Fail...";
		return false;
	}

	typedef std::unique_ptr<std::remove_pointer<HMODULE>::type,
		decltype(&FreeLibrary)> free_library;
	free_library dnsapi_library(dnsapi, &FreeLibrary);

	typedef BOOL(WINAPI* DnsFlushResolverCacheFunc)();
	auto DnsFlushResolverCache = (DnsFlushResolverCacheFunc)GetProcAddress(dnsapi, "DnsFlushResolverCache");
	if (DnsFlushResolverCache == NULL)
		return false;

	auto ret = DnsFlushResolverCache();
	if (!ret)
	{
		status  = GetLastError();
		LOG_WARN << "Set dns, DnsFlushResolverCache, code: " << status << ", message: " << error_format(status);
	}

	return ret;
}

bool set_default_route(const std::string& vaddr, const std::string& vgateway,
	const std::string& gateway, const std::string& server_ip)
{
	// 先为vaddr设置的METRIC为一个很小的值.
	// 再添加一条server_ip的路由通过gateway.
	// 再添加一条默认路由为vaddr通过vgateway.

	if (vaddr.empty()
		|| vgateway.empty()
		|| gateway.empty()
		|| server_ip.empty())
	{
		LOG_WARN << "set_default_route, params invalid!";
		return false;
	}

	int i = 0;
	int ifindex = 0;

	for (; i < 10; i++)
	{
		ULONG size = 0;
		DWORD status;

		auto pip_free = [](PIP_ADAPTER_INFO p) { free(p); };
		using ip_adapter_info_ptr = std::unique_ptr < IP_ADAPTER_INFO, decltype(pip_free)>;

		if ((status = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
		{
			LOG_WARN << "set_default_route, GetAdaptersInfo, code: " << status << ", message: " << error_format(status);
			return false;
		}

		auto pi = (PIP_ADAPTER_INFO)::malloc(size);
		ip_adapter_info_ptr spi(pi, pip_free);

		if ((status = GetAdaptersInfo(pi, &size)) != NO_ERROR)
		{
			LOG_WARN << "set_default_route, GetAdaptersInfo, code: " << status << ", message: " << error_format(status);
			return false;
		}

		PIP_ADAPTER_INFO it = pi;
		for (; it != NULL; it = it->Next)
		{
			std::string ip(it->IpAddressList.IpAddress.String);
			if (ip == vaddr)
			{
				ifindex = it->Index;
				break;
			}
		}

		if (it)
			break;

		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	if (i == 10)
	{
		LOG_WARN << "set_default_route, Not found local ip: " << vaddr;
		return false;
	}

	// 设置interface的metric, windows上的metric计算方法
	// 是interface的metric加上route的metric的和. 我们在
	// 这里全采用1, 也就是最大metric为2, 基本上都小于原来
	// 默认路由的metric, 除非默认路由被用户自己修改了. 这
	// 里不建议修改原interface的默认metric.
	// 相关命令为:
	// netsh interface ipv4 set interface <index> metric=<metric>
	auto [netsh, ret] = run_command("netsh interface ipv4 set interface " + std::to_string(ifindex) + " metric=1");
	if (!ret)
	{
		LOG_WARN << "set_default_route, set interface " << ifindex << " metric faild!";
		return false;
	}

	auto [sadd, sret] = add_route(server_ip + "/32 " + gateway);
	if (!sret)
	{
		LOG_WARN << "set_default_route, add server "
			<< server_ip << " for route: " << sadd;
		return false;
	}
	auto [dadd, dret] = add_route("0.0.0.0/0 " + vgateway + " 1");
	if (!dret)
	{
		LOG_WARN << "set_default_route, add default for route: " << dadd;
		return false;
	}

	return true;
}

static SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SECURITY_ATTRIBUTES) };

const void* ResourceGetAddress(LPCWSTR ResourceName, DWORD* Size)
{
	auto ResourceModule = GetModuleHandleA(nullptr);
	HRSRC FoundResource = FindResourceW(ResourceModule, ResourceName, RT_RCDATA);
	if (!FoundResource)
		return nullptr;

	*Size = SizeofResource(ResourceModule, FoundResource);
	if (!*Size)
		return nullptr;

	HGLOBAL LoadedResource = LoadResource(ResourceModule, FoundResource);
	if (!LoadedResource)
		return nullptr;

	BYTE* Address = (BYTE*)LockResource(LoadedResource);
	if (!Address)
	{
		SetLastError(ERROR_LOCK_FAILED);
		return nullptr;
	}

	return Address;
}

bool ResourceCopyToFile(LPCWSTR DestinationPath, LPCWSTR ResourceName)
{
	DWORD SizeResource;
	const void* LockedResource = ResourceGetAddress(ResourceName, &SizeResource);
	if (!LockedResource)
		return false;

	HANDLE DestinationHandle = CreateFileW(
		DestinationPath,
		GENERIC_WRITE,
		0,
		&SecurityAttributes,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
		NULL);
	if (DestinationHandle == INVALID_HANDLE_VALUE)
		return false;

	DWORD BytesWritten;
	DWORD LastError;
	if (!WriteFile(DestinationHandle, LockedResource, SizeResource, &BytesWritten, NULL))
	{
		LastError = GetLastError();
		goto cleanupDestinationHandle;
	}

	if (BytesWritten != SizeResource)
	{
		LastError = ERROR_WRITE_FAULT;
		goto cleanupDestinationHandle;
	}
	LastError = ERROR_SUCCESS;

cleanupDestinationHandle:
	CloseHandle(DestinationHandle);

	if (LastError != ERROR_SUCCESS)
		return false;

	return true;
}

bool ResourceCreateTemporaryDirectory(std::wstring& RandomTempSubDirectory)
{
	WCHAR WindowsDirectory[MAX_PATH];
	if (!GetWindowsDirectoryW(WindowsDirectory, _countof(WindowsDirectory)))
		return false;

	WCHAR WindowsTempDirectory[MAX_PATH];
	if (!PathCombineW(WindowsTempDirectory, WindowsDirectory, L"Temp"))
	{
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return false;
	}
	UCHAR RandomBytes[32] = { 0 };
	if (!RtlGenRandom(RandomBytes, sizeof(RandomBytes)))
	{
		SetLastError(ERROR_GEN_FAILURE);
		return false;
	}
	WCHAR RandomSubDirectory[sizeof(RandomBytes) * 2 + 1];
	for (int i = 0; i < sizeof(RandomBytes); ++i)
		swprintf_s(&RandomSubDirectory[i * 2], 3, L"%02x", RandomBytes[i]);

	std::filesystem::path path = WindowsTempDirectory;
	path = path / RandomSubDirectory;
	std::error_code ec;
	std::filesystem::create_directories(path, ec);
	if (ec)
		return false;

	RandomTempSubDirectory = path.wstring();

	return true;
}

std::filesystem::path current_system_director()
{
	std::string system_dir(GetSystemDirectoryA(NULL, 0), 0);
	GetSystemDirectoryA(&system_dir[0], static_cast<UINT>(system_dir.size()));
	system_dir.resize(system_dir.size() - 1);
	return system_dir;
}

#define WINTUN_HWID L"Wintun"
#define WINTUN_INF_FILETIME { (DWORD)((16340832000000000ULL + 116444736000000000ULL) & 0xffffffffU), (DWORD)((16340832000000000ULL + 116444736000000000ULL) >> 32) }
#define WINTUN_INF_VERSION ((0ULL << 48) | (14ULL << 32) | (0ULL << 16) | (0ULL << 0))

struct driver_info
{
	std::string published_name_;
	std::string origin_name_;
	std::string provider_;
	std::string class_;
	std::string guid_;
	std::string class_version_;
	std::string version_;
	std::string signer_;
};

std::vector<driver_info> enum_drivers()
{
	std::filesystem::path pnputil = current_system_director();
	pnputil /= "pnputil.exe";

	std::error_code ec;
	bool exist = std::filesystem::exists(pnputil, ec);
	if (!exist || ec)
		return {};

	auto [str, ret] = run_command(pnputil.string() + " /enum-drivers");
	if (!ret)
		return {};

	auto drivers = boost::nowide::widen(str);

	std::vector<std::wstring> lines;
	boost::split_regex(lines, drivers, boost::wregex(L"\n"));

	std::vector<std::wstring> fields;
	driver_info info;
	int field_cnt = 0;
	std::vector<driver_info> result;

	for (const auto& r : lines)
	{
		std::vector<std::wstring> item;
		boost::split_regex(item, r, boost::wregex(L":"));

		if (item.size() != 2)
		{
			if (field_cnt == 7)
			{
				info.published_name_ = boost::trim_copy(boost::nowide::narrow(fields[0]));
				info.origin_name_ = boost::trim_copy(boost::nowide::narrow(fields[1]));
				info.provider_ = boost::trim_copy(boost::nowide::narrow(fields[2]));
				info.class_ = boost::trim_copy(boost::nowide::narrow(fields[3]));
				info.guid_ = boost::trim_copy(boost::nowide::narrow(fields[4]));
				info.version_ = boost::trim_copy(boost::nowide::narrow(fields[5]));
				info.signer_ = boost::trim_copy(boost::nowide::narrow(fields[6]));

				result.push_back(info);
			}
			if (field_cnt == 8)
			{
				info.published_name_ = boost::trim_copy(boost::nowide::narrow(fields[0]));
				info.origin_name_ = boost::trim_copy(boost::nowide::narrow(fields[1]));
				info.provider_ = boost::trim_copy(boost::nowide::narrow(fields[2]));
				info.class_ = boost::trim_copy(boost::nowide::narrow(fields[3]));
				info.guid_ = boost::trim_copy(boost::nowide::narrow(fields[4]));
				info.class_version_ = boost::trim_copy(boost::nowide::narrow(fields[5]));
				info.version_ = boost::trim_copy(boost::nowide::narrow(fields[6]));
				info.signer_ = boost::trim_copy(boost::nowide::narrow(fields[7]));

				result.push_back(info);
			}

			info = {};
			field_cnt = 0;
			fields.clear();
			continue;
		}

		field_cnt++;
		fields.emplace_back(item[1]);
	}

	return result;
}

bool install_wintun()
{
	const static std::string newer = "10/13/2021 0.14.0.0";

	auto drivers = enum_drivers();

	SetupSetNonInteractiveMode(TRUE);

	auto sys_path = current_system_director();
	// 查找已经存在的wintun驱动.
	for (auto& driver : drivers)
	{
		if (driver.origin_name_ != "wintun.inf")
			continue;
		if (newer > driver.version_)
		{
			// 已安装的wintun驱动太旧, 先卸载.
			// pnputil /delete-driver <example.inf> /uninstall
			auto pnputil = sys_path / "pnputil.exe";
			auto remove_driver = pnputil.string() + " /delete-driver " + driver.origin_name_ + " /uninstall";
			auto [str, ret] = run_command(remove_driver);
			if (!ret)
			{
				LOG_ERR << "Remove old wintun driver failed: " << str;
				return false;
			}

			LOG_DBG << "Remove old wintun driver: " << driver.version_;
		}
		else
		{
			// 使用已安装的驱动.
			LOG_DBG << "Using existing wintun driver: " << driver.version_;
			return true;
		}
	}

	// 安装驱动.
	std::error_code ec;
	auto tmppath = std::filesystem::temp_directory_path(ec);
	if (ec)
	{
		LOG_ERR << "Install driver, temp_directory_path: " << ec.message();
		return false;
	}

	tmppath /= gen_unique_string(32);
	std::filesystem::create_directories(tmppath, ec);
	if (ec)
	{
		LOG_ERR << "Install driver, create_directories: " << tmppath.string() << ", ec: " << ec.message();
		return false;
	}

	auto CatSource = L"wintun.cat";
	auto SysSource = L"wintun.sys";
	auto InfSource = L"wintun.inf";

	auto catPath = tmppath / CatSource;
	auto sysPath = tmppath / SysSource;
	auto infPath = tmppath / InfSource;

	ResourceCopyToFile(catPath.wstring().data(), CatSource);
	ResourceCopyToFile(sysPath.wstring().data(), SysSource);
	ResourceCopyToFile(infPath.wstring().data(), InfSource);

	// 安装成功后删除解压文件夹.
	scoped_exit clean([&]() mutable { std::filesystem::remove_all(tmppath, ec); });

	// pnputil /add-driver x:\driver.inf
	auto pnputil = sys_path / "pnputil.exe";
	auto install_driver = pnputil.string() + " /add-driver " + infPath.string();
	auto [str, ret] = run_command(install_driver);
	if (!ret)
	{
		LOG_ERR << "Install wintun driver failed: " << str;
		return false;
	}

	LOG_DBG << "Install wintun driver";

	return true;
}

std::vector<windows_driver> enum_windows_devices()
{
	const auto ADAPTER_KEY = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
	std::vector<windows_driver> result;
	HKEY adapter_key;

	auto status = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		ADAPTER_KEY, 0, KEY_READ, &adapter_key);
	if (status != ERROR_SUCCESS)
		return result;

	scoped_exit close_dev_key([&]() mutable { RegCloseKey(adapter_key); });

	for (int i = 0; ; i++)
	{
		char enum_name[256] = { 0 };
		std::string unit_string;
		DWORD len = 256;
		status = RegEnumKeyExA(adapter_key,
			i, enum_name, &len, NULL, NULL, NULL, NULL);
		if (status == ERROR_NO_MORE_ITEMS)
			break;
		else if (status != ERROR_SUCCESS)
			break;
		else
		{
			unit_string = std::format("{}\\{}", ADAPTER_KEY, enum_name);

			HKEY unit_key;
			status = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
				unit_string.data(), 0, KEY_READ, &unit_key);
			if (status != ERROR_SUCCESS)
				break;
			scoped_exit unit_key_close([&]() mutable { RegCloseKey(unit_key); });

			const char* component_id_string = "ComponentId";
			const char* net_cfg_instance_id_string = "NetCfgInstanceId";
			DWORD data_type;
			char component_id[256] = { 0 };
			len = 256;
			status = RegQueryValueExA(
				unit_key,
				component_id_string,
				NULL,
				&data_type,
				(LPBYTE)component_id,
				&len);
			if (status != ERROR_SUCCESS)
				continue;

			char net_cfg_instance_id[256] = { 0 };
			len = 256;
			status = RegQueryValueExA(
				unit_key,
				net_cfg_instance_id_string,
				NULL,
				&data_type,
				(LPBYTE)net_cfg_instance_id,
				&len);
			if (status != ERROR_SUCCESS)
				continue;
			if (data_type != REG_SZ)
				continue;

			windows_driver driver;
			driver.type_ = WINDOWS_DRIVER_UNSPECIFIED;

			std::string id_string = boost::to_lower_copy(std::string(component_id));

			if (id_string.find("tap0901") != std::string::npos
				 || id_string.find("tapnordvpn") != std::string::npos)
			{
				driver.type_ = WINDOWS_DRIVER_TAP_WINDOWS6;
			}
			else if (id_string.find("wintun") != std::string::npos)
			{
				driver.type_ = WINDOWS_DRIVER_WINTUN;
			}

			driver.guid_ = net_cfg_instance_id;
			result.push_back(driver);
		}
	}

	const auto NETWORK_CONNECTIONS_KEY = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
	HKEY network_connections_key;
	status = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &network_connections_key);
	if (status != ERROR_SUCCESS)
		return result;

	scoped_exit close_network_connections_key([&]() mutable { RegCloseKey(network_connections_key); });

	for (int i = 0; ; i++)
	{
		char enum_name[256] = { 0 };
		DWORD len = 256;
		status = RegEnumKeyExA(network_connections_key,
			i, enum_name, &len, NULL, NULL, NULL, NULL);
		if (status != ERROR_SUCCESS)
			break;

		auto connection_string = std::format("{}\\{}\\Connection", NETWORK_CONNECTIONS_KEY, enum_name);

		HKEY connection_key;
		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			connection_string.data(), 0, KEY_READ, &connection_key);
		if (status != ERROR_SUCCESS)
			continue;
		scoped_exit connection_key_close([&]() mutable { RegCloseKey(connection_key); });

		TCHAR name_data[256] = { 0 };
		TCHAR name_string[] = TEXT("Name");
		len = 256;

		DWORD name_type;
		status = RegQueryValueEx(connection_key, name_string,
			NULL, &name_type, (LPBYTE)name_data, &len);
		if (status != ERROR_SUCCESS)
			continue;

		std::string dev_name;
		{
#ifdef UNICODE
			utf16_utf8(name_data, dev_name);
#else
			dev_name = name_data;
#endif
		}

		std::string guid_key = enum_name;
		for (auto& dev : result)
		{
			if (dev.guid_ != guid_key)
				continue;
			dev.name_ = dev_name;
		}
	}

	return result;
}

using device_instance = std::tuple<std::string, std::string>;
using device_instance_id_interface = std::vector<device_instance>;

static device_instance_id_interface get_device_instance_id_interface()
{
	HDEVINFO dev_info_set;
	DWORD err;
	device_instance_id_interface result;

	dev_info_set = SetupDiGetClassDevsEx(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
	if (dev_info_set == INVALID_HANDLE_VALUE)
	{
		err = GetLastError();
		LOG_FMT("Error [{}] opening device information set key: {}", (unsigned int)err, error_format(err));
	}

	for (DWORD i = 0;; ++i)
	{
		SP_DEVINFO_DATA device_info_data;
		BOOL res;
		HKEY dev_key;
		char net_cfg_instance_id_string[] = "NetCfgInstanceId";
		BYTE net_cfg_instance_id[256] = { 0 };
		char device_instance_id[256] = { 0 };
		DWORD len;
		DWORD data_type;
		LONG status;
		ULONG dev_interface_list_size;
		CONFIGRET cr;

		ZeroMemory(&device_info_data, sizeof(SP_DEVINFO_DATA));
		device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
		res = SetupDiEnumDeviceInfo(dev_info_set, i, &device_info_data);
		if (!res)
		{
			if (GetLastError() == ERROR_NO_MORE_ITEMS)
			{
				break;
			}
			else
			{
				continue;
			}
		}

		dev_key = SetupDiOpenDevRegKey(dev_info_set, &device_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
		if (dev_key == INVALID_HANDLE_VALUE)
		{
			continue;
		}

		scoped_exit close_dev_key([&]() mutable { RegCloseKey(dev_key); });

		len = sizeof(net_cfg_instance_id);
		data_type = REG_SZ;
		status = RegQueryValueExA(dev_key,
			net_cfg_instance_id_string,
			NULL,
			&data_type,
			net_cfg_instance_id,
			&len);
		if (status != ERROR_SUCCESS)
		{
			continue;
		}

		len = sizeof(device_instance_id);
		res = SetupDiGetDeviceInstanceIdA(dev_info_set, &device_info_data, device_instance_id, len, &len);
		if (!res)
		{
			continue;
		}

		cr = CM_Get_Device_Interface_List_SizeA(&dev_interface_list_size,
			(LPGUID)&GUID_DEVINTERFACE_NET,
			device_instance_id,
			CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

		if (cr != CR_SUCCESS)
		{
			continue;
		}

		std::string dev_interface_list(dev_interface_list_size, 0);
		cr = CM_Get_Device_Interface_ListA((LPGUID)&GUID_DEVINTERFACE_NET, device_instance_id,
			PZZSTR(dev_interface_list.data()),
			dev_interface_list_size,
			CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
		if (cr != CR_SUCCESS)
		{
			continue;
		}

		device_instance dev_if = std::make_tuple(std::string((char*)(&net_cfg_instance_id[0])), dev_interface_list);
		result.push_back(dev_if);
	}

	SetupDiDestroyDeviceInfoList(dev_info_set);

	return result;
}

HANDLE open_wintun(const std::string& name)
{
	auto ifs = get_device_instance_id_interface();
	auto devs = enum_windows_devices();

	windows_driver wintun;
	for (auto& dev : devs)
	{
		if (dev.type_ == WINDOWS_DRIVER_WINTUN &&
			dev.name_ == name
			)
		{
			wintun = dev;
			break;
		}
	}

	if (wintun.guid_.empty())
		return INVALID_HANDLE_VALUE;

	std::string path;
	for (auto& [guid, p] : ifs)
	{
		if (guid == wintun.guid_)
		{
			path = p;
			break;
		}
	}

	return CreateFileA(path.data(),
		GENERIC_READ | GENERIC_WRITE,
		0,         /* was: FILE_SHARE_READ */
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
		0);
}

#if 0


static HANDLE PrivateNamespace = NULL;
static HANDLE BoundaryDescriptor = NULL;
static CRITICAL_SECTION Initializing;
static BOOL IsLocalSystem;

static BOOL IsNewer(
	_In_ const FILETIME* DriverDate1,
	_In_ DWORDLONG DriverVersion1,
	_In_ const FILETIME* DriverDate2,
	_In_ DWORDLONG DriverVersion2)
{
	if (DriverDate1->dwHighDateTime > DriverDate2->dwHighDateTime)
		return TRUE;
	if (DriverDate1->dwHighDateTime < DriverDate2->dwHighDateTime)
		return FALSE;

	if (DriverDate1->dwLowDateTime > DriverDate2->dwLowDateTime)
		return TRUE;
	if (DriverDate1->dwLowDateTime < DriverDate2->dwLowDateTime)
		return FALSE;

	if (DriverVersion1 > DriverVersion2)
		return TRUE;
	if (DriverVersion1 < DriverVersion2)
		return FALSE;

	return FALSE;
}

BOOL DriverInstall(HDEVINFO* DevInfoExistingAdaptersForCleanup, SP_DEVINFO_DATA_LIST** ExistingAdaptersForCleanup)
{
	static const FILETIME OurDriverDate = WINTUN_INF_FILETIME; // 10/13/2021
	static const DWORDLONG OurDriverVersion = WINTUN_INF_VERSION; // 0.14.0.0

	DWORD LastError = ERROR_SUCCESS;
	HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
	if (DevInfo == INVALID_HANDLE_VALUE)
	{
		LastError = GetLastError();
		LOG_FMT("Failed to create empty device information set");
		goto cleanupDriverInstallationLock;
	}
	SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
	if (!SetupDiCreateDeviceInfoW(DevInfo, WINTUN_HWID, &GUID_DEVCLASS_NET, NULL, NULL, DICD_GENERATE_ID, &DevInfoData))
	{
		LastError = GetLastError();
		LOG_FMT("Failed to create new device information element");
		goto cleanupDevInfo;
	}
	static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
	if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE*)Hwids, sizeof(Hwids)))
	{
		LastError = GetLastError();
		LOG_FMT("Failed to set adapter hardware ID");
		goto cleanupDevInfo;
	}
	if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER))
	{
		LastError = GetLastError();
		LOG_FMT("Failed building adapter driver info list");
		goto cleanupDevInfo;
	}

	FILETIME DriverDate = { 0 };
	DWORDLONG DriverVersion = 0;
	HDEVINFO DevInfoExistingAdapters = INVALID_HANDLE_VALUE;
	SP_DEVINFO_DATA_LIST* ExistingAdapters = NULL;

	for (DWORD EnumIndex = 0;; ++EnumIndex)
	{
		SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
		if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
		{
			if (GetLastError() == ERROR_NO_MORE_ITEMS)
				break;
			continue;
		}
		if (IsNewer(&OurDriverDate, OurDriverVersion, &DrvInfoData.DriverDate, DrvInfoData.DriverVersion))
			continue;
		if (!IsNewer(&DrvInfoData.DriverDate, DrvInfoData.DriverVersion, &DriverDate, DriverVersion))
			continue;
		DriverDate = DrvInfoData.DriverDate;
		DriverVersion = DrvInfoData.DriverVersion;
	}

 	SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);

	if (DriverVersion)
	{
		LOG_FMT("Using existing driver {}.{}",
			(DWORD)((DriverVersion & 0xffff000000000000) >> 48),
			(DWORD)((DriverVersion & 0x0000ffff00000000) >> 32));
		LastError = ERROR_SUCCESS;
		goto cleanupExistingAdapters;
	}

	LOG_FMT("Installing driver {}.{}",
		(DWORD)((OurDriverVersion & 0xffff000000000000) >> 48),
		(DWORD)((OurDriverVersion & 0x0000ffff00000000) >> 32));
	std::wstring RandomTempSubDirectory;
	if (!ResourceCreateTemporaryDirectory(RandomTempSubDirectory))
	{
		LastError = GetLastError();
		LOG_FMT("Failed to create temporary folder {}", RandomTempSubDirectory);
		goto cleanupExistingAdapters;
	}

	WCHAR CatPath[MAX_PATH] = { 0 };
	WCHAR SysPath[MAX_PATH] = { 0 };
	WCHAR InfPath[MAX_PATH] = { 0 };
	if (!PathCombineW(CatPath, RandomTempSubDirectory.data(), L"wintun.cat") ||
		!PathCombineW(SysPath, RandomTempSubDirectory.data(), L"wintun.sys") ||
		!PathCombineW(InfPath, RandomTempSubDirectory.data(), L"wintun.inf"))
	{
		LastError = ERROR_BUFFER_OVERFLOW;
		goto cleanupDirectory;
	}

	auto CatSource = L"wintun-amd64.cat";
	auto SysSource = L"wintun-amd64.sys";
	auto InfSource = L"wintun-amd64.inf";

	LOG_FMT("Extracting driver");
	if (!ResourceCopyToFile(CatPath, CatSource) || !ResourceCopyToFile(SysPath, SysSource) ||
		!ResourceCopyToFile(InfPath, InfSource))
	{
		LastError = GetLastError();
		LOG_FMT("Failed to extract driver");
		goto cleanupDelete;
	}

	LOG_FMT("Installing driver");
	if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_NONE, 0, NULL, 0, NULL, NULL))
	{
		LastError = GetLastError();
		LOG_FMT("Could not install driver {} to store", InfPath);
	}

cleanupDelete:
	DeleteFileW(CatPath);
	DeleteFileW(SysPath);
	DeleteFileW(InfPath);
cleanupDirectory:
	RemoveDirectoryW(RandomTempSubDirectory.data());
cleanupExistingAdapters:
	if (LastError == ERROR_SUCCESS)
	{
		*DevInfoExistingAdaptersForCleanup = DevInfoExistingAdapters;
		*ExistingAdaptersForCleanup = ExistingAdapters;
	}
// 	else
// 		DriverInstallDeferredCleanup(DevInfoExistingAdapters, ExistingAdapters);
cleanupDevInfo:
	SetupDiDestroyDeviceInfoList(DevInfo);
cleanupDriverInstallationLock:
	if (LastError != ERROR_SUCCESS)
		return false;

	return true;
}

#endif

#elif __linux__

uint64_t get_process_id()
{
	return (uint64_t)getpid();
}

void set_thread_name(std::thread* thread, const char* name)
{
	auto handle = thread->native_handle();
	pthread_setname_np(handle, name);
}

void set_thread_name(const char* name)
{
	prctl(PR_SET_NAME, name, 0, 0, 0);
}

std::tuple<std::string, bool> run_command(const std::string& cmd) noexcept
{
	auto pf = popen(cmd.c_str(), "r");
	if (!pf)
		return { "", false };

	std::string result;
	int total = 0;

	while (!feof(pf))
	{
		result.resize(total + 1024);
		auto nread = fread((char*)(result.data() + total), 1, 1024, pf);
		if (nread <= 0)
			break;
		total += nread;
	}
	result.resize(total);

	int exit_code = pclose(pf);
	return { result, exit_code == EXIT_SUCCESS ? true : false };
}

bool set_dns(const std::string&/* dns*/, std::string/* local_ip = ""*/)
{
	return false;
}

bool set_default_route(const std::string&, const std::string&,
	const std::string&, const std::string&)
{
	return false;
}

#elif defined(__APPLE__)

uint64_t get_process_id()
{
	return (uint64_t)getpid();
}

void set_thread_name(std::thread*, const char*)
{
}

void set_thread_name(const char*/* name*/)
{
}

std::tuple<std::string, bool> run_command(const std::string& cmd) noexcept
{
	auto pf = popen(cmd.c_str(), "r");
	if (!pf)
		return { "", false };

	std::string result;
	int total = 0;

	while (!feof(pf))
	{
		result.resize(total + 1024);
		auto nread = fread((char*)(result.data() + total), 1, 1024, pf);
		if (nread <= 0)
			break;
		total += nread;
	}
	result.resize(total);

	int exit_code = pclose(pf);
	return { result, exit_code == EXIT_SUCCESS ? true : false };
}

bool set_dns(const std::string&/* dns*/, std::string/* local_ip = ""*/)
{
	return false;
}

bool set_default_route(const std::string&, const std::string&,
	const std::string&, const std::string&)
{
	return false;
}

#else

uint64_t get_process_id()
{
	return (uint64_t)getpid();
}

void set_thread_name(std::thread*, const char*)
{
}

void set_thread_name(const char*/* name*/)
{
}

bool set_dns(const std::string&/* dns*/, std::string/* local_ip = ""*/)
{
	return false;
}

bool set_default_route(const std::string&, const std::string&,
	const std::string&, const std::string&)
{
	return false;
}

#endif

void create_pid(std::string suffix, std::filesystem::path pidfile/* = {}*/ )
{
	std::error_code ignore_ec;
	std::ostringstream oss;
	oss << get_process_id();

	// pid文件.
	if (!pidfile.empty())
	{
		fs::remove(pidfile, ignore_ec);

		// 创建avpn.pid文件.
		fileop::write(pidfile, oss.str());
		return;
	}

	// 构造临时目录.
	auto tmppath = fs::temp_directory_path();
	auto avpn_tmppath = tmppath /
		std::format("avpn-{}", base58_encode(suffix));

	// 创建临时avpn文件夹.
	fs::create_directories(avpn_tmppath, ignore_ec);

	// 先删除存在的pid文件.
	auto pid = avpn_tmppath / "avpn.pid";
	fs::remove(pid, ignore_ec);

	// 创建avpn.pid文件.
	fileop::write(pid, oss.str());
}


uint64_t check_pid(std::string suffix)
{
	auto tmppath = fs::temp_directory_path();
	auto avpn_tmppath = tmppath /
		std::format("avpn-{}", base64_encode(suffix));

	if (!fs::exists(avpn_tmppath))
		return 0;

	std::string bufs(128, 0);
	auto bytes = fileop::read(avpn_tmppath / "avpn.pid", bufs);
	bufs.resize(bytes);

	return (uint64_t)std::atoll(bufs.c_str());
}


std::tuple<std::string, bool> route_ops(const std::string& route, bool flag = false)
{
	std::vector<std::string> result;
	boost::split_regex(result, route, boost::regex(" +"));

	if (result.size() < 2)
		return { "", false };

	net::ip::network_v4 net;
	boost::system::error_code ec;

	// 解析 destination and mask.
	auto it = result.begin();
	auto& dest = *it++;
	bool is_cidr = dest.find('/') != std::string::npos;
	if (is_cidr)
	{
		net = net::ip::make_network_v4(dest, ec);
		if (ec)
			return { "", false };
	}
	else
	{
		if (result.size() < 3)
			return { "", false };

		auto addr = net::ip::make_address_v4(dest, ec);
		auto& str = *it++;
		auto mask = net::ip::make_address_v4(str, ec);
		if (ec)
			return { "", false };

		net = net::ip::make_network_v4(addr, mask);
	}

	// 解析 gateway.
	auto& gw = *it++;
	auto gateway = net::ip::make_address_v4(gw, ec);
	if (ec)
		return { "", false };

	std::string metric;

	// 解析metric.
	if (it != result.end())
		metric = *it;

	// 根据平台构造命令.
	std::string add_route_cmd;

#ifdef _WIN32
	// route ADD 157.0.0.0 MASK 255.0.0.0  157.55.80.1 METRIC 3
	add_route_cmd = "route ";
	if (flag)
		add_route_cmd += "ADD ";
	else
		add_route_cmd += "DELETE ";
	add_route_cmd += net.address().to_string(ec) + " MASK ";
	if (ec)
		return { "", false };
	add_route_cmd += net.netmask().to_string(ec) + " ";
	if (ec)
		return { "", false };
	add_route_cmd += gateway.to_string(ec);
	if (ec)
		return { "", false };
	if (!metric.empty())
		add_route_cmd += " METRIC " + metric;
#elif __linux__
	// ip route add 183.230.32.0/24 via 10.0.0.1
	add_route_cmd = "ip route ";
	if (flag)
		add_route_cmd += "add ";
	else
		add_route_cmd += "del ";
	add_route_cmd += net.address().to_string(ec) + "/" + std::to_string(net.prefix_length());
	if (ec)
		return { "", false };
	add_route_cmd += " via " + gateway.to_string(ec);
	if (ec)
		return { "", false };
	if (!metric.empty())
		add_route_cmd += " metric " + metric;
#elif __APPLE__
	// route -n add -net 183.230.32.0/24 10.0.0.1
	add_route_cmd = "route -n ";
	if (flag)
		add_route_cmd += "add -net ";
	else
		add_route_cmd += "delete -net ";
	add_route_cmd += net.address().to_string(ec) + "/" + std::to_string(net.prefix_length());
	if (ec)
		return { "", false };
	add_route_cmd += " " + gateway.to_string(ec);
	if (ec)
		return { "", false };
	if (!metric.empty())
		add_route_cmd += " -hopcount " + metric;
#else
	// TODO: unsupported system.
	return { "", false };
#endif

	return run_command(add_route_cmd);
}

std::tuple<std::string, bool> add_route(const std::string& route)
{
	return route_ops(route, true);
}

std::tuple<std::string, bool> del_route(const std::string& route)
{
	return route_ops(route, false);
}

//////////////////////////////////////////////////////////////////////////

bool parse_endpoint_string(std::string_view str,
	std::string& host, std::string& port, bool& ipv6only)
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
		if (std::string_view(it, address_string.end()) == "ipv6only" ||
			std::string_view(it, address_string.end()) == "-ipv6only")
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

	endp.address(net::ip::address::from_string(host, ec));
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

	endp.address(net::ip::address::from_string(host, ec));
	endp.port(static_cast<unsigned short>(std::atoi(port.data())));

	return ipv6only;
}

bool same_ipv4_network(const net::ip::network_v4& net, uint32_t u32_addr)
{
	net::ip::address_v4 addr(u32_addr);
	net::ip::network_v4 other(addr, net.netmask());

	if (net.network() == other.network())
		return true;

	return false;
}

net::ip::network_v4
make_network(uint32_t u32_addr, unsigned short prefix_length)
{
	auto ipaddr = net::ip::address_v4(u32_addr);
	return net::ip::make_network_v4(ipaddr, prefix_length);
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

