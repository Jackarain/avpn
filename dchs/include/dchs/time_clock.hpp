//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <time.h>
#include <chrono>

#include <boost/system/error_code.hpp>

#ifdef __MACH__
#include <sys/time.h>
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#if defined BOOST_WINDOWS
#	ifndef WIN32_LEAN_AND_MEAN
#		define  WIN32_LEAN_AND_MEAN
#	endif // !WIN32_LEAN_AND_MEAN
#	include <windows.h>
#	include <mmsystem.h>	// for windows.
#	pragma comment(lib, "winmm.lib")
#endif

namespace time_clock {

	namespace internal{
		template <typename T = void>
		struct Null {};
		inline Null<> localtime_r(...) { return Null<>(); }
		inline Null<> localtime_s(...) { return Null<>(); }
		inline Null<> gmtime_r(...) { return Null<>(); }
		inline Null<> gmtime_s(...) { return Null<>(); }
	}

	// Thread-safe replacement for std::localtime
	inline bool localtime(std::time_t time, std::tm& tm)
	{
		struct LocalTime {
			std::time_t time_;
			std::tm tm_;

			LocalTime(std::time_t t) : time_(t) {}

			bool run() {
				using namespace time_clock::internal;
				return handle(localtime_r(&time_, &tm_));
			}

			bool handle(std::tm *tm) { return tm != nullptr; }

			bool handle(time_clock::internal::Null<>) {
				using namespace time_clock::internal;
				return fallback(localtime_s(&tm_, &time_));
			}

			bool fallback(int res) { return res == 0; }

			bool fallback(time_clock::internal::Null<>) {
				using namespace time_clock::internal;
				std::tm *tm = std::localtime(&time_);
				if (tm) tm_ = *tm;
				return tm != nullptr;
			}
		};

		LocalTime lt(time);
		if (lt.run()) {
			tm = lt.tm_;
			return true;
		}

		return false;
	}

	// Thread-safe replacement for std::gmtime
	inline bool gmtime(std::time_t time, std::tm& tm)
	{
		struct GMTime {
			std::time_t time_;
			std::tm tm_;

			GMTime(std::time_t t) : time_(t) {}

			bool run() {
				using namespace time_clock::internal;
				return handle(gmtime_r(&time_, &tm_));
			}

			bool handle(std::tm *tm) { return tm != nullptr; }

			bool handle(time_clock::internal::Null<>) {
				using namespace time_clock::internal;
				return fallback(gmtime_s(&tm_, &time_));
			}

			bool fallback(int res) { return res == 0; }

			bool fallback(time_clock::internal::Null<>) {
				std::tm *tm = std::gmtime(&time_);
				if (tm != nullptr) tm_ = *tm;
				return tm != nullptr;
			}
		};

		GMTime gt(time);
		if (gt.run()) {
			tm = gt.tm_;
			return true;
		}

		return false;
	}

	inline int64_t time_milliseconds()
	{
		int64_t time;
#if defined(BOOST_WINDOWS)
		static const boost::uint64_t epoch = 116444736000000000L;
		auto tmp = timeGetTime();
		static const int64_t system_start_time = [&tmp]() {
			boost::uint64_t ft_scalar;
			GetSystemTimeAsFileTime((FILETIME*)&ft_scalar);
			int64_t tim = (__int64)((ft_scalar - epoch) / (__int64)10000);
			return tim - tmp;
		}();
		thread_local int64_t system_current_time = 0;
		thread_local uint32_t last_time = 0;
		system_current_time += (tmp - last_time);
		last_time = tmp;
		time = system_start_time + system_current_time;
#elif __linux__
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		time = ts.tv_sec * 1000000000LL + ts.tv_nsec;
		time /= 1000000;
#elif __MACH__
		clock_serv_t cclock;
		mach_timespec_t mts;
		host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
		clock_get_time(cclock, &mts);
		mach_port_deallocate(mach_task_self(), cclock);
		time = mts.tv_sec * 1000000000LL + mts.tv_nsec;
		time /= 1000000;
#endif // BOOST_WINDOWS
		return time;
	}

	class steady_clock
	{
	public:
		using duration = std::chrono::milliseconds;
		using rep = duration::rep;
		using period = duration::period;
		using time_point = std::chrono::time_point<steady_clock>;
		BOOST_STATIC_CONSTEXPR bool is_steady = true;

		static time_point now() BOOST_NOEXCEPT
		{
			return steady_clock::time_point(
				steady_clock::duration(
					static_cast<steady_clock::rep>(time_milliseconds())));
		}

#if !defined BOOST_CHRONO_DONT_PROVIDE_HYBRID_ERROR_HANDLING
		static time_point now(boost::system::error_code & ec)
		{
			ec = boost::system::error_code();
			return steady_clock::time_point(
				steady_clock::duration(
					static_cast<steady_clock::rep>(time_milliseconds())));
		}
#endif
	};

}
