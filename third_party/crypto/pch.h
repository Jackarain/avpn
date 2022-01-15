// pch.h - written and placed in the public domain by Wei Dai

//! \headerfile pch.h
//! \brief Precompiled header file

#ifndef CRYPTOPP_PCH_H
#define CRYPTOPP_PCH_H

# ifdef CRYPTOPP_GENERATE_X64_MASM
	#include "./include/cryptopp/cpu.h"

# else
	#include "./include/cryptopp/config.h"

	#ifdef USE_PRECOMPILED_HEADERS
		#include "./include/cryptopp/simple.h"
		#include "./include/cryptopp/secblock.h"
		#include "./include/cryptopp/misc.h"
		#include "./include/cryptopp/smartptr.h"
		#include "./include/cryptopp/stdcpp.h"
	#endif
# endif

// Enable file and line numbers, if available.
// #if defined(_MSC_VER) && defined(_DEBUG) && defined(USE_PRECOMPILED_HEADERS)
// # define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
// # define new DEBUG_NEW
// #endif

#endif	// CRYPTOPP_PCH_H
