/* ----------------------------------------------------------------------------
Copyright (c) 2018-2020 Microsoft Research, Daan Leijen
This is free software; you can redistribute it and/or modify it under the
terms of the MIT license. A copy of the license can be found in the file
"LICENSE" at the root of this distribution.
-----------------------------------------------------------------------------*/
#pragma once
#ifndef MIMALLOC_NEW_DELETE_H
#define MIMALLOC_NEW_DELETE_H

// ----------------------------------------------------------------------------
// This header provides convenient overrides for the new and
// delete operations in C++.
//
// This header should be included in only one source file!
//
// On Windows, or when linking dynamically with mimalloc, these
// can be more performant than the standard new-delete operations.
// See <https://en.cppreference.com/w/cpp/memory/new/operator_new>
// ---------------------------------------------------------------------------
#if defined(__cplusplus)
  #include <new>
  #include <mimalloc.h>

  void operator delete(void* p) noexcept;
  void operator delete[](void* p) noexcept;

  void* operator new(std::size_t n) noexcept(false);
  void* operator new[](std::size_t n) noexcept(false);

  void* operator new  (std::size_t n, const std::nothrow_t& tag) noexcept;
  void* operator new[](std::size_t n, const std::nothrow_t& tag) noexcept;

  #if (__cplusplus >= 201402L || _MSC_VER >= 1916)
  void operator delete  (void* p, std::size_t n) noexcept;
  void operator delete[](void* p, std::size_t n) noexcept;
  #endif

  #if (__cplusplus > 201402L || defined(__cpp_aligned_new))
  void operator delete  (void* p, std::align_val_t al) noexcept;
  void operator delete[](void* p, std::align_val_t al) noexcept;
  void operator delete  (void* p, std::size_t n, std::align_val_t al) noexcept;
  void operator delete[](void* p, std::size_t n, std::align_val_t al) noexcept;

  void* operator new(std::size_t n, std::align_val_t al)   noexcept(false);
  void* operator new[](std::size_t n, std::align_val_t al) noexcept(false);
  void* operator new  (std::size_t n, std::align_val_t al, const std::nothrow_t&) noexcept;
  void* operator new[](std::size_t n, std::align_val_t al, const std::nothrow_t&) noexcept;
  #endif
#endif

#endif // MIMALLOC_NEW_DELETE_H
