//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <vector>
#include <sstream>
#include <iostream>
#include <cstring> // std::memcpy
#include <unordered_map>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <boost/date_time/posix_time/ptime.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

using boost::multiprecision::cpp_int;
using cpp_numeric = boost::multiprecision::cpp_dec_float_100;

#include <odb/section.hxx>
#include <odb/nullable.hxx>

#ifdef _MSC_VER
#	pragma warning (push)
#	pragma warning (disable:4068)
#endif // _MSC_VER

#pragma db model version(1, 1, open)

#pragma db map type("numeric")			\
               as("TEXT")				\
               to("(?)::numeric")		\
               from("(?)::TEXT")

#pragma db map type("cidr")			\
               as("TEXT")			\
               to("(?)::cidr")		\
               from("(?)::TEXT")

#pragma db map type("INTEGER *\\[(\\d*)\\]") \
               as("TEXT")                    \
               to("(?)::INTEGER[$1]")        \
               from("(?)::TEXT")

#pragma db map type("NUMERIC *\\[(\\d*)\\]") \
               as("TEXT")                    \
               to("(?)::NUMERIC[$1]")        \
               from("(?)::TEXT")

#pragma db map type("TEXT *\\[(\\d*)\\]") \
               as("TEXT")                 \
               to("(?)::TEXT[$1]")        \
               from("(?)::TEXT")

// 配置表.
#pragma db object
struct dchs_config {
	#pragma db id auto
	long long id_{-1};

	// 系统随机种子.
    std::string random_seed_;

    // 设定文件分片数.
	int64_t file_shards_{5};

	// 设定冗余分片数.
	int64_t parity_shards_{3};
};

// 文件存储表.
#pragma db object
struct dchs_file_store {
    #pragma db id auto
    long long id_{-1};

    // 原文件名.
    #pragma db index
    std::string origin_filename_;

    // 文件hash.
    #pragma db index
    std::string filehash_;

    // 文件大小.
    int64_t filesize_{0};

    // 文件分片数.
    int64_t file_shards_{5};

    // 冗余分片数.
    int64_t parity_shards_{3};
};

// 切片表.
#pragma db object
struct dchs_shards {
    #pragma db id auto
	long long id_{-1};

    // 文件hash.
    #pragma db index
    std::string filehash_;

    // 文件索引.
    #pragma db index
    int64_t file_index_{-1};

    // 文件切片hash.
    std::string file_shard_hash_;

    // 文件存储位置, ssh路径.
    #pragma db type("TEXT[]")
    std::vector<std::string> storage_path_;
};
