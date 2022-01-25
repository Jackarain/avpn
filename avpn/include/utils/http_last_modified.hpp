//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once
#include <string>

namespace util {
	std::string http_last_modified(const std::string& file);
	std::time_t http_parse_last_modified(const std::string& gmttime);
}
