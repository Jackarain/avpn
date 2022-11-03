#pragma once
#include <map>
#include <string>
#include <cstdint>

namespace avpn {
    using std::map;
    using std::string;

    int32_t run_hook(string cmd, map<string, string> env);
}