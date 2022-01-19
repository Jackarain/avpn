//
// Copyright (C) 2013 - 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#ifndef DCHS_VERSION_MAJOR
#define DCHS_VERSION_MAJOR 4
#endif // !DCHS_VERSION_MAJOR

#ifndef DCHS_VERSION_MINOR
#define DCHS_VERSION_MINOR 1
#endif //DCHS_VERSION_MINOR

#ifndef DCHS_VERSION_TINY
#define DCHS_VERSION_TINY 19
#endif //DCHS_VERSION_TINY

// the format of this version is: MMmmtt
// M = Major version, m = minor version, t = tiny version
#define DCHS_VERSION_NUM ((DCHS_VERSION_MAJOR * 10000) + (DCHS_VERSION_MINOR * 100) + DCHS_VERSION_TINY)
#define DCHS_VERSION "4.1.19"

#ifndef DCHS_GIT_REVISION
#define DCHS_GIT_REVISION "Git-a8425fd"
#endif

#define DCHS_VERSION_MIME "DCHS/" DCHS_VERSION "(" DCHS_GIT_REVISION ")"
