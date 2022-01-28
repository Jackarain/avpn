//
// Copyright (C) 2013 - 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#ifndef AVPN_VERSION_MAJOR
#define AVPN_VERSION_MAJOR 4
#endif // !AVPN_VERSION_MAJOR

#ifndef AVPN_VERSION_MINOR
#define AVPN_VERSION_MINOR 1
#endif //AVPN_VERSION_MINOR

#ifndef AVPN_VERSION_TINY
#define AVPN_VERSION_TINY 28
#endif //AVPN_VERSION_TINY

// the format of this version is: MMmmtt
// M = Major version, m = minor version, t = tiny version
#define AVPN_VERSION_NUM ((AVPN_VERSION_MAJOR * 10000) + (AVPN_VERSION_MINOR * 100) + AVPN_VERSION_TINY)
#define AVPN_VERSION "4.1.28"

#ifndef AVPN_GIT_REVISION
#define AVPN_GIT_REVISION "Git-6a583cd"
#endif

#define AVPN_VERSION_MIME "AVPN/" AVPN_VERSION "(" AVPN_GIT_REVISION ")"
