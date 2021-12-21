// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cstdint>
#include <cstdlib>
#if __linux__ && defined(HAVE_SYS_RANDOM_H)
#	include <sys/random.h>
#endif
#include <gromox/mapidefs.h>
#include <gromox/guid.hpp>

namespace gromox {

GUID guid_random_new()
{
	GUID guid;
#if __linux__ && defined(HAVE_SYS_RANDOM_H)
	if (getrandom(&guid, sizeof(guid), 0) != sizeof(guid)) {
	} else
#endif
	{
		int32_t v[4] = {rand(), rand(), rand(), rand()};
		static_assert(sizeof(v) == sizeof(guid));
		memcpy(&guid, v, sizeof(guid));
	}
	/* RFC 4122 pg 24 */
	guid.clock_seq[0] &= 0x3F;
	guid.clock_seq[0] |= 0x80;
	guid.time_hi_and_version &= 0x0FFF;
	guid.time_hi_and_version |= 4U << 12;
	return guid;
}

}
