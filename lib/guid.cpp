// SPDX-License-Identifier: GPL-3.0-or-later
// samba commit 6c9a185be260a914bc0bd2dcf76c9dcb9664a687 or earlier
/*
   Unix SMB/CIFS implementation.

   UUID/GUID functions

   Copyright (C) Theodore Ts'o               1996, 1997,
   Copyright (C) Jim McDonough                     2002.
   Copyright (C) Andrew Tridgell                   2003.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "config.h"
#include <gromox/guid.hpp>
#include <gromox/util.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <cstdio>

int guid_compare(const GUID *u1, const GUID *u2)
{
	if (u1->time_low != u2->time_low) {
		return u1->time_low > u2->time_low ? 1 : -1;
	}

	if (u1->time_mid != u2->time_mid) {
		return u1->time_mid > u2->time_mid ? 1 : -1;
	}

	if (u1->time_hi_and_version != u2->time_hi_and_version) {
		return u1->time_hi_and_version > u2->time_hi_and_version ? 1 : -1;
	}

	if (u1->clock_seq[0] != u2->clock_seq[0]) {
		return u1->clock_seq[0] > u2->clock_seq[0] ? 1 : -1;
	}

	if (u1->clock_seq[1] != u2->clock_seq[1]) {
		return u1->clock_seq[1] > u2->clock_seq[1] ? 1 : -1;
	}

	return memcmp(u1->node, u2->node, 6);
}

BOOL guid_from_string(GUID *guid, const char *guid_string)
{
	int length;
	uint32_t tmp_vals[11];
	
	length = strlen(guid_string);
	if (36 == length) {
		if (11 == sscanf(guid_string,
			"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			&tmp_vals[0], &tmp_vals[1], &tmp_vals[2], &tmp_vals[3],
			&tmp_vals[4], &tmp_vals[5], &tmp_vals[6], &tmp_vals[7],
			&tmp_vals[8], &tmp_vals[9], &tmp_vals[10])) {
			guid->time_low = tmp_vals[0];
			guid->time_mid = tmp_vals[1];
			guid->time_hi_and_version = tmp_vals[2];
			guid->clock_seq[0] = tmp_vals[3];
			guid->clock_seq[1] = tmp_vals[4];
			guid->node[0] = tmp_vals[5];
			guid->node[1] = tmp_vals[6];
			guid->node[2] = tmp_vals[7];
			guid->node[3] = tmp_vals[8];
			guid->node[4] = tmp_vals[9];
			guid->node[5] = tmp_vals[10];
			return TRUE;
		}
	} else if (38 == length) {
		if (11 == sscanf(guid_string, 
			"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
			&tmp_vals[0], &tmp_vals[1], &tmp_vals[2], &tmp_vals[3],
			&tmp_vals[4], &tmp_vals[5], &tmp_vals[6], &tmp_vals[7],
			&tmp_vals[8], &tmp_vals[9], &tmp_vals[10])) {
			guid->time_low = tmp_vals[0];
			guid->time_mid = tmp_vals[1];
			guid->time_hi_and_version = tmp_vals[2];
			guid->clock_seq[0] = tmp_vals[3];
			guid->clock_seq[1] = tmp_vals[4];
			guid->node[0] = tmp_vals[5];
			guid->node[1] = tmp_vals[6];
			guid->node[2] = tmp_vals[7];
			guid->node[3] = tmp_vals[8];
			guid->node[4] = tmp_vals[9];
			guid->node[5] = tmp_vals[10];
			return TRUE;
		}
	}
	return FALSE;
}
