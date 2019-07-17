#include "guid.h"
#include "util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>


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

void guid_to_string(const GUID *guid, char *buff, int buflen)
{
	snprintf(buff, buflen, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid->time_low, guid->time_mid,
		guid->time_hi_and_version,
		guid->clock_seq[0],
		guid->clock_seq[1],
		guid->node[0], guid->node[1],
		guid->node[2], guid->node[3],
		guid->node[4], guid->node[5]);
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

GUID guid_random_new(void)
{
	GUID guid;
	int urand_fd;
	
	urand_fd = open("/dev/urandom", O_RDONLY);
	if (-1 == urand_fd) {
		randstring((char*)&guid, sizeof(GUID) - 1);
	} else {
		if (sizeof(GUID) != read(urand_fd, &guid, sizeof(GUID))) {
			randstring((char*)&guid, sizeof(GUID) - 1);
		}
		close(urand_fd);
	}
	guid.clock_seq[0] = (guid.clock_seq[0] & 0x3F) | 0x80;
	guid.time_hi_and_version = (guid.time_hi_and_version & 0x0FFF) | 0x4000;
	return guid;
}
