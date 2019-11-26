#include "pcl.h"
#include "guid.h"
#include "rop_util.h"
#include "endian_macro.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


#define TIME_FIXUP_CONSTANT_INT				11644473600LL

static uint8_t rop_util_is_little_endian()
{
	int x;
	char *py;
	
	x = 1;
	py = (char*)&x;
	return *py;
}

uint16_t rop_util_get_replid(uint64_t eid)
{
	return eid & 0xFFFF;
}

uint64_t rop_util_get_gc_value(uint64_t eid)
{
	uint64_t value;
	
	if (rop_util_is_little_endian()) {
		((uint8_t*)&value)[0] = ((uint8_t*)&eid)[7];
		((uint8_t*)&value)[1] = ((uint8_t*)&eid)[6];
		((uint8_t*)&value)[2] = ((uint8_t*)&eid)[5];
		((uint8_t*)&value)[3] = ((uint8_t*)&eid)[4];
		((uint8_t*)&value)[4] = ((uint8_t*)&eid)[3];
		((uint8_t*)&value)[5] = ((uint8_t*)&eid)[2];
		((uint8_t*)&value)[6] = 0;
		((uint8_t*)&value)[7] = 0;
	} else {
		value = eid >> 16;
	}
	return value;
}

void rop_util_get_gc_array(uint64_t eid, uint8_t gc[6])
{
	if (rop_util_is_little_endian()) {
		memcpy(gc, (uint8_t*)&eid + 2, 6);
	} else {
		memcpy(gc, &eid, 6);
	}
}

void rop_util_value_to_gc(uint64_t value, uint8_t gc[6])
{
	if (rop_util_is_little_endian()) {
		gc[5] = ((uint8_t*)&value)[0];
		gc[4] = ((uint8_t*)&value)[1];
		gc[3] = ((uint8_t*)&value)[2];
		gc[2] = ((uint8_t*)&value)[3];
		gc[1] = ((uint8_t*)&value)[4];
		gc[0] = ((uint8_t*)&value)[5];
	} else {
		memcpy(gc, (uint8_t*)&value + 2, 6);
	}
}

uint64_t rop_util_gc_to_value(uint8_t gc[6])
{
	uint64_t value;
	
	if (rop_util_is_little_endian()) {
		((uint8_t*)&value)[0] = gc[5];
		((uint8_t*)&value)[1] = gc[4];
		((uint8_t*)&value)[2] = gc[3];
		((uint8_t*)&value)[3] = gc[2];
		((uint8_t*)&value)[4] = gc[1];
		((uint8_t*)&value)[5] = gc[0];
		((uint8_t*)&value)[6] = 0;
		((uint8_t*)&value)[7] = 0;
	} else {
		((uint8_t*)&value)[0] = 0;
		((uint8_t*)&value)[1] = 0;
		memcpy((uint8_t*)&value + 2, gc, 6);
	}
	return value;
	
}

uint64_t rop_util_make_eid(uint16_t replid, const uint8_t gc[6])
{
	uint64_t eid;
	
	if (rop_util_is_little_endian()) {
		((uint8_t*)&eid)[0] = 0;
		((uint8_t*)&eid)[1] = 0;
		memcpy((uint8_t*)&eid + 2, gc, 6);
	} else {
		memcpy(&eid, gc, 6);
		((uint8_t*)&eid)[6] = 0;
		((uint8_t*)&eid)[7] = 0;
	}
	return (eid | replid);
}

uint64_t rop_util_make_eid_ex(uint16_t replid, uint64_t value)
{
	uint8_t gc[6];
	
	rop_util_value_to_gc(value, gc);
	return rop_util_make_eid(replid, gc);
}

GUID rop_util_make_user_guid(int user_id)
{
	GUID guid;
	
	guid.time_low = user_id;
	guid.time_mid = 0x18a5;
	guid.time_hi_and_version = 0x6f7b;
	guid.clock_seq[0] = 0xbc;
	guid.clock_seq[1] = 0xdc;
	guid.node[0] = 0xea;
	guid.node[1] = 0x1e;
	guid.node[2] = 0xd0;
	guid.node[3] = 0x3c;
	guid.node[4] = 0x56;
	guid.node[5] = 0x57;
	return guid;
}

GUID rop_util_make_domain_guid(int domain_id)
{
	GUID guid;
	
	guid.time_low = domain_id;
	guid.time_mid = 0x0afb;
	guid.time_hi_and_version = 0x7df6;
	guid.clock_seq[0] = 0x91;
	guid.clock_seq[1] = 0x92;
	guid.node[0] = 0x49;
	guid.node[1] = 0x88;
	guid.node[2] = 0x6a;
	guid.node[3] = 0xa7;
	guid.node[4] = 0x38;
	guid.node[5] = 0xce;
	return guid;
}

int rop_util_make_user_id(GUID guid)
{
	if (guid.time_mid != 0x18a5 ||
		guid.time_hi_and_version != 0x6f7b ||
		guid.clock_seq[0] != 0xbc ||
		guid.clock_seq[1] != 0xdc ||
		guid.node[0] != 0xea ||
		guid.node[1] != 0x1e ||
		guid.node[2] != 0xd0 ||
		guid.node[3] != 0x3c ||
		guid.node[4] != 0x56 ||
		guid.node[5] != 0x57) {
		return -1;
	}
	return guid.time_low;
}

int rop_util_make_domain_id(GUID guid)
{
	if (guid.time_mid != 0x0afb ||
		guid.time_hi_and_version != 0x7df6 ||
		guid.clock_seq[0] != 0x91 ||
		guid.clock_seq[1] != 0x92 ||
		guid.node[0] != 0x49 ||
		guid.node[1] != 0x88 ||
		guid.node[2] != 0x6a ||
		guid.node[3] != 0xa7 ||
		guid.node[4] != 0x38 ||
		guid.node[5] != 0xce) {
		return -1;
	}
	return guid.time_low;
}

uint64_t rop_util_unix_to_nttime(time_t unix_time)
{
	uint64_t nt_time; 
	
	nt_time = unix_time;
	nt_time += TIME_FIXUP_CONSTANT_INT;
	nt_time *= 10000000;
	return nt_time;
}

time_t rop_util_nttime_to_unix(uint64_t nt_time)
{
	uint64_t unix_time;
	
	unix_time = nt_time;
	unix_time /= 10000000;
	unix_time -= TIME_FIXUP_CONSTANT_INT;
	return (time_t)unix_time;
}

uint64_t rop_util_current_nttime()
{
	struct timeval tvl;
	
	gettimeofday(&tvl, NULL);
	return rop_util_unix_to_nttime(tvl.tv_sec) + tvl.tv_usec*10;
}

GUID rop_util_binary_to_guid(const BINARY *pbin)
{
	GUID guid;
	uint32_t offset;
	
	offset = 0;
	guid.time_low = IVAL(pbin->pb, offset);
	offset += sizeof(uint32_t);
	guid.time_mid = SVAL(pbin->pb, offset);
	offset += sizeof(uint16_t);
	guid.time_hi_and_version = SVAL(pbin->pb, offset);
	offset += sizeof(uint16_t);
	memcpy(guid.clock_seq, pbin->pb + offset, 2);
	offset += 2;
	memcpy(guid.node, pbin->pb + offset, 6);
	return guid;
}

void rop_util_guid_to_binary(GUID guid, BINARY *pbin)
{
	SIVAL(pbin->pb, pbin->cb, guid.time_low);
	pbin->cb += sizeof(uint32_t);
	SSVAL(pbin->pb, pbin->cb, guid.time_mid);
	pbin->cb += sizeof(uint16_t);
	SSVAL(pbin->pb, pbin->cb, guid.time_hi_and_version);
	pbin->cb += sizeof(uint16_t);
	memcpy(pbin->pb + pbin->cb, guid.clock_seq, 2);
	pbin->cb += 2;
	memcpy(pbin->pb + pbin->cb, guid.node, 6);
	pbin->cb += 6;
}

BOOL rop_util_get_common_pset(int pset_type, GUID *pguid)
{
	static GUID guids[17];
	static BOOL b_pasred = FALSE;
	
	if (FALSE == b_pasred) {
		guid_from_string(&guids[0], "00020329-0000-0000-c000-000000000046");
		guid_from_string(&guids[1], "00062008-0000-0000-C000-000000000046");
		guid_from_string(&guids[2], "00062004-0000-0000-C000-000000000046");
		guid_from_string(&guids[3], "00020386-0000-0000-c000-000000000046");
		guid_from_string(&guids[4], "00062002-0000-0000-C000-000000000046");
		guid_from_string(&guids[5], "6ED8DA90-450B-101B-98DA-00AA003F1305");
		guid_from_string(&guids[6], "0006200A-0000-0000-C000-000000000046");
		guid_from_string(&guids[7], "41F28F13-83F4-4114-A584-EEDB5A6B0BFF");
		guid_from_string(&guids[8], "0006200E-0000-0000-C000-000000000046");
		guid_from_string(&guids[9], "00062041-0000-0000-C000-000000000046");
		guid_from_string(&guids[10], "00062003-0000-0000-C000-000000000046");
		guid_from_string(&guids[11], "4442858E-A9E3-4E80-B900-317A210CC15B");
		guid_from_string(&guids[12], "71035549-0739-4DCB-9163-00F0580DBBDF");
		guid_from_string(&guids[13], "00062040-0000-0000-C000-000000000046");
		guid_from_string(&guids[14], "23239608-685D-4732-9C55-4C95CB4E8E33");
		guid_from_string(&guids[15], "00020328-0000-0000-c000-000000000046");
		guid_from_string(&guids[16], "96357F7F-59E1-47D0-99A7-46515C183B54");
		b_pasred = TRUE;
	}
	if (pset_type < 0 || pset_type > 17) {
		return FALSE;
	}
	*pguid = guids[pset_type - 1];
	return TRUE;
}

BOOL rop_util_get_provider_uid(int provider_type, uint8_t *pflat_guid)
{
	static uint8_t store_entry_guid[] = {
		0x38, 0xA1, 0xBB, 0x10, 0x05, 0xE5, 0x10, 0x1A,
		0xA1, 0xBB, 0x08, 0x00, 0x2B, 0x2A, 0x56, 0xC2};
	static uint8_t wrapped_private_guid[] = {
		0x1B, 0x55, 0xFA, 0x20, 0xAA, 0x66, 0x11, 0xCD,
		0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
	static uint8_t wrapped_public_guid[] = {
		0x1C, 0x83, 0x02, 0x10, 0xAA, 0x66, 0x11, 0xCD,
		0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
	static uint8_t ab_entry_guid[] = {
		0xDC, 0xA7, 0x40, 0xC8, 0xC0, 0x42, 0x10, 0x1A,
		0xB4, 0xB9, 0x08, 0x00, 0x2B, 0x2F, 0xE1, 0x82};
	static uint8_t public_provider[] = {
		0x1A, 0x44, 0x73, 0x90, 0xAA, 0x66, 0x11, 0xCD,
		0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
	static uint8_t oneoff_guid[] ={
		0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19,
		0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54, 0x02}; 
	
	switch (provider_type) {
	case PROVIDER_UID_ADDRESS_BOOK:
		memcpy(pflat_guid, ab_entry_guid, 16);
		return TRUE;
	case PROVIDER_UID_PUBLIC:
		memcpy(pflat_guid, public_provider, 16);
		return TRUE;
	case PROVIDER_UID_ONE_OFF:
		memcpy(pflat_guid, oneoff_guid, 16);
		return TRUE;
	case PROVIDER_UID_STORE:
		memcpy(pflat_guid, store_entry_guid, 16);
		return TRUE;
	case PROVIDER_UID_WRAPPED_PRIVATE:
		memcpy(pflat_guid, wrapped_private_guid, 16);
		return TRUE;
	case PROVIDER_UID_WRAPPED_PUBLIC:
		memcpy(pflat_guid, wrapped_public_guid, 16);
		return TRUE;
	default:
		return FALSE;
	}
}

void rop_util_free_binary(BINARY *pbin)
{
	free(pbin->pb);
	free(pbin);
}
