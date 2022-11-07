// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iconv.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include <gromox/zz_ndr_stack.hpp>
#include "common_util.h"

using namespace gromox;

static constexpr unsigned int SR_GROW_NSP_PROPROW = 40, SR_GROW_NSP_ROWSET = 100;
static GUID g_server_guid;

GUID common_util_get_server_guid()
{
	return g_server_guid;
}

void common_util_day_to_filetime(const char *day, FILETIME *pftime)
{
	time_t tmp_time;
	struct tm tmp_tm;
	uint64_t file_time;
	
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	strptime(day, "%Y-%m-%d", &tmp_tm);
	tmp_time = mktime(&tmp_tm);
	file_time = ((uint64_t)tmp_time + EPOCH_DIFF)*10000000;
	pftime->low_datetime = file_time & 0xFFFFFFFF;
	pftime->high_datetime = file_time >> 32;
}

int common_util_from_utf8(uint32_t codepage,
	const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	
	auto charset = cpid_to_cset(codepage);
	if (NULL == charset) {
		return -1;
	}
	conv_id = iconv_open(charset, "UTF-8");
	if (conv_id == (iconv_t)-1)
		return -1;
	auto pin = deconst(src);
	auto pout = dst;
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	if (iconv(conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return -1;
	} else {
		iconv_close(conv_id);
		return out_len - len;
	}
}

int common_util_to_utf8(uint32_t codepage,
	const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	
	cpid_cstr_compatible(codepage);
	auto charset = cpid_to_cset(codepage);
	if (NULL == charset) {
		return -1;
	}
	conv_id = iconv_open("UTF-8", charset);
	if (conv_id == (iconv_t)-1)
		return -1;
	auto pin = deconst(src);
	auto pout = dst;
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	if (iconv(conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return -1;
	} else {
		iconv_close(conv_id);
		return out_len - len;
	}
}

void common_util_guid_to_binary(GUID *pguid, BINARY *pbin)
{
	pbin->cb = 16;
	pbin->pb[0] = pguid->time_low & 0XFF;
	pbin->pb[1] = (pguid->time_low >> 8) & 0XFF;
	pbin->pb[2] = (pguid->time_low >> 16) & 0XFF;
	pbin->pb[3] = (pguid->time_low >> 24) & 0XFF;
	pbin->pb[4] = pguid->time_mid & 0XFF;
	pbin->pb[5] = (pguid->time_mid >> 8) & 0XFF;
	pbin->pb[6] = pguid->time_hi_and_version & 0XFF;
	pbin->pb[7] = (pguid->time_hi_and_version >> 8) & 0XFF;
	memcpy(pbin->pb + 8,  pguid->clock_seq, sizeof(uint8_t) * 2);
	memcpy(pbin->pb + 10, pguid->node, sizeof(uint8_t) * 6);
}

void common_util_set_ephemeralentryid(uint32_t display_type,
	uint32_t minid, EPHEMERAL_ENTRYID *pephid)
{
	pephid->id_type = ENTRYID_TYPE_EPHEMERAL;
	pephid->r1 = 0x0;
	pephid->r2 = 0x0;
	pephid->r3 = 0x0;
	pephid->provider_uid.ab[0] =
		g_server_guid.time_low & 0XFF;
	pephid->provider_uid.ab[1] =
		(g_server_guid.time_low >> 8) & 0XFF;
	pephid->provider_uid.ab[2] =
		(g_server_guid.time_low >> 16) & 0XFF;
	pephid->provider_uid.ab[3] =
		(g_server_guid.time_low >> 24) & 0XFF;
	pephid->provider_uid.ab[4] =
		g_server_guid.time_mid & 0XFF;
	pephid->provider_uid.ab[5] =
		(g_server_guid.time_mid >> 8) & 0XFF;
	pephid->provider_uid.ab[6] =
		g_server_guid.time_hi_and_version & 0XFF;
	pephid->provider_uid.ab[7] =
		(g_server_guid.time_hi_and_version >> 8) & 0XFF;
	memcpy(pephid->provider_uid.ab + 8, 
		g_server_guid.clock_seq, sizeof(uint8_t) * 2);
	memcpy(pephid->provider_uid.ab + 10,
		g_server_guid.node, sizeof(uint8_t) * 6);
	pephid->r4 = 0x1;
	pephid->display_type = display_type;
	pephid->mid = minid;
}

BOOL common_util_set_permanententryid(uint32_t display_type,
	const GUID *pobj_guid, const char *pdn, PERMANENT_ENTRYID *ppermeid)
{
	int len;
	char buff[128];
	
	ppermeid->id_type = ENTRYID_TYPE_PERMANENT;
	ppermeid->r1 = 0x0;
	ppermeid->r2 = 0x0;
	ppermeid->r3 = 0x0;
	ppermeid->provider_uid = muidEMSAB;
	ppermeid->r4 = 0x1;
	ppermeid->display_type = display_type;
	ppermeid->pdn = NULL;
	if (DT_CONTAINER == display_type) {
		if (NULL == pobj_guid) {
			ppermeid->pdn = deconst("/");
		} else {
			len = gx_snprintf(buff, arsizeof(buff),
				"/guid=%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
				pobj_guid->time_low, pobj_guid->time_mid,
				pobj_guid->time_hi_and_version,
				pobj_guid->clock_seq[0],
				pobj_guid->clock_seq[1],
				pobj_guid->node[0], pobj_guid->node[1],
				pobj_guid->node[2], pobj_guid->node[3],
				pobj_guid->node[4], pobj_guid->node[5]);
			ppermeid->pdn = ndr_stack_anew<char>(NDR_STACK_OUT, len + 1);
			if (NULL == ppermeid->pdn) {
				return FALSE;
			}
			memcpy(ppermeid->pdn, buff, len + 1);
		}
	}  else {
		len = strlen(pdn);
		ppermeid->pdn = ndr_stack_anew<char>(NDR_STACK_OUT, len + 1);
		if (NULL == ppermeid->pdn) {
			return FALSE;
		}
		memcpy(ppermeid->pdn, pdn, len + 1);
	}
	return TRUE;
}

BOOL common_util_permanent_entryid_to_binary(
	const PERMANENT_ENTRYID *ppermeid, BINARY *pbin)
{
	int len;
	
	len = strlen(ppermeid->pdn) + 1;
	pbin->cb = 28 + len;
	pbin->pv = ndr_stack_alloc(NDR_STACK_OUT, pbin->cb);
	if (pbin->pv == nullptr)
		return FALSE;
	memset(pbin->pb, 0, pbin->cb);
	if (ppermeid->id_type != ENTRYID_TYPE_PERMANENT)
		mlog(LV_WARN, "W-2040: %s: conversion of a non-permanent entryid attempted", __func__);
	pbin->pb[0] = ppermeid->id_type;
	pbin->pb[1] = ppermeid->r1;
	pbin->pb[2] = ppermeid->r2;
	pbin->pb[3] = ppermeid->r3;
	memcpy(pbin->pb + 4, ppermeid->provider_uid.ab, 16);
	pbin->pb[20] = (ppermeid->r4 & 0xFF);
	pbin->pb[21] = ((ppermeid->r4 >> 8)  & 0xFF);
	pbin->pb[22] = ((ppermeid->r4 >> 16) & 0xFF);
	pbin->pb[23] = ((ppermeid->r4 >> 24) & 0xFF);
	pbin->pb[24] = (ppermeid->display_type & 0xFF);
	pbin->pb[25] = ((ppermeid->display_type >> 8)  & 0xFF);
	pbin->pb[26] = ((ppermeid->display_type >> 16) & 0xFF);
	pbin->pb[27] = ((ppermeid->display_type >> 24) & 0xFF);
	memcpy(pbin->pb + 28, ppermeid->pdn, len);
	return TRUE;
}

BOOL common_util_ephemeral_entryid_to_binary(
	const EPHEMERAL_ENTRYID *pephid, BINARY *pbin)
{
	pbin->cb = sizeof(EPHEMERAL_ENTRYID);
	pbin->pv = ndr_stack_alloc(NDR_STACK_OUT, pbin->cb);
	if (pbin->pv == nullptr)
		return FALSE;
	memset(pbin->pb, 0, pbin->cb);
	if (pephid->id_type != ENTRYID_TYPE_EPHEMERAL)
		mlog(LV_WARN, "W-2041: %s: conversion of a non-permanent entryid attempted", __func__);
	pbin->pb[0] = pephid->id_type;
	pbin->pb[1] = pephid->r1;
	pbin->pb[2] = pephid->r2;
	pbin->pb[3] = pephid->r3;
	memcpy(pbin->pb + 4, pephid->provider_uid.ab, 16);
	pbin->pb[20] = pephid->r4 & 0xFF;
	pbin->pb[21] = (pephid->r4 >> 8)  & 0xFF;
	pbin->pb[22] = (pephid->r4 >> 16) & 0xFF;
	pbin->pb[23] = (pephid->r4 >> 24) & 0xFF;
	pbin->pb[24] = pephid->display_type & 0xFF;
	pbin->pb[25] = (pephid->display_type >> 8)  & 0xFF;
	pbin->pb[26] = (pephid->display_type >> 16) & 0xFF;
	pbin->pb[27] = (pephid->display_type >> 24) & 0xFF;
	pbin->pb[28] = pephid->mid & 0xFF;
	pbin->pb[29] = (pephid->mid >> 8)  & 0xFF;
	pbin->pb[30] = (pephid->mid >> 16) & 0xFF;
	pbin->pb[31] = (pephid->mid >> 24) & 0xFF;
	return TRUE;
}

NSP_ROWSET* common_util_proprowset_init()
{
	auto pset = ndr_stack_anew<NSP_ROWSET>(NDR_STACK_OUT);
	if (NULL == pset) {
		return NULL;
	}
	memset(pset, 0, sizeof(NSP_ROWSET));
	auto count = strange_roundup(pset->crows, SR_GROW_NSP_ROWSET);
	pset->prows = ndr_stack_anew<NSP_PROPROW>(NDR_STACK_OUT, count);
	if (NULL == pset->prows) {
		return NULL;
	}
	return pset;
}

NSP_PROPROW* common_util_proprowset_enlarge(NSP_ROWSET *pset)
{
	NSP_PROPROW *prows;
	auto count = strange_roundup(pset->crows, SR_GROW_NSP_ROWSET);
	if (pset->crows + 1 >= count) {
		count += SR_GROW_NSP_ROWSET;
		prows = ndr_stack_anew<NSP_PROPROW>(NDR_STACK_OUT, count);
		if (NULL == prows) {
			return NULL;
		}
		memcpy(prows, pset->prows, sizeof(NSP_PROPROW)*pset->crows);
		pset->prows = prows;
	}
	pset->crows ++;
	return &pset->prows[pset->crows - 1]; 
}

NSP_PROPROW* common_util_propertyrow_init(NSP_PROPROW *prow)
{
	if (NULL == prow) {
		prow = ndr_stack_anew<NSP_PROPROW>(NDR_STACK_OUT);
		if (NULL == prow) {
			return NULL;
		}
	}
	memset(prow, 0, sizeof(NSP_PROPROW));
	auto count = strange_roundup(prow->cvalues, SR_GROW_NSP_PROPROW);
	prow->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, count);
	if (NULL == prow->pprops) {
		return NULL;
	}
	return prow;
}

PROPERTY_VALUE* common_util_propertyrow_enlarge(NSP_PROPROW *prow)
{
	PROPERTY_VALUE *pprops;
	auto count = strange_roundup(prow->cvalues, SR_GROW_NSP_PROPROW);
	if (prow->cvalues + 1 >= count) {
		count += SR_GROW_NSP_PROPROW;
		pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, count);
		if (NULL == pprops) {
			return NULL;
		}
		memcpy(pprops, prow->pprops,
			sizeof(PROPERTY_VALUE)*prow->cvalues);
		prow->pprops = pprops;
	}
	prow->cvalues ++;
	return &prow->pprops[prow->cvalues - 1]; 
}

LPROPTAG_ARRAY* common_util_proptagarray_init()
{
	auto pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_OUT);
	if (NULL == pproptags) {
		return NULL;
	}
	memset(pproptags, 0, sizeof(LPROPTAG_ARRAY));
	auto count = strange_roundup(pproptags->cvalues, SR_GROW_PROPTAG_ARRAY);
	pproptags->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, count);
	if (NULL == pproptags->pproptag) {
		return NULL;
	}
	return pproptags;
}

uint32_t* common_util_proptagarray_enlarge(LPROPTAG_ARRAY *pproptags)
{
	uint32_t *pproptag;
	auto count = strange_roundup(pproptags->cvalues, SR_GROW_PROPTAG_ARRAY);
	if (pproptags->cvalues + 1 >= count) {
		count += SR_GROW_PROPTAG_ARRAY;
		pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, count);
		if (NULL == pproptag) {
			return NULL;
		}
		memcpy(pproptag, pproptags->pproptag,
			sizeof(uint32_t)*pproptags->cvalues);
		pproptags->pproptag = pproptag;
	}
	pproptags->cvalues ++;
	return &pproptags->pproptag[pproptags->cvalues - 1]; 
}

BOOL common_util_load_file(const char *path, BINARY *pbin)
{
	struct stat node_state;
	wrapfd fd = open(path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_state) != 0)
		return FALSE;
	pbin->cb = node_state.st_size;
	pbin->pv = ndr_stack_alloc(NDR_STACK_OUT, node_state.st_size);
	if (pbin->pv == nullptr)
		return FALSE;
	if (read(fd.get(), pbin->pv, node_state.st_size) != node_state.st_size)
		return FALSE;
	return TRUE;
}

int common_util_run()
{
	g_server_guid = GUID::random_new();
	return 0;
}
