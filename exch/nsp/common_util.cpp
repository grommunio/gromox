// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iconv.h>
#include <unistd.h>
#include <libHX/endian.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"

using namespace gromox;

static constexpr unsigned int SR_GROW_NSP_PROPROW = 40, SR_GROW_NSP_ROWSET = 100;
static GUID g_server_guid;
decltype(get_named_propids) get_named_propids;
decltype(get_store_properties) get_store_properties;

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
	tmp_time = mktime(&tmp_tm); //mktime can return -1
	
	if (tmp_time == -1) {
		pftime->low_datetime = 0;
		pftime->high_datetime = 0;
		return;
	}
	
	file_time = ((uint64_t)tmp_time + EPOCH_DIFF) * 10000000;
	pftime->low_datetime = file_time & 0xFFFFFFFF;
	pftime->high_datetime = file_time >> 32;
}

int cu_utf8_to_mb(cpid_t codepage, const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	
	auto charset = cpid_to_cset(codepage);
	if (charset == nullptr)
		return -1;
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

int cu_mb_to_utf8(cpid_t codepage, const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	
	cpid_cstr_compatible(codepage);
	auto charset = cpid_to_cset(codepage);
	if (charset == nullptr)
		return -1;
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
	cpu_to_le32p(&pbin->pb[0], pguid->time_low);
	cpu_to_le16p(&pbin->pb[4], pguid->time_mid);
	cpu_to_le16p(&pbin->pb[6], pguid->time_hi_and_version);
	memcpy(pbin->pb + 8,  pguid->clock_seq, sizeof(uint8_t) * 2);
	memcpy(pbin->pb + 10, pguid->node, sizeof(uint8_t) * 6);
}

void common_util_set_ephemeralentryid(uint32_t display_type,
	uint32_t minid, EPHEMERAL_ENTRYID *pephid)
{
	pephid->flags = ENTRYID_TYPE_EPHEMERAL;
	pephid->display_type = display_type;
	pephid->mid = minid;
}

BOOL common_util_set_permanententryid(unsigned int display_type,
    const GUID *pobj_guid, const char *pdn, EMSAB_ENTRYID *ppermeid)
{
	int len;
	char buff[128];
	
	ppermeid->flags = ENTRYID_TYPE_PERMANENT;
	ppermeid->type = display_type;
	ppermeid->px500dn = nullptr;
	if (DT_CONTAINER == display_type) {
		if (NULL == pobj_guid) {
			ppermeid->px500dn = deconst("/");
		} else {
			memcpy(buff, "/guid=", 6);
			pobj_guid->to_str(&buff[6], 32);
			buff[38] = '\0';
			len = 38;
			ppermeid->px500dn = ndr_stack_anew<char>(NDR_STACK_OUT, len + 1);
			if (ppermeid->px500dn == nullptr)
				return FALSE;
			memcpy(ppermeid->px500dn, buff, len + 1);
		}
	}  else {
		len = strlen(pdn);
		ppermeid->px500dn = ndr_stack_anew<char>(NDR_STACK_OUT, len + 1);
		if (ppermeid->px500dn == nullptr)
			return FALSE;
		memcpy(ppermeid->px500dn, pdn, len + 1);
	}
	return TRUE;
}

BOOL common_util_permanent_entryid_to_binary(const EMSAB_ENTRYID *ppermeid, BINARY *pbin)
{
	size_t len = strlen(ppermeid->px500dn) + 1;
	pbin->cb = 28 + len;
	pbin->pv = ndr_stack_alloc(NDR_STACK_OUT, pbin->cb);
	if (pbin->pv == nullptr)
		return FALSE;
	memset(pbin->pb, 0, pbin->cb);
	if (ppermeid->flags != ENTRYID_TYPE_PERMANENT)
		mlog(LV_WARN, "W-2040: %s: conversion of a non-permanent entryid attempted", __func__);
	cpu_to_le32p(&pbin->pb[0], ppermeid->flags);
	FLATUID guid = muidEMSAB;
	memcpy(&pbin->pb[4], guid.ab, 16);
	cpu_to_le32p(&pbin->pb[20], 1);
	cpu_to_le32p(&pbin->pb[24], ppermeid->type);
	memcpy(&pbin->pb[28], ppermeid->px500dn, len);
	return TRUE;
}

BOOL common_util_ephemeral_entryid_to_binary(
	const EPHEMERAL_ENTRYID *pephid, BINARY *pbin)
{
	pbin->cb = 32;
	pbin->pv = ndr_stack_alloc(NDR_STACK_OUT, pbin->cb);
	if (pbin->pv == nullptr)
		return FALSE;
	memset(pbin->pb, 0, pbin->cb);
	if (pephid->flags != ENTRYID_TYPE_EPHEMERAL)
		mlog(LV_WARN, "W-2041: %s: conversion of a non-permanent entryid attempted", __func__);
	cpu_to_le32p(&pbin->pb[0], pephid->flags);
	FLATUID f = g_server_guid;
	memcpy(&pbin->pb[4], &f, 16);
	cpu_to_le32p(&pbin->pb[20], 1);
	cpu_to_le32p(&pbin->pb[24], pephid->display_type);
	cpu_to_le32p(&pbin->pb[28], pephid->mid);
	return TRUE;
}

NSP_ROWSET* common_util_proprowset_init()
{
	auto pset = ndr_stack_anew<NSP_ROWSET>(NDR_STACK_OUT);
	if (pset == nullptr)
		return NULL;
	memset(pset, 0, sizeof(NSP_ROWSET));
	auto count = strange_roundup(pset->crows, SR_GROW_NSP_ROWSET);
	pset->prows = ndr_stack_anew<NSP_PROPROW>(NDR_STACK_OUT, count);
	if (pset->prows == nullptr)
		return NULL;
	return pset;
}

NSP_PROPROW* common_util_proprowset_enlarge(NSP_ROWSET *pset)
{
	NSP_PROPROW *prows;
	auto count = strange_roundup(pset->crows, SR_GROW_NSP_ROWSET);
	if (pset->crows + 1 >= count) {
		count += SR_GROW_NSP_ROWSET;
		prows = ndr_stack_anew<NSP_PROPROW>(NDR_STACK_OUT, count);
		if (prows == nullptr)
			return NULL;
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
		if (prow == nullptr)
			return NULL;
	}
	memset(prow, 0, sizeof(NSP_PROPROW));
	auto count = strange_roundup(prow->cvalues, SR_GROW_NSP_PROPROW);
	prow->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, count);
	if (prow->pprops == nullptr)
		return NULL;
	return prow;
}

PROPERTY_VALUE* common_util_propertyrow_enlarge(NSP_PROPROW *prow)
{
	PROPERTY_VALUE *pprops;
	auto count = strange_roundup(prow->cvalues, SR_GROW_NSP_PROPROW);
	if (prow->cvalues + 1 >= count) {
		count += SR_GROW_NSP_PROPROW;
		pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, count);
		if (pprops == nullptr)
			return NULL;
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
	if (pproptags == nullptr)
		return NULL;
	memset(pproptags, 0, sizeof(LPROPTAG_ARRAY));
	auto count = strange_roundup(pproptags->cvalues, SR_GROW_PROPTAG_ARRAY);
	pproptags->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, count);
	if (pproptags->pproptag == nullptr)
		return NULL;
	return pproptags;
}

uint32_t* common_util_proptagarray_enlarge(LPROPTAG_ARRAY *pproptags)
{
	uint32_t *pproptag;
	auto count = strange_roundup(pproptags->cvalues, SR_GROW_PROPTAG_ARRAY);
	if (pproptags->cvalues + 1 >= count) {
		count += SR_GROW_PROPTAG_ARRAY;
		pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, count);
		if (pproptag == nullptr)
			return NULL;
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
	/*
	 * Work around odd behavior of gcc-12 in conjunction with -std=c++20
	 * and call a.op==(b) instead of a==b.
	 */
	if (g_server_guid.operator==(muidEMSAB))
		g_server_guid = GUID::random_new();
	if (g_server_guid.operator==(muidEMSAB)) {
		mlog(LV_ERR, "nsp: unlucky random number generator");
		return -1;
	}
	return 0;
}
