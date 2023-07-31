// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstring>
#include <utility>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/propval.hpp>
#include <gromox/safeint.hpp>
#include <gromox/util.hpp>
#include "attachment_object.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "logon_object.h"
#include "message_object.h"
#include "processor_types.h"
#include "rop_funcs.hpp"
#include "rop_processor.h"
#include "stream_object.h"

using namespace gromox;

ec_error_t rop_getpropertyidsfromnames(uint8_t flags,
    const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	BOOL b_create;
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	switch (object_type) {
	case ems_objtype::logon:
	case ems_objtype::folder:
	case ems_objtype::message:
	case ems_objtype::attach:
		break;
	default:
		return ecNotSupported;
	}
	if (flags == MAPI_CREATE)
		b_create = plogon->is_private() &&
		           plogon->logon_mode == logon_mode::guest ? false : TRUE;
	else if (flags == MAPI_READONLY)
		b_create = FALSE;
	else
		return ecInvalidParam;

	if (ppropnames->count == 0 && object_type == ems_objtype::logon) {
		if (!exmdb_client::get_all_named_propids(plogon->get_dir(), ppropids))
			return ecError;
		return ecSuccess;
	}
	if (!plogon->get_named_propids(b_create, ppropnames, ppropids))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_getnamesfrompropertyids(const PROPID_ARRAY *ppropids,
    PROPNAME_ARRAY *ppropnames, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	switch (object_type) {
	case ems_objtype::logon:
	case ems_objtype::folder:
	case ems_objtype::message:
	case ems_objtype::attach:
		if (!plogon->get_named_propnames(ppropids, ppropnames))
			return ecError;
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

static uint16_t size_in_utf16(const char *u8str)
{
	uint32_t len = 0;
	auto ptr = reinterpret_cast<const unsigned char *>(u8str);
	auto clen = strlen(u8str);

	while (*ptr != '\0' && ptr < reinterpret_cast<const unsigned char *>(u8str) + clen) {
		auto byte_num = utf8_byte_num[*ptr];
		if (byte_num == 0) {
			++ptr;
			continue;
		}
		if (byte_num >= 1 && byte_num < 4)
			len += 2;
		else if (byte_num == 4)
			len += 4; /* UTF-16 surrogate pair */
		/* else: iconv emits nothing for broken bytes */
		if (len >= 0x8000)
			break;
		ptr += byte_num;
	}
	return len;
}

/* Caller does not care for an exact count above 0x8000, so always break early. */
static uint32_t propval_size_xfer(uint16_t type, void *val)
{
	if (type == PT_UNICODE)
		return size_in_utf16(static_cast<char *>(val)) + 2;
	else if (type != PT_MV_UNICODE)
		return propval_size(type, val);
	uint32_t len = 0;
	auto sa = static_cast<STRING_ARRAY *>(val);
	for (size_t i = 0; i < sa->count; ++i) {
		len += size_in_utf16(sa->ppstr[i]);
		if (len >= 0x8000)
			break;
	}
	return len;
}

ec_error_t rop_getpropertiesspecific(uint16_t size_limit, uint16_t want_unicode,
    const PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	int i;
	cpid_t cpid;
	ems_objtype object_type;
	uint16_t proptype;
	uint32_t total_size;
	TPROPVAL_ARRAY propvals;
	PROPTAG_ARRAY *ptmp_proptags;
	
	/* we ignore the size_limit as
		mentioned in MS-OXCPRPT 3.2.5.1 */
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	BOOL b_unicode = want_unicode == 0 ? false : TRUE;
	ptmp_proptags = common_util_trim_proptags(pproptags);
	if (NULL == ptmp_proptags) {
		return ecServerOOM;
	}
	switch (object_type) {
	case ems_objtype::logon: {
		if (!static_cast<logon_object *>(pobject)->get_properties(ptmp_proptags, &propvals))
			return ecError;
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (pinfo == nullptr)
			return ecError;
		cpid = pinfo->cpid;
		break;
	}
	case ems_objtype::folder: {
		if (!static_cast<folder_object *>(pobject)->get_properties(ptmp_proptags, &propvals))
			return ecError;
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (pinfo == nullptr)
			return ecError;
		cpid = pinfo->cpid;
		break;
	}
	case ems_objtype::message: {
		auto msg = static_cast<message_object *>(pobject);
		if (!msg->get_properties(0, ptmp_proptags, &propvals))
			return ecError;
		cpid = msg->get_cpid();
		break;
	}
	case ems_objtype::attach: {
		auto atx = static_cast<attachment_object *>(pobject);
		if (!atx->get_properties(0, ptmp_proptags, &propvals))
			return ecError;
		cpid = atx->get_cpid();
		break;
	}
	default:
		return ecNotSupported;
	}
	total_size = 0;
	for (i=0; i<propvals.count; i++) {
		auto tmp_size = propval_size_xfer(PROP_TYPE(propvals.ppropval[i].proptag),
		                propvals.ppropval[i].pvalue);
		if (tmp_size < 0x8000) {
			total_size += tmp_size;
			continue;
		}
		propvals.ppropval[i].proptag = CHANGE_PROP_TYPE(propvals.ppropval[i].proptag, PT_ERROR);
		propvals.ppropval[i].pvalue = cu_alloc<uint32_t>();
		if (NULL == propvals.ppropval[i].pvalue) {
			return ecServerOOM;
		}
		*static_cast<uint32_t *>(propvals.ppropval[i].pvalue) = ecMAPIOOM;
	}
	if (total_size >= 0x7000) {
		for (i=0; i<propvals.count; i++) {
			proptype = PROP_TYPE(propvals.ppropval[i].proptag);
			switch (proptype) {
			case PT_BINARY:
			case PT_OBJECT:
			case PT_STRING8:
			case PT_UNICODE:
				if (propval_size_xfer(proptype, propvals.ppropval[i].pvalue) < 0x1000)
					break;
				propvals.ppropval[i].proptag = CHANGE_PROP_TYPE(propvals.ppropval[i].proptag, PT_ERROR);
				propvals.ppropval[i].pvalue = cu_alloc<uint32_t>();
				if (NULL == propvals.ppropval[i].pvalue) {
					return ecServerOOM;
				}
				*static_cast<uint32_t *>(propvals.ppropval[i].pvalue) = ecMAPIOOM;
				break;
			}
		}
	}
	if (!common_util_propvals_to_row_ex(cpid, b_unicode,
	    &propvals, pproptags, prow))
		return ecServerOOM;
	return ecSuccess;
}

ec_error_t rop_getpropertiesall(uint16_t size_limit, uint16_t want_unicode,
    TPROPVAL_ARRAY *ppropvals, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	cpid_t cpid;
	BOOL b_unicode = false;
	ems_objtype object_type;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY *ptmp_proptags;
	
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (object_type) {
	case ems_objtype::logon: {
		auto xlog = static_cast<logon_object *>(pobject);
		if (!xlog->get_all_proptags(&proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecServerOOM;
		}
		if (!xlog->get_properties(ptmp_proptags, ppropvals))
			return ecError;
		for (i=0; i<ppropvals->count; i++) {
			if (propval_size(PROP_TYPE(ppropvals->ppropval[i].proptag),
			    ppropvals->ppropval[i].pvalue) <= size_limit)
				continue;
			ppropvals->ppropval[i].proptag = CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_ERROR);
			ppropvals->ppropval[i].pvalue = cu_alloc<uint32_t>();
			if (NULL == ppropvals->ppropval[i].pvalue) {
				return ecServerOOM;
			}
			*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) = ecMAPIOOM;
		}
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (pinfo == nullptr)
			return ecError;
		cpid = pinfo->cpid;
		break;
	}
	case ems_objtype::folder: {
		auto fld = static_cast<folder_object *>(pobject);
		if (!fld->get_all_proptags(&proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecServerOOM;
		}
		if (!fld->get_properties(ptmp_proptags, ppropvals))
			return ecError;
		for (i=0; i<ppropvals->count; i++) {
			if (propval_size(PROP_TYPE(ppropvals->ppropval[i].proptag),
			    ppropvals->ppropval[i].pvalue) <= size_limit)
				continue;
			ppropvals->ppropval[i].proptag = CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_ERROR);
			ppropvals->ppropval[i].pvalue = cu_alloc<uint32_t>();
			if (NULL == ppropvals->ppropval[i].pvalue) {
				return ecServerOOM;
			}
			*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) = ecMAPIOOM;
		}
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (pinfo == nullptr)
			return ecError;
		cpid = pinfo->cpid;
		break;
	}
	case ems_objtype::message: {
		auto msg = static_cast<message_object *>(pobject);
		if (!msg->get_all_proptags(&proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecServerOOM;
		}
		if (!msg->get_properties(size_limit, ptmp_proptags, ppropvals))
			return ecError;
		cpid = msg->get_cpid();
		break;
	}
	case ems_objtype::attach: {
		auto atx = static_cast<attachment_object *>(pobject);
		if (!atx->get_all_proptags(&proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecServerOOM;
		}
		if (!atx->get_properties(size_limit, ptmp_proptags, ppropvals))
			return ecError;
		cpid = atx->get_cpid();
		break;
	}
	default:
		return ecNotSupported;
	}
	for (i=0; i<ppropvals->count; i++) {
		if (PROP_TYPE(ppropvals->ppropval[i].proptag) != PT_UNSPECIFIED)
			continue;	
		if (!common_util_convert_unspecified(cpid, b_unicode,
		    static_cast<TYPED_PROPVAL *>(ppropvals->ppropval[i].pvalue)))
			return ecServerOOM;
	}
	return ecSuccess;
}

ec_error_t rop_getpropertieslist(PROPTAG_ARRAY *pproptags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (object_type) {
	case ems_objtype::logon:
		if (!static_cast<logon_object *>(pobject)->get_all_proptags(pproptags))
			return ecError;
		return ecSuccess;
	case ems_objtype::folder:
		if (!static_cast<folder_object *>(pobject)->get_all_proptags(pproptags))
			return ecError;
		return ecSuccess;
	case ems_objtype::message:
		if (!static_cast<message_object *>(pobject)->get_all_proptags(pproptags))
			return ecError;
		return ecSuccess;
	case ems_objtype::attach:
		if (!static_cast<attachment_object *>(pobject)->get_all_proptags(pproptags))
			return ecError;
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

ec_error_t rop_setproperties(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	uint32_t permission;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (object_type) {
	case ems_objtype::logon:
		if (plogon->logon_mode == logon_mode::guest)
			return ecAccessDenied;
		if (!static_cast<logon_object *>(pobject)->set_properties(ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	case ems_objtype::folder: {
		auto fld = static_cast<folder_object *>(pobject);
		auto rpc_info = get_rpc_info();
		if (plogon->logon_mode != logon_mode::owner) {
			if (!exmdb_client::get_folder_perm(plogon->get_dir(),
			    fld->folder_id, rpc_info.username, &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		if (!fld->set_properties(ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	case ems_objtype::message: {
		auto msg = static_cast<message_object *>(pobject);
		auto tag_access = msg->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		if (!msg->set_properties(ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	case ems_objtype::attach: {
		auto atx = static_cast<attachment_object *>(pobject);
		auto tag_access = atx->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		if (!atx->set_properties(ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

ec_error_t rop_setpropertiesnoreplicate(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return rop_setproperties(ppropvals,
		pproblems, plogmap, logon_id, hin);
}

ec_error_t rop_deleteproperties(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	uint32_t permission;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (object_type) {
	case ems_objtype::logon:
		if (plogon->logon_mode == logon_mode::guest)
			return ecAccessDenied;
		if (!static_cast<logon_object *>(pobject)->remove_properties(pproptags, pproblems))
			return ecError;
		return ecSuccess;
	case ems_objtype::folder: {
		auto fld = static_cast<folder_object *>(pobject);
		auto rpc_info = get_rpc_info();
		if (plogon->logon_mode != logon_mode::owner) {
			if (!exmdb_client::get_folder_perm(plogon->get_dir(),
			    fld->folder_id, rpc_info.username, &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		if (!fld->remove_properties(pproptags, pproblems))
			return ecError;
		return ecSuccess;
	}
	case ems_objtype::message: {
		auto msg = static_cast<message_object *>(pobject);
		auto tag_access = msg->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		if (!msg->remove_properties(pproptags, pproblems))
			return ecError;
		return ecSuccess;
	}
	case ems_objtype::attach: {
		auto atx = static_cast<attachment_object *>(pobject);
		auto tag_access = atx->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		if (!atx->remove_properties(pproptags, pproblems))
			return ecError;
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

ec_error_t rop_deletepropertiesnoreplicate(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return rop_deleteproperties(pproptags,
		pproblems, plogmap, logon_id, hin);
}

ec_error_t rop_querynamedproperties(uint8_t query_flags, const GUID *pguid,
    PROPIDNAME_ARRAY *ppropidnames, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	int i;
	ems_objtype object_type;
	uint16_t propid;
	PROPID_ARRAY propids;
	PROPTAG_ARRAY proptags;
	PROPNAME_ARRAY propnames;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	if ((query_flags & QUERY_FLAG_NOIDS) &&
		(query_flags & QUERY_FLAG_NOSTRINGS)) {
		ppropidnames->count = 0;
		ppropidnames->ppropid = NULL;
		ppropidnames->ppropname = NULL;
		return ecSuccess;
	}
	switch (object_type) {
	case ems_objtype::logon:
		if (!static_cast<logon_object *>(pobject)->get_all_proptags(&proptags))
			return ecError;
		break;
	case ems_objtype::folder:
		if (!static_cast<folder_object *>(pobject)->get_all_proptags(&proptags))
			return ecError;
		break;
	case ems_objtype::message:
		if (!static_cast<message_object *>(pobject)->get_all_proptags(&proptags))
			return ecError;
		break;
	case ems_objtype::attach:
		if (!static_cast<attachment_object *>(pobject)->get_all_proptags(&proptags))
			return ecError;
		break;
	default:
		return ecNotSupported;
	}
	propids.count = 0;
	propids.ppropid = cu_alloc<uint16_t>(proptags.count);
	if (NULL == propids.ppropid) {
		return ecServerOOM;
	}
	for (i=0; i<proptags.count; i++) {
		propid = PROP_ID(proptags.pproptag[i]);
		if (!is_nameprop_id(propid))
			continue;
		propids.ppropid[propids.count++] = propid;
	}
	if (0 == propids.count) {
		ppropidnames->count = 0;
		ppropidnames->ppropid = NULL;
		ppropidnames->ppropname = NULL;
		return ecSuccess;
	}
	ppropidnames->count = 0;
	ppropidnames->ppropid = cu_alloc<uint16_t>(propids.count);
	if (NULL == ppropidnames->ppropid) {
		return ecServerOOM;
	}
	ppropidnames->ppropname = cu_alloc<PROPERTY_NAME>(propids.count);
	if (NULL == ppropidnames->ppropid) {
		return ecServerOOM;
	}
	if (!plogon->get_named_propnames(&propids, &propnames))
		return ecError;
	for (i=0; i<propids.count; i++) {
		if (KIND_NONE == propnames.ppropname[i].kind) {
			continue;
		}
		if (pguid != nullptr && *pguid != propnames.ppropname[i].guid)
			continue;
		if ((query_flags & QUERY_FLAG_NOSTRINGS) &&
		    propnames.ppropname[i].kind == MNID_STRING)
			continue;
		if ((query_flags & QUERY_FLAG_NOIDS) &&
		    ppropidnames->ppropname[i].kind == MNID_ID)
			continue;
		ppropidnames->ppropid[ppropidnames->count] =
										propids.ppropid[i];
		ppropidnames->ppropname[ppropidnames->count++] = ppropidnames->ppropname[i];
	}
	return ecSuccess;
}

ec_error_t rop_copyproperties(uint8_t want_asynchronous, uint8_t copy_flags,
    const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	int i;
	BOOL b_force;
	BOOL b_result;
	ems_objtype object_type, dst_type;
	uint32_t permission;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY proptags1;
	TPROPVAL_ARRAY propvals;
	PROBLEM_ARRAY tmp_problems;
	
	/* We do not support MAPI_MOVE, just like EXC 2010 or later */
	if (copy_flags & ~(MAPI_MOVE | MAPI_NOREPLACE))
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hsrc, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	auto pobject_dst = rop_processor_get_object(plogmap, logon_id, hdst, &dst_type);
	if (pobject_dst == nullptr)
		return ecDstNullObject;
	if (object_type != dst_type)
		return MAPI_E_DECLINE_COPY;
	if (object_type == ems_objtype::folder && copy_flags & MAPI_MOVE)
		return ecNotSupported;
	proptags.count = 0;
	proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == proptags.pproptag) {
		return ecServerOOM;
	}
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (NULL == pproblems->pproblem) {
		return ecServerOOM;
	}
	auto poriginal_indices = cu_alloc<uint16_t>(pproptags->count);
	if (NULL == poriginal_indices) {
		return ecError;
	}
	switch (object_type) {
	case ems_objtype::folder: {
		auto fldsrc = static_cast<folder_object *>(pobject);
		auto flddst = static_cast<folder_object *>(pobject_dst);
		auto rpc_info = get_rpc_info();
		if (plogon->logon_mode != logon_mode::owner) {
			if (!exmdb_client::get_folder_perm(plogon->get_dir(),
			    flddst->folder_id, rpc_info.username, &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		if (copy_flags & MAPI_NOREPLACE &&
		    !flddst->get_all_proptags(&proptags1))
			return ecError;
		for (i=0; i<pproptags->count; i++) {
			if (flddst->is_readonly_prop(pproptags->pproptag[i])) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
				continue;
			}
			if (copy_flags & MAPI_NOREPLACE &&
			    proptags1.has(pproptags->pproptag[i]))
				continue;
			proptags.pproptag[proptags.count] = 
							pproptags->pproptag[i];
			poriginal_indices[proptags.count++] = i;
		}
		if (!fldsrc->get_properties(&proptags, &propvals))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (propvals.has(proptags.pproptag[i]))
				continue;
			pproblems->pproblem[pproblems->count].index =
				poriginal_indices[i];
			pproblems->pproblem[pproblems->count].proptag =
				pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count++].err = ecNotFound;
		}
		if (!flddst->set_properties(&propvals, &tmp_problems))
			return ecError;
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index = pproptags->indexof(tmp_problems.pproblem[i].proptag);
		}
		*pproblems += std::move(tmp_problems);
		return ecSuccess;
	}
	case ems_objtype::message: {
		auto msgsrc = static_cast<message_object *>(pobject);
		auto msgdst = static_cast<message_object* >(pobject_dst);
		auto tag_access = msgdst->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		b_force = TRUE;
		if (copy_flags & MAPI_NOREPLACE) {
			b_force = FALSE;
			if (!msgdst->get_all_proptags(&proptags1))
				return ecError;
		}
		for (i=0; i<pproptags->count; i++) {
			if (pproptags->pproptag[i] == PR_MESSAGE_ATTACHMENTS) {
				if (!msgdst->copy_attachments(msgsrc, b_force, &b_result))
					return ecError;
				if (!b_result) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag = PR_MESSAGE_ATTACHMENTS;
					pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
				}
				continue;
			} else if (pproptags->pproptag[i] == PR_MESSAGE_RECIPIENTS) {
				if (!msgdst->copy_rcpts(msgsrc, b_force, &b_result))
					return ecError;
				if (!b_result) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag = PR_MESSAGE_RECIPIENTS;
					pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
				}
				continue;
			}
			if (msgdst->is_readonly_prop(pproptags->pproptag[i])) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
				continue;
			}
			if (copy_flags & MAPI_NOREPLACE &&
			    proptags1.has(pproptags->pproptag[i]))
				continue;
			proptags.pproptag[proptags.count] = 
							pproptags->pproptag[i];
			poriginal_indices[proptags.count++] = i;
		}
		if (!msgsrc->get_properties(0, &proptags, &propvals))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (propvals.has(proptags.pproptag[i]))
				continue;
			pproblems->pproblem[pproblems->count].index =
				poriginal_indices[i];
			pproblems->pproblem[pproblems->count].proptag =
				pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count++].err = ecNotFound;
		}
		if (!msgdst->set_properties(&propvals, &tmp_problems))
			return ecError;
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index = pproptags->indexof(tmp_problems.pproblem[i].proptag);
		}
		*pproblems += std::move(tmp_problems);
		return ecSuccess;
	}
	case ems_objtype::attach: {
		auto atsrc = static_cast<attachment_object *>(pobject);
		auto atdst = static_cast<attachment_object *>(pobject_dst);
		auto tag_access = atdst->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		if (copy_flags & MAPI_NOREPLACE &&
		    !atdst->get_all_proptags(&proptags1))
			return ecError;
		for (i=0; i<pproptags->count; i++) {
			if (atdst->is_readonly_prop(pproptags->pproptag[i])) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
				continue;
			}
			if (copy_flags & MAPI_NOREPLACE &&
			    proptags1.has(pproptags->pproptag[i]))
				continue;
			proptags.pproptag[proptags.count] = 
							pproptags->pproptag[i];
			poriginal_indices[proptags.count++] = i;
		}
		if (!atsrc->get_properties(0, &proptags, &propvals))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (propvals.has(proptags.pproptag[i]))
				continue;
			pproblems->pproblem[pproblems->count].index =
				poriginal_indices[i];
			pproblems->pproblem[pproblems->count].proptag =
				pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count++].err = ecNotFound;
		}
		if (!atdst->set_properties(&propvals, &tmp_problems))
			return ecError;
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index = pproptags->indexof(tmp_problems.pproblem[i].proptag);
		}
		*pproblems += std::move(tmp_problems);
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

ec_error_t rop_copyto(uint8_t want_asynchronous, uint8_t want_subobjects,
    uint8_t copy_flags, const PROPTAG_ARRAY *pexcluded_proptags,
    PROBLEM_ARRAY *pproblems, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hsrc, uint32_t hdst)
{
	int i;
	BOOL b_sub;
	BOOL b_cycle;
	BOOL b_collid;
	BOOL b_partial;
	ems_objtype object_type, dst_type;
	uint32_t permission;
	const char *username;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY proptags1;
	TPROPVAL_ARRAY propvals;
	PROPTAG_ARRAY tmp_proptags;
	
	/* We do not support MAPI_MOVE, just like EXC 2010 or later */
	if (copy_flags & ~(MAPI_MOVE | MAPI_NOREPLACE))
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hsrc, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	auto pobject_dst = rop_processor_get_object(plogmap, logon_id, hdst, &dst_type);
	if (pobject_dst == nullptr)
		return ecDstNullObject;
	if (object_type != dst_type)
		return MAPI_E_DECLINE_COPY;
	if (object_type == ems_objtype::folder && copy_flags & MAPI_MOVE)
		return ecNotSupported;
	BOOL b_force = (copy_flags & MAPI_NOREPLACE) ? false : TRUE;
	switch (object_type) {
	case ems_objtype::folder: {
		auto fldsrc = static_cast<folder_object *>(pobject);
		auto flddst = static_cast<folder_object *>(pobject_dst);
		/* MS-OXCPRPT 3.2.5.8, public folder not supported */
		if (!plogon->is_private())
			return ecNotSupported;
		auto rpc_info = get_rpc_info();
		if (plogon->logon_mode != logon_mode::owner) {
			if (!exmdb_client::get_folder_perm(plogon->get_dir(),
			    fldsrc->folder_id, rpc_info.username, &permission))
				return ecError;
			if (permission & frightsOwner) {
				username = NULL;
			} else {
				if (!(permission & frightsReadAny))
					return ecAccessDenied;
				username = rpc_info.username;
			}
			if (!exmdb_client::get_folder_perm(plogon->get_dir(),
			    flddst->folder_id, rpc_info.username, &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		} else {
			username = NULL;
		}
		if (!pexcluded_proptags->has(PR_CONTAINER_HIERARCHY)) {
			if (!exmdb_client::check_folder_cycle(plogon->get_dir(),
			    fldsrc->folder_id, flddst->folder_id, &b_cycle))
				return ecError;
			if (b_cycle)
				return ecRootFolder;
			b_sub = TRUE;
		} else {
			b_sub = FALSE;
		}
		BOOL b_normal = !pexcluded_proptags->has(PR_CONTAINER_CONTENTS) ? TRUE : false;
		BOOL b_fai    = !pexcluded_proptags->has(PR_FOLDER_ASSOCIATED_CONTENTS) ? TRUE : false;
		if (!fldsrc->get_all_proptags(&proptags))
			return ecError;
		common_util_reduce_proptags(&proptags, pexcluded_proptags);
		tmp_proptags.count = 0;
		tmp_proptags.pproptag = cu_alloc<uint32_t>(proptags.count);
		if (NULL == tmp_proptags.pproptag) {
			return ecServerOOM;
		}
		if (!b_force && !flddst->get_all_proptags(&proptags1))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (flddst->is_readonly_prop(proptags.pproptag[i]))
				continue;
			if (!b_force && proptags1.has(proptags.pproptag[i]))
				continue;
			tmp_proptags.pproptag[tmp_proptags.count++] = proptags.pproptag[i];
		}
		if (!fldsrc->get_properties(&tmp_proptags, &propvals))
			return ecError;
		if (b_sub || b_normal || b_fai) {
			auto pinfo = emsmdb_interface_get_emsmdb_info();
			BOOL b_guest = username == nullptr ? false : TRUE;
			if (!exmdb_client::copy_folder_internal(plogon->get_dir(),
			    plogon->account_id, pinfo->cpid, b_guest,
			    rpc_info.username, fldsrc->folder_id,
			    b_normal, b_fai, b_sub, flddst->folder_id,
			    &b_collid, &b_partial))
				return ecError;
			if (b_collid)
				return ecDuplicateName;
			if (!flddst->set_properties(&propvals, pproblems))
				return ecError;
			return ecSuccess;
		}
		if (!flddst->set_properties(&propvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	case ems_objtype::message: {
		auto msgdst = static_cast<message_object *>(pobject_dst);
		auto tag_access = msgdst->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		if (!msgdst->copy_to(static_cast<message_object *>(pobject),
		    pexcluded_proptags, b_force, &b_cycle, pproblems))
			return ecError;
		if (b_cycle)
			return ecMsgCycle;
		return ecSuccess;
	}
	case ems_objtype::attach: {
		auto atdst = static_cast<attachment_object *>(pobject_dst);
		auto tag_access = atdst->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		if (!atdst->copy_properties(static_cast<attachment_object *>(pobject),
		    pexcluded_proptags, b_force, &b_cycle, pproblems))
			return ecError;
		if (b_cycle)
			return ecMsgCycle;
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

ec_error_t rop_progress(uint8_t want_cancel, uint32_t *pcompleted_count,
    uint32_t *ptotal_count, uint8_t *prop_id, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return ecNotSupported;
}

ec_error_t rop_openstream(uint32_t proptag, uint8_t flags, uint32_t *pstream_size,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	uint32_t max_length;
	uint32_t permission;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	BOOL b_write = flags == MAPI_CREATE || flags == MAPI_MODIFY ? TRUE : false;
	switch (object_type) {
	case ems_objtype::folder:
		/* MS-OXCPERM 3.1.4.1 */
		if (proptag == PR_NT_SECURITY_DESCRIPTOR_AS_XML)
			return ecNotSupported;
		if (!plogon->is_private() && flags != MAPI_READONLY)
			return ecNotSupported;
		if (PROP_TYPE(proptag) != PT_BINARY)
			return ecNotSupported;
		if (b_write) {
			auto rpc_info = get_rpc_info();
			if (plogon->logon_mode != logon_mode::owner) {
				if (!exmdb_client::get_folder_perm(plogon->get_dir(),
				    static_cast<folder_object *>(pobject)->folder_id,
				    rpc_info.username, &permission))
					return ecError;
				if (!(permission & frightsOwner))
					return ecAccessDenied;
			}
		}
		max_length = MAX_LENGTH_FOR_FOLDER;
		break;
	case ems_objtype::message:
	case ems_objtype::attach:
		switch (PROP_TYPE(proptag)) {
		case PT_BINARY:
		case PT_STRING8:
		case PT_UNICODE:
			break;
		case PT_OBJECT:
			if (proptag == PR_ATTACH_DATA_OBJ)
				break;
			return ecNotFound;
		default:
			return ecNotSupported;
		}
		if (b_write) {
			auto tag_access = object_type == ems_objtype::message ?
				static_cast<message_object *>(pobject)->get_tag_access() :
				static_cast<attachment_object *>(pobject)->get_tag_access();
			if (!(tag_access & MAPI_ACCESS_MODIFY))
				return ecAccessDenied;
		}
		max_length = g_max_mail_len;
		break;
	default:
		return ecNotSupported;
	}
	auto pstream = stream_object::create(pobject, object_type, flags,
	               proptag, max_length);
	if (pstream == nullptr)
		return ecError;
	if (!pstream->check())
		return ecNotFound;
	auto rstream = pstream.get();
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::stream, std::move(pstream)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	*pstream_size = rstream->get_length();
	return ecSuccess;
}

ec_error_t rop_readstream(uint16_t byte_count, uint32_t max_byte_count,
    BINARY *pdata_bin, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	uint16_t max_rop;
	uint16_t read_len;
	uint32_t buffer_size;
	ems_objtype object_type;
	
	auto pstream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hin, &object_type);
	if (pstream == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::stream)
		return ecNotSupported;
	if (0xBABE == byte_count) {
		if (max_byte_count > static_cast<uint32_t>(INT32_MAX) + 1)
			return ecRpcFormat;
		buffer_size = max_byte_count;
	} else {
		buffer_size = byte_count;
	}
	emsmdb_interface_get_rop_left(&max_rop);
	if (max_rop >= 16)
		max_rop -= 16;
	else
		max_rop = 0;
	if (buffer_size > max_rop) {
		buffer_size = max_rop;
	}
	if (0 == buffer_size) {
		pdata_bin->cb = 0;
		pdata_bin->pb = NULL;
		return ecSuccess;
	}
	pdata_bin->pv = common_util_alloc(buffer_size);
	if (pdata_bin->pv == nullptr)
		return ecServerOOM;
	read_len = pstream->read(pdata_bin->pv, buffer_size);
	pdata_bin->cb = read_len;
	return ecSuccess;
}

ec_error_t rop_writestream(const BINARY *pdata_bin, uint16_t *pwritten_size,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto pstream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hin, &object_type);
	if (pstream == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::stream)
		return ecNotSupported;
	if (pstream->get_open_flags() == MAPI_READONLY)
		return STG_E_ACCESSDENIED;	
	if (0 == pdata_bin->cb) {
		*pwritten_size = 0;
		return ecSuccess;
	}
	if (pstream->get_seek_position() >= pstream->get_max_length())
		return ecTooBig;
	auto result = pstream->write(pdata_bin->pb, pdata_bin->cb);
	if (result.second != ecSuccess) {
		*pwritten_size = 0;
		return result.second;
	}
	*pwritten_size = result.first;
	if (*pwritten_size < pdata_bin->cb) {
		return ecTooBig;
	}
	return ecSuccess;
}

ec_error_t rop_commitstream(LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto pstream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hin, &object_type);
	if (pstream == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::stream)
		return ecNotSupported;
	switch (pstream->get_parent_type()) {
	case ems_objtype::folder:
		if (!pstream->commit())
			return ecError;
		return ecSuccess;
	case ems_objtype::message:
	case ems_objtype::attach:
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

ec_error_t rop_getstreamsize(uint32_t *pstream_size, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto pstream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hin, &object_type);
	if (pstream == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::stream)
		return ecNotSupported;
	*pstream_size = pstream->get_length();
	return ecSuccess;
}

ec_error_t rop_setstreamsize(uint64_t stream_size, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	if (stream_size > static_cast<uint64_t>(INT32_MAX) + 1)
		/* That weird +1 is specified in MS-OXCPRPT v17 §2.2.19 and §2.2.20 */
		return ecInvalidParam;
	auto pstream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hin, &object_type);
	if (pstream == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::stream)
		return ecNotSupported;
	if (stream_size > pstream->get_max_length())
		return ecTooBig;
	return pstream->set_length(stream_size);
}

ec_error_t rop_seekstream(uint8_t seek_pos, int64_t offset, uint64_t *pnew_pos,
   LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	switch (seek_pos) {
	case STREAM_SEEK_SET:
	case STREAM_SEEK_CUR:
	case STREAM_SEEK_END:
		break;
	default:
		return ecInvalidParam;
	}
	if (offset < INT32_MIN)
		return StreamSeekError;
	if (offset > 0 && static_cast<uint64_t>(offset) > static_cast<uint64_t>(INT32_MAX) + 1)
		return StreamSeekError;
	auto pstream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hin, &object_type);
	if (pstream == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::stream)
		return ecNotSupported;
	auto ret = pstream->seek(seek_pos, offset);
	if (ret != ecSuccess)
		return ret;
	*pnew_pos = pstream->get_seek_position();
	return ecSuccess;
}

ec_error_t rop_copytostream(uint64_t byte_count, uint64_t *pread_bytes,
    uint64_t *pwritten_bytes, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hsrc, uint32_t hdst)
{
	ems_objtype object_type;
	uint32_t length;
	
	auto psrc_stream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hsrc, &object_type);
	if (psrc_stream == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::stream)
		return ecNotSupported;
	auto pdst_stream = rop_proc_get_obj<stream_object>(plogmap, logon_id, hdst, &object_type);
	if (pdst_stream == nullptr)
		return ecDstNullObject;
	if (pdst_stream->get_open_flags() == MAPI_READONLY)
		return ecAccessDenied;
	if (0 == byte_count) {
		*pread_bytes = 0;
		*pwritten_bytes = 0;
		return ecSuccess;
	}
	length = byte_count;
	if (!pdst_stream->copy(psrc_stream, &length))
		return ecError;
	*pread_bytes = length;
	*pwritten_bytes = length;
	return ecSuccess;
}

ec_error_t rop_lockregionstream(uint64_t region_offset, uint64_t region_size,
    uint32_t lock_flags, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	 /* just like exchange 2010 or later */
	 return NotImplemented;
}

ec_error_t rop_unlockregionstream(uint64_t region_offset, uint64_t region_size,
    uint32_t lock_flags, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	 /* just like exchange 2010 or later */
	return NotImplemented;
}

ec_error_t rop_writeandcommitstream(const BINARY *pdata, uint16_t *pwritten_size,
   LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	 /* just like exchange 2010 or later */
	return NotImplemented;
}

ec_error_t rop_clonestream(LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hin, uint32_t *phout)
{
	 /* just like exchange 2010 or later */
	return NotImplemented;
}
