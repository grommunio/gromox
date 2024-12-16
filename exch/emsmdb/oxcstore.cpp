// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <ctime>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "logon_object.hpp"
#include "rop_funcs.hpp"
#include "rop_processor.hpp"

using namespace gromox;

ec_error_t rop_logon_pmb(uint8_t logon_flags, uint32_t open_flags,
    uint32_t store_stat, char *pessdn, size_t dnmax, uint64_t *pfolder_id,
    uint8_t *presponse_flags, GUID *pmailbox_guid, uint16_t *replid,
    GUID *replguid, LOGON_TIME *plogon_time, uint64_t *pgwart_time,
    uint32_t *pstore_stat, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t *phout) try
{
	enum logon_mode logon_mode;
	struct tm *ptm;
	struct tm tmp_tm;
	uint32_t permission;
	TPROPVAL_ARRAY propvals;
	
	auto rpc_info = get_rpc_info();
	if (!(open_flags & LOGON_OPEN_FLAG_USE_PER_MDB_REPLID_MAPPING))
		/* MS-OXCSTOR v25 §3.2.5.1.1, §3.2.5.1.3 */
		return ecInvalidParam;
	std::string username;
	auto ret = cvt_essdn_to_username(pessdn, g_emsmdb_org_name,
	           cu_id2user, username);
	if (ret != ecSuccess)
		return ret;
	unsigned int user_id = 0, dom_id = 0;
	if (!mysql_adaptor_get_user_ids(username.c_str(), &user_id, &dom_id, nullptr))
		return ecUnknownUser;
	if (open_flags & LOGON_OPEN_FLAG_ALTERNATE_SERVER) {
		std::string serverdn;
		auto err = cvt_username_to_serverdn(rpc_info.username,
		           g_emsmdb_org_name, user_id, serverdn);
		if (err != ecSuccess)
			return err;
		gx_strlcpy(pessdn, serverdn.c_str(), dnmax);
		return ecWrongServer;
	}
	std::string maildir;
	if (strcasecmp(username.c_str(), rpc_info.username) != 0) {
		if (open_flags & LOGON_OPEN_FLAG_USE_ADMIN_PRIVILEGE)
			return ecLoginPerm;
		sql_meta_result mres;
		if (mysql_adaptor_meta(username.c_str(), WANTPRIV_METAONLY, mres) != 0)
			return ecError;
		maildir = std::move(mres.maildir);
		if (!exmdb_client::get_mbox_perm(maildir.c_str(),
		    rpc_info.username, &permission))
			return ecError;
		if (permission == rightsNone)
			return ecLoginPerm;
		*presponse_flags = RESPONSE_FLAG_RESERVED;
		if (permission & frightsGromoxSendAs) {
			permission ^= frightsGromoxSendAs;
			*presponse_flags |= RESPONSE_FLAG_SENDASRIGHT;
			logon_mode = logon_mode::delegate;
		} else {
			logon_mode = logon_mode::guest;
		}
		if (permission & frightsGromoxStoreOwner) {
			permission ^= frightsGromoxStoreOwner;
			*presponse_flags |= RESPONSE_FLAG_OWNERRIGHT;
			logon_mode = logon_mode::owner;
		}
	} else {
		*presponse_flags = RESPONSE_FLAG_RESERVED | RESPONSE_FLAG_OWNERRIGHT |
		                   RESPONSE_FLAG_SENDASRIGHT;
		maildir = rpc_info.maildir;
		logon_mode = logon_mode::owner;
	}

	static constexpr proptag_t proptag_buff[] =
		{PR_STORE_RECORD_KEY, PR_OOF_STATE};
	static constexpr PROPTAG_ARRAY proptags =
		{std::size(proptag_buff), deconst(proptag_buff)};
	if (!exmdb_client::get_store_properties(maildir.c_str(), CP_ACP,
	    &proptags, &propvals))
		return ecError;
	auto bin = propvals.get<const BINARY>(PR_STORE_RECORD_KEY);
	if (bin == nullptr)
		return ecError;
	*pmailbox_guid = rop_util_binary_to_guid(bin);
	auto flag = propvals.get<const uint8_t>(PR_OOF_STATE);
	if (flag != nullptr && *flag != 0)
		*presponse_flags |= RESPONSE_FLAG_OOF;
	
	pfolder_id[0]  = rop_util_make_eid_ex(1, PRIVATE_FID_ROOT);
	pfolder_id[1]  = rop_util_make_eid_ex(1, PRIVATE_FID_DEFERRED_ACTION);
	pfolder_id[2]  = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	pfolder_id[3]  = rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE);
	pfolder_id[4]  = rop_util_make_eid_ex(1, PRIVATE_FID_INBOX);
	pfolder_id[5]  = rop_util_make_eid_ex(1, PRIVATE_FID_OUTBOX);
	pfolder_id[6]  = rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS);
	pfolder_id[7]  = rop_util_make_eid_ex(1, PRIVATE_FID_DELETED_ITEMS);
	pfolder_id[8]  = rop_util_make_eid_ex(1, PRIVATE_FID_COMMON_VIEWS);
	pfolder_id[9]  = rop_util_make_eid_ex(1, PRIVATE_FID_SCHEDULE);
	pfolder_id[10] = rop_util_make_eid_ex(1, PRIVATE_FID_FINDER);
	pfolder_id[11] = rop_util_make_eid_ex(1, PRIVATE_FID_VIEWS);
	pfolder_id[12] = rop_util_make_eid_ex(1, PRIVATE_FID_SHORTCUTS);
	
	*replid   = 5;
	*replguid = *pmailbox_guid; /* send PR_MAPPING_SIGNATURE */
	
	auto cur_time = time(nullptr);
	ptm = gmtime_r(&cur_time, &tmp_tm);
	if (ptm != nullptr) {
		plogon_time->second = ptm->tm_sec;
		plogon_time->minute = ptm->tm_min;
		plogon_time->hour = ptm->tm_hour;
		plogon_time->day_of_week = ptm->tm_wday;
		plogon_time->day = ptm->tm_mday;
		plogon_time->month = ptm->tm_mon + 1;
		plogon_time->year = ptm->tm_year + 1900;
	} else {
		*plogon_time = {};
	}
	*pgwart_time = rop_util_unix_to_nttime(cur_time);
	
	*pstore_stat = 0;
	auto plogon = logon_object::create(logon_flags, open_flags, logon_mode,
	              user_id, dom_id, username.c_str(), maildir.c_str(),
	              *pmailbox_guid);
	if (plogon == nullptr)
		return ecServerOOM;
	g_last_rop_dir = plogon->get_dir();
	/* create logon map and logon object */
	auto handle = rop_processor_create_logon_item(plogmap, logon_id, std::move(plogon));
	if (handle < 0) {
		g_last_rop_dir = nullptr;
		return aoh_to_error(handle);
	}
	*phout = handle;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2554: ENOMEM");
	return ecServerOOM;
}
	
ec_error_t rop_logon_pf(uint8_t logon_flags, uint32_t open_flags,
    uint32_t store_stat, char *pessdn, uint64_t *pfolder_id,
    uint16_t *replid, GUID *replguid, GUID *pper_user_guid,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t *phout)
{
	void *pvalue;
	char homedir[256];
	GUID mailbox_guid;
	const char *pdomain;
	
	if (!(open_flags & LOGON_OPEN_FLAG_PUBLIC) ||
	    (open_flags & LOGON_OPEN_FLAG_ALTERNATE_SERVER))
		return ecLoginFailure;
	auto rpc_info = get_rpc_info();
	pdomain = strchr(rpc_info.username, '@');
	if (pdomain == nullptr)
		return ecUnknownUser;
	pdomain ++;
	unsigned int domain_id = 0, org_id = 0;
	if (!mysql_adaptor_get_domain_ids(pdomain, &domain_id, &org_id))
		return ecUnknownUser;
	if (NULL != pessdn) {
		auto pdomain1 = cvt_serverdn_to_domain(pessdn, g_emsmdb_org_name);
		if (NULL != pdomain1 && 0 != strcasecmp(pdomain, pdomain1)) {
			if (org_id == 0)
				return ecLoginFailure;
			unsigned int domain_id1 = 0, org_id1 = 0;
			if (!mysql_adaptor_get_domain_ids(pdomain1, &domain_id1, &org_id1))
				return ecError;
			if (org_id != org_id1)
				return ecLoginFailure;
			domain_id = domain_id1;
			pdomain = pdomain1;
		}
	}
	if (!mysql_adaptor_get_homedir_by_id(domain_id, homedir, std::size(homedir)))
		return ecError;
	/* like EXCHANGE 2013 or later, we only
		return four folder_ids to client */
	pfolder_id[0]  = rop_util_make_eid_ex(1, PUBLIC_FID_ROOT);
	pfolder_id[1]  = rop_util_make_eid_ex(1, PUBLIC_FID_IPMSUBTREE);
	pfolder_id[2]  = rop_util_make_eid_ex(1, PUBLIC_FID_NONIPMSUBTREE);
	pfolder_id[3]  = rop_util_make_eid_ex(1, PUBLIC_FID_EFORMSREGISTRY);
	pfolder_id[4]  = 0; /* Free/Busy data */
	pfolder_id[5]  = 0; /* Offline Address Book data */
	pfolder_id[6]  = 0; /* EForms Registry for the user's locale */
	pfolder_id[7]  = 0; /* Local site's Free/Busy data */
	pfolder_id[8]  = 0; /* Local site's Offline Addressbook data */
	pfolder_id[9]  = 0; /* NNTP article index */
	pfolder_id[10] = 0;
	pfolder_id[11] = 0;
	pfolder_id[12] = 0;
	
	
	if (!exmdb_client::get_store_property(homedir, CP_ACP,
	    PR_STORE_RECORD_KEY, &pvalue))
		return ecError;
	if (pvalue == nullptr)
		return ecError;
	mailbox_guid = rop_util_binary_to_guid(static_cast<BINARY *>(pvalue));
	*replid   = 5;
	*replguid = mailbox_guid; /* send PR_MAPPING_SIGNATURE */
	memset(pper_user_guid, 0, sizeof(GUID));
	auto plogon = logon_object::create(logon_flags, open_flags,
	              logon_mode::guest, domain_id, domain_id,
	              pdomain, homedir, mailbox_guid);
	if (plogon == nullptr)
		return ecServerOOM;
	g_last_rop_dir = plogon->get_dir();
	/* create logon map and logon object */
	auto handle = rop_processor_create_logon_item(plogmap, logon_id, std::move(plogon));
	if (handle < 0) {
		g_last_rop_dir = nullptr;
		return aoh_to_error(handle);
	}
	*phout = handle;
	return ecSuccess;
}

ec_error_t rop_getreceivefolder(const char *pstr_class, uint64_t *pfolder_id,
    std::string *ppstr_explicit, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ret = cu_validate_msgclass(pstr_class);
	if (ret != ecSuccess)
		return ret;
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	if (!plogon->is_private())
		return ecNotSupported;
	if (!exmdb_client::get_folder_by_class(plogon->get_dir(), pstr_class,
	    pfolder_id, ppstr_explicit))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_setreceivefolder(uint64_t folder_id, const char *pstr_class,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pvalue;
	BOOL b_result;
	ems_objtype object_type;
	
	auto ret = cu_validate_msgclass(pstr_class);
	if (ret != ecSuccess)
		return ret;
	if (*pstr_class == '\0' && folder_id == 0)
		return ecError;
	if (strcasecmp(pstr_class, "IPM") == 0 ||
	    strcasecmp(pstr_class, "REPORT.IPM") == 0)
		return ecAccessDenied;
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	if (!plogon->is_private())
		return ecNotSupported;
	if (0 != folder_id) {
		if (!exmdb_client::get_folder_property(plogon->get_dir(),
		    CP_ACP, folder_id, PR_FOLDER_TYPE, &pvalue))
			return ecError;
		if (pvalue == nullptr)
			return ecNotFound;
		if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
			return ecNotSupported;
	}
	if (plogon->logon_mode != logon_mode::owner)
		return ecAccessDenied;
	if (!exmdb_client::set_folder_by_class(plogon->get_dir(),
	    folder_id, pstr_class, &b_result))
		return ecError;
	if (!b_result)
		return ecNotFound;
	return ecSuccess;
}

ec_error_t rop_getreceivefoldertable(PROPROW_SET *prows, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	PROPTAG_ARRAY columns;
	TARRAY_SET class_table;
	uint32_t proptags[] = {PidTagFolderId, PR_MESSAGE_CLASS_A, PR_LAST_MODIFICATION_TIME};
	
	columns.count = std::size(proptags);
	columns.pproptag = proptags;
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	if (!plogon->is_private())
		return ecNotSupported;
	if (!exmdb_client::get_folder_class_table(plogon->get_dir(), &class_table))
		return ecError;
	if (class_table.count == 0)
		return ecNoReceiveFolder;
	prows->count = class_table.count;
	prows->prows = cu_alloc<PROPERTY_ROW>(class_table.count);
	if (prows->prows == nullptr)
		return ecServerOOM;
	for (size_t i = 0; i < class_table.count; ++i)
		if (!common_util_propvals_to_row(class_table.pparray[i],
		    &columns, &prows->prows[i]))
			return ecServerOOM;
	return ecSuccess;
}

ec_error_t rop_getstorestat(uint32_t *pstat, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	/* just like EXCHANGE 2010 or later,
		we do not implement this rop */
	return NotImplemented;
}

ec_error_t rop_getowningservers(uint64_t folder_id, GHOST_SERVER *pghost,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	if (plogon->is_private())
		return ecNotSupported;
	pghost->server_count = 1;
	pghost->cheap_server_count = 1;
	pghost->ppservers = cu_alloc<char *>();
	if (pghost->ppservers == nullptr)
		return ecServerOOM;
	auto username = get_rpc_info().username;
	unsigned int user_id = 0;
	if (!mysql_adaptor_get_user_ids(username, &user_id, nullptr, nullptr))
		return ecUnknownUser;
	std::string serverdn;
	auto err = cvt_username_to_serverdn(username,
	           g_emsmdb_org_name, user_id, serverdn);
	if (err != ecSuccess)
		return err;
	pghost->ppservers[0] = cu_alloc<char>(serverdn.size() + 1);
	if (pghost->ppservers[0] == nullptr)
		return ecServerOOM;
	gx_strlcpy(pghost->ppservers[0], serverdn.c_str(), serverdn.size() + 1);
	return ecSuccess;
}

ec_error_t rop_publicfolderisghosted(uint64_t folder_id, GHOST_SERVER **ppghost,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	/* Gromox does not have split-server public folders / ghosted content */
	*ppghost = nullptr;
	return ecSuccess;
}

ec_error_t rop_longtermidfromid(uint64_t id, LONG_TERM_ID *plong_term_id,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	memset(plong_term_id, 0, sizeof(LONG_TERM_ID));
	plong_term_id->global_counter = rop_util_get_gc_array(id);
	return replid_to_replguid(*plogon, rop_util_get_replid(id), plong_term_id->guid);
}	

ec_error_t rop_idfromlongtermid(const LONG_TERM_ID *plong_term_id, uint64_t *pid,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	uint16_t replid = 0;
	auto ret = replguid_to_replid(*plogon, plong_term_id->guid, replid);
	if (ret != ecSuccess)
		return ecInvalidParam;
	*pid = rop_util_make_eid(replid, plong_term_id->global_counter);
	return ecSuccess;
}

ec_error_t rop_getperuserlongtermids(const GUID *pguid,
    LONG_TERM_ID_ARRAY *plong_term_ids, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	if (plogon->is_private()) {
		plong_term_ids->count = 0;
		return ecSuccess;
	}
	return ecNotSupported;
}

ec_error_t rop_getperuserguid(const LONG_TERM_ID *plong_term_id, GUID *pguid,
    LOGMAP *plogmap,uint8_t logon_id,  uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	return plogon->is_private() ? ecNotFound : ecNotSupported;
}

ec_error_t rop_readperuserinformation(const LONG_TERM_ID *plong_folder_id,
    uint8_t reserved, uint32_t data_offset, uint16_t max_data_size,
    uint8_t *phas_finished, BINARY *pdata, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	*phas_finished = 1;
	pdata->cb = 0;
	pdata->pb = NULL;
	return ecSuccess;
}

ec_error_t rop_writeperuserinformation(const LONG_TERM_ID *plong_folder_id,
    uint8_t has_finished, uint32_t offset, const BINARY *pdata,
    const GUID *pguid, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecNotSupported;
	return ecSuccess;
}
