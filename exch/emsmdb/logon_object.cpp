// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/msgchg_grouping.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "logon_object.hpp"

using namespace std::string_literals;
using namespace gromox;

static bool propname_to_packed(const PROPERTY_NAME &n, char *dst, size_t z)
{
	char guid[GUIDSTR_SIZE];
	n.guid.to_str(guid, std::size(guid));
	if (n.kind == MNID_ID)
		snprintf(dst, z, "%s:lid:%u", guid, n.lid);
	else if (n.kind == MNID_STRING)
		snprintf(dst, z, "%s:name:%s", guid, n.pname);
	else
		return false;
	HX_strlower(dst);
	return true;
}

static BOOL logon_object_cache_propname(logon_object *plogon,
    uint16_t propid, const PROPERTY_NAME *ppropname) try
{
	char s[NP_STRBUF_SIZE];
	if (!propname_to_packed(*ppropname, s, std::size(s)))
		return false;
	plogon->propid_hash.emplace(propid, *ppropname);
	plogon->propname_hash.emplace(s, propid);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1633: ENOMEM");
	return false;
}

std::unique_ptr<logon_object> logon_object::create(uint8_t logon_flags,
    uint32_t open_flags, enum logon_mode logon_mode, int account_id,
    int dom_id, const char *account, const char *dir, GUID mailbox_guid)
{
	std::unique_ptr<logon_object> plogon;
	try {
		plogon.reset(new logon_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	plogon->logon_flags = logon_flags;
	plogon->open_flags = open_flags;
	plogon->logon_mode = logon_mode;
	plogon->account_id = account_id;
	plogon->domain_id = dom_id;
	gx_strlcpy(plogon->account, account, std::size(plogon->account));
	gx_strlcpy(plogon->dir, dir, std::size(plogon->dir));
	plogon->mailbox_guid = mailbox_guid;
	return plogon;
}

GUID logon_object::guid() const
{
	return is_private() ? rop_util_make_user_guid(account_id) :
	       rop_util_make_domain_guid(account_id);
}

BOOL logon_object::get_named_propname(uint16_t propid,
    PROPERTY_NAME *ppropname)
{
	if (!is_nameprop_id(propid)) {
		ppropname->guid = PS_MAPI;
		ppropname->kind = MNID_ID;
		ppropname->lid = propid;
	}
	auto plogon = this;
	auto iter = propid_hash.find(propid);
	if (iter != propid_hash.end()) {
		*ppropname = static_cast<PROPERTY_NAME>(iter->second);
		return TRUE;
	}
	if (!exmdb_client::get_named_propname(plogon->dir, propid, ppropname))
		return FALSE;	
	if (ppropname->kind == MNID_ID || ppropname->kind == MNID_STRING)
		logon_object_cache_propname(plogon, propid, ppropname);
	return TRUE;
}

BOOL logon_object::get_named_propnames(const PROPID_ARRAY &propids,
    PROPNAME_ARRAY *ppropnames) try
{
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	if (propids.empty()) {
		ppropnames->count = 0;
		return TRUE;
	}
	auto pindex_map = cu_alloc<int>(propids.size());
	if (pindex_map == nullptr)
		return FALSE;
	ppropnames->ppropname = cu_alloc<PROPERTY_NAME>(propids.size());
	if (ppropnames->ppropname == nullptr)
		return FALSE;
	ppropnames->count = propids.size();
	auto plogon = this;
	for (size_t i = 0; i < propids.size(); ++i) {
		if (!is_nameprop_id(propids[i])) {
			ppropnames->ppropname[i].guid = PS_MAPI;
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].lid = propids[i];
			pindex_map[i] = i;
			continue;
		}
		auto iter = propid_hash.find(propids[i]);
		if (iter != propid_hash.end()) {
			pindex_map[i] = i;
			ppropnames->ppropname[i] = static_cast<PROPERTY_NAME>(iter->second);
		} else {
			tmp_propids.push_back(propids[i]);
			pindex_map[i] = -static_cast<int>(tmp_propids.size());
		}
	}
	if (tmp_propids.empty())
		return TRUE;
	if (!exmdb_client::get_named_propnames(plogon->dir,
	    tmp_propids, &tmp_propnames) || tmp_propnames.size() != tmp_propids.size())
		return FALSE;	
	for (size_t i = 0; i < propids.size(); ++i) {
		if (pindex_map[i] >= 0)
			continue;
		ppropnames->ppropname[i] = tmp_propnames.ppropname[-pindex_map[i]-1];
		if (ppropnames->ppropname[i].kind == MNID_ID ||
		    ppropnames->ppropname[i].kind == MNID_STRING)
			logon_object_cache_propname(plogon,
				propids[i], ppropnames->ppropname + i);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2236: ENOMEM");
	return false;
}

BOOL logon_object::get_named_propid(BOOL b_create,
    const PROPERTY_NAME *ppropname, uint16_t *ppropid)
{
	if (ppropname->guid == PS_MAPI) {
		*ppropid = ppropname->kind == MNID_ID ? ppropname->lid : 0;
		return TRUE;
	}
	char ps[NP_STRBUF_SIZE];
	if (!propname_to_packed(*ppropname, ps, std::size(ps))) {
		*ppropid = 0;
		return TRUE;
	}
	auto plogon = this;
	auto iter = propname_hash.find(ps);
	if (iter != propname_hash.end()) {
		*ppropid = iter->second;
		return TRUE;
	}
	if (!exmdb_client::get_named_propid(plogon->dir, b_create,
	    ppropname, ppropid))
		return FALSE;
	if (*ppropid == 0)
		return TRUE;
	logon_object_cache_propname(plogon, *ppropid, ppropname);
	return TRUE;
}

BOOL logon_object::get_named_propids(BOOL b_create,
    const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids) try
{
	auto &propids = *ppropids;
	
	if (0 == ppropnames->count) {
		ppropids->clear();
		return TRUE;
	}
	auto pindex_map = cu_alloc<int>(ppropnames->count);
	if (pindex_map == nullptr)
		return FALSE;
	PROPID_ARRAY tmp_propids;
	propids.resize(ppropnames->count);
	PROPNAME_ARRAY tmp_propnames = {0, cu_alloc<PROPERTY_NAME>(ppropnames->count)};
	if (tmp_propnames.ppropname == nullptr)
		return FALSE;
	auto plogon = this;
	for (unsigned int i = 0; i < ppropnames->count; ++i) {
		if (ppropnames->ppropname[i].guid == PS_MAPI) {
			propids[i] = ppropnames->ppropname[i].kind == MNID_ID ?
			             ppropnames->ppropname[i].lid : 0;
			pindex_map[i] = i;
			continue;
		}
		char ps[NP_STRBUF_SIZE];
		if (!propname_to_packed(ppropnames->ppropname[i], ps, std::size(ps))) {
			propids[i] = 0;
			pindex_map[i] = i;
			continue;
		}
		auto iter = propname_hash.find(ps);
		if (iter != propname_hash.end()) {
			pindex_map[i] = i;
			propids[i] = iter->second;
		} else {
			tmp_propnames.ppropname[tmp_propnames.count++] = ppropnames->ppropname[i];
			pindex_map[i] = -tmp_propnames.count;
		}
	}
	if (tmp_propnames.count == 0)
		return TRUE;
	if (!exmdb_client::get_named_propids(plogon->dir, b_create,
	    &tmp_propnames, &tmp_propids) ||
	    tmp_propids.size() != tmp_propnames.size())
		return FALSE;	
	for (unsigned int i = 0; i < ppropnames->count; ++i) {
		if (pindex_map[i] >= 0)
			continue;
		propids[i] = tmp_propids[-pindex_map[i]-1];
		if (propids[i] != 0)
			logon_object_cache_propname(plogon,
				propids[i], ppropnames->ppropname + i);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2177: ENOMEM");
	return false;
}

static BOOL gnpwrap(void *obj, BOOL create, const PROPERTY_NAME *pn, uint16_t *pid)
{
	return static_cast<logon_object *>(obj)->get_named_propid(create, pn, pid);
}

const property_groupinfo *logon_object::get_last_property_groupinfo()
{
	auto plogon = this;
	if (m_gpinfo == nullptr)
		m_gpinfo = msgchg_grouping_get_groupinfo(gnpwrap,
		           plogon, msgchg_grouping_get_last_group_id());
	return m_gpinfo.get();
}

const property_groupinfo *
logon_object::get_property_groupinfo(uint32_t group_id) try
{
	auto plogon = this;
	
	if (group_id == msgchg_grouping_get_last_group_id())
		return get_last_property_groupinfo();
	auto node = std::find_if(group_list.begin(), group_list.end(),
	            [&](const property_groupinfo &p) { return p.group_id == group_id; });
	if (node != group_list.end())
		return &*node;
	auto pgpinfo = msgchg_grouping_get_groupinfo(gnpwrap, plogon, group_id);
	if (pgpinfo == nullptr)
		return NULL;
	group_list.push_back(std::move(*pgpinfo));
	return &group_list.back();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1631: ENOMEM");
	return nullptr;
}

BOOL logon_object::get_all_proptags(PROPTAG_ARRAY *pproptags) const
{
	auto plogon = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_store_all_proptags(plogon->dir, &tmp_proptags))
		return FALSE;	
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 25);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;

	static constexpr uint32_t pvt_tags[] = {
		PR_MAILBOX_OWNER_NAME, PR_MAILBOX_OWNER_ENTRYID,
		PR_MAX_SUBMIT_MESSAGE_SIZE, PR_EXTENDED_RULE_SIZE_LIMIT,
		PR_EMS_AB_DISPLAY_NAME_PRINTABLE,
	};
	static constexpr uint32_t tags[] = {
		PR_DELETED_ASSOC_MESSAGE_SIZE,
		PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED,
		PR_DELETED_ASSOC_MSG_COUNT, PR_DELETED_MESSAGE_SIZE,
		PR_DELETED_MESSAGE_SIZE_EXTENDED, PR_DELETED_MSG_COUNT,
		PR_DELETED_NORMAL_MESSAGE_SIZE,
		PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED,
		PR_ASSOC_MESSAGE_SIZE,
		PR_MESSAGE_SIZE, PR_NORMAL_MESSAGE_SIZE,
		PR_CONTENT_COUNT, PR_ASSOC_CONTENT_COUNT,
		PR_EMAIL_ADDRESS, PR_ROOT_ENTRYID, PR_IPM_INBOX_ENTRYID,
		PidTagXSpoolerQueueEntryId, PR_NON_IPM_SUBTREE_ENTRYID,
		PR_EFORMS_REGISTRY_ENTRYID,
	};
	if (plogon->is_private())
		for (auto t : pvt_tags)
			pproptags->emplace_back(t);
	for (auto t : tags)
		pproptags->emplace_back(t);
	return TRUE;
}

static bool lo_is_readonly_prop(const logon_object *plogon, uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return true;
	switch (proptag) {
	case PR_ACCESS_LEVEL:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A:
	case PR_CODE_PAGE_ID:
	case PR_CONTENT_COUNT:
	case PR_DELETE_AFTER_SUBMIT:
	case PR_DELETED_ASSOC_MESSAGE_SIZE:
	case PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED:
	case PR_DELETED_ASSOC_MSG_COUNT:
	case PR_DELETED_MESSAGE_SIZE:
	case PR_DELETED_MESSAGE_SIZE_EXTENDED:
	case PR_DELETED_MSG_COUNT:
	case PR_DELETED_NORMAL_MESSAGE_SIZE:
	case PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED:
	case PR_EMAIL_ADDRESS:
	case PR_EMAIL_ADDRESS_A:
	case PR_EXTENDED_RULE_SIZE_LIMIT:
	case PR_INTERNET_ARTICLE_NUMBER:
	case PR_LOCALE_ID:
	case PR_MAX_SUBMIT_MESSAGE_SIZE:
	case PR_MAILBOX_OWNER_ENTRYID:
	case PR_MAILBOX_OWNER_NAME:
	case PR_MAILBOX_OWNER_NAME_A:
	case PR_MESSAGE_SIZE:
	case PR_MESSAGE_SIZE_EXTENDED:
	case PR_ASSOC_MESSAGE_SIZE:
	case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
	case PR_NORMAL_MESSAGE_SIZE:
	case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
	case PR_OBJECT_TYPE:
	case PR_OOF_STATE:
	case PR_PROHIBIT_RECEIVE_QUOTA:
	case PR_PROHIBIT_SEND_QUOTA:
	case PR_RECORD_KEY:
	case PR_SEARCH_KEY:
	case PR_SORT_LOCALE_ID:
	case PR_STORAGE_QUOTA_LIMIT:
	case PR_STORE_ENTRYID:
	case PR_STORE_OFFLINE:
	case PR_MDB_PROVIDER:
	case PR_STORE_RECORD_KEY:
	case PR_STORE_STATE:
	case PR_STORE_SUPPORT_MASK:
	case PR_TEST_LINE_SPEED:
	case PR_USER_ENTRYID:
	case PR_VALID_FOLDER_MASK:
	case PR_HIERARCHY_SERVER:
	case PR_ROOT_ENTRYID:
	case PR_IPM_INBOX_ENTRYID:
	case PidTagXSpoolerQueueEntryId:
	case PR_NON_IPM_SUBTREE_ENTRYID:
	case PR_EFORMS_REGISTRY_ENTRYID:
		return TRUE;
	}
	return FALSE;
}

static inline const char *account_to_domain(const char *u)
{
	auto at = strchr(u, '@');
	return at != nullptr ? at + 1 : u;
}

static BOOL logon_object_get_calculated_property(const logon_object *plogon,
    uint32_t proptag, void **ppvalue)
{
	void *pvalue;
	char temp_buff[1024];
	static constexpr uint64_t tmp_ll = 0;
	static constexpr uint8_t test_buff[256]{};
	static constexpr BINARY test_bin = {std::size(test_buff), {deconst(test_buff)}};
	
	switch (proptag) {
	case PR_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		if (!exmdb_client::get_store_property(plogon->dir, CP_ACP,
		    PR_MESSAGE_SIZE_EXTENDED, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
	}
	case PR_ASSOC_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		if (!exmdb_client::get_store_property(plogon->dir, CP_ACP,
		    PR_ASSOC_MESSAGE_SIZE_EXTENDED, &pvalue) || pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
	}
	case PR_NORMAL_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		if (!exmdb_client::get_store_property(plogon->dir, CP_ACP,
		    PR_NORMAL_MESSAGE_SIZE_EXTENDED, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
	}
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A: {
		if (!plogon->is_private())
			return FALSE;
		auto dispname = cu_alloc<char>(UADDR_SIZE);
		*ppvalue = dispname;
		if (*ppvalue == nullptr)
			return FALSE;
		if (!mysql_adaptor_get_user_displayname(plogon->account, dispname, UADDR_SIZE))
			return FALSE;	
		auto temp_len = strlen(dispname);
		for (size_t i = 0; i < temp_len; ++i) {
			if (isascii(dispname[i]))
				continue;
			gx_strlcpy(dispname, plogon->account, UADDR_SIZE);
			auto p = strchr(dispname, '@');
			if (p != nullptr)
				*p = '\0';
			break;
		}
		return TRUE;
	}
	case PR_CODE_PAGE_ID: {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		*ppvalue = &pinfo->cpid;
		return TRUE;
	}
	case PR_DELETED_ASSOC_MESSAGE_SIZE:
	case PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED:
	case PR_DELETED_ASSOC_MSG_COUNT:
	case PR_DELETED_MESSAGE_SIZE:
	case PR_DELETED_MESSAGE_SIZE_EXTENDED:
	case PR_DELETED_MSG_COUNT:
	case PR_DELETED_NORMAL_MESSAGE_SIZE:
	case PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED:
		*ppvalue = deconst(&tmp_ll);
		return TRUE;
	case PR_EMAIL_ADDRESS:
	case PR_EMAIL_ADDRESS_A: {
		std::string essdn;
		if (cvt_username_to_essdn(plogon->is_private() ? plogon->account :
		    account_to_domain(plogon->account), g_emsmdb_org_name,
		    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		    essdn) != ecSuccess)
			return false;
		auto tstr = cu_alloc<char>(essdn.size() + 1);
		*ppvalue = tstr;
		if (*ppvalue == nullptr)
			return FALSE;
		gx_strlcpy(tstr, essdn.c_str(), essdn.size() + 1);
		return TRUE;
	}
	case PR_EXTENDED_RULE_SIZE_LIMIT: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		*v = g_max_extrule_len;
		return TRUE;
	}
	case PR_LOCALE_ID: {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		*ppvalue = &pinfo->lcid_string;
		return TRUE;
	}
	case PR_MAILBOX_OWNER_ENTRYID:
		*ppvalue = plogon->is_private() ?
		           common_util_username_to_addressbook_entryid(plogon->account) :
		           common_util_username_to_addressbook_entryid(account_to_domain(plogon->account));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_MAILBOX_OWNER_NAME:
		if (!plogon->is_private())
			return FALSE;
		if (!mysql_adaptor_get_user_displayname(plogon->account,
		    temp_buff, std::size(temp_buff)))
			return FALSE;	
		if ('\0' == temp_buff[0]) {
			auto tstr = cu_alloc<char>(strlen(plogon->account) + 1);
			*ppvalue = tstr;
			if (*ppvalue == nullptr)
				return FALSE;
			strcpy(tstr, plogon->account);
		} else {
			auto tstr = cu_alloc<char>(strlen(temp_buff) + 1);
			*ppvalue = tstr;
			if (*ppvalue == nullptr)
				return FALSE;
			strcpy(tstr, temp_buff);
		}
		return TRUE;
	case PR_MAILBOX_OWNER_NAME_A: {
		if (!plogon->is_private())
			return FALSE;
		if (!mysql_adaptor_get_user_displayname(plogon->account,
		    temp_buff, std::size(temp_buff)))
			return FALSE;	
		auto temp_len = utf8_to_mb_len(temp_buff);
		auto tstr = cu_alloc<char>(temp_len);
		*ppvalue = tstr;
		if (*ppvalue == nullptr)
			return FALSE;
		if (common_util_convert_string(false, temp_buff,
		    tstr, temp_len) < 0)
			return FALSE;	
		if (*tstr == '\0')
			strcpy(tstr, plogon->account);
		return TRUE;
	}
	case PR_MAX_SUBMIT_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		*v = g_max_mail_len;
		return TRUE;
	}
	case PR_SORT_LOCALE_ID: {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		*ppvalue = &pinfo->lcid_sort;
		return TRUE;
	}
	case PR_STORE_RECORD_KEY:
		*ppvalue = common_util_guid_to_binary(plogon->mailbox_guid);
		return TRUE;
	case PR_USER_ENTRYID: {
		auto rpc_info = get_rpc_info();
		*ppvalue = common_util_username_to_addressbook_entryid(rpc_info.username);
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	}
	case PR_ROOT_ENTRYID:
		*ppvalue = cu_fid_to_entryid(plogon, plogon->is_private() ? PRIVATE_FID_ROOT : PUBLIC_FID_ROOT);
		return *ppvalue != nullptr ? TRUE : false;
	case PR_IPM_INBOX_ENTRYID:
		*ppvalue = cu_fid_to_entryid(plogon, plogon->is_private() ? PRIVATE_FID_INBOX : PUBLIC_FID_IPMSUBTREE);
		return *ppvalue != nullptr ? TRUE : false;
	case PidTagXSpoolerQueueEntryId:
		*ppvalue = cu_fid_to_entryid(plogon, plogon->is_private() ?
		           PRIVATE_FID_SPOOLER_QUEUE : PUBLIC_FID_NONIPMSUBTREE);
		return *ppvalue != nullptr ? TRUE : false;
	case PR_NON_IPM_SUBTREE_ENTRYID:
		if (plogon->is_private())
			return false;
		*ppvalue = cu_fid_to_entryid(plogon, PUBLIC_FID_NONIPMSUBTREE);
		return *ppvalue != nullptr ? TRUE : false;
	case PR_EFORMS_REGISTRY_ENTRYID:
		if (plogon->is_private())
			return false;
		*ppvalue = cu_fid_to_entryid(plogon, PUBLIC_FID_EFORMSREGISTRY);
		return *ppvalue != nullptr ? TRUE : false;
	case PR_TEST_LINE_SPEED:
		*ppvalue = deconst(&test_bin);
		return TRUE;
	}
	return FALSE;
}

/**
 * @pproptags:	[in] proptags that are being asked for
 * @ppropvals:	[out] requested property values
 *
 * The output order is not necessarily the same as the input order.
 *
 * PR_HIERARCHY_SERVER:
 *
 * When calling IMsgStore::GetProps(NULL) client-side to obtain the list of
 * available store object property tags, MSMAPI implicitly and unconditionally
 * adds PR_HIERARCHY_SERVER on its own, and also does not merge duplicates if
 * the server had already responded with PR_HIERARCHY_SERVER. (The lack of
 * merging is also apparent with PR_DISPLAY_NAME.) Naturally, MSMAPI also
 * overrides any server-provided value, and instead presents the value from the
 * <Server> element of a recent Autodiscover response.
 *
 * When OL2021 accesses EXC2019, oxdisco _omits_ EXCH/EXPR protocol sections
 * normally, and thus there is also no <Server>. Subsequently, there is no
 * PR_HIERARCHY_SERVER property on the store visible with MFCMAPI, which means
 * EXC2019 also does not synthesize anything server-side in any way.
 */
BOOL logon_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals) const
{
	static const uint32_t err_code = ecError, invalid_code = ecInvalidParam;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	PROPTAG_ARRAY tmp_proptags = {0, cu_alloc<uint32_t>(pproptags->count)};
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	auto plogon = this;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];

		if (PROP_ID(tag) == PROP_ID(PR_HIERARCHY_SERVER))
			ppropvals->emplace_back(CHANGE_PROP_TYPE(tag, PT_ERROR), &invalid_code);
		else if (!logon_object_get_calculated_property(plogon, tag, &pvalue))
			tmp_proptags.emplace_back(tag);
		else if (pvalue != nullptr)
			ppropvals->emplace_back(tag, pvalue);
		else
			ppropvals->emplace_back(CHANGE_PROP_TYPE(tag, PT_ERROR), &err_code);
	}
	if (tmp_proptags.count == 0)
		return TRUE;

	TPROPVAL_ARRAY tmp_propvals;
	if (!exmdb_client::get_store_properties(plogon->dir,
	    pinfo->cpid, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (tmp_propvals.count == 0)
		return TRUE;
	memcpy(ppropvals->ppropval + ppropvals->count,
		tmp_propvals.ppropval,
		sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

BOOL logon_object::set_properties(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems) try
{
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	TPROPVAL_ARRAY tmp_propvals = {0, cu_alloc<TAGGED_PROPVAL>(ppropvals->count)};
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	std::vector<uint16_t> poriginal_indices;
	auto plogon = this;
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		const auto &pv = ppropvals->ppropval[i];
		if (lo_is_readonly_prop(plogon, pv.proptag)) {
			pproblems->emplace_back(i, pv.proptag, ecAccessDenied);
		} else {
			tmp_propvals.ppropval[tmp_propvals.count++] = pv;
			poriginal_indices.push_back(i);
		}
	}
	if (tmp_propvals.count == 0)
		return TRUE;
	PROBLEM_ARRAY tmp_problems;
	if (!exmdb_client::set_store_properties(plogon->dir,
	    pinfo->cpid, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count == 0)
		return TRUE;
	tmp_problems.transform(poriginal_indices);
	*pproblems += std::move(tmp_problems);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1744: ENOMEM");
	return false;
}

BOOL logon_object::remove_properties(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems)
{
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	PROPTAG_ARRAY tmp_proptags = {0, cu_alloc<uint32_t>(pproptags->count)};
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	auto plogon = this;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (lo_is_readonly_prop(plogon, tag))
			pproblems->emplace_back(i, tag, ecAccessDenied);
		else
			tmp_proptags.emplace_back(tag);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	return exmdb_client::remove_store_properties(plogon->dir, &tmp_proptags);
}

/**
 * Returns the effective username to use for permission checking.
 * %nullptr is returned when we are the store owner ("root").
 */
const char *logon_object::eff_user() const
{
	if (logon_mode == logon_mode::owner)
		return STORE_OWNER_GRANTED;
	/*
	 * If rpcinfo is empty for some unexplained reason, yield a username
	 * that fails most permission checks.
	 */
	return znul(get_rpc_info().username);
}

/**
 * Returns the effective username to use for operations that do some kind of
 * state tracking (or if there is a special need to treat private store
 * delegate access and private store guest access differently from public store
 * guest access).
 */
const char *logon_object::readstate_user() const
{
	return is_private() ? nullptr : get_rpc_info().username;
}
