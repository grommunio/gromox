// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/msgchg_grouping.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "logon_object.h"

using namespace std::string_literals;
using namespace gromox;

static bool propname_to_packed(const PROPERTY_NAME &n, char *dst, size_t z)
{
	char guid[GUIDSTR_SIZE];
	n.guid.to_str(guid, arsizeof(guid));
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
	if (!propname_to_packed(*ppropname, s, arsizeof(s)))
		return false;
	plogon->propid_hash.emplace(propid, *ppropname);
	plogon->propname_hash.emplace(s, propid);
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1633: ENOMEM\n");
	return false;
}

std::unique_ptr<logon_object> logon_object::create(uint8_t logon_flags,
	uint32_t open_flags, int logon_mode, int account_id,
	const char *account, const char *dir, GUID mailbox_guid)
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
	gx_strlcpy(plogon->account, account, GX_ARRAY_SIZE(plogon->account));
	gx_strlcpy(plogon->dir, dir, GX_ARRAY_SIZE(plogon->dir));
	plogon->mailbox_guid = mailbox_guid;
	return plogon;
}

GUID logon_object::guid() const
{
	return is_private() ? rop_util_make_user_guid(account_id) :
	       rop_util_make_domain_guid(account_id);
}

BOOL logon_object::get_named_propname(uint16_t propid, PROPERTY_NAME *ppropname)
{
	if (propid < 0x8000) {
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
	if (!exmdb_client_get_named_propname(plogon->dir, propid, ppropname))
		return FALSE;	
	if (ppropname->kind == MNID_ID || ppropname->kind == MNID_STRING)
		logon_object_cache_propname(plogon, propid, ppropname);
	return TRUE;
}

BOOL logon_object::get_named_propnames(const PROPID_ARRAY *ppropids,
    PROPNAME_ARRAY *ppropnames)
{
	int i;
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	if (0 == ppropids->count) {
		ppropnames->count = 0;
		return TRUE;
	}
	auto pindex_map = cu_alloc<int>(ppropids->count);
	if (NULL == pindex_map) {
		return FALSE;
	}
	ppropnames->ppropname = cu_alloc<PROPERTY_NAME>(ppropids->count);
	if (NULL == ppropnames->ppropname) {
		return FALSE;
	}
	ppropnames->count = ppropids->count;
	tmp_propids.count = 0;
	tmp_propids.ppropid = cu_alloc<uint16_t>(ppropids->count);
	if (NULL == tmp_propids.ppropid) {
		return FALSE;
	}
	auto plogon = this;
	for (i=0; i<ppropids->count; i++) {
		if (ppropids->ppropid[i] < 0x8000) {
			ppropnames->ppropname[i].guid = PS_MAPI;
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].lid = ppropids->ppropid[i];
			pindex_map[i] = i;
			continue;
		}
		auto iter = propid_hash.find(ppropids->ppropid[i]);
		if (iter != propid_hash.end()) {
			pindex_map[i] = i;
			ppropnames->ppropname[i] = static_cast<PROPERTY_NAME>(iter->second);
		} else {
			tmp_propids.ppropid[tmp_propids.count++] = ppropids->ppropid[i];
			pindex_map[i] = -tmp_propids.count;
		}
	}
	if (0 == tmp_propids.count) {
		return TRUE;
	}
	if (!exmdb_client_get_named_propnames(plogon->dir,
	    &tmp_propids, &tmp_propnames))
		return FALSE;	
	for (i=0; i<ppropids->count; i++) {
		if (pindex_map[i] >= 0)
			continue;
		ppropnames->ppropname[i] = tmp_propnames.ppropname[-pindex_map[i]-1];
		if (ppropnames->ppropname[i].kind == MNID_ID ||
		    ppropnames->ppropname[i].kind == MNID_STRING)
			logon_object_cache_propname(plogon,
				ppropids->ppropid[i], ppropnames->ppropname + i);
	}
	return TRUE;
}

BOOL logon_object::get_named_propid(BOOL b_create,
    const PROPERTY_NAME *ppropname, uint16_t *ppropid)
{
	if (ppropname->guid == PS_MAPI) {
		*ppropid = ppropname->kind == MNID_ID ? ppropname->lid : 0;
		return TRUE;
	}
	char ps[NP_STRBUF_SIZE];
	if (!propname_to_packed(*ppropname, ps, arsizeof(ps))) {
		*ppropid = 0;
		return TRUE;
	}
	auto plogon = this;
	auto iter = propname_hash.find(ps);
	if (iter != propname_hash.end()) {
		*ppropid = iter->second;
		return TRUE;
	}
	if (!exmdb_client_get_named_propid(plogon->dir, b_create,
	    ppropname, ppropid))
		return FALSE;
	if (0 == *ppropid) {
		return TRUE;
	}
	logon_object_cache_propname(plogon, *ppropid, ppropname);
	return TRUE;
}

BOOL logon_object::get_named_propids(BOOL b_create,
    const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids)
{
	int i;
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	if (0 == ppropnames->count) {
		ppropids->count = 0;
		return TRUE;
	}
	auto pindex_map = cu_alloc<int>(ppropnames->count);
	if (NULL == pindex_map) {
		return FALSE;
	}
	ppropids->count = ppropnames->count;
	ppropids->ppropid = cu_alloc<uint16_t>(ppropnames->count);
	if (NULL == ppropids->ppropid) {
		return FALSE;
	}
	tmp_propnames.count = 0;
	tmp_propnames.ppropname = cu_alloc<PROPERTY_NAME>(ppropnames->count);
	if (NULL == tmp_propnames.ppropname) {
		return FALSE;
	}
	auto plogon = this;
	for (i=0; i<ppropnames->count; i++) {
		if (ppropnames->ppropname[i].guid == PS_MAPI) {
			ppropids->ppropid[i] = ppropnames->ppropname[i].kind == MNID_ID ?
					       ppropnames->ppropname[i].lid : 0;
			pindex_map[i] = i;
			continue;
		}
		char ps[NP_STRBUF_SIZE];
		if (!propname_to_packed(ppropnames->ppropname[i], ps, arsizeof(ps))) {
			ppropids->ppropid[i] = 0;
			pindex_map[i] = i;
			continue;
		}
		auto iter = propname_hash.find(ps);
		if (iter != propname_hash.end()) {
			pindex_map[i] = i;
			ppropids->ppropid[i] = iter->second;
		} else {
			tmp_propnames.ppropname[tmp_propnames.count++] = ppropnames->ppropname[i];
			pindex_map[i] = -tmp_propnames.count;
		}
	}
	if (0 == tmp_propnames.count) {
		return TRUE;
	}
	if (!exmdb_client_get_named_propids(plogon->dir, b_create,
	    &tmp_propnames, &tmp_propids))
		return FALSE;	
	for (i=0; i<ppropnames->count; i++) {
		if (pindex_map[i] >= 0)
			continue;
		ppropids->ppropid[i] = tmp_propids.ppropid[-pindex_map[i]-1];
		if (0 != ppropids->ppropid[i]) {
			logon_object_cache_propname(plogon,
				ppropids->ppropid[i], ppropnames->ppropname + i);
		}
	}
	return TRUE;
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
	
	if (group_id == msgchg_grouping_get_last_group_id()) {
		return get_last_property_groupinfo();
	}
	auto node = std::find_if(group_list.begin(), group_list.end(),
	            [&](const property_groupinfo &p) { return p.group_id == group_id; });
	if (node != group_list.end())
		return &*node;
	auto pgpinfo = msgchg_grouping_get_groupinfo(gnpwrap, plogon, group_id);
	if (NULL == pgpinfo) {
		return NULL;
	}
	group_list.push_back(std::move(*pgpinfo));
	return &group_list.back();
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1631: ENOMEM\n");
	return nullptr;
}

BOOL logon_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto plogon = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client_get_store_all_proptags(plogon->dir, &tmp_proptags))
		return FALSE;	
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 25);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	if (plogon->is_private()) {
		pproptags->pproptag[pproptags->count++] = PR_MAILBOX_OWNER_NAME;
		pproptags->pproptag[pproptags->count++] = PR_MAILBOX_OWNER_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_MAX_SUBMIT_MESSAGE_SIZE;
		pproptags->pproptag[pproptags->count++] = PR_EMAIL_ADDRESS;
		pproptags->pproptag[pproptags->count++] = PR_EMS_AB_DISPLAY_NAME_PRINTABLE;
	} else {
		pproptags->pproptag[pproptags->count++] = PR_HIERARCHY_SERVER;
		/* TODO: For PR_EMAIL_ADDRESS,
		check if mail address of public folder exists. */
	}
	pproptags->pproptag[pproptags->count++] = PR_DELETED_ASSOC_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED;
	pproptags->pproptag[pproptags->count++] = PR_DELETED_ASSOC_MSG_COUNT;
	pproptags->pproptag[pproptags->count++] = PR_DELETED_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_DELETED_MESSAGE_SIZE_EXTENDED;
	pproptags->pproptag[pproptags->count++] = PR_DELETED_MSG_COUNT;
	pproptags->pproptag[pproptags->count++] = PR_DELETED_NORMAL_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED;
	pproptags->pproptag[pproptags->count++] = PR_EXTENDED_RULE_SIZE_LIMIT;
	pproptags->pproptag[pproptags->count++] = PR_ASSOC_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_NORMAL_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_USER_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_CONTENT_COUNT;
	pproptags->pproptag[pproptags->count++] = PR_ASSOC_CONTENT_COUNT;
	pproptags->pproptag[pproptags->count++] = PR_TEST_LINE_SPEED;
	return TRUE;
}

static BOOL lo_check_readonly_property(const logon_object *plogon, uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
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
		return TRUE;
	}
	return FALSE;
}

static BOOL logon_object_get_calculated_property(logon_object *plogon,
    uint32_t proptag, void **ppvalue)
{
	void *pvalue;
	char temp_buff[1024];
	static constexpr uint64_t tmp_ll = 0;
	static constexpr uint8_t test_buff[256]{};
	static constexpr BINARY test_bin = {arsizeof(test_buff), {deconst(test_buff)}};
	
	switch (proptag) {
	case PR_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!exmdb_client_get_store_property(plogon->dir, 0,
		    PR_MESSAGE_SIZE_EXTENDED, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
	}
	case PR_ASSOC_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!exmdb_client_get_store_property(plogon->dir, 0,
		    PR_ASSOC_MESSAGE_SIZE_EXTENDED, &pvalue) || pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
	}
	case PR_NORMAL_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!exmdb_client_get_store_property(plogon->dir, 0,
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
		auto dispname = cu_alloc<char>(256);
		*ppvalue = dispname;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!common_util_get_user_displayname(plogon->account, dispname, 256))
			return FALSE;	
		auto temp_len = strlen(dispname);
		for (size_t i = 0; i < temp_len; ++i) {
			if (!isascii(dispname[i])) {
				strcpy(dispname, plogon->account);
				auto p = strchr(dispname, '@');
				if (p != nullptr)
					*p = '\0';
				break;
			}
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
		bool ok = plogon->is_private() ?
		          common_util_username_to_essdn(plogon->account, temp_buff, arsizeof(temp_buff)) :
		          common_util_public_to_essdn(plogon->account, temp_buff, arsizeof(temp_buff));
		if (!ok)
			return false;
		auto tstr = cu_alloc<char>(strlen(temp_buff) + 1);
		*ppvalue = tstr;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		strcpy(tstr, temp_buff);
		return TRUE;
	}
	case PR_EXTENDED_RULE_SIZE_LIMIT: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*v = g_max_extrule_len;
		return TRUE;
	}
	case PR_HIERARCHY_SERVER: {
		if (plogon->is_private())
			return FALSE;
		common_util_get_domain_server(plogon->account, temp_buff);
		auto tstr = cu_alloc<char>(strlen(temp_buff) + 1);
		*ppvalue = tstr;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		strcpy(tstr, temp_buff);
		return TRUE;
	}
	case PR_LOCALE_ID: {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		*ppvalue = &pinfo->lcid_string;
		return TRUE;
	}
	case PR_MAILBOX_OWNER_ENTRYID:
		if (!plogon->is_private())
			return FALSE;
		*ppvalue = common_util_username_to_addressbook_entryid(
												plogon->account);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	case PR_MAILBOX_OWNER_NAME:
		if (!plogon->is_private())
			return FALSE;
		if (!common_util_get_user_displayname(plogon->account,
		    temp_buff, arsizeof(temp_buff)))
			return FALSE;	
		if ('\0' == temp_buff[0]) {
			auto tstr = cu_alloc<char>(strlen(plogon->account) + 1);
			*ppvalue = tstr;
			if (NULL == *ppvalue) {
				return FALSE;
			}
			strcpy(tstr, plogon->account);
		} else {
			auto tstr = cu_alloc<char>(strlen(temp_buff) + 1);
			*ppvalue = tstr;
			if (NULL == *ppvalue) {
				return FALSE;
			}
			strcpy(tstr, temp_buff);
		}
		return TRUE;
	case PR_MAILBOX_OWNER_NAME_A: {
		if (!plogon->is_private())
			return FALSE;
		if (!common_util_get_user_displayname(plogon->account,
		    temp_buff, arsizeof(temp_buff)))
			return FALSE;	
		auto temp_len = 2 * strlen(temp_buff) + 1;
		auto tstr = cu_alloc<char>(temp_len);
		*ppvalue = tstr;
		if (NULL == *ppvalue) {
			return FALSE;
		}
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
		if (NULL == *ppvalue) {
			return FALSE;
		}
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
		*ppvalue = common_util_username_to_addressbook_entryid(
											rpc_info.username);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	}
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
 */
BOOL logon_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint32_t err_code = ecError;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	ppropvals->count = 0;
	auto plogon = this;
	for (i=0; i<pproptags->count; i++) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		if (logon_object_get_calculated_property(
			plogon, pproptags->pproptag[i], &pvalue)) {
			if (NULL != pvalue) {
				pv.proptag = pproptags->pproptag[i];
				pv.pvalue = pvalue;
			} else {
				pv.proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_ERROR);
				pv.pvalue = deconst(&err_code);
			}
			ppropvals->count ++;
		} else {
			tmp_proptags.pproptag[tmp_proptags.count++] = pproptags->pproptag[i];
		}
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client_get_store_properties(plogon->dir,
	    pinfo->cpid, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	memcpy(ppropvals->ppropval + ppropvals->count,
		tmp_propvals.ppropval,
		sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

BOOL logon_object::set_properties(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems)
{
	int i;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	auto poriginal_indices = cu_alloc<uint16_t>(ppropvals->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	auto plogon = this;
	for (i=0; i<ppropvals->count; i++) {
		if (lo_check_readonly_property(plogon, ppropvals->ppropval[i].proptag)) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
		} else {
			tmp_propvals.ppropval[tmp_propvals.count] =
									ppropvals->ppropval[i];
			poriginal_indices[tmp_propvals.count++] = i;
		}
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	if (!exmdb_client_set_store_properties(plogon->dir,
	    pinfo->cpid, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (0 == tmp_problems.count) {
		return TRUE;
	}
	tmp_problems.transform(poriginal_indices);
	*pproblems += std::move(tmp_problems);
	return TRUE;
}

BOOL logon_object::remove_properties(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems)
{
	int i;
	PROPTAG_ARRAY tmp_proptags;
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	auto plogon = this;
	for (i=0; i<pproptags->count; i++) {
		if (lo_check_readonly_property(plogon, pproptags->pproptag[i])) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
									pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
		} else {
			tmp_proptags.pproptag[tmp_proptags.count++] = pproptags->pproptag[i];
		}
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	return exmdb_client_remove_store_properties(plogon->dir, &tmp_proptags);
}
