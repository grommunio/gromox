// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cctype>
#include <cstdint>
#include <memory>
#include <utility>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/int_hash.hpp>
#include <gromox/proc_common.h>
#include <gromox/str_hash.hpp>
#include "emsmdb_interface.h"
#include "msgchg_grouping.h"
#include "logon_object.h"
#include "exmdb_client.h"
#include "common_util.h"
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define HGROWING_SIZE									0x500

using namespace gromox;

static BOOL logon_object_enlarge_propid_hash(logon_object *plogon)
{
	int tmp_id;
	void *ptmp_value;
	auto phash = INT_HASH_TABLE::create(plogon->ppropid_hash->capacity +
	                        HGROWING_SIZE, sizeof(PROPERTY_NAME));
	if (phash == nullptr)
		return FALSE;
	auto iter = plogon->ppropid_hash->make_iter();
	for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		ptmp_value = int_hash_iter_get_value(iter, &tmp_id);
		phash->add(tmp_id, ptmp_value);
	}
	int_hash_iter_free(iter);
	plogon->ppropid_hash = std::move(phash);
	return TRUE;
}

static BOOL logon_object_enlarge_propname_hash(logon_object *plogon)
{
	void *ptmp_value;
	char tmp_string[256];
	
	auto phash = STR_HASH_TABLE::create(plogon->ppropname_hash->capacity
				+ HGROWING_SIZE, sizeof(uint16_t), NULL);
	if (phash == nullptr)
		return FALSE;
	auto iter = plogon->ppropname_hash->make_iter();
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ptmp_value = str_hash_iter_get_value(iter, tmp_string);
		phash->add(tmp_string, ptmp_value);
	}
	str_hash_iter_free(iter);
	plogon->ppropname_hash = std::move(phash);
	return TRUE;
}

static BOOL logon_object_cache_propname(logon_object *plogon,
	uint16_t propid, const PROPERTY_NAME *ppropname)
{
	PROPERTY_NAME tmp_name;
	
	if (NULL == plogon->ppropid_hash) {
		plogon->ppropid_hash = INT_HASH_TABLE::create(HGROWING_SIZE,
		                       sizeof(PROPERTY_NAME));
		if (plogon->ppropid_hash == nullptr)
			return FALSE;
	}
	if (NULL == plogon->ppropname_hash) {
		plogon->ppropname_hash = STR_HASH_TABLE::create(HGROWING_SIZE, sizeof(uint16_t), nullptr);
		if (NULL == plogon->ppropname_hash) {
			plogon->ppropid_hash.reset();
			return FALSE;
		}
	}
	tmp_name.kind = ppropname->kind;
	tmp_name.guid = ppropname->guid;
	char tmp_string[NP_STRBUF_SIZE], tmp_guid[GUIDSTR_SIZE];
	guid_to_string(&ppropname->guid, tmp_guid, arsizeof(tmp_guid));
	switch (ppropname->kind) {
	case MNID_ID:
		tmp_name.lid = ppropname->lid;
		tmp_name.pname = NULL;
		snprintf(tmp_string, arsizeof(tmp_string), "%s:lid:%u", tmp_guid, ppropname->lid);
		break;
	case MNID_STRING:
		tmp_name.lid = 0;
		tmp_name.pname = strdup(ppropname->pname);
		if (NULL == tmp_name.pname) {
			return FALSE;
		}
		snprintf(tmp_string, arsizeof(tmp_string), "%s:name:%s", tmp_guid, ppropname->pname);
		break;
	default:
		return FALSE;
	}
	if (plogon->ppropid_hash->query1(propid) == nullptr) {
		if (plogon->ppropid_hash->add(propid, &tmp_name) != 1) {
			if (FALSE == logon_object_enlarge_propid_hash(plogon) ||
			    plogon->ppropid_hash->add(propid, &tmp_name) != 1) {
				if (NULL != tmp_name.pname) {
					free(tmp_name.pname);
				}
				return FALSE;
			}
		}
	} else {
		if (NULL != tmp_name.pname) {
			free(tmp_name.pname);
		}
	}
	HX_strlower(tmp_string);
	if (plogon->ppropname_hash->query1(tmp_string) == nullptr &&
	    plogon->ppropname_hash->add(tmp_string, &propid) != 1)
		if (!logon_object_enlarge_propname_hash(plogon) ||
		    plogon->ppropname_hash->add(tmp_string, &propid) != 1)
			return FALSE;
	return TRUE;
}

logon_object::logon_object()
{
	double_list_init(&group_list);
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

logon_object::~logon_object()
{
	DOUBLE_LIST_NODE *pnode;
	PROPERTY_NAME *ppropname;

	auto plogon = this;
	if (m_gpinfo != nullptr)
		property_groupinfo_free(m_gpinfo);
	while ((pnode = double_list_pop_front(&plogon->group_list)) != nullptr) {
		property_groupinfo_free(static_cast<PROPERTY_GROUPINFO *>(pnode->pdata));
		free(pnode);
	}
	double_list_free(&plogon->group_list);
	if (NULL != plogon->ppropid_hash) {
		auto piter = plogon->ppropid_hash->make_iter();
		for (int_hash_iter_begin(piter); !int_hash_iter_done(piter);
			int_hash_iter_forward(piter)) {
			ppropname = static_cast<PROPERTY_NAME *>(int_hash_iter_get_value(piter, nullptr));
			switch( ppropname->kind) {
			case MNID_STRING:
				free(ppropname->pname);
				break;
			}
		}
		int_hash_iter_free(piter);
		plogon->ppropid_hash.reset();
	}
	plogon->ppropname_hash.reset();
}

GUID logon_object::guid() const
{
	return check_private() ? rop_util_make_user_guid(account_id) :
	       rop_util_make_domain_guid(account_id);
}

BOOL logon_object::get_named_propname(uint16_t propid, PROPERTY_NAME *ppropname)
{
	PROPERTY_NAME *pname;
	
	if (propid < 0x8000) {
		rop_util_get_common_pset(PS_MAPI, &ppropname->guid);
		ppropname->kind = MNID_ID;
		ppropname->lid = propid;
	}
	auto plogon = this;
	if (NULL != plogon->ppropid_hash) {
		pname = plogon->ppropid_hash->query<PROPERTY_NAME>(propid);
		if (NULL != pname) {
			*ppropname = *pname;
			return TRUE;
		}
	}
	if (FALSE == exmdb_client_get_named_propname(
		plogon->dir, propid, ppropname)) {
		return FALSE;	
	}
	if (ppropname->kind == MNID_ID || ppropname->kind == MNID_STRING)
		logon_object_cache_propname(plogon, propid, ppropname);
	return TRUE;
}

BOOL logon_object::get_named_propnames(const PROPID_ARRAY *ppropids,
    PROPNAME_ARRAY *ppropnames)
{
	int i;
	PROPERTY_NAME *pname;
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
			rop_util_get_common_pset(PS_MAPI,
				&ppropnames->ppropname[i].guid);
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].lid = ppropids->ppropid[i];
			pindex_map[i] = i;
			continue;
		}
		pname = plogon->ppropid_hash == nullptr ? nullptr :
		        plogon->ppropid_hash->query<PROPERTY_NAME>(ppropids->ppropid[i]);
		if (NULL != pname) {
			pindex_map[i] = i;
			ppropnames->ppropname[i] = *pname;
		} else {
			tmp_propids.ppropid[tmp_propids.count++] = ppropids->ppropid[i];
			pindex_map[i] = -tmp_propids.count;
		}
	}
	if (0 == tmp_propids.count) {
		return TRUE;
	}
	if (FALSE == exmdb_client_get_named_propnames(
		plogon->dir, &tmp_propids, &tmp_propnames)) {
		return FALSE;	
	}
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
	GUID guid;
	
	rop_util_get_common_pset(PS_MAPI, &guid);
	if (ppropname->guid == guid) {
		*ppropid = ppropname->kind == MNID_ID ? ppropname->lid : 0;
		return TRUE;
	}
	char tmp_string[NP_STRBUF_SIZE], tmp_guid[GUIDSTR_SIZE];
	guid_to_string(&ppropname->guid, tmp_guid, arsizeof(tmp_guid));
	switch (ppropname->kind) {
	case MNID_ID:
		snprintf(tmp_string, arsizeof(tmp_string), "%s:lid:%u", tmp_guid, ppropname->lid);
		break;
	case MNID_STRING:
		snprintf(tmp_string, arsizeof(tmp_string), "%s:name:%s", tmp_guid, ppropname->pname);
		HX_strlower(tmp_string);
		break;
	default:
		*ppropid = 0;
		return TRUE;
	}
	auto plogon = this;
	if (NULL != plogon->ppropname_hash) {
		auto pid = plogon->ppropname_hash->query<uint16_t>(tmp_string);
		if (NULL != pid) {
			*ppropid = *pid;
			return TRUE;
		}
	}
	if (FALSE == exmdb_client_get_named_propid(
		plogon->dir, b_create, ppropname, ppropid)) {
		return FALSE;
	}
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
	GUID guid;
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	if (0 == ppropnames->count) {
		ppropids->count = 0;
		return TRUE;
	}
	rop_util_get_common_pset(PS_MAPI, &guid);
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
		if (ppropnames->ppropname[i].guid == guid) {
			ppropids->ppropid[i] = ppropnames->ppropname[i].kind == MNID_ID ?
					       ppropnames->ppropname[i].lid : 0;
			pindex_map[i] = i;
			continue;
		}
		char tmp_string[NP_STRBUF_SIZE], tmp_guid[GUIDSTR_SIZE];
		guid_to_string(&ppropnames->ppropname[i].guid, tmp_guid, arsizeof(tmp_guid));
		switch (ppropnames->ppropname[i].kind) {
		case MNID_ID:
			snprintf(tmp_string, arsizeof(tmp_string), "%s:lid:%u",
			         tmp_guid, ppropnames->ppropname[i].lid);
			break;
		case MNID_STRING:
			snprintf(tmp_string, arsizeof(tmp_string), "%s:name:%s",
				tmp_guid, ppropnames->ppropname[i].pname);
			HX_strlower(tmp_string);
			break;
		default:
			ppropids->ppropid[i] = 0;
			pindex_map[i] = i;
			continue;
		}
		auto pid = plogon->ppropname_hash == nullptr ? nullptr :
		           plogon->ppropname_hash->query<uint16_t>(tmp_string);
		if (NULL != pid) {
			pindex_map[i] = i;
			ppropids->ppropid[i] = *pid;
		} else {
			tmp_propnames.ppropname[tmp_propnames.count++] = ppropnames->ppropname[i];
			pindex_map[i] = -tmp_propnames.count;
		}
	}
	if (0 == tmp_propnames.count) {
		return TRUE;
	}
	if (FALSE == exmdb_client_get_named_propids(plogon->dir,
		b_create, &tmp_propnames, &tmp_propids)) {
		return FALSE;	
	}
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

PROPERTY_GROUPINFO *logon_object::get_last_property_groupinfo()
{
	auto plogon = this;
	if (m_gpinfo == nullptr)
		m_gpinfo = msgchg_grouping_get_groupinfo(gnpwrap,
		           plogon, msgchg_grouping_get_last_group_id());
	return m_gpinfo;
}

PROPERTY_GROUPINFO *logon_object::get_property_groupinfo(uint32_t group_id)
{
	auto plogon = this;
	DOUBLE_LIST_NODE *pnode;
	PROPERTY_GROUPINFO *pgpinfo;
	
	if (group_id == msgchg_grouping_get_last_group_id()) {
		return get_last_property_groupinfo();
	}
	for (pnode=double_list_get_head(&plogon->group_list); NULL!=pnode;
		pnode=double_list_get_after(&plogon->group_list, pnode)) {
		pgpinfo = (PROPERTY_GROUPINFO*)pnode->pdata;
		if (pgpinfo->group_id == group_id) {
			return pgpinfo;
		}
	}
	pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		return NULL;
	}
	pgpinfo = msgchg_grouping_get_groupinfo(gnpwrap, plogon, group_id);
	if (NULL == pgpinfo) {
		free(pnode);
		return NULL;
	}
	pnode->pdata = pgpinfo;
	double_list_append_as_tail(&plogon->group_list, pnode);
	return pgpinfo;
}

BOOL logon_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto plogon = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (FALSE == exmdb_client_get_store_all_proptags(
		plogon->dir, &tmp_proptags)) {
		return FALSE;	
	}
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 25);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	if (plogon->check_private()) {
		pproptags->pproptag[pproptags->count++] = PR_MAILBOX_OWNER_NAME;
		pproptags->pproptag[pproptags->count++] = PR_MAILBOX_OWNER_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_MAX_SUBMIT_MESSAGE_SIZE;
		pproptags->pproptag[pproptags->count++] = PR_EMAIL_ADDRESS;
		pproptags->pproptag[pproptags->count++] = PR_EMS_AB_DISPLAY_NAME_PRINTABLE;
	} else {
		pproptags->pproptag[pproptags->count++] = PROP_TAG_HIERARCHYSERVER;
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
	pproptags->pproptag[pproptags->count++] = PROP_TAG_EXTENDEDRULESIZELIMIT;
	pproptags->pproptag[pproptags->count++] = PR_ASSOC_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_NORMAL_MESSAGE_SIZE;
	pproptags->pproptag[pproptags->count++] = PR_USER_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PROP_TAG_CONTENTCOUNT;
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
	case PROP_TAG_CODEPAGEID:
	case PROP_TAG_CONTENTCOUNT:
	case PROP_TAG_DELETEAFTERSUBMIT:
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
	case PROP_TAG_EXTENDEDRULESIZELIMIT:
	case PR_INTERNET_ARTICLE_NUMBER:
	case PR_LOCALE_ID:
	case PR_MAX_SUBMIT_MESSAGE_SIZE:
	case PR_MAILBOX_OWNER_ENTRYID:
	case PR_MAILBOX_OWNER_NAME:
	case PROP_TAG_MAILBOXOWNERNAME_STRING8:
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
	case PROP_TAG_SORTLOCALEID:
	case PR_STORAGE_QUOTA_LIMIT:
	case PR_STORE_ENTRYID:
	case PR_STORE_OFFLINE:
	case PR_MDB_PROVIDER:
	case PR_STORE_RECORD_KEY:
	case PR_STORE_STATE:
	case PR_STORE_SUPPORT_MASK:
	case PR_TEST_LINE_SPEED:
	case PR_USER_ENTRYID:
	case PROP_TAG_VALIDFOLDERMASK:
	case PROP_TAG_HIERARCHYSERVER:
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
	case PR_MESSAGE_SIZE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!exmdb_client_get_store_property(plogon->dir, 0,
		    PR_MESSAGE_SIZE_EXTENDED, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		**reinterpret_cast<uint32_t **>(ppvalue) = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(0x7FFFFFFF));
		return TRUE;
	case PR_ASSOC_MESSAGE_SIZE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!exmdb_client_get_store_property(plogon->dir, 0,
		    PR_ASSOC_MESSAGE_SIZE_EXTENDED, &pvalue) || pvalue == nullptr)
			return FALSE;	
		**reinterpret_cast<uint32_t **>(ppvalue) = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(0x7FFFFFFF));
		return TRUE;
	case PR_NORMAL_MESSAGE_SIZE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!exmdb_client_get_store_property(plogon->dir, 0,
		    PR_NORMAL_MESSAGE_SIZE_EXTENDED, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		**reinterpret_cast<uint32_t **>(ppvalue) = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(0x7FFFFFFF));
		return TRUE;
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A: {
		if (!plogon->check_private())
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
	case PROP_TAG_CODEPAGEID: {
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
		if (plogon->check_private()) {
			if (!common_util_username_to_essdn(plogon->account,
			    temp_buff, GX_ARRAY_SIZE(temp_buff)))
				return FALSE;	
		} else {
			if (!common_util_public_to_essdn(plogon->account,
			    temp_buff, GX_ARRAY_SIZE(temp_buff)))
				return FALSE;	
		}
		auto tstr = cu_alloc<char>(strlen(temp_buff) + 1);
		*ppvalue = tstr;
		if (NULL == *ppvalue) {
			return FALSE;
		}
		strcpy(tstr, temp_buff);
		return TRUE;
	}
	case PROP_TAG_EXTENDEDRULESIZELIMIT:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = common_util_get_param(
						COMMON_UTIL_MAX_EXTRULE_LENGTH);
		return TRUE;
	case PROP_TAG_HIERARCHYSERVER: {
		if (plogon->check_private())
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
		if (!plogon->check_private())
			return FALSE;
		*ppvalue = common_util_username_to_addressbook_entryid(
												plogon->account);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	case PR_MAILBOX_OWNER_NAME:
		if (!plogon->check_private())
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
	case PROP_TAG_MAILBOXOWNERNAME_STRING8: {
		if (!plogon->check_private())
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
		if (common_util_convert_string(FALSE, temp_buff,
		    tstr, temp_len) < 0)
			return FALSE;	
		if (*tstr == '\0')
			strcpy(tstr, plogon->account);
		return TRUE;
	}
	case PR_MAX_SUBMIT_MESSAGE_SIZE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = common_util_get_param(
							COMMON_UTIL_MAX_MAIL_LENGTH);
		return TRUE;
	case PROP_TAG_SORTLOCALEID: {
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
		if (TRUE == logon_object_get_calculated_property(
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
	if (FALSE == exmdb_client_get_store_properties(plogon->dir,
		pinfo->cpid, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
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
	uint16_t *poriginal_indices;
	
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
	poriginal_indices = cu_alloc<uint16_t>(ppropvals->count);
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
	if (FALSE == exmdb_client_set_store_properties(plogon->dir,
		pinfo->cpid, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
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
	if (FALSE == exmdb_client_remove_store_properties(
		plogon->dir, &tmp_proptags)) {
		return FALSE;	
	}
	return TRUE;
}
