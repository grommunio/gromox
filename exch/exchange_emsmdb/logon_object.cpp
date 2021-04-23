// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
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

static BOOL logon_object_enlarge_propid_hash(
	LOGON_OBJECT *plogon)
{
	int tmp_id;
	void *ptmp_value;
	INT_HASH_ITER *iter;
	INT_HASH_TABLE *phash = int_hash_init(plogon->ppropid_hash->capacity +
	                        HGROWING_SIZE, sizeof(PROPERTY_NAME));
	if (NULL == phash) {
		return FALSE;
	}
	iter = int_hash_iter_init(plogon->ppropid_hash);
	for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		ptmp_value = int_hash_iter_get_value(iter, &tmp_id);
		int_hash_add(phash, tmp_id, ptmp_value);
	}
	int_hash_iter_free(iter);
	int_hash_free(plogon->ppropid_hash);
	plogon->ppropid_hash = phash;
	return TRUE;
}

static BOOL logon_object_enlarge_propname_hash(
	LOGON_OBJECT *plogon)
{
	void *ptmp_value;
	STR_HASH_ITER *iter;
	char tmp_string[256];
	STR_HASH_TABLE *phash;
	
	phash = str_hash_init(plogon->ppropname_hash->capacity
				+ HGROWING_SIZE, sizeof(uint16_t), NULL);
	if (NULL == phash) {
		return FALSE;
	}
	iter = str_hash_iter_init(plogon->ppropname_hash);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ptmp_value = str_hash_iter_get_value(iter, tmp_string);
		str_hash_add(phash, tmp_string, ptmp_value);
	}
	str_hash_iter_free(iter);
	str_hash_free(plogon->ppropname_hash);
	plogon->ppropname_hash = phash;
	return TRUE;
}

static BOOL logon_object_cache_propname(LOGON_OBJECT *plogon,
	uint16_t propid, const PROPERTY_NAME *ppropname)
{
	char tmp_guid[64];
	char tmp_string[256];
	PROPERTY_NAME tmp_name;
	
	if (NULL == plogon->ppropid_hash) {
		plogon->ppropid_hash = int_hash_init(HGROWING_SIZE,
		                       sizeof(PROPERTY_NAME));
		if (NULL == plogon->ppropid_hash) {
			return FALSE;
		}
	}
	if (NULL == plogon->ppropname_hash) {
		plogon->ppropname_hash = str_hash_init(
			HGROWING_SIZE, sizeof(uint16_t), NULL);
		if (NULL == plogon->ppropname_hash) {
			int_hash_free(plogon->ppropid_hash);
			return FALSE;
		}
	}
	tmp_name.kind = ppropname->kind;
	tmp_name.guid = ppropname->guid;
	guid_to_string(&ppropname->guid, tmp_guid, 64);
	switch (ppropname->kind) {
	case MNID_ID:
		tmp_name.plid = me_alloc<uint32_t>();
		if (NULL == tmp_name.plid) {
			return FALSE;
		}
		*tmp_name.plid = *ppropname->plid;
		tmp_name.pname = NULL;
		snprintf(tmp_string, 256, "%s:lid:%u", tmp_guid, *ppropname->plid);
		break;
	case MNID_STRING:
		tmp_name.plid = NULL;
		tmp_name.pname = strdup(ppropname->pname);
		if (NULL == tmp_name.pname) {
			return FALSE;
		}
		snprintf(tmp_string, 256, "%s:name:%s", tmp_guid, ppropname->pname);
		break;
	default:
		return FALSE;
	}
	if (NULL == int_hash_query(plogon->ppropid_hash, propid)) {
		if (1 != int_hash_add(plogon->ppropid_hash, propid, &tmp_name)) {
			if (FALSE == logon_object_enlarge_propid_hash(plogon) ||
				1 != int_hash_add(plogon->ppropid_hash, propid, &tmp_name)) {
				if (NULL != tmp_name.plid) {
					free(tmp_name.plid);
				}
				if (NULL != tmp_name.pname) {
					free(tmp_name.pname);
				}
				return FALSE;
			}
		}
	} else {
		if (NULL != tmp_name.plid) {
			free(tmp_name.plid);
		}
		if (NULL != tmp_name.pname) {
			free(tmp_name.pname);
		}
	}
	HX_strlower(tmp_string);
	if (NULL == str_hash_query(plogon->ppropname_hash, tmp_string)) {
		if (1 != str_hash_add(plogon->ppropname_hash, tmp_string, &propid)) {
			if (FALSE == logon_object_enlarge_propname_hash(plogon)
				|| 1 != str_hash_add(plogon->ppropname_hash,
				tmp_string, &propid)) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

std::unique_ptr<LOGON_OBJECT> logon_object_create(uint8_t logon_flags,
	uint32_t open_flags, int logon_mode, int account_id,
	const char *account, const char *dir, GUID mailbox_guid)
{
	std::unique_ptr<LOGON_OBJECT> plogon;
	try {
		plogon = std::make_unique<LOGON_OBJECT>();
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
	plogon->pgpinfo = NULL;
	plogon->ppropid_hash = NULL;
	plogon->ppropname_hash = NULL;
	double_list_init(&plogon->group_list);
	return plogon;
}

LOGON_OBJECT::~LOGON_OBJECT()
{
	INT_HASH_ITER *piter;
	DOUBLE_LIST_NODE *pnode;
	PROPERTY_NAME *ppropname;

	auto plogon = this;
	if (NULL != plogon->pgpinfo) {
		property_groupinfo_free(plogon->pgpinfo);
	}
	while ((pnode = double_list_pop_front(&plogon->group_list)) != nullptr) {
		property_groupinfo_free(static_cast<PROPERTY_GROUPINFO *>(pnode->pdata));
		free(pnode);
	}
	double_list_free(&plogon->group_list);
	if (NULL != plogon->ppropid_hash) {
		piter = int_hash_iter_init(plogon->ppropid_hash);
		for (int_hash_iter_begin(piter); !int_hash_iter_done(piter);
			int_hash_iter_forward(piter)) {
			ppropname = static_cast<PROPERTY_NAME *>(int_hash_iter_get_value(piter, nullptr));
			switch( ppropname->kind) {
			case MNID_ID:
				free(ppropname->plid);
				break;
			case MNID_STRING:
				free(ppropname->pname);
				break;
			}
		}
		int_hash_iter_free(piter);
		int_hash_free(plogon->ppropid_hash);
	}
	if (NULL != plogon->ppropname_hash) {
		str_hash_free(plogon->ppropname_hash);
	}
}

BOOL logon_object_check_private(LOGON_OBJECT *plogon)
{
	return (plogon->logon_flags & LOGON_FLAG_PRIVATE) ? TRUE : false;
}

GUID logon_object_guid(LOGON_OBJECT *l)
{
	auto id = logon_object_get_account_id(l);
	return logon_object_check_private(l) ? rop_util_make_user_guid(id) :
	       rop_util_make_domain_guid(id);
}

int logon_object_get_mode(LOGON_OBJECT *plogon)
{
	return plogon->logon_mode;
}

int logon_object_get_account_id(LOGON_OBJECT *plogon)
{
	return plogon->account_id;
}

const char* logon_object_get_account(LOGON_OBJECT *plogon)
{
	return plogon->account;
}

const char* logon_object_get_dir(LOGON_OBJECT *plogon)
{
	return plogon->dir;
}

GUID logon_object_get_mailbox_guid(LOGON_OBJECT *plogon)
{
	return plogon->mailbox_guid;
}

BOOL logon_object_get_named_propname(LOGON_OBJECT *plogon,
	uint16_t propid, PROPERTY_NAME *ppropname)
{
	PROPERTY_NAME *pname;
	
	if (propid < 0x8000) {
		rop_util_get_common_pset(PS_MAPI, &ppropname->guid);
		ppropname->kind = MNID_ID;
		ppropname->plid = cu_alloc<uint32_t>();
		if (NULL == ppropname->plid) {
			return FALSE;
		}
		*ppropname->plid = propid;
	}
	if (NULL != plogon->ppropid_hash) {
		pname = static_cast<PROPERTY_NAME *>(int_hash_query(plogon->ppropid_hash, propid));
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

BOOL logon_object_get_named_propnames(LOGON_OBJECT *plogon,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
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
	for (i=0; i<ppropids->count; i++) {
		if (ppropids->ppropid[i] < 0x8000) {
			rop_util_get_common_pset(PS_MAPI,
				&ppropnames->ppropname[i].guid);
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].plid = cu_alloc<uint32_t>();
			if (NULL == ppropnames->ppropname[i].plid) {
				return FALSE;
			}
			*ppropnames->ppropname[i].plid = ppropids->ppropid[i];
			pindex_map[i] = i;
			continue;
		}
		pname = plogon->ppropid_hash == nullptr ? nullptr :
		        static_cast<PROPERTY_NAME *>(int_hash_query(plogon->ppropid_hash, ppropids->ppropid[i]));
		if (NULL != pname) {
			pindex_map[i] = i;
			ppropnames->ppropname[i] = *pname;
		} else {
			tmp_propids.ppropid[tmp_propids.count] =
								ppropids->ppropid[i];
			tmp_propids.count ++;
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

BOOL logon_object_get_named_propid(LOGON_OBJECT *plogon,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid)
{
	GUID guid;
	uint16_t *pid;
	char tmp_guid[64];
	char tmp_string[256];
	
	rop_util_get_common_pset(PS_MAPI, &guid);
	if (0 == guid_compare(&ppropname->guid, &guid)) {
		*ppropid = ppropname->kind == MNID_ID ? *ppropname->plid : 0;
		return TRUE;
	}
	guid_to_string(&ppropname->guid, tmp_guid, 64);
	switch (ppropname->kind) {
	case MNID_ID:
		snprintf(tmp_string, 256, "%s:lid:%u", tmp_guid, *ppropname->plid);
		break;
	case MNID_STRING:
		snprintf(tmp_string, 256, "%s:name:%s", tmp_guid, ppropname->pname);
		HX_strlower(tmp_string);
		break;
	default:
		*ppropid = 0;
		return TRUE;
	}
	if (NULL != plogon->ppropname_hash) {
		pid = static_cast<uint16_t *>(str_hash_query(plogon->ppropname_hash, tmp_string));
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

BOOL logon_object_get_named_propids(LOGON_OBJECT *plogon,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	int i;
	GUID guid;
	uint16_t *pid;
	char tmp_guid[64];
	char tmp_string[256];
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
	for (i=0; i<ppropnames->count; i++) {
		if (0 == guid_compare(&ppropnames->ppropname[i].guid, &guid)) {
			ppropids->ppropid[i] = ppropnames->ppropname[i].kind == MNID_ID ?
					       *ppropnames->ppropname[i].plid : 0;
			pindex_map[i] = i;
			continue;
		}
		guid_to_string(&ppropnames->ppropname[i].guid, tmp_guid, 64);
		switch (ppropnames->ppropname[i].kind) {
		case MNID_ID:
			snprintf(tmp_string, 256, "%s:lid:%u",
				tmp_guid, *ppropnames->ppropname[i].plid);
			break;
		case MNID_STRING:
			snprintf(tmp_string, 256, "%s:name:%s",
				tmp_guid, ppropnames->ppropname[i].pname);
			HX_strlower(tmp_string);
			break;
		default:
			ppropids->ppropid[i] = 0;
			pindex_map[i] = i;
			continue;
		}
		pid = plogon->ppropname_hash == nullptr ? nullptr :
		      static_cast<uint16_t *>(str_hash_query(plogon->ppropname_hash, tmp_string));
		if (NULL != pid) {
			pindex_map[i] = i;
			ppropids->ppropid[i] = *pid;
		} else {
			tmp_propnames.ppropname[tmp_propnames.count] =
									ppropnames->ppropname[i];
			tmp_propnames.count ++;
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
	return logon_object_get_named_propid(static_cast<LOGON_OBJECT *>(obj), create, pn, pid);
}

PROPERTY_GROUPINFO* logon_object_get_last_property_groupinfo(
	LOGON_OBJECT *plogon)
{
	if (NULL == plogon->pgpinfo) {
		plogon->pgpinfo = msgchg_grouping_get_groupinfo(gnpwrap,
		                  plogon, msgchg_grouping_get_last_group_id());
	}
	return plogon->pgpinfo;
}

PROPERTY_GROUPINFO* logon_object_get_property_groupinfo(
	LOGON_OBJECT *plogon, uint32_t group_id)
{
	DOUBLE_LIST_NODE *pnode;
	PROPERTY_GROUPINFO *pgpinfo;
	
	if (group_id == msgchg_grouping_get_last_group_id()) {
		return logon_object_get_last_property_groupinfo(plogon);
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

BOOL logon_object_get_all_proptags(LOGON_OBJECT *plogon,
	PROPTAG_ARRAY *pproptags)
{
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
	if (TRUE == logon_object_check_private(plogon)) {
		pproptags->pproptag[pproptags->count] =
					PR_MAILBOX_OWNER_NAME;
		pproptags->count ++;
		pproptags->pproptag[pproptags->count] =
					PR_MAILBOX_OWNER_ENTRYID;
		pproptags->count ++;
		pproptags->pproptag[pproptags->count++] = PR_MAX_SUBMIT_MESSAGE_SIZE;
		pproptags->pproptag[pproptags->count] = PR_EMAIL_ADDRESS;
		pproptags->count ++;
		pproptags->pproptag[pproptags->count] =
		PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE;
		pproptags->count ++;
	} else {
		pproptags->pproptag[pproptags->count] =
						PROP_TAG_HIERARCHYSERVER;
		pproptags->count ++;
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
	pproptags->pproptag[pproptags->count] =
			PROP_TAG_EXTENDEDRULESIZELIMIT;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] =
				PROP_TAG_ASSOCMESSAGESIZE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PR_MESSAGE_SIZE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] =
				PROP_TAG_NORMALMESSAGESIZE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count++] = PR_USER_ENTRYID;
	pproptags->pproptag[pproptags->count] =
					PROP_TAG_CONTENTCOUNT;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] =
			PROP_TAG_ASSOCIATEDCONTENTCOUNT;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] =
					PROP_TAG_TESTLINESPEED;
	pproptags->count ++;
	return TRUE;
}

static BOOL logon_object_check_readonly_property(
	LOGON_OBJECT *plogon, uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
	switch (proptag) {
	case PR_ACCESS_LEVEL:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8:
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
	case PROP_TAG_INTERNETARTICLENUMBER:
	case PROP_TAG_LOCALEID:
	case PR_MAX_SUBMIT_MESSAGE_SIZE:
	case PR_MAILBOX_OWNER_ENTRYID:
	case PR_MAILBOX_OWNER_NAME:
	case PROP_TAG_MAILBOXOWNERNAME_STRING8:
	case PR_MESSAGE_SIZE:
	case PR_MESSAGE_SIZE_EXTENDED:
	case PROP_TAG_ASSOCMESSAGESIZE:
	case PROP_TAG_ASSOCMESSAGESIZEEXTENDED:
	case PROP_TAG_NORMALMESSAGESIZE:
	case PROP_TAG_NORMALMESSAGESIZEEXTENDED:
	case PR_OBJECT_TYPE:
	case PROP_TAG_OUTOFOFFICESTATE:
	case PROP_TAG_PROHIBITRECEIVEQUOTA:
	case PROP_TAG_PROHIBITSENDQUOTA:
	case PR_RECORD_KEY:
	case PROP_TAG_SEARCHKEY:
	case PROP_TAG_SORTLOCALEID:
	case PROP_TAG_STORAGEQUOTALIMIT:
	case PR_STORE_ENTRYID:
	case PR_STORE_OFFLINE:
	case PR_MDB_PROVIDER:
	case PR_STORE_RECORD_KEY:
	case PR_STORE_STATE:
	case PR_STORE_SUPPORT_MASK:
	case PROP_TAG_TESTLINESPEED:
	case PR_USER_ENTRYID:
	case PROP_TAG_VALIDFOLDERMASK:
	case PROP_TAG_HIERARCHYSERVER:
		return TRUE;
	}
	return FALSE;
}

static BOOL logon_object_get_calculated_property(
	LOGON_OBJECT *plogon, uint32_t proptag, void **ppvalue)
{
	int i;
	int temp_len;
	void *pvalue;
	char temp_buff[1024];
	static constexpr uint64_t tmp_ll = 0;
	static constexpr uint8_t test_buff[256]{};
	static constexpr BINARY test_bin = {sizeof(test_buff), (uint8_t *)test_buff};
	
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
	case PROP_TAG_ASSOCMESSAGESIZE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (FALSE == exmdb_client_get_store_property(
			plogon->dir, 0, PROP_TAG_ASSOCMESSAGESIZEEXTENDED,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		**reinterpret_cast<uint32_t **>(ppvalue) = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(0x7FFFFFFF));
		return TRUE;
	case PROP_TAG_NORMALMESSAGESIZE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (FALSE == exmdb_client_get_store_property(
			plogon->dir, 0, PROP_TAG_NORMALMESSAGESIZEEXTENDED,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		**reinterpret_cast<uint32_t **>(ppvalue) = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(0x7FFFFFFF));
		return TRUE;
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8:
		if (FALSE == logon_object_check_private(plogon)) {
			return FALSE;
		}
		*ppvalue = common_util_alloc(256);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (!common_util_get_user_displayname(plogon->account, static_cast<char *>(*ppvalue)))
			return FALSE;	
		temp_len = strlen(static_cast<char *>(*ppvalue));
		for (i=0; i<temp_len; i++) {
			if (0 == isascii(((char*)(*ppvalue))[i])) {
				strcpy(static_cast<char *>(*ppvalue), plogon->account);
				pvalue = strchr(static_cast<char *>(*ppvalue), '@');
				*(char*)pvalue = '\0';
				break;
			}
		}
		return TRUE;
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
	case PR_EMAIL_ADDRESS_A:
		if (TRUE == logon_object_check_private(plogon)) {
			if (!common_util_username_to_essdn(plogon->account,
			    temp_buff, GX_ARRAY_SIZE(temp_buff)))
				return FALSE;	
		} else {
			if (!common_util_public_to_essdn(plogon->account,
			    temp_buff, GX_ARRAY_SIZE(temp_buff)))
				return FALSE;	
		}
		*ppvalue = common_util_alloc(strlen(temp_buff) + 1);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		strcpy(static_cast<char *>(*ppvalue), temp_buff);
		return TRUE;
	case PROP_TAG_EXTENDEDRULESIZELIMIT:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = common_util_get_param(
						COMMON_UTIL_MAX_EXTRULE_LENGTH);
		return TRUE;
	case PROP_TAG_HIERARCHYSERVER:
		if (TRUE == logon_object_check_private(plogon)) {
			return FALSE;
		}
		common_util_get_domain_server(plogon->account, temp_buff);
		*ppvalue = common_util_alloc(strlen(temp_buff) + 1);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		strcpy(static_cast<char *>(*ppvalue), temp_buff);
		return TRUE;
	case PROP_TAG_LOCALEID: {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		*ppvalue = &pinfo->lcid_string;
		return TRUE;
	}
	case PR_MAILBOX_OWNER_ENTRYID:
		if (FALSE == logon_object_check_private(plogon)) {
			return FALSE;
		}
		*ppvalue = common_util_username_to_addressbook_entryid(
												plogon->account);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	case PR_MAILBOX_OWNER_NAME:
		if (FALSE == logon_object_check_private(plogon)) {
			return FALSE;
		}
		if (FALSE == common_util_get_user_displayname(
			plogon->account, temp_buff)) {
			return FALSE;	
		}
		if ('\0' == temp_buff[0]) {
			*ppvalue = common_util_alloc(strlen(plogon->account) + 1);
			if (NULL == *ppvalue) {
				return FALSE;
			}
			strcpy(static_cast<char *>(*ppvalue), plogon->account);
		} else {
			*ppvalue = common_util_alloc(strlen(temp_buff) + 1);
			if (NULL == *ppvalue) {
				return FALSE;
			}
			strcpy(static_cast<char *>(*ppvalue), temp_buff);
		}
		return TRUE;
	case PROP_TAG_MAILBOXOWNERNAME_STRING8:
		if (FALSE == logon_object_check_private(plogon)) {
			return FALSE;
		}
		if (FALSE == common_util_get_user_displayname(
			plogon->account, temp_buff)) {
			return FALSE;	
		}
		temp_len = 2*strlen(temp_buff) + 1;
		*ppvalue = common_util_alloc(temp_len);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (common_util_convert_string(FALSE, temp_buff,
		    static_cast<char *>(*ppvalue), temp_len) < 0)
			return FALSE;	
		if ('\0' == ((char*)*ppvalue)[0]) {
			strcpy(static_cast<char *>(*ppvalue), plogon->account);
		}
		return TRUE;
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
	case PROP_TAG_TESTLINESPEED:
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
BOOL logon_object_get_properties(LOGON_OBJECT *plogon,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint32_t err_code = ecError;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return FALSE;
	}
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
			tmp_proptags.pproptag[tmp_proptags.count] =
											pproptags->pproptag[i];
			tmp_proptags.count ++;
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

BOOL logon_object_set_properties(LOGON_OBJECT *plogon,
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
{
	int i;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	uint16_t *poriginal_indices;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return FALSE;
	}
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
	for (i=0; i<ppropvals->count; i++) {
		if (TRUE == logon_object_check_readonly_property(
			plogon, ppropvals->ppropval[i].proptag)) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count].err = ecAccessDenied;
			pproblems->count ++;
		} else {
			tmp_propvals.ppropval[tmp_propvals.count] =
									ppropvals->ppropval[i];
			poriginal_indices[tmp_propvals.count] = i;
			tmp_propvals.count ++;
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
	for (i=0; i<tmp_problems.count; i++) {
		tmp_problems.pproblem[i].index =
			poriginal_indices[tmp_problems.pproblem[i].index];
	}
	memcpy(pproblems->pproblem + pproblems->count,
		tmp_problems.pproblem, tmp_problems.count*
		sizeof(PROPERTY_PROBLEM));
	pproblems->count += tmp_problems.count;
	qsort(pproblems->pproblem, pproblems->count,
		sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
	return TRUE;
}

BOOL logon_object_remove_properties(LOGON_OBJECT *plogon,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems)
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
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == logon_object_check_readonly_property(
			plogon, pproptags->pproptag[i])) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
									pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count].err = ecAccessDenied;
			pproblems->count ++;
		} else {
			tmp_proptags.pproptag[tmp_proptags.count] =
									pproptags->pproptag[i];
			tmp_proptags.count ++;
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
