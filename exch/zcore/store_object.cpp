// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/msgchg_grouping.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "object_tree.hpp"
#include "store_object.hpp"
#include "system_services.hpp"
#include "zserver.hpp"

using namespace std::string_literals;
using namespace gromox;

static inline const char *account_to_domain(const char *u)
{
	auto at = strchr(u, '@');
	return at != nullptr ? at + 1 : u;
}

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

static BOOL store_object_cache_propname(store_object *pstore,
    uint16_t propid, const PROPERTY_NAME *ppropname) try
{
	char s[NP_STRBUF_SIZE];
	if (!propname_to_packed(*ppropname, s, std::size(s)))
		return false;
	pstore->propid_hash.emplace(propid, *ppropname);
	pstore->propname_hash.emplace(s, propid);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1634: ENOMEM");
	return false;
}

std::unique_ptr<store_object> store_object::create(BOOL b_private,
	int account_id, const char *account, const char *dir)
{
	static constexpr proptag_t proptag = PR_STORE_RECORD_KEY;
	const PROPTAG_ARRAY proptags = {1, deconst(&proptag)};
	TPROPVAL_ARRAY propvals;
	
	if (!exmdb_client::get_store_properties(dir, CP_ACP,
	    &proptags, &propvals)) {
		mlog(LV_ERR, "get_store_properties %s: failed", dir);
		return NULL;	
	}
	auto bin = propvals.get<const BINARY>(PR_STORE_RECORD_KEY);
	if (bin == nullptr)
		return NULL;
	std::unique_ptr<store_object> pstore;
	try {
		pstore.reset(new store_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pstore->b_private = b_private;
	pstore->account_id = account_id;
	gx_strlcpy(pstore->account, account, std::size(pstore->account));
	gx_strlcpy(pstore->dir, dir, std::size(pstore->dir));
	pstore->mailbox_guid = rop_util_binary_to_guid(bin);
	return pstore;
}

GUID store_object::guid() const
{
	return b_private ? rop_util_make_user_guid(account_id) :
	       rop_util_make_domain_guid(account_id);
}

bool store_object::owner_mode() const
{
	auto pstore = this;
	if (!pstore->b_private)
		return FALSE;
	auto pinfo = zs_get_info();
	if (pinfo->user_id == pstore->account_id)
		return true;
	std::unique_lock lk(pinfo->eowner_lock);
	auto i = pinfo->extra_owner.find(pstore->account_id);
	if (i == pinfo->extra_owner.end())
		return false;
	auto age = time(nullptr) - i->second;
	if (age < 60)
		return true;
	lk.unlock();
	uint32_t perm = rightsNone;
	if (!exmdb_client::get_mbox_perm(pstore->dir, pinfo->get_username(), &perm))
		return false;
	if (!(perm & frightsGromoxStoreOwner))
		return false;
	lk.lock();
	i = pinfo->extra_owner.find(pstore->account_id);
	if (i == pinfo->extra_owner.end())
		return false;
	i->second = time(nullptr);
	return true;
}

bool store_object::primary_mode() const
{
	if (!b_private)
		return false;
	auto pinfo = zs_get_info();
	return pinfo->user_id == account_id;
}

BOOL store_object::get_named_propnames(const PROPID_ARRAY &propids,
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
	auto pstore = this;
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
	if (!exmdb_client::get_named_propnames(
	    pstore->dir, tmp_propids, &tmp_propnames) ||
	    tmp_propnames.size() != tmp_propids.size())
		return FALSE;	
	for (size_t i = 0; i < propids.size(); ++i) {
		if (pindex_map[i] >= 0)
			continue;
		ppropnames->ppropname[i] = tmp_propnames.ppropname[-pindex_map[i]-1];
		if (ppropnames->ppropname[i].kind == MNID_ID ||
		    ppropnames->ppropname[i].kind == MNID_STRING)
			store_object_cache_propname(pstore,
				propids[i], ppropnames->ppropname + i);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2231: ENOMEM");
	return false;
}

static BOOL store_object_get_named_propid(store_object *pstore,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid)
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
	auto iter = pstore->propname_hash.find(ps);
	if (iter != pstore->propname_hash.end()) {
		*ppropid = iter->second;
		return TRUE;
	}
	if (!exmdb_client_get_named_propid(pstore->dir,
	    b_create, ppropname, ppropid))
		return FALSE;
	if (*ppropid == 0)
		return TRUE;
	store_object_cache_propname(pstore, *ppropid, ppropname);
	return TRUE;
}

BOOL store_object::get_named_propids(BOOL b_create,
    const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids) try
{
	auto &propids = *ppropids;
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	if (0 == ppropnames->count) {
		ppropids->clear();
		return TRUE;
	}
	auto pindex_map = cu_alloc<int>(ppropnames->count);
	if (pindex_map == nullptr)
		return FALSE;
	propids.resize(ppropnames->count);
	tmp_propnames.count = 0;
	tmp_propnames.ppropname = cu_alloc<PROPERTY_NAME>(ppropnames->count);
	if (tmp_propnames.ppropname == nullptr)
		return FALSE;
	auto pstore = this;
	for (size_t i = 0; i < ppropnames->count; ++i) {
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
	if (!exmdb_client::get_named_propids(pstore->dir,
	    b_create, &tmp_propnames, &tmp_propids) ||
	    tmp_propids.size() != tmp_propnames.size())
		return FALSE;	
	for (size_t i = 0; i < ppropnames->count; ++i) {
		if (pindex_map[i] >= 0)
			continue;
		propids[i] = tmp_propids[-pindex_map[i]-1];
		if (propids[i] != 0)
			store_object_cache_propname(pstore,
				propids[i], ppropnames->ppropname + i);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2233: ENOMEM");
	return false;
}

static BOOL gnpwrap(void *store, BOOL create, const PROPERTY_NAME *pn, uint16_t *pid)
{
	return store_object_get_named_propid(static_cast<store_object *>(store), create, pn, pid);
}

const property_groupinfo *store_object::get_last_property_groupinfo()
{
	auto pstore = this;
	if (m_gpinfo == nullptr)
		m_gpinfo = msgchg_grouping_get_groupinfo(gnpwrap,
		           pstore, msgchg_grouping_get_last_group_id());
	return m_gpinfo.get();
}

const property_groupinfo *
store_object::get_property_groupinfo(uint32_t group_id) try
{
	auto pstore = this;
	
	if (group_id == msgchg_grouping_get_last_group_id())
		return get_last_property_groupinfo();
	auto node = std::find_if(group_list.begin(), group_list.end(),
	            [&](const property_groupinfo &p) { return p.group_id == group_id; });
	if (node != group_list.end())
		return &*node;
	auto pgpinfo = msgchg_grouping_get_groupinfo(gnpwrap, pstore, group_id);
	if (pgpinfo == nullptr)
		return NULL;
	group_list.push_back(std::move(*pgpinfo));
	return &group_list.back();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1630: ENOMEM");
	return nullptr;
}

static BOOL store_object_is_readonly_prop(store_object *pstore, uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
	switch (proptag) {
	case PidTagXSpoolerQueueEntryId:
	case PR_ACCESS:
	case PR_ACCESS_LEVEL:
	case PR_ASSOC_MESSAGE_SIZE:
	case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
	case PR_CODE_PAGE_ID:
	case PR_COMMON_VIEWS_ENTRYID:
	case PR_CONTENT_COUNT:
	case PR_DEFAULT_STORE:
	case PR_DELETED_ASSOC_MESSAGE_SIZE:
	case PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED:
	case PR_DELETED_ASSOC_MSG_COUNT:
	case PR_DELETED_MESSAGE_SIZE:
	case PR_DELETED_MESSAGE_SIZE_EXTENDED:
	case PR_DELETED_MSG_COUNT:
	case PR_DELETED_NORMAL_MESSAGE_SIZE:
	case PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED:
	case PR_DELETE_AFTER_SUBMIT:
	case PR_EC_ENABLED_FEATURES_L:
	case PR_EFORMS_REGISTRY_ENTRYID:
	case PR_EMAIL_ADDRESS:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE:
	case PR_ENTRYID:
	case PR_EXTENDED_RULE_SIZE_LIMIT:
	case PR_FINDER_ENTRYID:
	case PR_HIERARCHY_SERVER:
	case PR_INSTANCE_KEY:
	case PR_INTERNET_ARTICLE_NUMBER:
	case PR_IPM_DAF_ENTRYID:
	case PR_IPM_FAVORITES_ENTRYID:
	case PR_IPM_INBOX_ENTRYID:
	case PR_IPM_OUTBOX_ENTRYID:
	case PR_IPM_PUBLIC_FOLDERS_ENTRYID:
	case PR_IPM_SENTMAIL_ENTRYID:
	case PR_IPM_SUBTREE_ENTRYID:
	case PR_IPM_WASTEBASKET_ENTRYID:
	case PR_LOCALE_ID:
	case PR_MAILBOX_OWNER_ENTRYID:
	case PR_MAILBOX_OWNER_NAME:
	case PR_MAPPING_SIGNATURE:
	case PR_MAX_SUBMIT_MESSAGE_SIZE:
	case PR_MDB_PROVIDER:
	case PR_MESSAGE_SIZE:
	case PR_MESSAGE_SIZE_EXTENDED:
	case PR_NON_IPM_SUBTREE_ENTRYID:
	case PR_NORMAL_MESSAGE_SIZE:
	case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
	case PR_OBJECT_TYPE:
	case PR_OOF_STATE:
	case PR_PROHIBIT_RECEIVE_QUOTA:
	case PR_PROHIBIT_SEND_QUOTA:
	case PR_RECORD_KEY:
	case PR_ROOT_ENTRYID:
	case PR_RIGHTS:
	case PR_SCHEDULE_FOLDER_ENTRYID:
	case PR_SEARCH_KEY:
	case PR_SORT_LOCALE_ID:
	case PR_STORAGE_QUOTA_LIMIT:
	case PR_STORE_ENTRYID:
	case PR_STORE_OFFLINE:
	case PR_STORE_RECORD_KEY:
	case PR_STORE_STATE:
	case PR_STORE_SUPPORT_MASK:
	case PR_TEST_LINE_SPEED:
	case PR_USER_ENTRYID:
	case PR_VALID_FOLDER_MASK:
	case PR_VIEWS_ENTRYID:
		return TRUE;
	}
	return FALSE;
}

BOOL store_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pstore = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_store_all_proptags(pstore->dir, &tmp_proptags))
		return FALSE;	
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 56);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	if (pstore->b_private) {
		pproptags->pproptag[pproptags->count++] = PidTagXSpoolerQueueEntryId;
		pproptags->pproptag[pproptags->count++] = PR_COMMON_VIEWS_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_EC_ALLOW_EXTERNAL;
		pproptags->pproptag[pproptags->count++] = PR_EC_EXTERNAL_AUDIENCE;
		pproptags->pproptag[pproptags->count++] = PR_EC_EXTERNAL_REPLY;
		pproptags->pproptag[pproptags->count++] = PR_EC_EXTERNAL_SUBJECT;
		pproptags->pproptag[pproptags->count++] = PR_EC_OUTOFOFFICE;
		pproptags->pproptag[pproptags->count++] = PR_EC_OUTOFOFFICE_FROM;
		pproptags->pproptag[pproptags->count++] = PR_EC_OUTOFOFFICE_MSG;
		pproptags->pproptag[pproptags->count++] = PR_EC_OUTOFOFFICE_SUBJECT;
		pproptags->pproptag[pproptags->count++] = PR_EC_OUTOFOFFICE_UNTIL;
		pproptags->pproptag[pproptags->count++] = PR_EMAIL_ADDRESS;
		pproptags->pproptag[pproptags->count++] = PR_EMS_AB_DISPLAY_NAME_PRINTABLE;
		pproptags->pproptag[pproptags->count++] = PR_FINDER_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_IPM_DAF_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_IPM_INBOX_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_IPM_OUTBOX_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_IPM_SENTMAIL_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_IPM_WASTEBASKET_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_MAILBOX_OWNER_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_MAILBOX_OWNER_NAME;
		pproptags->pproptag[pproptags->count++] = PR_MAX_SUBMIT_MESSAGE_SIZE;
		pproptags->pproptag[pproptags->count++] = PR_SCHEDULE_FOLDER_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_VIEWS_ENTRYID;
	} else {
		pproptags->pproptag[pproptags->count++] = PR_EFORMS_REGISTRY_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_IPM_PUBLIC_FOLDERS_ENTRYID;
		pproptags->pproptag[pproptags->count++] = PR_NON_IPM_SUBTREE_ENTRYID;
	}
	pproptags->pproptag[pproptags->count++] = PR_CONTENT_COUNT;
	pproptags->pproptag[pproptags->count++] = PR_DEFAULT_STORE;
	pproptags->pproptag[pproptags->count++] = PR_DISPLAY_NAME;
	pproptags->pproptag[pproptags->count++] = PR_EC_SERVER_VERSION;
	pproptags->pproptag[pproptags->count++] = PR_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_EXTENDED_RULE_SIZE_LIMIT;
	pproptags->pproptag[pproptags->count++] = PR_INSTANCE_KEY;
	pproptags->pproptag[pproptags->count++] = PR_IPM_FAVORITES_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_IPM_SUBTREE_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_MAPPING_SIGNATURE;
	pproptags->pproptag[pproptags->count++] = PR_MDB_PROVIDER;
	pproptags->pproptag[pproptags->count++] = PR_OBJECT_TYPE;
	pproptags->pproptag[pproptags->count++] = PR_PROVIDER_DISPLAY;
	pproptags->pproptag[pproptags->count++] = PR_RECORD_KEY;
	pproptags->pproptag[pproptags->count++] = PR_RESOURCE_FLAGS;
	pproptags->pproptag[pproptags->count++] = PR_RESOURCE_TYPE;
	pproptags->pproptag[pproptags->count++] = PR_ROOT_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_STORE_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_STORE_RECORD_KEY;
	pproptags->pproptag[pproptags->count++] = PR_STORE_SUPPORT_MASK;
	pproptags->pproptag[pproptags->count++] = PR_USER_ENTRYID;
	return TRUE;
}

static constexpr struct cfg_directive oof_defaults[] = {
	{"allow_external_oof", "0", CFG_BOOL},
	{"external_audience", "0", CFG_BOOL},
	{"oof_state", "0"},
	CFG_TABLE_END,
};

static void *store_object_get_oof_property(const char *maildir,
    uint32_t proptag) try
{
	int offset;
	char *pbuff;
	int buff_len;
	void *pvalue;
	const char *str_value;
	char subject[1024];
	MIME_FIELD mime_field;
	struct stat node_stat;
	static constexpr uint8_t fake_true = true;
	static constexpr uint8_t fake_false = false;
	std::string path;

	switch (proptag) {
	case PR_EC_OUTOFOFFICE:
	case PR_EC_OUTOFOFFICE_FROM:
	case PR_EC_OUTOFOFFICE_UNTIL:
	case PR_EC_ALLOW_EXTERNAL:
	case PR_EC_EXTERNAL_AUDIENCE:
		path = maildir + "/config/autoreply.cfg"s;
		break;
	case PR_EC_OUTOFOFFICE_MSG:
	case PR_EC_OUTOFOFFICE_SUBJECT:
		path = maildir + "/config/internal-reply"s;
		break;
	case PR_EC_EXTERNAL_REPLY:
	case PR_EC_EXTERNAL_SUBJECT:
		path = maildir + "/config/external-reply"s;
		break;
	}

	switch (proptag) {
	case PR_EC_OUTOFOFFICE: {
		auto oofstate = cu_alloc<uint32_t>();
		if (oofstate == nullptr)
			return NULL;
		pvalue = oofstate;
		auto pconfig = config_file_init(path.c_str(), oof_defaults);
		*oofstate = pconfig != nullptr ? pconfig->get_ll("oof_state") : 0;
		return pvalue;
	}
	case PR_EC_OUTOFOFFICE_MSG:
	case PR_EC_EXTERNAL_REPLY: {
		wrapfd fd = open(path.c_str(), O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
			return nullptr;
		buff_len = node_stat.st_size;
		pbuff = cu_alloc<char>(buff_len + 1);
		if (pbuff == nullptr || read(fd.get(), pbuff, buff_len) != buff_len)
			return NULL;
		pbuff[buff_len] = '\0';
		auto ptr = strstr(pbuff, "\r\n\r\n");
		return ptr != nullptr ? ptr + 4 : nullptr;
	}
	case PR_EC_OUTOFOFFICE_SUBJECT:
	case PR_EC_EXTERNAL_SUBJECT: {
		wrapfd fd = open(path.c_str(), O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
			return NULL;
		buff_len = node_stat.st_size;
		pbuff = cu_alloc<char>(buff_len);
		if (pbuff == nullptr || read(fd.get(), pbuff, buff_len) != buff_len)
			return NULL;
		offset = 0;
		size_t parsed_length;
		while ((parsed_length = parse_mime_field(pbuff + offset, buff_len - offset, &mime_field)) != 0) {
			offset += parsed_length;
			if (strcasecmp(mime_field.name.c_str(), "Subject") == 0 &&
			    mime_field.value.size() < std::size(subject) &&
			    mime_string_to_utf8("utf-8", mime_field.value.c_str(), subject,
			    std::size(subject)))
					return common_util_dup(subject);
			if (pbuff[offset] == '\r' && pbuff[offset+1] == '\n')
				return NULL;
		}
		return NULL;
	}
	case PR_EC_OUTOFOFFICE_FROM:
	case PR_EC_OUTOFOFFICE_UNTIL: {
		auto pconfig = config_file_init(path.c_str(), oof_defaults);
		if (pconfig == nullptr)
			return NULL;
		pvalue = cu_alloc<uint64_t>();
		if (pvalue == nullptr)
			return NULL;
		str_value = pconfig->get_value(proptag == PR_EC_OUTOFOFFICE_FROM ? "START_TIME" : "END_TIME");
		if (str_value == nullptr)
			return NULL;
		*static_cast<uint64_t *>(pvalue) = rop_util_unix_to_nttime(strtoll(str_value, nullptr, 0));
		return pvalue;
	}
	case PR_EC_ALLOW_EXTERNAL:
	case PR_EC_EXTERNAL_AUDIENCE: {
		auto pconfig = config_file_init(path.c_str(), oof_defaults);
		if (pconfig == nullptr)
			return deconst(&fake_false);
		auto key = proptag == PR_EC_ALLOW_EXTERNAL ? "allow_external_oof" : "external_audience";
		pvalue = deconst(pconfig->get_ll(key) == 0 ? &fake_false : &fake_true);
		return pvalue;
	}
	}
	return NULL;
} catch (const std::bad_alloc &) {
	return nullptr;
}

static BOOL store_object_get_calculated_property(store_object *pstore,
    uint32_t proptag, void **ppvalue)
{
	uint32_t permission;
	char temp_buff[1024];
	
	switch (proptag) {
	case PR_MDB_PROVIDER: {
		auto bv = cu_alloc<BINARY>();
		if (bv == nullptr)
			return FALSE;
		*ppvalue = bv;
		bv->cb = 16;
		bv->pv = deconst(!pstore->b_private ? &pbExchangeProviderPublicGuid :
		         pstore->primary_mode() ? &pbExchangeProviderPrimaryUserGuid :
		         &pbExchangeProviderDelegateGuid);
		return TRUE;
	}
	case PR_DISPLAY_NAME: {
		static constexpr size_t dsize = UADDR_SIZE + 17;
		auto dispname = cu_alloc<char>(dsize);
		*ppvalue = dispname;
		if (*ppvalue == nullptr)
			return FALSE;
		if (!pstore->b_private)
			snprintf(dispname, dsize, "Public Folders - %s", pstore->account);
		else if (!mysql_adaptor_get_user_displayname(pstore->account,
		    dispname, dsize))
			gx_strlcpy(dispname, pstore->account, dsize);
		return TRUE;
	}
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE: {
		if (!pstore->b_private)
			return FALSE;
		static constexpr size_t dsize = UADDR_SIZE;
		auto dispname = cu_alloc<char>(dsize);
		*ppvalue = dispname;
		if (*ppvalue == nullptr)
			return FALSE;
		if (!mysql_adaptor_get_user_displayname(pstore->account,
		    dispname, dsize))
			return FALSE;	
		auto temp_len = strlen(dispname);
		for (size_t i = 0; i < temp_len; ++i) {
			if (!isascii(dispname[i]))
				continue;
			gx_strlcpy(dispname, pstore->account, dsize);
			auto p = strchr(dispname, '@');
			if (p != nullptr)
				*p = '\0';
			break;
		}
		return TRUE;
	}
	case PR_DEFAULT_STORE:
		*ppvalue = cu_alloc<uint8_t>();
		if (*ppvalue == nullptr)
			return FALSE;
		*static_cast<uint8_t *>(*ppvalue) = pstore->primary_mode();
		return TRUE;
	case PR_ACCESS: {
		auto acval = cu_alloc<uint32_t>();
		*ppvalue = acval;
		if (*ppvalue == nullptr)
			return FALSE;
		if (pstore->owner_mode()) {
			*acval = MAPI_ACCESS_AllSix;
			return TRUE;
		}
		auto pinfo = zs_get_info();
		if (!pstore->b_private) {
			*acval = MAPI_ACCESS_AllSix;
			return TRUE;
		}
		if (!exmdb_client::get_mbox_perm(pstore->dir,
		    pinfo->get_username(), &permission))
			return FALSE;
		permission &= ~frightsGromoxStoreOwner;
		*acval = MAPI_ACCESS_READ;
		if (permission & frightsOwner) {
			*acval = MAPI_ACCESS_AllSix;
			return TRUE;
		}
		if (permission & frightsCreate)
			*acval |= MAPI_ACCESS_CREATE_CONTENTS | MAPI_ACCESS_CREATE_ASSOCIATED;
		if (permission & frightsCreateSubfolder)
			*acval |= MAPI_ACCESS_CREATE_HIERARCHY;
		return TRUE;
	}
	case PR_RIGHTS: {
		*ppvalue = cu_alloc<uint32_t>();
		if (*ppvalue == nullptr)
			return FALSE;
		if (pstore->owner_mode()) {
			*static_cast<uint32_t *>(*ppvalue) = rightsAll | frightsContact;
			return TRUE;
		}
		auto pinfo = zs_get_info();
		if (pstore->b_private) {
			if (!exmdb_client::get_mbox_perm(pstore->dir,
			    pinfo->get_username(), &permission))
				return FALSE;
			*static_cast<uint32_t *>(*ppvalue) &= ~(frightsGromoxSendAs | frightsGromoxStoreOwner);
			return TRUE;
		}
		*static_cast<uint32_t *>(*ppvalue) = rightsAll | frightsContact;
		return TRUE;
	}
	case PR_EMAIL_ADDRESS: {
		std::string essdn;
		if (cvt_username_to_essdn(pstore->b_private ? pstore->account :
		    account_to_domain(pstore->account), g_org_name,
		    mysql_adaptor_get_user_ids,
		    mysql_adaptor_get_domain_ids, essdn) != ecSuccess)
			return FALSE;
		auto tstr = cu_alloc<char>(essdn.size() + 1);
		*ppvalue = tstr;
		if (*ppvalue == nullptr)
			return FALSE;
		gx_strlcpy(tstr, essdn.c_str(), essdn.size() + 1);
		return TRUE;
	}
	case PR_EXTENDED_RULE_SIZE_LIMIT: {
		auto r = cu_alloc<uint32_t>();
		*ppvalue = r;
		if (*ppvalue == nullptr)
			return FALSE;
		*r = g_max_extrule_len;
		return TRUE;
	}
	case PR_MAILBOX_OWNER_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = common_util_username_to_addressbook_entryid(pstore->account);
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_MAILBOX_OWNER_NAME: {
		if (!pstore->b_private)
			return FALSE;
		if (!mysql_adaptor_get_user_displayname(pstore->account,
		    temp_buff, std::size(temp_buff)))
			return FALSE;	
		if ('\0' == temp_buff[0]) {
			auto tstr = cu_alloc<char>(strlen(pstore->account) + 1);
			*ppvalue = tstr;
			if (*ppvalue == nullptr)
				return FALSE;
			strcpy(tstr, pstore->account);
			return TRUE;
		}
		auto tstr = cu_alloc<char>(strlen(temp_buff) + 1);
		*ppvalue = tstr;
		if (*ppvalue == nullptr)
			return FALSE;
		strcpy(tstr, temp_buff);
		return TRUE;
	}
	case PR_MAX_SUBMIT_MESSAGE_SIZE: {
		auto r = cu_alloc<uint32_t>();
		*ppvalue = r;
		if (*ppvalue == nullptr)
			return FALSE;
		*r = g_max_mail_len;
		return TRUE;
	}
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = static_cast<uint32_t>(MAPI_STORE);
		return TRUE;
	}
	case PR_PROVIDER_DISPLAY:
		*ppvalue = deconst("Exchange Message Store");
		return TRUE;
	case PR_RESOURCE_FLAGS: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		*v = pstore->owner_mode() ?
		     STATUS_PRIMARY_IDENTITY | STATUS_DEFAULT_STORE | STATUS_PRIMARY_STORE :
		     STATUS_NO_DEFAULT_STORE;
		return TRUE;
	}
	case PR_RESOURCE_TYPE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = static_cast<uint32_t>(MAPI_STORE_PROVIDER);
		return TRUE;
	}
	case PR_STORE_SUPPORT_MASK: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		if (!pstore->b_private) {
			*v = EC_SUPPORTMASK_PUBLIC;
			return TRUE;
		}
		if (pstore->owner_mode()) {
			*v = EC_SUPPORTMASK_OWNER;
			return TRUE;
		}
		*v = EC_SUPPORTMASK_OTHER;
		auto pinfo = zs_get_info();
		auto ret = cu_get_delegate_perm_MD(pinfo->get_username(), pstore->dir);
		if (ret >= repr_grant::send_on_behalf)
			*v |= STORE_SUBMIT_OK;
		return TRUE;
	}
	case PR_RECORD_KEY:
	case PR_INSTANCE_KEY:
	case PR_STORE_RECORD_KEY:
	case PR_MAPPING_SIGNATURE:
		*ppvalue = common_util_guid_to_binary(pstore->mailbox_guid);
		return TRUE;
	case PR_ENTRYID:
	case PR_STORE_ENTRYID:
		*ppvalue = common_util_to_store_entryid(pstore);
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_USER_NAME: {
		auto pinfo = zs_get_info();
		*ppvalue = deconst(pinfo->get_username());
		return TRUE;
	}
	case PR_USER_ENTRYID: {
		auto pinfo = zs_get_info();
		*ppvalue = common_util_username_to_addressbook_entryid(pinfo->get_username());
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	}
	case PR_ROOT_ENTRYID:
		*ppvalue = cu_fid_to_entryid(pstore, rop_util_make_eid_ex(1, pstore->b_private ?
		           PRIVATE_FID_ROOT : PUBLIC_FID_ROOT));
		return *ppvalue != nullptr ? TRUE : false;
	case PR_FINDER_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_FINDER));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_IPM_FAVORITES_ENTRYID:
		/*
		 * Our PR_IPM_FAVORITES_ENTRYID for public stores is not
		 * replicating the behavior exhibited by MSMAPI.
		 */
		*ppvalue = cu_fid_to_entryid(pstore,
		           rop_util_make_eid_ex(1, pstore->b_private ?
		           PRIVATE_FID_SHORTCUTS : PUBLIC_FID_IPMSUBTREE));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_IPM_SUBTREE_ENTRYID:
		/* else case:: different from native MAPI */
		*ppvalue = cu_fid_to_entryid(pstore, rop_util_make_eid_ex(1,
		           pstore->b_private ? PRIVATE_FID_IPMSUBTREE : PUBLIC_FID_IPMSUBTREE));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_IPM_INBOX_ENTRYID:
		*ppvalue = cu_fid_to_entryid(pstore, rop_util_make_eid_ex(1,
		           pstore->b_private ? PRIVATE_FID_INBOX : PUBLIC_FID_IPMSUBTREE));
		if (*ppvalue == nullptr)
			return false;
		return TRUE;
	case PR_IPM_OUTBOX_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_OUTBOX));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_IPM_SENTMAIL_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_IPM_WASTEBASKET_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_DELETED_ITEMS));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_IPM_DAF_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore, rop_util_make_eid_ex(1,
		           PRIVATE_FID_DEFERRED_ACTION));
		return *ppvalue != nullptr ? TRUE : false;
	case PR_SCHEDULE_FOLDER_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_SCHEDULE));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_VIEWS_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore, rop_util_make_eid_ex(1, PRIVATE_FID_VIEWS));
		return *ppvalue != nullptr ? TRUE : false;
	case PR_COMMON_VIEWS_ENTRYID:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_COMMON_VIEWS));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_IPM_PUBLIC_FOLDERS_ENTRYID:
		/*
		 * Our PR_IPM_PUBLIC_FOLDERS_ENTRYID for public stores is not
		 * replicating the behavior exhibited by MSMAPI.
		 */
	case PR_NON_IPM_SUBTREE_ENTRYID:
		if (pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PUBLIC_FID_NONIPMSUBTREE));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_EFORMS_REGISTRY_ENTRYID:
		if (pstore->b_private)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pstore,
			rop_util_make_eid_ex(1, PUBLIC_FID_EFORMSREGISTRY));
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PidTagXSpoolerQueueEntryId:
		*ppvalue = cu_fid_to_entryid(pstore, rop_util_make_eid_ex(1,
		           pstore->b_private ? PRIVATE_FID_SPOOLER_QUEUE : PUBLIC_FID_NONIPMSUBTREE));
		return *ppvalue != nullptr ? TRUE : false;
	case PR_EC_SERVER_VERSION:
		*ppvalue = deconst(PACKAGE_VERSION);
		return TRUE;
	case PR_EC_OUTOFOFFICE:
	case PR_EC_OUTOFOFFICE_MSG:
	case PR_EC_OUTOFOFFICE_SUBJECT:
	case PR_EC_OUTOFOFFICE_FROM:
	case PR_EC_OUTOFOFFICE_UNTIL:
	case PR_EC_ALLOW_EXTERNAL:
	case PR_EC_EXTERNAL_AUDIENCE:
	case PR_EC_EXTERNAL_REPLY:
	case PR_EC_EXTERNAL_SUBJECT:
		if (!pstore->b_private)
			return FALSE;
		*ppvalue = store_object_get_oof_property(pstore->get_dir(), proptag);
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PR_EC_USER_LANGUAGE: {
		if (!pstore->b_private)
			return FALSE;
		sql_meta_result mres;
		if (mysql_adaptor_meta(pstore->account, WANTPRIV_METAONLY, mres) != 0)
			return FALSE;	
		if (mres.lang.size() > 0)
			mres.lang += ".UTF-8";
		*ppvalue = common_util_dup(mres.lang.c_str());
		return TRUE;
	}
	case PR_EC_USER_TIMEZONE: {
		if (!pstore->b_private)
			return FALSE;
		sql_meta_result mres;
		auto tmzone = mysql_adaptor_meta(pstore->account, WANTPRIV_METAONLY, mres) == 0 ?
		              mres.timezone.c_str() : nullptr;
		if (*znul(tmzone) == '\0') {
			*ppvalue = deconst(common_util_get_default_timezone());
			return TRUE;
		}
		*ppvalue = common_util_dup(tmzone);
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	}
	case PR_EC_WEBACCESS_SETTINGS_JSON:
		*ppvalue = cu_read_storenamedprop(pstore->dir, PSETID_Gromox,
		           "websettings", PT_UNICODE);
		if (*ppvalue == nullptr)
			return false;
		return TRUE;
	case PR_EC_RECIPIENT_HISTORY_JSON:
		*ppvalue = cu_read_storenamedprop(pstore->dir, PSETID_Gromox,
		           "websettings_recipienthistory", PT_UNICODE);
		if (*ppvalue == nullptr)
			return false;
		return TRUE;
	case PR_EC_WEBAPP_PERSISTENT_SETTINGS_JSON:
		*ppvalue = cu_read_storenamedprop(pstore->dir, PSETID_Gromox,
		           "websettings_persistent", PT_UNICODE);
		if (*ppvalue == nullptr)
			return false;
		return TRUE;
	case PR_EC_ENABLED_FEATURES_L: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return false;
		auto info = zs_get_info();
		*v = info->privbits;
		*ppvalue = v;
		return TRUE;
	}
	/*
	 * Do *not* handle PR_EMS_AB_THUMBNAIL_PHOTO. EMSAB proptags are not
	 * valid in their intended sense for IMsgStores.
	 */
	}
	return FALSE;
}

BOOL store_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	auto pstore = this;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (!store_object_get_calculated_property(this, tag, &pvalue))
			tmp_proptags.emplace_back(tag);
		else if (pvalue != nullptr)
			ppropvals->emplace_back(tag, pvalue);
		else
			return false;
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	auto pinfo = zs_get_info();
	if (pstore->b_private && pinfo->user_id == pstore->account_id) {
		for (unsigned int i = 0; i < tmp_proptags.count; ++i) {
			auto pvalue = pinfo->ptree->get_zstore_propval(tmp_proptags.pproptag[i]);
			if (pvalue == nullptr)
				continue;
			ppropvals->emplace_back(tmp_proptags.pproptag[i], pvalue);
			tmp_proptags.count--;
			if (i < tmp_proptags.count) {
				memmove(tmp_proptags.pproptag + i,
					tmp_proptags.pproptag + i + 1,
					sizeof(uint32_t) * (tmp_proptags.count - i));
			}
		}	
		if (tmp_proptags.count == 0)
			return TRUE;
	}
	if (!exmdb_client::get_store_properties(
		pstore->dir, pinfo->cpid, &tmp_proptags,
	    &tmp_propvals))
		return FALSE;	
	if (tmp_propvals.count == 0)
		return TRUE;
	memcpy(ppropvals->ppropval +
		ppropvals->count, tmp_propvals.ppropval,
		sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

static BOOL store_object_set_oof_property(const char *maildir,
	uint32_t proptag, const void *pvalue)
{
	char *pbuff;
	int buff_len;
	char *ptoken;
	std::string autoreply_path;
	
	try {
		autoreply_path = maildir + "/config/autoreply.cfg"s;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1483: ENOMEM");
		return false;
	}
	/* Ensure file exists for config_file_prg */
	auto fdtest = open(autoreply_path.c_str(), O_CREAT | O_WRONLY, FMODE_PUBLIC);
	if (fdtest < 0)
		return false;
	close(fdtest);
	switch (proptag) {
	case PR_EC_OUTOFOFFICE: {
		auto pconfig = config_file_init(autoreply_path.c_str(), oof_defaults);
		if (pconfig == nullptr)
			return FALSE;
		auto v = *static_cast<const uint32_t *>(pvalue);
		pconfig->set_value("OOF_STATE", v == 1 ? "1" : v == 2 ? "2" : "0");
		return pconfig->save();
	}
	case PR_EC_OUTOFOFFICE_FROM:
	case PR_EC_OUTOFOFFICE_UNTIL: {
		auto pconfig = config_file_init(autoreply_path.c_str(), oof_defaults);
		if (pconfig == nullptr)
			return FALSE;
		long long t = rop_util_nttime_to_unix(*static_cast<const uint64_t *>(pvalue));
		pconfig->set_value(proptag == PR_EC_OUTOFOFFICE_FROM ?
			"START_TIME" : "END_TIME", std::to_string(t).c_str());
		return pconfig->save();
	}
	case PR_EC_OUTOFOFFICE_MSG:
	case PR_EC_EXTERNAL_REPLY: {
		try {
			autoreply_path = maildir;
			autoreply_path += proptag == PR_EC_OUTOFOFFICE_MSG ?
			             "/config/internal-reply" : "/config/external-reply";
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1484: ENOMEM");
			return false;
		}
		wrapfd fd = open(autoreply_path.c_str(), O_RDONLY);
		struct stat node_stat;
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0) {
			buff_len = strlen(static_cast<const char *>(pvalue));
			pbuff = cu_alloc<char>(buff_len + 256);
			if (pbuff == nullptr)
				return FALSE;
			buff_len = sprintf(pbuff, "Content-Type: text/html;\r\n"
			           "\tcharset=\"utf-8\"\r\n\r\n%s",
			           static_cast<const char *>(pvalue));
		} else {
			buff_len = node_stat.st_size;
			pbuff = cu_alloc<char>(buff_len + strlen(static_cast<const char *>(pvalue)) + 1);
			if (pbuff == nullptr || read(fd.get(), pbuff, buff_len) != buff_len)
				return FALSE;
			pbuff[buff_len] = '\0';
			ptoken = strstr(pbuff, "\r\n\r\n");
			if (NULL != ptoken) {
				strcpy(ptoken + 4, static_cast<const char *>(pvalue));
				buff_len = strlen(pbuff);
			} else {
				buff_len = sprintf(pbuff, "Content-Type: text/html;\r\n"
				           "\tcharset=\"utf-8\"\r\n\r\n%s",
				           static_cast<const char *>(pvalue));
			}
		}
		fd = open(autoreply_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PUBLIC);
		if (fd.get() < 0 || write(fd.get(), pbuff, buff_len) != buff_len)
			return FALSE;
		return TRUE;
	}
	case PR_EC_OUTOFOFFICE_SUBJECT:
	case PR_EC_EXTERNAL_SUBJECT: {
		try {
			autoreply_path = maildir;
			autoreply_path += proptag == PR_EC_OUTOFOFFICE_SUBJECT ?
			             "/config/internal-reply" : "/config/external-reply";
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1485: ENOMEM");
			return false;
		}
		struct stat node_stat;
		wrapfd fd = open(autoreply_path.c_str(), O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0) {
			buff_len = strlen(static_cast<const char *>(pvalue));
			pbuff = cu_alloc<char>(buff_len + 256);
			if (pbuff == nullptr)
				return FALSE;
			buff_len = sprintf(pbuff, "Content-Type: text/html;\r\n\t"
			           "charset=\"utf-8\"\r\nSubject: %s\r\n\r\n",
			           static_cast<const char *>(pvalue));
		} else {
			buff_len = node_stat.st_size;
			pbuff = cu_alloc<char>(buff_len + strlen(static_cast<const char *>(pvalue)) + 16);
			if (pbuff == nullptr)
				return FALSE;
			ptoken = cu_alloc<char>(buff_len + 1);
			if (ptoken == nullptr)
				return FALSE;
			if (read(fd.get(), ptoken, buff_len) != buff_len)
				return FALSE;
			ptoken[buff_len] = '\0';
			ptoken = strstr(ptoken, "\r\n\r\n");
			if (ptoken == nullptr)
				buff_len = sprintf(pbuff, "Content-Type: text/html;\r\n\t"
				           "charset=\"utf-8\"\r\nSubject: %s\r\n\r\n",
				           static_cast<const char *>(pvalue));
			else
				buff_len = sprintf(pbuff, "Content-Type: text/html;\r\n\t"
				           "charset=\"utf-8\"\r\nSubject: %s%s",
				           static_cast<const char *>(pvalue), ptoken);
		}
		fd = open(autoreply_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PUBLIC);
		if (fd.get() < 0 || write(fd.get(), pbuff, buff_len) != buff_len)
			return FALSE;
		return TRUE;
	}
	case PR_EC_ALLOW_EXTERNAL:
	case PR_EC_EXTERNAL_AUDIENCE: {
		auto pconfig = config_file_init(autoreply_path.c_str(), oof_defaults);
		if (pconfig == nullptr)
			return FALSE;
		pconfig->set_value(proptag == PR_EC_ALLOW_EXTERNAL ?
		                      "ALLOW_EXTERNAL_OOF" : "EXTERNAL_AUDIENCE",
		                      *static_cast<const uint8_t *>(pvalue) == 0 ? "0" : "1");
		return pconfig->save();
	}
	}
	return FALSE;
}

static BOOL store_object_set_folder_name(store_object *pstore,
	uint64_t fid_val, const char *pdisplayname)
{
	BINARY *pbin_pcl;
	uint64_t folder_id;
	uint64_t last_time;
	uint64_t change_num;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[5];
	
	if (!pstore->b_private)
		return FALSE;
	folder_id = rop_util_make_eid_ex(1, fid_val);
	tmp_propvals.ppropval = propval_buff;
	tmp_propvals.count = 5;
	tmp_propvals.ppropval[0].proptag = PR_DISPLAY_NAME;
	tmp_propvals.ppropval[0].pvalue = deconst(pdisplayname);
	if (!exmdb_client::allocate_cn(pstore->dir, &change_num))
		return FALSE;
	tmp_propvals.ppropval[1].proptag = PidTagChangeNumber;
	tmp_propvals.ppropval[1].pvalue = &change_num;
	if (!exmdb_client_get_folder_property(pstore->dir, CP_ACP, folder_id,
	    PR_PREDECESSOR_CHANGE_LIST, reinterpret_cast<void **>(&pbin_pcl)))
		return FALSE;
	auto pbin_changekey = cu_xid_to_bin({rop_util_make_user_guid(pstore->account_id), change_num});
	if (pbin_changekey == nullptr)
		return FALSE;
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (pbin_pcl == nullptr)
		return FALSE;
	last_time = rop_util_current_nttime();
	tmp_propvals.ppropval[2].proptag = PR_CHANGE_KEY;
	tmp_propvals.ppropval[2].pvalue = pbin_changekey;
	tmp_propvals.ppropval[3].proptag = PR_PREDECESSOR_CHANGE_LIST;
	tmp_propvals.ppropval[3].pvalue = pbin_pcl;
	tmp_propvals.ppropval[4].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals.ppropval[4].pvalue = &last_time;
	return exmdb_client::set_folder_properties(pstore->dir, CP_ACP,
	       folder_id, &tmp_propvals, &tmp_problems);
}

/**
 * @locale:	input string like "en_US.UTF-8"
 */
static void set_store_lang(store_object *store, const char *locale)
{
	/*
	 * If Offline Mode happens to write this prop even though it is
	 * unchanged, it may appear as if folder names have reset.
	 */
	if (!store->b_private)
		return;
	auto lang = folder_namedb_resolve(locale);
	if (lang == nullptr) {
		mlog(LV_WARN, "W-1506: %s requested to set folder names to %s, but this language is unknown.",
		        store->account, locale);
	} else {
		static constexpr unsigned int fids[] = {
			PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_SENT_ITEMS,
			PRIVATE_FID_DELETED_ITEMS, PRIVATE_FID_OUTBOX,
			PRIVATE_FID_INBOX, PRIVATE_FID_DRAFT,
			PRIVATE_FID_CALENDAR, PRIVATE_FID_JOURNAL,
			PRIVATE_FID_NOTES, PRIVATE_FID_TASKS,
			PRIVATE_FID_CONTACTS, PRIVATE_FID_JUNK,
			PRIVATE_FID_SYNC_ISSUES, PRIVATE_FID_CONFLICTS,
			PRIVATE_FID_LOCAL_FAILURES, PRIVATE_FID_SERVER_FAILURES,
		};
		for (auto fid_val : fids) {
			auto name = folder_namedb_get(lang, fid_val);
			if (name != nullptr)
				store_object_set_folder_name(store, fid_val, name);
		}
	}

	char mloc[32];
	gx_strlcpy(mloc, locale, std::size(mloc));
	auto p = strchr(mloc, '.');
	if (p != nullptr)
		*p = '\0';
	p = strchr(mloc, '@');
	if (p != nullptr)
		*p = '\0';
	mysql_adaptor_set_user_lang(store->account, mloc);
}

/*
 * This function is tailored to grommunio-web and does not behave like normal.
 */
BOOL store_object::set_properties(const TPROPVAL_ARRAY *ppropvals)
{
	auto pinfo = zs_get_info();
	auto pstore = this;
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		const auto &pv = ppropvals->ppropval[i];
		if (store_object_is_readonly_prop(pstore, pv.proptag))
			continue;
		switch (pv.proptag) {
		/* OOF is stored outside the information store. */
		case PR_EC_OUTOFOFFICE:
		case PR_EC_OUTOFOFFICE_FROM:
		case PR_EC_OUTOFOFFICE_UNTIL:
		case PR_EC_OUTOFOFFICE_MSG:
		case PR_EC_OUTOFOFFICE_SUBJECT:
		case PR_EC_ALLOW_EXTERNAL:
		case PR_EC_EXTERNAL_AUDIENCE:
		case PR_EC_EXTERNAL_SUBJECT:
		case PR_EC_EXTERNAL_REPLY:
			if (!store_object_set_oof_property(pstore->get_dir(),
			    pv.proptag, pv.pvalue))
				return FALSE;	
			continue;
		case PR_EC_USER_LANGUAGE:
			set_store_lang(pstore, static_cast<char *>(pv.pvalue));
			continue;
		case PR_EC_USER_TIMEZONE:
			if (pstore->b_private)
				mysql_adaptor_set_timezone(pstore->account,
					static_cast<char *>(pv.pvalue));
			continue;
		case PR_EMS_AB_THUMBNAIL_PHOTO: {
			/*
			 * Translate g-web issuing a set_property call with a
			 * silly proptag.
			 */
			if (!pstore->b_private)
				continue;
			auto bv = static_cast<BINARY *>(pv.pvalue);
			cu_write_storenamedprop(pstore->dir, PSETID_Gromox,
				"photo", PT_BINARY, bv->pb, bv->cb);
			continue;
		}
		case PR_EC_WEBACCESS_SETTINGS_JSON: {
			if (!pstore->b_private)
				break;
			cu_write_storenamedprop(pstore->dir, PSETID_Gromox,
				"websettings", PT_UNICODE, pv.pvalue, 0);
			/* Remove old copy in shadow store */
			pinfo->ptree->remove_zstore_propval(pv.proptag);
			continue;
		}
		case PR_EC_RECIPIENT_HISTORY_JSON: {
			if (!pstore->b_private)
				break;
			cu_write_storenamedprop(pstore->dir, PSETID_Gromox,
				"websettings_recipienthistory", PT_UNICODE, pv.pvalue, 0);
			/* Remove old copy in shadow store */
			pinfo->ptree->remove_zstore_propval(pv.proptag);
			continue;
		}
		case PR_EC_WEBAPP_PERSISTENT_SETTINGS_JSON: {
			if (!pstore->b_private)
				break;
			cu_write_storenamedprop(pstore->dir, PSETID_Gromox,
				"websettings_persistent", PT_UNICODE, pv.pvalue, 0);
			/* Remove old copy in shadow store */
			pinfo->ptree->remove_zstore_propval(pv.proptag);
			continue;
		}
		}
		/*
		 * The rest is written to a *shadow* store object only visible
		 * to zcore (unexplored historic reasons).
		 */
		if (!pinfo->ptree->set_zstore_propval(&pv))
			return FALSE;
	}
	return TRUE;
}

BOOL store_object::remove_properties(const PROPTAG_ARRAY *pproptags)
{
	auto pstore = this;
	auto pinfo = zs_get_info();
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (store_object_is_readonly_prop(pstore, tag))
			continue;
		pinfo->ptree->remove_zstore_propval(tag);
	}
	return TRUE;
}

static BOOL store_object_get_folder_permissions(store_object *pstore,
    uint64_t folder_id, PERMISSION_SET *pperm_set)
{
	uint32_t row_num;
	uint32_t table_id;
	uint32_t max_count;
	TARRAY_SET permission_set;
	PERMISSION_ROW *pperm_row;
	static constexpr uint32_t proptag_buff[] = {PR_ENTRYID, PR_MEMBER_RIGHTS, PR_MEMBER_ID};
	static constexpr PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	
	if (!exmdb_client::load_permission_table(
	    pstore->dir, folder_id, 0, &table_id, &row_num))
		return FALSE;
	if (!exmdb_client::query_table(pstore->dir, nullptr, CP_ACP, table_id,
	    &proptags, 0, row_num, &permission_set)) {
		exmdb_client::unload_table(pstore->dir, table_id);
		return FALSE;
	}
	exmdb_client::unload_table(pstore->dir, table_id);
	max_count = (pperm_set->count/100)*100;
	for (size_t i = 0; i < permission_set.count; ++i) {
		if (max_count == pperm_set->count) {
			max_count += 100;
			pperm_row = cu_alloc<PERMISSION_ROW>(max_count);
			if (pperm_row == nullptr)
				return FALSE;
			if (pperm_set->count != 0)
				memcpy(pperm_row, pperm_set->prows,
					sizeof(PERMISSION_ROW)*pperm_set->count);
			pperm_set->prows = pperm_row;
		}
		auto mbid = permission_set.pparray[i]->get<uint32_t>(PR_MEMBER_ID);
		auto pentryid = permission_set.pparray[i]->get<BINARY>(PR_ENTRYID);
		size_t j;
		for (j = 0; j < pperm_set->count; j++)
			if (permrow_entryids_equal(pperm_set->prows[j], mbid, pentryid))
				break;	
		auto v = permission_set.pparray[i]->get<uint32_t>(PR_MEMBER_RIGHTS);
		if (v == nullptr)
			continue;
		if (j < pperm_set->count) {
			pperm_set->prows[j].member_rights |= *v;
			continue;
		}
		auto &cur = pperm_set->prows[pperm_set->count];
		cur.flags = RIGHT_NORMAL;
		cur.member_rights = *v;
		v = permission_set.pparray[i]->get<uint32_t>(PR_MEMBER_ID);
		cur.member_id = v != nullptr ? *v : 0xdeadbeefU;
		cur.entryid = pentryid != nullptr ? *pentryid : BINARY{};
		++pperm_set->count;
	}
	return TRUE;
}

BOOL store_object::get_permissions(PERMISSION_SET *pperm_set)
{
	auto pstore = this;
	uint32_t row_num;
	uint32_t table_id;
	TARRAY_SET tmp_set;
	uint64_t folder_id = rop_util_make_eid_ex(1, pstore->b_private ?
	                     PRIVATE_FID_IPMSUBTREE : PUBLIC_FID_IPMSUBTREE);
	
	if (!exmdb_client::load_hierarchy_table(
		pstore->dir, folder_id, NULL, TABLE_FLAG_DEPTH,
	    NULL, &table_id, &row_num))
		return FALSE;
	static constexpr proptag_t tmp_proptag[] = {PidTagFolderId};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
	if (!exmdb_client::query_table(pstore->dir, nullptr, CP_ACP, table_id,
	    &proptags, 0, row_num, &tmp_set))
		return FALSE;
	pperm_set->count = 0;
	pperm_set->prows = NULL;
	for (size_t i = 0; i < tmp_set.count; ++i) {
		if (tmp_set.pparray[i]->count == 0)
			continue;
		if (!store_object_get_folder_permissions(this,
		    *static_cast<uint64_t *>(tmp_set.pparray[i]->ppropval[0].pvalue), pperm_set))
			return FALSE;	
	}
	return TRUE;
}
