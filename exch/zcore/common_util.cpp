// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vmime/message.hpp>
#include <vmime/text.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/gab.hpp>
#include <gromox/ical.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/process.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#include <gromox/zcore_types.hpp>
#include "bounce_producer.hpp"
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "objects.hpp"
#include "store_object.hpp"
#include "system_services.hpp"
#include "zserver.hpp"
#include "../bounce_exch.cpp"

using namespace std::string_literals;
using namespace gromox;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;
using LLU = unsigned long long;

enum {
	SMTP_SEND_OK = 0,
	SMTP_CANNOT_CONNECT,
	SMTP_CONNECT_ERROR,
	SMTP_TIME_OUT,
	SMTP_TEMP_ERROR,
	SMTP_UNKOWN_RESPONSE,
	SMTP_PERMANENT_ERROR
};

namespace {

struct env_context {
	alloc_context allocator;
	int clifd = -1;
};

struct LANGMAP_ITEM {
	char lang[32];
	char i18n[32];
};

}

size_t g_max_mail_len;
unsigned int g_max_rcpt, g_max_message;
unsigned int g_max_rule_len, g_max_extrule_len, zcore_backfill_transporthdr;
static std::string g_smtp_url;
char g_org_name[256];
static thread_local const char *g_dir_key;
static thread_local unsigned int g_env_refcount;
static thread_local std::unique_ptr<env_context> g_env_key;
static char g_default_charset[32];
static char g_submit_command[1024];
static constexpr char ZCORE_UA[] = PACKAGE_NAME "-zcore " PACKAGE_VERSION;

BOOL common_util_verify_columns_and_sorts(
	const PROPTAG_ARRAY *pcolumns,
	const SORTORDER_SET *psort_criteria)
{
	proptag_t proptag = 0;
	for (size_t i = 0; i < psort_criteria->count; ++i) {
		if (!(psort_criteria->psort[i].type & MV_INSTANCE))
			continue;
		if (!(psort_criteria->psort[i].type & MV_FLAG))
			return FALSE;
		proptag = PROP_TAG(psort_criteria->psort[i].type, psort_criteria->psort[i].propid);
		break;
	}
	for (size_t i = 0; i < pcolumns->count; ++i)
		if (pcolumns->pproptag[i] & MV_INSTANCE &&
		    proptag != pcolumns->pproptag[i])
			return FALSE;
	return TRUE;
}

/* Cf. oxomsg_extract_delegate for comments */
bool cu_extract_delegate(message_object *pmessage, std::string &username)
{
	TPROPVAL_ARRAY tmp_propvals;
	static constexpr proptag_t proptag_buff[] =
		{PR_SENT_REPRESENTING_ADDRTYPE, PR_SENT_REPRESENTING_EMAIL_ADDRESS,
		PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_SENT_REPRESENTING_ENTRYID};
	static constexpr PROPTAG_ARRAY tmp_proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	if (!pmessage->get_properties(&tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (0 == tmp_propvals.count) {
		username.clear();
		return TRUE;
	}
	auto addrtype = tmp_propvals.get<const char>(PR_ADDRTYPE);
	auto emaddr   = tmp_propvals.get<const char>(PR_EMAIL_ADDRESS);
	if (addrtype != nullptr) {
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr, g_org_name,
		           mysql_adaptor_userid_to_name, username);
		if (ret == ecSuccess)
			return true;
		else if (ret != ecNullObject)
			return false;
	}
	auto str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr) {
		username = str;
		return TRUE;
	}
	auto ret = cvt_entryid_to_smtpaddr(tmp_propvals.get<const BINARY>(PR_SENT_REPRESENTING_ENTRYID),
		   g_org_name, mysql_adaptor_userid_to_name, username);
	if (ret == ecSuccess)
		return TRUE;
	if (ret == ecNullObject) {
		username.clear();
		return TRUE;
	}
	mlog(LV_WARN, "W-2100: rejecting submission of msgid %llxh because "
		"its PR_SENT_REPRESENTING_ENTRYID does not reference "
		"a user in the local system",
		static_cast<unsigned long long>(pmessage->message_id));
	return false;
}

/**
 * Check whether @account (secretary) is allowed to represent @maildir.
 * @send_as:	whether to evaluate either the Send-As or Send-On-Behalf list
 */
static int cu_test_delegate_perm_MD(const char *account,
    const char *maildir, bool send_as) try
{
	std::vector<std::string> delegate_list;
	auto path = maildir + std::string(send_as ? "/config/sendas.txt" : "/config/delegates.txt");
	auto ret = read_file_by_line(path.c_str(), delegate_list);
	if (ret != 0 && ret != ENOENT) {
		mlog(LV_WARN, "W-2057: %s: %s", path.c_str(), strerror(ret));
		return ret;
	}
	for (const auto &d : delegate_list)
		if (strcasecmp(d.c_str(), account) == 0)
			return 1;
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2056: ENOMEM");
	return false;
}

/**
 * @account:	"secretary account"
 * @maildir:	"boss account"
 */
repr_grant cu_get_delegate_perm_MD(const char *account, const char *maildir)
{
	auto ret = cu_test_delegate_perm_MD(account, maildir, true);
	if (ret < 0)
		return repr_grant::error;
	if (ret > 0)
		return repr_grant::send_as;
	ret = cu_test_delegate_perm_MD(account, maildir, false);
	if (ret < 0)
		return repr_grant::error;
	if (ret > 0)
		return repr_grant::send_on_behalf;
	return repr_grant::no_impersonation;
}

repr_grant cu_get_delegate_perm_AA(const char *account, const char *repr)
{
	if (strcasecmp(account, repr) == 0)
		return repr_grant::send_as;
	sql_meta_result mres;
	if (mysql_adaptor_meta(repr, WANTPRIV_METAONLY, mres) != 0)
		return repr_grant::error;
	return cu_get_delegate_perm_MD(account, mres.maildir.c_str());
}

ec_error_t cu_set_propval(TPROPVAL_ARRAY *parray, proptag_t tag, const void *data)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (parray->ppropval[i].proptag == tag) {
			parray->ppropval[i].pvalue = deconst(data);
			return ecSuccess;
		}
	}

	if (parray->count >= UINT16_MAX)
		return ecTooBig;
	auto newarr = cu_alloc<TAGGED_PROPVAL>(parray->count + 1);
	if (newarr == nullptr)
		return ecServerOOM;
	if (parray->ppropval != nullptr)
		memcpy(newarr, parray->ppropval, parray->count * sizeof(TAGGED_PROPVAL));
	parray->ppropval = newarr;
	parray->emplace_back(tag, data);
	return ecSuccess;
}

void common_util_remove_propvals(TPROPVAL_ARRAY *parray, proptag_t proptag)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (proptag != parray->ppropval[i].proptag)
			continue;
		parray->count--;
		if (i < parray->count)
			memmove(parray->ppropval + i, parray->ppropval + i + 1,
			        (parray->count - i) * sizeof(TAGGED_PROPVAL));
		return;
	}
}

void common_util_reduce_proptags(PROPTAG_ARRAY *pproptags_minuend,
	const PROPTAG_ARRAY *pproptags_subtractor)
{
	for (unsigned int j = 0; j < pproptags_subtractor->count; ++j) {
		for (unsigned int i = 0; i < pproptags_minuend->count; ++i) {
			if (pproptags_subtractor->pproptag[j] != pproptags_minuend->pproptag[i])
				continue;
			pproptags_minuend->count--;
			if (i < pproptags_minuend->count)
				memmove(pproptags_minuend->pproptag + i,
					pproptags_minuend->pproptag + i + 1,
					(pproptags_minuend->count - i) *
					sizeof(uint32_t));
			break;
		}
	}
}

BOOL common_util_essdn_to_uid(const char *pessdn, int *puid)
{
	char tmp_essdn[1024];
	auto tmp_len = snprintf(tmp_essdn, std::size(tmp_essdn),
	               "/o=%s/" EAG_RCPTS "/cn=", g_org_name);
	if (strncasecmp(pessdn, tmp_essdn, tmp_len) != 0 ||
	    pessdn[tmp_len+16] != '-')
		return FALSE;
	*puid = decode_hex_int(pessdn + tmp_len + 8);
	return TRUE;
}

BOOL common_util_essdn_to_ids(const char *pessdn,
	int *pdomain_id, int *puser_id)
{
	char tmp_essdn[1024];
	auto tmp_len = snprintf(tmp_essdn, std::size(tmp_essdn),
	               "/o=%s/" EAG_RCPTS "/cn=", g_org_name);
	if (strncasecmp(pessdn, tmp_essdn, tmp_len) != 0 ||
	    pessdn[tmp_len+16] != '-')
		return FALSE;
	*pdomain_id = decode_hex_int(pessdn + tmp_len);
	*puser_id = decode_hex_int(pessdn + tmp_len + 8);
	return TRUE;	
}

BOOL common_util_exmdb_locinfo_from_string(
	const char *loc_string, uint8_t *ptype,
	int *pdb_id, uint64_t *peid)
{
	int tmp_len;
	uint64_t tmp_val;
	char tmp_buff[16];
	
	if (strncmp(loc_string, "1:", 2) == 0)
		*ptype = LOC_TYPE_PRIVATE_FOLDER;
	else if (strncmp(loc_string, "2:", 2) == 0)
		*ptype = LOC_TYPE_PUBLIC_FOLDER;
	else if (strncmp(loc_string, "3:", 2) == 0)
		*ptype = LOC_TYPE_PRIVATE_MESSAGE;
	else if (strncmp(loc_string, "4:", 2) == 0)
		*ptype = LOC_TYPE_PUBLIC_MESSAGE;
	else
		return FALSE;

	auto ptoken = strchr(loc_string + 2, ':');
	if (ptoken == nullptr)
		return FALSE;
	tmp_len = ptoken - (loc_string + 2);
	if (tmp_len > 12)
		return FALSE;
	memcpy(tmp_buff, loc_string + 2, tmp_len);
	tmp_buff[tmp_len] = '\0';
	*pdb_id = strtol(tmp_buff, nullptr, 0);
	if (*pdb_id == 0)
		return FALSE;
	tmp_val = strtoll(ptoken + 1, NULL, 16);
	if (tmp_val == 0)
		return FALSE;
	*peid = rop_util_make_eid_ex(1, tmp_val);
	return TRUE;
}

void common_util_init(const char *org_name, const char *default_charset,
    unsigned int max_rcpt, unsigned int max_message, size_t max_mail_len,
    unsigned int max_rule_len, std::string &&smtp_url, const char *submit_command)
{
	gx_strlcpy(g_org_name, org_name, std::size(g_org_name));
	gx_strlcpy(g_default_charset, default_charset, std::size(g_default_charset));
	g_max_rcpt = max_rcpt;
	g_max_message = max_message;
	g_max_mail_len = max_mail_len;
	g_max_rule_len = g_max_extrule_len = max_rule_len;
	g_smtp_url = std::move(smtp_url);
	gx_strlcpy(g_submit_command, submit_command, std::size(g_submit_command));
}

int common_util_run(const char *data_path)
{
	if (!oxcmail_init_library(g_org_name, mysql_adaptor_get_user_ids,
	    mysql_adaptor_get_domain_ids, mysql_adaptor_userid_to_name)) {
		mlog(LV_ERR, "common_util: failed to init oxcmail library");
		return -2;
	}
	return 0;
}

BOOL common_util_build_environment() try
{
	if (++g_env_refcount > 1)
		return TRUE;
	g_env_key = std::make_unique<env_context>();
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1977: ENOMEM");
	return false;
}

void common_util_free_environment()
{
	if (--g_env_refcount > 0)
		return;
	if (g_env_key == nullptr)
		mlog(LV_WARN, "W-1908: T%lu: g_env_key already unset", gx_gettid());
	else
		g_env_key.reset();
}

void* common_util_alloc(size_t size)
{
	auto pctx = g_env_key.get();
	if (pctx == nullptr) {
		mlog(LV_ERR, "E-1909: T%lu: g_env_key is unset, allocator is unset", gx_gettid());
		return NULL;
	}
	return pctx->allocator.alloc(size);
}

void common_util_set_clifd(int clifd)
{
	auto pctx = g_env_key.get();
	if (pctx == nullptr)
		mlog(LV_ERR, "E-1810: T%lu: g_env_key is unset, cannot set clifd", gx_gettid());
	else
		pctx->clifd = clifd;
}

int common_util_get_clifd()
{
	auto pctx = g_env_key.get();
	if (pctx != nullptr)
		return pctx->clifd;
	mlog(LV_ERR, "E-1811: T%lu: g_env_key is unset, clifd is unset", gx_gettid());
	return -1;
}

char *common_util_dup(std::string_view sv)
{
	auto out = cu_alloc<char>(sv.size() + 1);
	if (out != nullptr) {
		memcpy(out, sv.data(), sv.size());
		out[sv.size()] = '\0';
	}
	return out;
}

BOOL common_util_parse_addressbook_entryid(BINARY entryid_bin, uint32_t *ptype,
    char *pessdn, size_t dsize)
{
	EXT_PULL ext_pull;
	EMSAB_ENTRYID tmp_entryid;

	ext_pull.init(entryid_bin.pb, entryid_bin.cb, common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_abk_eid(&tmp_entryid) != pack_result::ok)
		return FALSE;
	*ptype = tmp_entryid.type;
	gx_strlcpy(pessdn, tmp_entryid.px500dn, dsize);
	return TRUE;
}

BINARY* common_util_username_to_addressbook_entryid(
	const char *username)
{
	std::string eidbuf;
	
	if (cvt_username_to_abkeid(username, g_org_name, DT_MAILUSER,
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	    eidbuf) != ecSuccess)
		return NULL;
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->cb = eidbuf.size();
	pbin->pv = common_util_alloc(pbin->cb);
	if (pbin->pv == nullptr)
		return NULL;
	memcpy(pbin->pv, eidbuf.data(), pbin->cb);
	return pbin;
}

BOOL common_util_essdn_to_entryid(const char *essdn, BINARY *pbin,
    unsigned int etyp)
{
	EXT_PUSH ext_push;
	EMSAB_ENTRYID tmp_entryid;
	
	pbin->pv = common_util_alloc(1280);
	if (pbin->pv == nullptr)
		return FALSE;
	tmp_entryid.flags = 0;
	tmp_entryid.type = etyp;
	tmp_entryid.px500dn = deconst(essdn);

	if (!ext_push.init(pbin->pv, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != pack_result::ok)
		return false;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

static BOOL common_util_username_to_entryid(const char *username,
    const char *pdisplay_name, BINARY *pbin, enum display_type *dtpp)
{
	unsigned int user_id = 0, domain_id = 0;
	char *pdomain;
	EXT_PUSH ext_push;
	char tmp_name[UADDR_SIZE];
	ONEOFF_ENTRYID oneoff_entry;
	enum display_type dtypx = DT_MAILUSER;
	
	if (mysql_adaptor_get_user_ids(username, &user_id, &domain_id, &dtypx)) {
		gx_strlcpy(tmp_name, username, std::size(tmp_name));
		pdomain = strchr(tmp_name, '@');
		if (pdomain == nullptr)
			return FALSE;
		*pdomain = '\0';
		std::string essdn;
		if (cvt_username_to_essdn(tmp_name, g_org_name, user_id,
		    domain_id, essdn) != ecSuccess)
			return false;
		if (!common_util_essdn_to_entryid(essdn.c_str(), pbin,
		    dtypx_to_etyp(dtypx)))
			return FALSE;
		if (dtpp != nullptr)
			*dtpp = dtypx;
		return TRUE;
	}
	pbin->pv = common_util_alloc(1280);
	if (pbin->pv == nullptr)
		return FALSE;
	oneoff_entry.flags = 0;
	oneoff_entry.version = 0;
	oneoff_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_UNICODE;
	oneoff_entry.pdisplay_name = pdisplay_name != nullptr && *pdisplay_name != '\0' ?
	                             deconst(pdisplay_name) : deconst(username);
	oneoff_entry.paddress_type = deconst("SMTP");
	oneoff_entry.pmail_address = deconst(username);
	if (!ext_push.init(pbin->pv, 1280, EXT_FLAG_UTF16))
		return false;
	auto status = ext_push.p_oneoff_eid(oneoff_entry);
	if (status == pack_result::charconv) {
		oneoff_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO;
		status = ext_push.p_oneoff_eid(oneoff_entry);
	}
	if (status != pack_result::ok)
		return FALSE;
	pbin->cb = ext_push.m_offset;
	if (dtpp != nullptr)
		*dtpp = DT_MAILUSER;
	return TRUE;
}

uint16_t common_util_get_messaging_entryid_type(BINARY bin)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	uint16_t folder_type;
	FLATUID provider_uid;
	
	ext_pull.init(bin.pb, bin.cb, common_util_alloc, 0);
	if (ext_pull.g_uint32(&flags) != pack_result::ok ||
	    ext_pull.g_guid(&provider_uid) != pack_result::ok)
		return 0;
	/*
	 * The GUID determines how things look after byte 20. Without
	 * inspecting the GUID, pulling an uint16_t here is undefined if going
	 * by specification. I suppose the caller ought to ensure it is only
	 * used with FOLDER_ENTRYIDs and MESSAGE_ENTRYIDs.
         */
	if (ext_pull.g_uint16(&folder_type) != pack_result::ok)
		return 0;
	return folder_type;
}

BOOL cu_entryid_to_fid(BINARY bin,
	BOOL *pb_private, int *pdb_id, uint64_t *pfolder_id)
{
	uint16_t replid;
	EXT_PULL ext_pull;
	FOLDER_ENTRYID tmp_entryid;
	
	ext_pull.init(bin.pb, bin.cb, common_util_alloc, 0);
	if (ext_pull.g_folder_eid(&tmp_entryid) != pack_result::ok)
		return FALSE;	
	switch (tmp_entryid.folder_type) {
	case EITLT_PRIVATE_FOLDER:
		*pb_private = TRUE;
		*pdb_id = rop_util_get_user_id(tmp_entryid.database_guid);
		if (*pdb_id == -1)
			return FALSE;
		*pfolder_id = rop_util_make_eid(1,
				tmp_entryid.global_counter);
		return TRUE;
	case EITLT_PUBLIC_FOLDER: {
		*pb_private = FALSE;
		*pdb_id = rop_util_get_domain_id(tmp_entryid.database_guid);
		if (*pdb_id > 0) {
			*pfolder_id = rop_util_make_eid(1,
					tmp_entryid.global_counter);
			return TRUE;
		}
		auto pinfo = zs_get_info();
		if (pinfo == nullptr || *pdb_id != pinfo->domain_id)
			return FALSE;
		ec_error_t ret = ecSuccess;
		if (!exmdb_client->get_mapping_replid(pinfo->get_homedir(),
		    tmp_entryid.database_guid, &replid, &ret) || ret != ecSuccess)
			return FALSE;
		*pfolder_id = rop_util_make_eid(replid,
					tmp_entryid.global_counter);
		return TRUE;
	}
	default:
		return FALSE;
	}
}

BOOL cu_entryid_to_mid(BINARY bin, BOOL *pb_private,
	int *pdb_id, uint64_t *pfolder_id, uint64_t *pmessage_id)
{
	uint16_t replid;
	EXT_PULL ext_pull;
	MESSAGE_ENTRYID tmp_entryid;
	
	ext_pull.init(bin.pb, bin.cb, common_util_alloc, 0);
	if (ext_pull.g_msg_eid(&tmp_entryid) != pack_result::ok)
		return FALSE;	
	if (tmp_entryid.folder_database_guid != tmp_entryid.message_database_guid)
		return FALSE;
	switch (tmp_entryid.message_type) {
	case EITLT_PRIVATE_MESSAGE:
		*pb_private = TRUE;
		*pdb_id = rop_util_get_user_id(tmp_entryid.folder_database_guid);
		if (*pdb_id == -1)
			return FALSE;
		*pfolder_id = rop_util_make_eid(1,
			tmp_entryid.folder_global_counter);
		*pmessage_id = rop_util_make_eid(1,
			tmp_entryid.message_global_counter);
		return TRUE;
	case EITLT_PUBLIC_MESSAGE: {
		*pb_private = FALSE;
		*pdb_id = rop_util_get_domain_id(tmp_entryid.folder_database_guid);
		if (*pdb_id > 0) {
			*pfolder_id = rop_util_make_eid(1,
				tmp_entryid.folder_global_counter);
			*pmessage_id = rop_util_make_eid(1,
				tmp_entryid.message_global_counter);
			return TRUE;
		}
		auto pinfo = zs_get_info();
		if (pinfo == nullptr || *pdb_id != pinfo->domain_id)
			return FALSE;
		ec_error_t ret = ecSuccess;
		if (!exmdb_client->get_mapping_replid(pinfo->get_homedir(),
		    tmp_entryid.folder_database_guid, &replid, &ret) ||
		    ret != ecSuccess)
			return FALSE;
		*pfolder_id = rop_util_make_eid(replid,
			tmp_entryid.folder_global_counter);
		*pmessage_id = rop_util_make_eid(replid,
			tmp_entryid.message_global_counter);
		return TRUE;
	}
	default:
		return FALSE;
	}
}

static ec_error_t replid_to_replguid(const store_object &logon,
    uint16_t replid, GUID &guid)
{
	auto dir = logon.get_dir();
	BOOL b_found = false;
	if (replid == 1)
		guid = logon.b_private ?
		       rop_util_make_user_guid(logon.account_id) :
		       rop_util_make_domain_guid(logon.account_id);
	else if (replid == 2)
		guid = exc_replid2;
	else if (replid == 3)
		guid = exc_replid3;
	else if (replid == 4)
		guid = exc_replid4;
	else if (replid == 5)
		guid = logon.mailbox_guid;
	else if (!exmdb_client->get_mapping_guid(dir, replid, &b_found, &guid))
		return ecError;
	else if (!b_found)
		return ecNotFound;
	return ecSuccess;
}

BINARY *cu_fid_to_entryid(const store_object &store, uint64_t folder_id)
{
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (replid_to_replguid(store, rop_util_get_replid(folder_id),
	    tmp_entryid.database_guid) != ecSuccess)
		return nullptr;
	if (store.b_private) {
		tmp_entryid.provider_uid = store.mailbox_guid;
		tmp_entryid.folder_type = EITLT_PRIVATE_FOLDER;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		tmp_entryid.folder_type = EITLT_PUBLIC_FOLDER;
	}
	tmp_entryid.global_counter = rop_util_get_gc_array(folder_id);
	tmp_entryid.pad[0] = 0;
	tmp_entryid.pad[1] = 0;
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(46); /* MS-OXCDATA v19 §2.2.4.1 */
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 46, 0) ||
	    ext_push.p_folder_eid(tmp_entryid) != pack_result::ok)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

/**
 * If the returned std::string has length 0, this signals an error.
 * Callers ought to check the return value.
 */
std::string cu_fid_to_entryid_s(const store_object &store, uint64_t folder_id) try
{
	FOLDER_ENTRYID eid;
	if (replid_to_replguid(store, rop_util_get_replid(folder_id),
	    eid.database_guid) != ecSuccess)
		return {};
	if (store.b_private) {
		eid.provider_uid = store.mailbox_guid;
		eid.folder_type  = EITLT_PRIVATE_FOLDER;
	} else {
		eid.provider_uid = pbLongTermNonPrivateGuid;
		eid.folder_type  = EITLT_PUBLIC_FOLDER;
	}
	eid.global_counter = rop_util_get_gc_array(folder_id);

	std::string out;
	out.resize(46); /* MS-OXCDATA v19 §2.2.4.1 */
	EXT_PUSH ep;
	if (!ep.init(out.data(), 46, 0) ||
	    ep.p_folder_eid(eid) != pack_result::ok)
		return {};
	out.resize(ep.m_offset);
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2257: ENOMEM");
	return {};
}

BINARY *cu_fid_to_sk(const store_object &store, uint64_t folder_id)
{
	EXT_PUSH ext_push;
	LONG_TERM_ID longid;
	
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->cb = 22;
	pbin->pv = common_util_alloc(22);
	if (pbin->pv == nullptr)
		return NULL;
	if (replid_to_replguid(store, rop_util_get_replid(folder_id),
	    longid.guid) != ecSuccess)
		return nullptr;
	longid.global_counter = rop_util_get_gc_array(folder_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != pack_result::ok ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != pack_result::ok)
		return NULL;
	return pbin;
}

/**
 * If the returned std::string has length 0, this signals an error.
 * Callers ought to check the return value.
 */
std::string cu_fid_to_sk_s(const store_object &store, uint64_t folder_id) try
{
	LONG_TERM_ID longid;
	longid.global_counter = rop_util_get_gc_array(folder_id);
	if (replid_to_replguid(store, rop_util_get_replid(folder_id),
	    longid.guid) != ecSuccess)
		return {};

	std::string out;
	out.resize(22);
	EXT_PUSH ep;
	if (!ep.init(out.data(), 22, 0) ||
	    ep.p_guid(longid.guid) != pack_result::ok ||
	    ep.p_bytes(longid.global_counter.ab, 6) != pack_result::ok)
		return {};
	out.resize(ep.m_offset);
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2258: ENOMEM");
	return {};
}

BINARY *cu_mid_to_entryid(const store_object &store,
	uint64_t folder_id, uint64_t message_id)
{
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (replid_to_replguid(store, rop_util_get_replid(folder_id),
	    tmp_entryid.folder_database_guid) != ecSuccess)
		return nullptr;
	if (replid_to_replguid(store, rop_util_get_replid(message_id),
	    tmp_entryid.message_database_guid) != ecSuccess)
		return nullptr;
	if (store.b_private) {
		tmp_entryid.provider_uid = store.mailbox_guid;
		tmp_entryid.message_type = EITLT_PRIVATE_MESSAGE;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		tmp_entryid.message_type = EITLT_PUBLIC_MESSAGE;
	}
	tmp_entryid.folder_global_counter = rop_util_get_gc_array(folder_id);
	tmp_entryid.message_global_counter = rop_util_get_gc_array(message_id);
	tmp_entryid.pad1[0] = 0;
	tmp_entryid.pad1[1] = 0;
	tmp_entryid.pad2[0] = 0;
	tmp_entryid.pad2[1] = 0;
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(70); /* MS-OXCDATA v19 §2.2.4.2 */
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 70, 0) ||
	    ext_push.p_msg_eid(tmp_entryid) != pack_result::ok)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

/**
 * If the returned std::string has length 0, this signals an error.
 * Callers ought to check the return value.
 */
std::string cu_mid_to_entryid_s(const store_object &store, uint64_t folder_id,
    uint64_t msg_id) try
{
	EXT_PUSH ep;
	MESSAGE_ENTRYID eid{};

	if (replid_to_replguid(store, rop_util_get_replid(folder_id),
	    eid.folder_database_guid) != ecSuccess)
		return {};
	if (replid_to_replguid(store, rop_util_get_replid(msg_id),
	    eid.message_database_guid) != ecSuccess)
		return {};
	if (store.b_private) {
		eid.provider_uid = store.mailbox_guid;
		eid.message_type = EITLT_PRIVATE_MESSAGE;
	} else {
		eid.provider_uid = pbLongTermNonPrivateGuid;
		eid.message_type = EITLT_PUBLIC_MESSAGE;
	}
	eid.folder_global_counter  = rop_util_get_gc_array(folder_id);
	eid.message_global_counter = rop_util_get_gc_array(msg_id);

	std::string out;
	out.resize(255);
	if (!ep.init(out.data(), 255, 0) ||
	    ep.p_msg_eid(eid) != pack_result::ok)
		return {};
	out.resize(ep.m_offset);
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2259: ENOMEM");
	return {};
}

ec_error_t cu_calc_msg_access(const store_object &store, const char *user,
    uint64_t folder_id, uint64_t message_id, uint32_t &tag_access)
{
	BOOL b_owner = false;
	uint32_t permission = 0;

	tag_access = 0;
	if (store.owner_mode()) {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		goto PERMISSION_CHECK;
	}
	if (!exmdb_client->get_folder_perm(store.get_dir(),
	    folder_id, user, &permission))
		return ecError;
	if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
		return ecAccessDenied;
	if (permission & frightsOwner) {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		goto PERMISSION_CHECK;
	}
	if (!exmdb_client_check_message_owner(store.get_dir(),
	    message_id, user, &b_owner))
		return ecError;
	if (b_owner || (permission & frightsReadAny))
		tag_access |= MAPI_ACCESS_READ;
	if ((permission & frightsEditAny) ||
	    (b_owner && (permission & frightsEditOwned)))
		tag_access |= MAPI_ACCESS_MODIFY;
	if ((permission & frightsDeleteAny) ||
	    (b_owner && (permission & frightsDeleteOwned)))
		tag_access |= MAPI_ACCESS_DELETE;
 PERMISSION_CHECK:
	if (!(tag_access & MAPI_ACCESS_READ))
		return ecAccessDenied;
	return ecSuccess;
}

BINARY *cu_mid_to_sk(const store_object &store, uint64_t message_id)
{
	EXT_PUSH ext_push;
	LONG_TERM_ID longid;
	
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->cb = 22;
	pbin->pv = common_util_alloc(22);
	if (pbin->pv == nullptr)
		return NULL;
	longid.guid = store.guid();
	longid.global_counter = rop_util_get_gc_array(message_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != pack_result::ok ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != pack_result::ok)
		return NULL;
	return pbin;
}

/**
 * If the returned std::string has length 0, this signals an error.
 * Callers ought to check the return value.
 */
std::string cu_mid_to_sk_s(const store_object &store, uint64_t msg_id) try
{
	std::string out;
	EXT_PUSH ep;
	LONG_TERM_ID longid;

	out.resize(22);
	longid.guid = store.guid();
	longid.global_counter = rop_util_get_gc_array(msg_id);
	if (!ep.init(out.data(), 22, 0) ||
	    ep.p_guid(longid.guid) != pack_result::ok ||
	    ep.p_bytes(longid.global_counter.ab, 6) != pack_result::ok)
		return {};
	out.resize(ep.m_offset);
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2260: ENOMEM");
	return {};
}

BINARY *cu_xid_to_bin(const XID &xid)
{
	EXT_PUSH ext_push;
	
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(24);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 24, 0) ||
	    ext_push.p_xid(xid) != pack_result::ok)
		return NULL;
	pbin->cb = ext_push.m_offset;
	return pbin;
}

std::string cu_xid_to_bin_s(const XID &xid) try
{
	std::string out;
	EXT_PUSH ep;

	out.resize(24);
	if (!ep.init(out.data(), 24, 0) ||
	    ep.p_xid(xid) != pack_result::ok)
		return {};
	out.resize(ep.m_offset);
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2261: ENOMEM");
	return {};
}

BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid)
{
	EXT_PULL ext_pull;
	
	if (pbin->cb < 17 || pbin->cb > 24)
		return FALSE;
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	return ext_pull.g_xid(pbin->cb, pxid) == pack_result::ok ? TRUE : false;
}

BINARY *common_util_guid_to_binary(FLATUID guid)
{
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->cb = 16;
	pbin->pv = common_util_alloc(16);
	if (pbin->pv == nullptr)
		return NULL;
	memcpy(pbin->pv, &guid, sizeof(guid));
	return pbin;
}

BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key)
{
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	PCL ppcl;
	if (pbin_pcl != nullptr && !ppcl.deserialize(pbin_pcl))
		return nullptr;
	XID xid;
	xid.size = pchange_key->cb;
	if (!common_util_binary_to_xid(pchange_key, &xid))
		return NULL;
	if (!ppcl.append(xid))
		return NULL;
	auto ptmp_bin = ppcl.serialize();
	ppcl.clear();
	if (ptmp_bin == nullptr)
		return NULL;
	pbin->cb = ptmp_bin->cb;
	pbin->pv = common_util_alloc(ptmp_bin->cb);
	if (pbin->pv == nullptr) {
		rop_util_free_binary(ptmp_bin);
		return NULL;
	}
	memcpy(pbin->pv, ptmp_bin->pv, pbin->cb);
	rop_util_free_binary(ptmp_bin);
	return pbin;
}

BOOL common_util_load_file(const char *path, BINARY *pbin)
{
	struct stat node_state;
	
	auto fd = open(path, O_RDONLY);
	if (fd < 0)
		return FALSE;
	if (fstat(fd, &node_state) != 0) {
		close(fd);
		return FALSE;
	}
	pbin->cb = node_state.st_size;
	pbin->pv = common_util_alloc(node_state.st_size);
	if (pbin->pv == nullptr ||
	    read(fd, pbin->pv, node_state.st_size) != node_state.st_size) {
		close(fd);
		return FALSE;
	}
	close(fd);
	return TRUE;
}

static void common_util_set_dir(const char *dir)
{
	g_dir_key = dir;
}

static const char* common_util_get_dir()
{
	return g_dir_key;
}

static BOOL common_util_get_propids(
	const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	return exmdb_client->get_named_propids(
			common_util_get_dir(), FALSE,
			ppropnames, ppropids);
}

static BOOL common_util_get_propids_create(const PROPNAME_ARRAY *names,
    PROPID_ARRAY *ids)
{
	return exmdb_client->get_named_propids(common_util_get_dir(),
	       TRUE, names, ids);
}

static BOOL common_util_get_propname(propid_t propid, PROPERTY_NAME **pppropname) try
{
	PROPNAME_ARRAY propnames;
	
	if (!exmdb_client->get_named_propnames(common_util_get_dir(),
	    {propid}, &propnames) || propnames.size() != 1)
		return FALSE;
	*pppropname = propnames.ppropname;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2230: ENOMEM");
	return false;
}

ec_error_t cu_send_message(store_object *pstore, message_object *msg,
    bool b_submit) try
{
	uint64_t message_id = msg->get_id();
	void *pvalue;
	BOOL b_result;
	BOOL b_private;
	BOOL b_partial;
	int account_id;
	uint64_t new_id;
	uint64_t folder_id;
	TAGGED_PROPVAL *ppropval;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zs_get_info();
	cpid_t cpid = pinfo == nullptr ? CP_UTF8 : pinfo->cpid;
	if (!exmdb_client_get_message_property(pstore->get_dir(), nullptr, CP_ACP,
	    message_id, PidTagParentFolderId, &pvalue) || pvalue == nullptr)
		return ecNotFound;
	auto parent_id = *static_cast<uint64_t *>(pvalue);
	if (!exmdb_client->read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return ecRpcFailed;
	if (!pmsgctnt->proplist.has(PR_INTERNET_CPID)) {
		ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 1);
		if (ppropval == nullptr)
			return ecServerOOM;
		memcpy(ppropval, pmsgctnt->proplist.ppropval,
			sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
		ppropval[pmsgctnt->proplist.count].proptag = PR_INTERNET_CPID;
		ppropval[pmsgctnt->proplist.count++].pvalue = &cpid;
		pmsgctnt->proplist.ppropval = ppropval;
	}
	auto num = pmsgctnt->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	bool b_resend = num != nullptr && *num & MSGFLAG_RESEND;
	auto log_id = pstore->get_dir() + ":m"s + std::to_string(rop_util_get_gc_value(message_id));
	const tarray_set *prcpts = pmsgctnt->children.prcpts;
	if (prcpts == nullptr || prcpts->count == 0) {
		mlog(LV_ERR, "E-1504: Tried to send %s but message has 0 recipients", log_id.c_str());
		return MAPI_E_NO_RECIPIENTS;
	}
	std::vector<std::string> rcpt_list;
	for (auto &rcpt : *prcpts) {
		auto ret = cu_rcpt_to_list(rcpt, g_org_name, rcpt_list,
		           mysql_adaptor_userid_to_name, b_resend);
		if (ret != ecSuccess)
			return ret;
	}
	if (rcpt_list.size() == 0) {
		mlog(LV_ERR, "E-1750: Empty converted recipients list attempting to send %s", log_id.c_str());
		return MAPI_E_NO_RECIPIENTS;
	}

	auto body_type = get_override_format(*pmsgctnt);
	common_util_set_dir(pstore->get_dir());
	/* try to avoid TNEF message */
	MAIL imail;
	if (!oxcmail_export(pmsgctnt, log_id.c_str(), false, body_type,
	    &imail, common_util_alloc, common_util_get_propids,
	    common_util_get_propname))
		return ecError;

	imail.set_header("X-Mailer", ZCORE_UA);
	if (zcore_backfill_transporthdr) {
		std::unique_ptr<MESSAGE_CONTENT, mc_delete> rmsg(oxcmail_import(nullptr,
			"UTC", &imail, common_util_alloc, common_util_get_propids));
		if (rmsg != nullptr) {
			for (auto tag : {PR_TRANSPORT_MESSAGE_HEADERS, PR_TRANSPORT_MESSAGE_HEADERS_A}) {
				auto th = rmsg->proplist.get<const char>(tag);
				if (th == nullptr)
					continue;
				TAGGED_PROPVAL tp  = {tag, deconst(th)};
				TPROPVAL_ARRAY tpa = {1, &tp};
				if (!msg->set_properties(&tpa))
					break;
				/* Unclear if permitted to save (specs say nothing) */
				msg->save();
				break;
			}
		}
	}

	auto ret = cu_send_mail(imail, g_smtp_url.c_str(),
		   pstore->get_account(), rcpt_list);
	if (ret != ecSuccess) {
		mlog(LV_ERR, "E-1194: failed to send %s via SMTP: %s",
			log_id.c_str(), mapi_strerror(ret));
		return ret;
	}
	imail.clear();

	auto flag = pmsgctnt->proplist.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagSentMailSvrEID);
	auto ptarget = pmsgctnt->proplist.get<BINARY>(PR_TARGET_ENTRYID);
	if (NULL != ptarget) {
		if (!cu_entryid_to_mid(*ptarget,
		    &b_private, &account_id, &folder_id, &new_id))
			return ecWarnWithErrors;
		if (!exmdb_client->clear_submit(pstore->get_dir(), message_id, false))
			return ecWarnWithErrors;
		if (!exmdb_client->movecopy_message(pstore->get_dir(), cpid,
		    message_id, folder_id, new_id, TRUE, &b_result))
			return ecWarnWithErrors;
		return ecSuccess;
	} else if (b_delete) {
		exmdb_client_delete_message(pstore->get_dir(),
			pstore->account_id, cpid, parent_id, message_id,
			TRUE, &b_result);
		return ecSuccess;
	}
	if (!exmdb_client->clear_submit(pstore->get_dir(), message_id, false))
		return ecWarnWithErrors;
	ptarget = pmsgctnt->proplist.get<BINARY>(PR_SENTMAIL_ENTRYID);
	if (ptarget == nullptr || !cu_entryid_to_fid(*ptarget,
	    &b_private, &account_id, &folder_id))
		folder_id = rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS);

	const EID_ARRAY ids = {1, &message_id};
	if (!exmdb_client->movecopy_messages(pstore->get_dir(), cpid, false,
	    STORE_OWNER_GRANTED, parent_id, folder_id, false, &ids, &b_partial))
		return ecWarnWithErrors;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2549: ENOMEM");
	return ecServerOOM;
}

void common_util_notify_receipt(const char *username, int type,
    MESSAGE_CONTENT *pbrief) try
{
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str == nullptr)
		return;
	std::vector<std::string> rcpt_list = {str};
	auto bounce_type = type == NOTIFY_RECEIPT_READ ?
	                   "BOUNCE_NOTIFY_READ" : "BOUNCE_NOTIFY_NON_READ";
	vmime::shared_ptr<vmime::message> imail;
	if (!exch_bouncer_make(mysql_adaptor_get_user_displayname,
	    mysql_adaptor_meta, username, pbrief, bounce_type, imail))
		return;
	imail->getHeader()->getField("X-Mailer")->setValue(vmime::text(ZCORE_UA));
	auto ret = cu_send_vmail(std::move(imail), g_smtp_url.c_str(),
	           username, rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "E-1193: cu_send_mail: %xh", static_cast<unsigned int>(ret));
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2038: ENOMEM");
}

static MOVECOPY_ACTION *cu_cvt_from_zmovecopy(const ZMOVECOPY_ACTION &src)
{
	int db_id;
	int user_id;
	BOOL b_private;
	SVREID *psvreid;
	EXT_PULL ext_pull;
	
	auto dst = cu_alloc<MOVECOPY_ACTION>();
	if (dst == nullptr)
		return NULL;
	auto pstore_entryid = cu_alloc<STORE_ENTRYID>();
	if (pstore_entryid == nullptr)
		return NULL;
	ext_pull.init(src.store_eid.pb, src.store_eid.cb,
		common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_store_eid(pstore_entryid) != pack_result::ok)
		return NULL;
	bool tgt_public = pstore_entryid->wrapped_provider_uid == g_muidStorePublic;
	if (tgt_public) {
		dst->same_store  = 0;
		dst->pstore_eid  = pstore_entryid;
		dst->pfolder_eid = deconst(&src.folder_eid);
		return dst;
	}
	if (!common_util_essdn_to_uid(pstore_entryid->pmailbox_dn, &user_id))
		return NULL;	
	auto pinfo = zs_get_info();
	if (user_id != pinfo->user_id) {
		dst->same_store = 0;
		dst->pstore_eid = pstore_entryid;
		dst->pfolder_eid = deconst(&src.folder_eid);
		return dst;
	}
	dst->same_store = 1;
	dst->pstore_eid = nullptr;
	psvreid = cu_alloc<SVREID>();
	if (psvreid == nullptr)
		return NULL;
	psvreid->pbin = NULL;
	if (!cu_entryid_to_fid(src.folder_eid,
	    &b_private, &db_id, &psvreid->folder_id))
		return NULL;
	psvreid->message_id = 0;
	psvreid->instance = 0;
	dst->pfolder_eid = psvreid;
	return dst;
}

static REPLY_ACTION *cu_cvt_from_zreply(const ZREPLY_ACTION &src)
{
	int db_id;
	BOOL b_private;
	
	auto dst = cu_alloc<REPLY_ACTION>();
	if (dst == nullptr)
		return NULL;
	if (!cu_entryid_to_mid(src.message_eid, &b_private,
	    &db_id, &dst->template_folder_id, &dst->template_message_id))
		return NULL;	
	dst->template_guid = src.template_guid;
	return dst;
}

BOOL common_util_convert_from_zrule(TPROPVAL_ARRAY *ppropvals)
{
	auto pactions = ppropvals->get<RULE_ACTIONS>(PR_RULE_ACTIONS);
	if (pactions == nullptr)
		return TRUE;
	for (auto &act : *pactions) {
		switch (act.type) {
		case OP_MOVE:
		case OP_COPY:
			act.pdata = cu_cvt_from_zmovecopy(*static_cast<const ZMOVECOPY_ACTION *>(act.pdata));
			if (act.pdata == nullptr)
				return FALSE;
			break;
		case OP_REPLY:
		case OP_OOF_REPLY:
			act.pdata = cu_cvt_from_zreply(*static_cast<const ZREPLY_ACTION *>(act.pdata));
			if (act.pdata == nullptr)
				return FALSE;
			break;
		}
	}
	return TRUE;
}

BINARY *cu_to_store_entryid(const store_object &store)
{
	EXT_PUSH ext_push;
	std::string essdn;
	STORE_ENTRYID store_entryid = {};
	
	store_entryid.pserver_name = deconst(store.get_account());
	if (store.b_private) {
		store_entryid.wrapped_provider_uid = g_muidStorePrivate;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_TAKE_OWNERSHIP;
		if (cvt_username_to_essdn(store.get_account(), g_org_name,
		    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		    essdn) != ecSuccess)
			return NULL;	
	} else {
		store_entryid.wrapped_provider_uid = g_muidStorePublic;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_PUBLIC;
		auto pinfo = zs_get_info();
		if (cvt_username_to_essdn(pinfo->get_username(), g_org_name,
		    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		    essdn) != ecSuccess)
			return NULL;	
	}
	store_entryid.pmailbox_dn = deconst(essdn.c_str());
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	/*
	 * The anecdotal DN length limit in MSAD & OpenLDAP is 255. MS-OXOAB
	 * v15 §2.7 says ESSDNs are limited to 256.
	 *
	 * 60 bytes leading part (MS-OXCDATA v19 §2.2.4.3), 254 bytes
	 * servername/FQDN (always ASCII AFAICT), \0, 256 bytes ESSDN (always
	 * ASCII AFAICT), \0, 16 bytes V3 header, 319 chars SmtpAddress
	 * (possibly Unicode), \0 (possibly Unicode).
	 *
	 * In zcore we do not output V3 store entryids (as seen in MFCMAPI), so
	 * 572 bytes shall be our more-than-generous buffer size.
	 */
	pbin->pv = common_util_alloc(572);
	if (pbin->pb == nullptr ||
	    !ext_push.init(pbin->pv, 572, EXT_FLAG_UTF16) ||
	    ext_push.p_store_eid(store_entryid) != pack_result::ok)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

std::string cu_to_store_entryid_s(const store_object &store) try
{
	std::string essdn;
	STORE_ENTRYID store_entryid{};

	store_entryid.pserver_name = deconst(store.get_account());
	if (store.b_private) {
		store_entryid.wrapped_provider_uid = g_muidStorePrivate;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_TAKE_OWNERSHIP;
		if (cvt_username_to_essdn(store.get_account(), g_org_name,
		    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		    essdn) != ecSuccess)
			return {};
	} else {
		store_entryid.wrapped_provider_uid = g_muidStorePublic;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_PUBLIC;
		auto pinfo = zs_get_info();
		if (cvt_username_to_essdn(pinfo->get_username(), g_org_name,
		    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		    essdn) != ecSuccess)
			return {};
	}
	store_entryid.pmailbox_dn = deconst(essdn.c_str());

	std::string out;
	out.resize(572);
	EXT_PUSH ep;
	if (!ep.init(out.data(), out.size(), EXT_FLAG_UTF16) ||
	    ep.p_store_eid(store_entryid) != pack_result::ok)
		return {};
	out.resize(ep.m_offset);
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2262: ENOMEM");
	return {};
}

static ZMOVECOPY_ACTION *cu_cvt_to_zmovecopy(store_object *pstore, const MOVECOPY_ACTION &src)
{
	EXT_PUSH ext_push;
	
	auto dst = cu_alloc<ZMOVECOPY_ACTION>();
	if (dst == nullptr)
		return NULL;
	if (!src.same_store) {
		dst->store_eid.pv = common_util_alloc(1024);
		if (dst->store_eid.pv == nullptr ||
		    !ext_push.init(dst->store_eid.pv, 1024, EXT_FLAG_UTF16) ||
		    ext_push.p_store_eid(*src.pstore_eid) != pack_result::ok)
			return NULL;	
		dst->store_eid.cb = ext_push.m_offset;
		dst->folder_eid = *static_cast<BINARY *>(src.pfolder_eid);
	} else {
		auto pbin = cu_to_store_entryid(*pstore);
		if (pbin == nullptr)
			return NULL;
		dst->store_eid = *pbin;
		pbin = cu_fid_to_entryid(*pstore, static_cast<SVREID *>(src.pfolder_eid)->folder_id);
		if (pbin == nullptr)
			return NULL;
		dst->folder_eid = *pbin;
	}
	return dst;
}

static ZREPLY_ACTION *cu_cvt_to_zreply(store_object *pstore, const REPLY_ACTION &src)
{
	auto dst = cu_alloc<ZREPLY_ACTION>();
	if (dst == nullptr)
		return NULL;
	if (cu_mid_to_entryid(*pstore, src.template_folder_id,
	    src.template_message_id) == nullptr)
		return NULL;	
	dst->template_guid = src.template_guid;
	return dst;
}

BOOL common_util_convert_to_zrule_data(store_object *pstore, TPROPVAL_ARRAY *ppropvals)
{
	auto pactions = ppropvals->get<RULE_ACTIONS>(PR_RULE_ACTIONS);
	if (pactions == nullptr)
		return TRUE;
	for (auto &act : *pactions) {
		switch (act.type) {
		case OP_MOVE:
		case OP_COPY:
			act.pdata = cu_cvt_to_zmovecopy(pstore, *static_cast<const MOVECOPY_ACTION *>(act.pdata));
			if (act.pdata == nullptr)
				return FALSE;
			break;
		case OP_REPLY:
		case OP_OOF_REPLY:
			act.pdata = cu_cvt_to_zreply(pstore, *static_cast<const REPLY_ACTION *>(act.pdata));
			if (act.pdata == nullptr)
				return FALSE;
			break;
		}
	}
	return TRUE;
}

ec_error_t cu_remote_copy_message(store_object *src_store, uint64_t message_id,
    store_object *dst_store, uint64_t folder_id1)
{
	uint64_t change_num;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zs_get_info();
	auto username = src_store->b_private ? nullptr : pinfo->get_username();
	if (!exmdb_client->read_message(src_store->get_dir(), username,
	    pinfo->cpid, message_id, &pmsgctnt))
		return ecError;
	if (pmsgctnt == nullptr)
		return ecSuccess;
	static constexpr uint32_t tags[] = {
		PR_CONVERSATION_ID, PR_DISPLAY_TO,
		PR_DISPLAY_TO_A, PR_DISPLAY_CC,
		PR_DISPLAY_CC_A, PR_DISPLAY_BCC, PR_DISPLAY_BCC_A, PidTagMid,
		PR_MESSAGE_SIZE, PR_MESSAGE_SIZE_EXTENDED,
		PR_HAS_NAMED_PROPERTIES, PR_HASATTACH,
		PR_ENTRYID, PidTagFolderId, PR_OBJECT_TYPE,
		PR_PARENT_ENTRYID, PR_STORE_RECORD_KEY,
	};
	for (auto t : tags)
		common_util_remove_propvals(&pmsgctnt->proplist, t);
	if (!exmdb_client->allocate_cn(dst_store->get_dir(), &change_num))
		return ecError;
	auto err = cu_set_propval(&pmsgctnt->proplist, PidTagChangeNumber, &change_num);
	if (err != ecSuccess)
		return err;
	auto pbin = cu_xid_to_bin({src_store->guid(), change_num});
	if (pbin == nullptr)
		return ecError;
	err = cu_set_propval(&pmsgctnt->proplist, PR_CHANGE_KEY, pbin);
	if (err != ecSuccess)
		return err;
	auto pbin1 = pmsgctnt->proplist.get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	auto newpcl = common_util_pcl_append(pbin1, pbin);
	if (newpcl == nullptr)
		return ecError;
	err = cu_set_propval(&pmsgctnt->proplist, PR_PREDECESSOR_CHANGE_LIST, newpcl);
	if (err != ecSuccess)
		return err;
	err = ecError;
	if (!exmdb_client->write_message(dst_store->get_dir(), pinfo->cpid,
	    folder_id1, pmsgctnt, &err) || err != ecSuccess)
		return err;
	return ecSuccess;
}

static ec_error_t cu_create_folder(store_object *pstore, uint64_t parent_id,
    TPROPVAL_ARRAY *pproplist, uint64_t *pfolder_id)
{
	uint64_t tmp_id;
	BINARY *pentryid;
	uint32_t tmp_type;
	uint64_t change_num;
	uint32_t permission;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];

	static constexpr uint32_t tags[] = {	
		PR_ACCESS, PR_ACCESS_LEVEL, PR_ADDRESS_BOOK_ENTRYID,
		PR_ASSOC_CONTENT_COUNT, PR_ATTR_READONLY,
		PR_CONTENT_COUNT, PR_CONTENT_UNREAD,
		PR_DELETED_COUNT_TOTAL, PR_DELETED_FOLDER_COUNT,
		PR_INTERNET_ARTICLE_NUMBER_NEXT, PR_INTERNET_ARTICLE_NUMBER,
		PR_DISPLAY_TYPE, PR_DELETED_ON, PR_ENTRYID,
		PR_FOLDER_CHILD_COUNT, PR_FOLDER_FLAGS, PidTagFolderId,
		PR_FOLDER_TYPE, PR_HAS_RULES, PR_HIERARCHY_CHANGE_NUM,
		PR_LOCAL_COMMIT_TIME, PR_LOCAL_COMMIT_TIME_MAX,
		PR_MESSAGE_SIZE, PR_MESSAGE_SIZE_EXTENDED, PR_NATIVE_BODY_INFO,
		PR_OBJECT_TYPE, PR_PARENT_ENTRYID, PR_RECORD_KEY,
		PR_SEARCH_KEY, PR_STORE_ENTRYID, PR_STORE_RECORD_KEY,
		PR_SOURCE_KEY, PR_PARENT_SOURCE_KEY,
	};
	for (auto t : tags)
		common_util_remove_propvals(pproplist, t);
	if (!pproplist->has(PR_DISPLAY_NAME))
		return ecInvalidParam;
	tmp_type = FOLDER_GENERIC;
	auto err = cu_set_propval(pproplist, PR_FOLDER_TYPE, &tmp_type);
	if (err != ecSuccess)
		return err;
	err = cu_set_propval(pproplist, PidTagParentFolderId, &parent_id);
	if (err != ecSuccess)
		return err;
	if (!exmdb_client->allocate_cn(pstore->get_dir(), &change_num))
		return ecError;
	err = cu_set_propval(pproplist, PidTagChangeNumber, &change_num);
	if (err != ecSuccess)
		return err;
	auto pbin = cu_xid_to_bin({pstore->guid(), change_num});
	if (pbin == nullptr)
		return ecMAPIOOM;
	err = cu_set_propval(pproplist, PR_CHANGE_KEY, pbin);
	if (err != ecSuccess)
		return err;
	auto pbin1 = pproplist->get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	auto newpcl = common_util_pcl_append(pbin1, pbin);
	if (newpcl == nullptr)
		return ecMAPIOOM;
	err = cu_set_propval(pproplist, PR_PREDECESSOR_CHANGE_LIST, newpcl);
	if (err != ecSuccess)
		return err;
	auto pinfo = zs_get_info();
	err = ecSuccess;
	if (!exmdb_client->create_folder(pstore->get_dir(), pinfo->cpid,
	    pproplist, pfolder_id, &err))
		return ecError;
	if (err != ecSuccess)
		return err;
	if (*pfolder_id == 0)
		return ecError;
	if (pstore->owner_mode())
		return ecSuccess;
	pentryid = common_util_username_to_addressbook_entryid(pinfo->get_username());
	if (pentryid == nullptr)
		return ecSuccess;
	tmp_id = 1;
	permission = rightsGromox7;
	permission_row.flags = ROW_ADD;
	permission_row.propvals.count = 3;
	permission_row.propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PR_ENTRYID;
	propval_buff[0].pvalue = pentryid;
	propval_buff[1].proptag = PR_MEMBER_ID;
	propval_buff[1].pvalue = &tmp_id;
	propval_buff[2].proptag = PR_MEMBER_RIGHTS;
	propval_buff[2].pvalue = &permission;
	exmdb_client->update_folder_permission(pstore->get_dir(),
		*pfolder_id, FALSE, 1, &permission_row);
	return ecSuccess;
}

static EID_ARRAY *common_util_load_folder_messages(store_object *pstore,
    uint64_t folder_id, const char *username)
{
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	EID_ARRAY *pmessage_ids;
	
	if (!exmdb_client->load_content_table(pstore->get_dir(), CP_ACP,
	    folder_id, username, TABLE_FLAG_NONOTIFICATIONS,
	    nullptr, nullptr, &table_id, &row_count))
		return NULL;	
	static constexpr proptag_t tmp_proptag[] = {PidTagMid};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
	if (!exmdb_client->query_table(pstore->get_dir(), nullptr, CP_ACP,
	    table_id, &proptags, 0, row_count, &tmp_set))
		return NULL;	
	exmdb_client->unload_table(pstore->get_dir(), table_id);
	pmessage_ids = cu_alloc<EID_ARRAY>();
	if (pmessage_ids == nullptr)
		return NULL;
	pmessage_ids->count = 0;
	pmessage_ids->pids = cu_alloc<uint64_t>(tmp_set.count);
	if (pmessage_ids->pids == nullptr)
		return NULL;
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto pmid = tmp_set.pparray[i]->get<uint64_t>(PidTagMid);
		if (pmid == nullptr)
			return NULL;
		pmessage_ids->pids[pmessage_ids->count++] = *pmid;
	}
	return pmessage_ids;
}

ec_error_t cu_remote_copy_folder(store_object *src_store, uint64_t folder_id,
    store_object *dst_store, uint64_t folder_id1, const char *new_name)
{
	uint64_t new_fid;
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	uint32_t permission;
	EID_ARRAY *pmessage_ids;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (!exmdb_client->get_folder_all_proptags(src_store->get_dir(),
	    folder_id, &tmp_proptags))
		return ecError;
	if (!exmdb_client->get_folder_properties(src_store->get_dir(), CP_ACP,
	    folder_id, &tmp_proptags, &tmp_propvals))
		return ecError;
	if (new_name != nullptr) {
		auto err = cu_set_propval(&tmp_propvals, PR_DISPLAY_NAME, new_name);
		if (err != ecSuccess)
			return err;
	}
	auto err = cu_create_folder(dst_store, folder_id1, &tmp_propvals, &new_fid);
	if (err != ecSuccess)
		return err;
	auto pinfo = zs_get_info();
	const char *username = nullptr;
	if (!src_store->owner_mode()) {
		username = pinfo->get_username();
		if (!exmdb_client->get_folder_perm(src_store->get_dir(),
		    folder_id, username, &permission))
			return ecError;
		if (!(permission & (frightsReadAny | frightsOwner)))
			return ecAccessDenied;
	}
	pmessage_ids = common_util_load_folder_messages(
						src_store, folder_id, username);
	if (pmessage_ids == nullptr)
		return ecError;
	for (auto mid : *pmessage_ids) {
		err = cu_remote_copy_message(src_store, mid, dst_store, new_fid);
		if (err != ecSuccess)
			return err;
	}
	username = src_store->owner_mode() ? nullptr : pinfo->get_username();
	if (!exmdb_client->load_hierarchy_table(src_store->get_dir(), folder_id,
	    username, TABLE_FLAG_NONOTIFICATIONS, nullptr,
	    &table_id, &row_count))
		return ecError;

	static constexpr proptag_t xb_proptag[] = {PidTagFolderId};
	static constexpr PROPTAG_ARRAY xb_proptags = {std::size(xb_proptag), deconst(xb_proptag)};
	if (!exmdb_client->query_table(src_store->get_dir(), nullptr, CP_ACP,
	    table_id, &xb_proptags, 0, row_count, &tmp_set))
		return ecError;
	exmdb_client->unload_table(src_store->get_dir(), table_id);
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto pfolder_id = tmp_set.pparray[i]->get<uint64_t>(PidTagFolderId);
		if (pfolder_id == nullptr)
			return ecError;
		err = cu_remote_copy_folder(src_store, *pfolder_id, dst_store,
		      new_fid, nullptr);
		if (err != ecSuccess)
			return err;
	}
	return ecSuccess;
}

BOOL common_util_message_to_rfc822(store_object *pstore, uint64_t inst_id,
    BINARY *peml_bin) try
{
	int size;
	void *ptr;
	TAGGED_PROPVAL *ppropval;
	MESSAGE_CONTENT msgctnt{}, *pmsgctnt = &msgctnt;
	
	auto pinfo = zs_get_info();
	cpid_t cpid = pinfo == nullptr ? CP_UTF8 : pinfo->cpid;
	if (!exmdb_client->read_message_instance(pstore->get_dir(),
	    inst_id, &msgctnt))
		return FALSE;
	if (!pmsgctnt->proplist.has(PR_INTERNET_CPID)) {
		ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 1);
		if (ppropval == nullptr)
			return FALSE;
		memcpy(ppropval, pmsgctnt->proplist.ppropval,
			sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
		ppropval[pmsgctnt->proplist.count].proptag = PR_INTERNET_CPID;
		ppropval[pmsgctnt->proplist.count++].pvalue = &cpid;
		pmsgctnt->proplist.ppropval = ppropval;
	}
	auto body_type = get_override_format(*pmsgctnt);
	common_util_set_dir(pstore->get_dir());
	/* try to avoid TNEF message */
	auto log_id = pstore->get_dir() + ":i"s + std::to_string(inst_id);
	MAIL imail;
	if (!oxcmail_export(pmsgctnt, log_id.c_str(), false, body_type, &imail,
	    common_util_alloc, common_util_get_propids, common_util_get_propname))
		return FALSE;	
	auto mail_len = imail.get_length();
	if (mail_len < 0)
		return false;
	STREAM tmp_stream;
	if (!imail.serialize(&tmp_stream))
		return FALSE;
	imail.clear();
	peml_bin->pv = common_util_alloc(mail_len + 128);
	if (peml_bin->pv == nullptr)
		return FALSE;

	peml_bin->cb = 0;
	size = STREAM_BLOCK_SIZE;
	while ((ptr = tmp_stream.get_read_buf(reinterpret_cast<unsigned int *>(&size))) != nullptr) {
		memcpy(peml_bin->pb + peml_bin->cb, ptr, size);
		peml_bin->cb += size;
		size = STREAM_BLOCK_SIZE;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2548: ENOMEM");
	return false;
}

static void zc_unwrap_clearsigned(MAIL &ma) try
{
	auto part = ma.get_head();
	if (part == nullptr ||
	    strcasecmp(part->content_type, "multipart/signed") != 0)
		return;
	part = part->get_child();
	if (part == nullptr)
		return;
	ma.load_from_str(part->head_begin, part->content_begin + part->content_length - part->head_begin);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1996: ENOMEM");
}

MESSAGE_CONTENT *cu_rfc822_to_message(store_object *pstore,
    unsigned int mxf_flags, /* effective-moved-from */ BINARY *peml_bin)
{
	char charset[32];
	auto pinfo = zs_get_info();
	MAIL imail;
	if (!imail.load_from_str(peml_bin->pc, peml_bin->cb))
		return NULL;
	if (mxf_flags & MXF_UNWRAP_SMIME_CLEARSIGNED)
		zc_unwrap_clearsigned(imail);
	auto c = lang_to_charset(pinfo->get_lang());
	if (c != nullptr && *c != '\0')
		gx_strlcpy(charset, c, std::size(charset));
	else
		strcpy(charset, g_default_charset);
	sql_meta_result mres;
	auto tmzone = mysql_adaptor_meta(pinfo->get_username(),
	              WANTPRIV_METAONLY, mres) == 0 ?
	              mres.timezone.c_str() : nullptr;
	if (*znul(tmzone) == '\0')
		tmzone = common_util_get_default_timezone();
	common_util_set_dir(pstore->get_dir());
	auto pmsgctnt = oxcmail_import(charset, tmzone, &imail,
	                common_util_alloc, common_util_get_propids_create);
	return pmsgctnt;
}

BOOL common_util_message_to_ical(store_object *pstore, uint64_t message_id,
    BINARY *pical_bin) try
{
	ical ical;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zs_get_info();
	cpid_t cpid = pinfo == nullptr ? CP_UTF8 : pinfo->cpid;
	auto dir = pstore->get_dir();
	if (!exmdb_client->read_message(dir, nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	common_util_set_dir(dir);
	auto log_id = dir + ":m"s + std::to_string(message_id);
	if (!oxcical_export(pmsgctnt, log_id.c_str(), ical, g_org_name,
	    common_util_alloc, common_util_get_propids, mysql_adaptor_userid_to_name)) {
		mlog(LV_ERR, "E-2202: oxcical_export %s failed", log_id.c_str());
		return FALSE;
	}
	std::string tmp_buff;
	if (ical.serialize(tmp_buff) != ecSuccess) {
		mlog(LV_ERR, "E-2552: ical_serialize %s failed", log_id.c_str());
		return FALSE;	
	}
	pical_bin->cb = tmp_buff.size();
	pical_bin->pc = common_util_dup(tmp_buff);
	return pical_bin->pc != nullptr ? TRUE : FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2183: ENOMEM");
	return false;
}

message_ptr cu_ical_to_message(store_object *pstore, const BINARY *pical_bin) try
{
	ical ical;
	auto pinfo = zs_get_info();
	sql_meta_result mres;
	auto tmzone = mysql_adaptor_meta(pinfo->get_username(),
	              WANTPRIV_METAONLY, mres) == 0 ?
	              mres.timezone.c_str() : nullptr;
	if (*znul(tmzone) == '\0')
		tmzone = common_util_get_default_timezone();
	auto pbuff = cu_alloc<char>(pical_bin->cb + 1);
	if (pbuff == nullptr)
		return nullptr;
	memcpy(pbuff, pical_bin->pb, pical_bin->cb);
	pbuff[pical_bin->cb] = '\0';
	if (!ical.load_from_str_move(pbuff))
		return NULL;
	common_util_set_dir(pstore->get_dir());
	return oxcical_import_single(tmzone, ical, common_util_alloc,
	       common_util_get_propids_create, common_util_username_to_entryid);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2184: ENOMEM");
	return nullptr;
}

ec_error_t cu_ical_to_message2(store_object *store, char *ical_data,
    std::vector<message_ptr> &msgvec) try
{
	auto info = zs_get_info();
	sql_meta_result mres;
	auto tmzone = mysql_adaptor_meta(info->get_username(),
	              WANTPRIV_METAONLY, mres) == 0 ?
	              mres.timezone.c_str() : nullptr;
	if (*znul(tmzone) == '\0')
		tmzone = common_util_get_default_timezone();

	ical icobj;
	if (!icobj.load_from_str_move(ical_data))
		return ecError;
	common_util_set_dir(store->get_dir());
	return oxcical_import_multi(tmzone, icobj, common_util_alloc,
	       common_util_get_propids_create,
	       common_util_username_to_entryid, msgvec);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2185: ENOMEM");
	return ecServerOOM;
}

BOOL common_util_message_to_vcf(message_object *pmessage, BINARY *pvcf_bin)
{
	auto pstore = pmessage->get_store();
	auto message_id = pmessage->get_id();
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zs_get_info();
	cpid_t cpid = pinfo == nullptr ? CP_UTF8 : pinfo->cpid;
	if (!exmdb_client->read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	common_util_set_dir(pstore->get_dir());
	auto log_id = pstore->get_dir() + ":m"s + std::to_string(rop_util_get_gc_value(message_id));
	vcard vcard;
	if (!oxvcard_export(pmsgctnt, log_id.c_str(), vcard, common_util_get_propids))
		return FALSE;
	pvcf_bin->pv = common_util_alloc(VCARD_MAX_BUFFER_LEN);
	if (pvcf_bin->pv == nullptr)
		return FALSE;
	if (!vcard.serialize(pvcf_bin->pc, VCARD_MAX_BUFFER_LEN))
		return FALSE;	
	pvcf_bin->cb = strlen(pvcf_bin->pc);
	if (!pmessage->write_message(pmsgctnt))
		/* ignore */;
	return TRUE;
}
	
MESSAGE_CONTENT *common_util_vcf_to_message(store_object *pstore,
    const BINARY *pvcf_bin)
{
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pbuff = cu_alloc<char>(pvcf_bin->cb + 1);
	if (pbuff == nullptr)
		return nullptr;
	memcpy(pbuff, pvcf_bin->pb, pvcf_bin->cb);
	pbuff[pvcf_bin->cb] = '\0';
	vcard vcard;
	auto ret = vcard.load_single_from_str_move(pbuff);
	if (ret != ecSuccess)
		return nullptr;
	common_util_set_dir(pstore->get_dir());
	pmsgctnt = oxvcard_import(&vcard, common_util_get_propids_create);
	return pmsgctnt;
}

ec_error_t cu_vcf_to_message2(store_object *store, char *vcf_data,
    std::vector<message_ptr> &msgvec) try
{
	std::vector<vcard> cardvec;
	auto ret = vcard_load_multi_from_str_move(vcf_data, cardvec);
	if (ret != ecSuccess)
		return ret;
	common_util_set_dir(store->get_dir());
	for (const auto &vcard : cardvec) {
		message_ptr mc(oxvcard_import(&vcard, common_util_get_propids_create));
		if (mc == nullptr)
			return ecError;
		msgvec.push_back(std::move(mc));
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2048: ENOMEM");
	return ecServerOOM;
}

const char* common_util_get_default_timezone()
{
	return GROMOX_FALLBACK_TIMEZONE;
}

const char* common_util_get_submit_command()
{
	return g_submit_command;
}

void *cu_read_storenamedprop(const char *dir, const GUID &guid,
    const char *name, proptype_t proptype)
{
	if (*dir == '\0')
		return nullptr;
	const PROPERTY_NAME xn = {MNID_STRING, guid, 0, deconst(name)};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!exmdb_client->get_named_propids(dir, false, &name_req, &name_rsp) ||
	    name_rsp.size() != name_req.size() || name_rsp[0] == 0)
		return nullptr;
	auto proptag = PROP_TAG(proptype, name_rsp[0]);
	const PROPTAG_ARRAY tags = {1, deconst(&proptag)};
	TPROPVAL_ARRAY values{};
	if (!exmdb_client->get_store_properties(dir, CP_ACP, &tags, &values))
		return nullptr;
	return values.getval(proptag);
}

errno_t cu_write_storenamedprop(const char *dir, const GUID &guid,
    const char *name, proptype_t proptype, const void *buf, size_t size)
{
	if (*dir == '\0')
		return EINVAL;
	const PROPERTY_NAME xn = {MNID_STRING, guid, 0, deconst(name)};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!exmdb_client->get_named_propids(dir, true, &name_req, &name_rsp) ||
	    name_rsp.size() != name_req.size() || name_rsp[0] == 0)
		return EINVAL;
	TAGGED_PROPVAL pv = {PROP_TAG(proptype, name_rsp[0])};
	BINARY bin;
	if (proptype == PT_BINARY) {
		bin.cb = size;
		bin.pv = deconst(buf);
		pv.pvalue = &bin;
	} else if (proptype == PT_STRING8 || proptype == PT_UNICODE) {
		pv.pvalue = deconst(buf);
	} else {
		return EINVAL;
	}
	TPROPVAL_ARRAY values = {1, &pv};
	PROBLEM_ARRAY prob;
	if (!exmdb_client->set_store_properties(dir, CP_ACP, &values, &prob))
		return EINVAL;
	return 0;
}

ec_error_t cu_fbdata_to_ical(const char *user, const char *fbuser,
    time_t starttime, time_t endtime, const std::vector<freebusy_event> &fbdata,
    BINARY *bin) try
{
	ical ical;
	if (!oxcical_export_freebusy(user, fbuser, starttime, endtime,
	    fbdata, ical)) {
		mlog(LV_DEBUG, "D-2203: oxcical_export_freebusy for %s failed", fbuser);
		return ecError;
	}
	std::string tmp_buff;
	if (ical.serialize(tmp_buff) != ecSuccess)
		return ecError;
	bin->cb = tmp_buff.size();
	bin->pc = common_util_dup(tmp_buff.c_str());
	if (bin->pc == nullptr)
		return ecServerOOM;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2188: ENOMEM");
	return ecServerOOM;
}

bool permrow_entryids_equal(const PERMISSION_ROW &row, const uint32_t *oidp, const BINARY *other)
{
	auto other_cb = other != nullptr ? other->cb : 0;
	if (row.entryid.cb != other_cb)
		return false;
	if (row.entryid.cb != 0)
		return memcmp(row.entryid.pv, other->pv, other_cb) == 0;
	auto oid = oidp != nullptr ? *oidp : 0xdeadbeefU;
	return row.member_id == oid;
}
