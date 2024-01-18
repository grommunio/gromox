// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2022 grommunio GmbH
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
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/ical.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#include "bounce_producer.hpp"
#include "common_util.h"
#include "exmdb_client.h"
#include "objects.hpp"
#include "store_object.h"
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

unsigned int g_max_rcpt, g_max_message, g_max_mail_len;
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
	uint32_t proptag;
	
	proptag = 0;
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
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 4;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_SENT_REPRESENTING_ADDRTYPE;
	proptag_buff[1] = PR_SENT_REPRESENTING_EMAIL_ADDRESS;
	proptag_buff[2] = PR_SENT_REPRESENTING_SMTP_ADDRESS;
	proptag_buff[3] = PR_SENT_REPRESENTING_ENTRYID;
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
		           cu_id2user, username);
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
		   g_org_name, cu_id2user, username);
	if (ret == ecSuccess)
		return TRUE;
	if (ret == ecNullObject) {
		username.clear();
		return TRUE;
	}
	mlog(LV_WARN, "W-1643: rejecting submission of msgid %llxh because "
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
	char repdir[256];
	if (!system_services_get_maildir(repr, repdir, std::size(repdir)))
		return repr_grant::error;
	return cu_get_delegate_perm_MD(account, repdir);
}

void common_util_set_propvals(TPROPVAL_ARRAY *parray,
	const TAGGED_PROPVAL *ppropval)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (ppropval->proptag == parray->ppropval[i].proptag) {
			parray->ppropval[i].pvalue = ppropval->pvalue;
			return;
		}
	}
	parray->ppropval[parray->count++] = *ppropval;
}

void common_util_remove_propvals(
	TPROPVAL_ARRAY *parray, uint32_t proptag)
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

BOOL common_util_username_to_essdn(const char *username, char *pessdn, size_t dnmax)
{
	char *pdomain;
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];
	
	gx_strlcpy(tmp_name, username, std::size(tmp_name));
	pdomain = strchr(tmp_name, '@');
	if (pdomain == nullptr)
		return FALSE;
	*pdomain++ = '\0';
	unsigned int user_id = 0, domain_id = 0;
	if (!system_services_get_user_ids(username, &user_id, &domain_id, nullptr))
		return FALSE;
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, dnmax, "/o=%s/" EAG_RCPTS "/cn=%s%s-%s",
			g_org_name, hex_string2, hex_string, tmp_name);
	HX_strupper(pessdn);
	return TRUE;
}

BOOL common_util_public_to_essdn(const char *username, char *pessdn, size_t dnmax)
{
	//TODO
	return FALSE;
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
    unsigned int max_rcpt, unsigned int max_message, unsigned int max_mail_len,
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
	if (!oxcmail_init_library(g_org_name, system_services_get_user_ids,
		system_services_get_username_from_id)) {
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

char *common_util_dup(const char *src)
{
	int len;
	
	len = strlen(src) + 1;
	auto dst = cu_alloc<char>(len);
	if (dst == nullptr)
		return NULL;
	memcpy(dst, src, len);
	return dst;
}

static BINARY *common_util_dup_binary(const BINARY *src)
{
	auto dst = cu_alloc<BINARY>();
	if (dst == nullptr)
		return NULL;
	dst->cb = src->cb;
	if (src->cb == 0) {
		dst->pb = nullptr;
		return dst;
	}
	dst->pv = common_util_alloc(src->cb);
	if (dst->pv == nullptr)
		return NULL;
	memcpy(dst->pv, src->pv, src->cb);
	return dst;
}

ZNOTIFICATION *common_util_dup_znotification(const ZNOTIFICATION *src, BOOL b_temp)
{
	auto dst = !b_temp ? me_alloc<ZNOTIFICATION>() : cu_alloc<ZNOTIFICATION>();
	
	if (dst == nullptr)
		return NULL;
	dst->event_type = src->event_type;
	if (src->event_type == NF_NEW_MAIL) {
		auto src_nm = static_cast<const NEWMAIL_ZNOTIFICATION *>(src->pnotification_data);
		NEWMAIL_ZNOTIFICATION *dst_nm;
		if (!b_temp) {
			dst_nm = me_alloc<NEWMAIL_ZNOTIFICATION>();
			if (dst_nm == nullptr) {
				free(dst);
				return NULL;
			}
		} else {
			dst_nm = cu_alloc<NEWMAIL_ZNOTIFICATION>();
			if (dst_nm == nullptr)
				return NULL;
		}
		memset(dst_nm, 0, sizeof(*dst_nm));
		dst->pnotification_data = dst_nm;
		dst_nm->entryid.cb = src_nm->entryid.cb;
		if (!b_temp) {
			dst_nm->entryid.pv = malloc(dst_nm->entryid.cb);
			if (dst_nm->entryid.pv == nullptr) {
				dst_nm->entryid.cb = 0;
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_nm->entryid.pv = common_util_alloc(dst_nm->entryid.cb);
			if (dst_nm->entryid.pv == nullptr) {
				dst_nm->entryid.cb = 0;
				return NULL;
			}
		}
		memcpy(dst_nm->entryid.pv, src_nm->entryid.pv, dst_nm->entryid.cb);
		dst_nm->parentid.cb = src_nm->parentid.cb;
		if (!b_temp) {
			dst_nm->parentid.pv = malloc(dst_nm->parentid.cb);
			if (dst_nm->parentid.pv == nullptr) {
				dst_nm->parentid.cb = 0;
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_nm->parentid.pv = common_util_alloc(dst_nm->parentid.cb);
			if (dst_nm->parentid.pv == nullptr) {
				dst_nm->parentid.cb = 0;
				return NULL;
			}
		}
		memcpy(dst_nm->parentid.pv, src_nm->parentid.pv, dst_nm->parentid.cb);
		dst_nm->flags = src_nm->flags;
		if (!b_temp) {
			dst_nm->message_class = strdup(src_nm->message_class);
			if (dst_nm->message_class == nullptr) {
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_nm->message_class = common_util_dup(src_nm->message_class);
			if (dst_nm->message_class == nullptr)
				return NULL;
		}
		dst_nm->message_flags = src_nm->message_flags;
		return dst;
	}

	auto src_ob = static_cast<OBJECT_ZNOTIFICATION *>(src->pnotification_data);
	OBJECT_ZNOTIFICATION *dst_ob;
	if (!b_temp) {
		dst_ob = me_alloc<OBJECT_ZNOTIFICATION>();
		if (dst_ob == nullptr) {
			free(dst);
			return NULL;
		}
	} else {
		dst_ob = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (dst_ob == nullptr)
			return NULL;
	}
	memset(dst_ob, 0, sizeof(*dst_ob));
	dst->pnotification_data = dst_ob;
	dst_ob->object_type = src_ob->object_type;
	if (src_ob->pentryid != nullptr) {
		if (!b_temp) {
			dst_ob->pentryid = static_cast<BINARY *>(propval_dup(PT_BINARY, src_ob->pentryid));
			if (dst_ob->pentryid == nullptr) {
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_ob->pentryid = common_util_dup_binary(src_ob->pentryid);
			if (dst_ob->pentryid == nullptr)
				return NULL;
		}
	}
	if (src_ob->pparentid != nullptr) {
		if (!b_temp) {
			dst_ob->pparentid = static_cast<BINARY *>(propval_dup(PT_BINARY, src_ob->pparentid));
			if (dst_ob->pparentid == nullptr) {
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_ob->pparentid = common_util_dup_binary(src_ob->pparentid);
			if (dst_ob->pparentid == nullptr)
				return NULL;
		}
	}
	if (src_ob->pold_entryid != nullptr) {
		if (!b_temp) {
			dst_ob->pold_entryid = static_cast<BINARY *>(propval_dup(PT_BINARY, src_ob->pold_entryid));
			if (dst_ob->pold_entryid == nullptr) {
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_ob->pold_entryid = common_util_dup_binary(src_ob->pold_entryid);
			if (dst_ob->pold_entryid == nullptr)
				return NULL;
		}
	}
	if (src_ob->pold_parentid != nullptr) {
		if (!b_temp) {
			dst_ob->pold_parentid = static_cast<BINARY *>(propval_dup(PT_BINARY, src_ob->pold_parentid));
			if (dst_ob->pold_parentid == nullptr) {
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_ob->pold_parentid = common_util_dup_binary(src_ob->pold_parentid);
			if (dst_ob->pold_parentid == nullptr)
				return NULL;
		}
	}
	if (src_ob->pproptags != nullptr) {
		if (!b_temp) {
			dst_ob->pproptags = proptag_array_dup(src_ob->pproptags);
			if (dst_ob->pproptags == nullptr) {
				common_util_free_znotification(dst);
				return NULL;
			}
		} else {
			dst_ob->pproptags = cu_alloc<PROPTAG_ARRAY>();
			if (dst_ob->pproptags == nullptr)
				return NULL;
			dst_ob->pproptags->count = src_ob->pproptags->count;
			dst_ob->pproptags->pproptag = cu_alloc<uint32_t>(src_ob->pproptags->count);
			if (dst_ob->pproptags->pproptag == nullptr)
				return NULL;
			memcpy(dst_ob->pproptags->pproptag, src_ob->pproptags->pproptag,
			       sizeof(uint32_t) * src_ob->pproptags->count);
		}
	}
	return dst;
}

void common_util_free_znotification(ZNOTIFICATION *pnotification)
{
	if (pnotification->event_type == NF_NEW_MAIL) {
		auto pnew_notify = static_cast<NEWMAIL_ZNOTIFICATION *>(pnotification->pnotification_data);
		if (pnew_notify->entryid.pb != nullptr)
			free(pnew_notify->entryid.pb);
		if (pnew_notify->parentid.pb != nullptr)
			free(pnew_notify->parentid.pb);
		if (pnew_notify->message_class != nullptr)
			free(pnew_notify->message_class);
		free(pnew_notify);
	} else {
		auto pobj_notify = static_cast<OBJECT_ZNOTIFICATION *>(pnotification->pnotification_data);
		if (pobj_notify->pentryid != nullptr)
			rop_util_free_binary(pobj_notify->pentryid);
		if (pobj_notify->pparentid != nullptr)
			rop_util_free_binary(pobj_notify->pparentid);
		if (pobj_notify->pold_entryid != nullptr)
			rop_util_free_binary(pobj_notify->pold_entryid);
		if (pobj_notify->pold_parentid != nullptr)
			rop_util_free_binary(pobj_notify->pold_parentid);
		if (pobj_notify->pproptags != nullptr)
			proptag_array_free(pobj_notify->pproptags);
	}
	free(pnotification);
}

BOOL common_util_parse_addressbook_entryid(BINARY entryid_bin, uint32_t *ptype,
    char *pessdn, size_t dsize)
{
	EXT_PULL ext_pull;
	EMSAB_ENTRYID tmp_entryid;

	ext_pull.init(entryid_bin.pb, entryid_bin.cb, common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_abk_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;
	*ptype = tmp_entryid.type;
	gx_strlcpy(pessdn, tmp_entryid.px500dn, dsize);
	return TRUE;
}

BINARY* common_util_username_to_addressbook_entryid(
	const char *username)
{
	char x500dn[1024];
	EXT_PUSH ext_push;
	EMSAB_ENTRYID tmp_entryid;
	
	if (!common_util_username_to_essdn(username, x500dn, std::size(x500dn)))
		return NULL;
	tmp_entryid.flags = 0;
	tmp_entryid.version = 1;
	tmp_entryid.type = DT_MAILUSER;
	tmp_entryid.px500dn = x500dn;
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(1280);
	if (pbin->pv == nullptr ||
	    !ext_push.init(pbin->pv, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BOOL common_util_essdn_to_entryid(const char *essdn, BINARY *pbin)
{
	EXT_PUSH ext_push;
	EMSAB_ENTRYID tmp_entryid;
	
	pbin->pv = common_util_alloc(1280);
	if (pbin->pv == nullptr)
		return FALSE;
	tmp_entryid.flags = 0;
	tmp_entryid.version = 1;
	tmp_entryid.type = DT_MAILUSER;
	tmp_entryid.px500dn = deconst(essdn);
	if (!ext_push.init(pbin->pv, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return false;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

static BOOL common_util_username_to_entryid(const char *username,
    const char *pdisplay_name, BINARY *pbin, enum display_type *dtpp)
{
	unsigned int user_id = 0, domain_id = 0;
	char *pdomain;
	char x500dn[1024];
	EXT_PUSH ext_push;
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];
	ONEOFF_ENTRYID oneoff_entry;
	auto dtypx = DT_MAILUSER;
	
	if (system_services_get_user_ids(username, &user_id, &domain_id, &dtypx)) {
		gx_strlcpy(tmp_name, username, std::size(tmp_name));
		pdomain = strchr(tmp_name, '@');
		if (pdomain == nullptr)
			return FALSE;
		*pdomain = '\0';
		encode_hex_int(user_id, hex_string);
		encode_hex_int(domain_id, hex_string2);
		snprintf(x500dn, std::size(x500dn), "/o=%s/" EAG_RCPTS "/cn=%s%s-%s",
				g_org_name, hex_string2, hex_string, tmp_name);
		HX_strupper(x500dn);
		if (!common_util_essdn_to_entryid(x500dn, pbin))
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
	if (EXT_ERR_CHARCNV == status) {
		oneoff_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO;
		status = ext_push.p_oneoff_eid(oneoff_entry);
	}
	if (status != EXT_ERR_SUCCESS)
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
	if (ext_pull.g_uint32(&flags) != EXT_ERR_SUCCESS ||
	    ext_pull.g_guid(&provider_uid) != EXT_ERR_SUCCESS)
		return 0;
	/*
	 * The GUID determines how things look after byte 20. Without
	 * inspecting the GUID, pulling an uint16_t here is undefined if going
	 * by specification. I suppose the caller ought to ensure it is only
	 * used with FOLDER_ENTRYIDs and MESSAGE_ENTRYIDs.
         */
	if (ext_pull.g_uint16(&folder_type) != EXT_ERR_SUCCESS)
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
	if (ext_pull.g_folder_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
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
		if (!exmdb_client::get_mapping_replid(pinfo->get_homedir(),
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
	if (ext_pull.g_msg_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
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
		if (!exmdb_client::get_mapping_replid(pinfo->get_homedir(),
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

#if 0
static ec_error_t replguid_to_replid(const store_object &logon,
    const GUID &guid, uint16_t &replid)
{
	if (guid == GUID_NONE) {
		replid = 0;
		return ecInvalidParam;
	}
	if (guid == logon.mailbox_guid) {
		replid = 5;
		return ecSuccess;
	} else if (memcmp(reinterpret_cast<const char *>(&guid) + 4,
	    reinterpret_cast<const char *>(&gx_dbguid_store_private) + 4, 12) == 0) {
		auto usr_id = rop_util_get_user_id(guid);
		if (usr_id == logon.account_id) {
			replid = 1;
			return ecSuccess;
		}
	} else if (memcmp(reinterpret_cast<const char *>(&guid) + 4,
	    reinterpret_cast<const char *>(&gx_dbguid_store_public) + 4, 12) == 0) {
		auto dom_id = rop_util_get_domain_id(guid);
		if (!system_services_check_same_org(dom_id, logon.account_id))
			return ecInvalidParam;
	}
	ec_error_t ret = ecSuccess;
	if (!exmdb_client::get_mapping_replid(logon.get_dir(),
	    guid, &replid, &ret))
		return ecError;
	return ret;
}
#endif

static ec_error_t replid_to_replguid(const store_object &logon,
    uint16_t replid, GUID &guid)
{
	auto dir = logon.get_dir();
	BOOL b_found = false;
	if (replid == 1)
		guid = logon.b_private ?
		       rop_util_make_user_guid(logon.account_id) :
		       rop_util_make_domain_guid(logon.account_id);
	else if (replid == 5)
		guid = logon.mailbox_guid;
	else if (!exmdb_client::get_mapping_guid(dir, replid, &b_found, &guid))
		return ecError;
	else if (!b_found)
		return ecNotFound;
	return ecSuccess;
}

BINARY *cu_fid_to_entryid(store_object *pstore, uint64_t folder_id)
{
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (replid_to_replguid(*pstore, rop_util_get_replid(folder_id),
	    tmp_entryid.database_guid) != ecSuccess)
		return nullptr;
	if (pstore->b_private) {
		tmp_bin.cb = 0;
		tmp_bin.pv = &tmp_entryid.provider_uid;
		rop_util_guid_to_binary(pstore->mailbox_guid, &tmp_bin);
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
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 256, 0) ||
	    ext_push.p_folder_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BINARY *cu_fid_to_sk(store_object *pstore,
    uint64_t folder_id)
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
	if (replid_to_replguid(*pstore, rop_util_get_replid(folder_id),
	    longid.guid) != ecSuccess)
		return nullptr;
	longid.global_counter = rop_util_get_gc_array(folder_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != EXT_ERR_SUCCESS)
		return NULL;
	return pbin;
}

BINARY *cu_mid_to_entryid(store_object *pstore,
	uint64_t folder_id, uint64_t message_id)
{
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (replid_to_replguid(*pstore, rop_util_get_replid(folder_id),
	    tmp_entryid.folder_database_guid) != ecSuccess)
		return nullptr;
	if (replid_to_replguid(*pstore, rop_util_get_replid(message_id),
	    tmp_entryid.message_database_guid) != ecSuccess)
		return nullptr;
	if (pstore->b_private) {
		tmp_bin.cb = 0;
		tmp_bin.pv = &tmp_entryid.provider_uid;
		rop_util_guid_to_binary(pstore->mailbox_guid, &tmp_bin);
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
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 256, 0) ||
	    ext_push.p_msg_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

ec_error_t cu_calc_msg_access(store_object *pstore, const char *user,
    uint64_t folder_id, uint64_t message_id, uint32_t &tag_access)
{
	BOOL b_owner = false;
	uint32_t permission = 0;

	tag_access = 0;
	if (pstore->owner_mode()) {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		goto PERMISSION_CHECK;
	}
	if (!exmdb_client::get_folder_perm(pstore->get_dir(),
	    folder_id, user, &permission))
		return ecError;
	if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
		return ecAccessDenied;
	if (permission & frightsOwner) {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		goto PERMISSION_CHECK;
	}
	if (!exmdb_client_check_message_owner(pstore->get_dir(),
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

BINARY *cu_mid_to_sk(store_object *pstore,
    uint64_t message_id)
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
	longid.guid = pstore->guid();
	longid.global_counter = rop_util_get_gc_array(message_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != EXT_ERR_SUCCESS)
		return NULL;
	return pbin;
}

BINARY *cu_xid_to_bin(const XID &xid)
{
	EXT_PUSH ext_push;
	
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(24);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 24, 0) ||
	    ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
		return NULL;
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid)
{
	EXT_PULL ext_pull;
	
	if (pbin->cb < 17 || pbin->cb > 24)
		return FALSE;
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	return ext_pull.g_xid(pbin->cb, pxid) == EXT_ERR_SUCCESS ? TRUE : false;
}

BINARY* common_util_guid_to_binary(GUID guid)
{
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->cb = 0;
	pbin->pv = common_util_alloc(16);
	if (pbin->pv == nullptr)
		return NULL;
	rop_util_guid_to_binary(guid, pbin);
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
	return exmdb_client::get_named_propids(
			common_util_get_dir(), FALSE,
			ppropnames, ppropids);
}

static BOOL common_util_get_propids_create(const PROPNAME_ARRAY *names,
    PROPID_ARRAY *ids)
{
	return exmdb_client::get_named_propids(common_util_get_dir(),
	       TRUE, names, ids);
}

static BOOL common_util_get_propname(
	uint16_t propid, PROPERTY_NAME **pppropname)
{
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	
	propids.count = 1;
	propids.ppropid = &propid;
	if (!exmdb_client::get_named_propnames(common_util_get_dir(),
	    &propids, &propnames))
		return FALSE;
	*pppropname = propnames.count != 1 ? nullptr : propnames.ppropname;
	return TRUE;
}

static bool mapi_p1(const TPROPVAL_ARRAY &props)
{
	auto v = props.get<const uint32_t>(PR_RECIPIENT_TYPE);
	return v != nullptr && *v & MAPI_P1;
}

#if 0
static bool xp_is_in_charge(const TPROPVAL_ARRAY &props)
{
	auto v = props.get<const uint32_t>(PR_RESPONSIBILITY);
	return v == nullptr || *v != 0;
}
#endif

static ec_error_t cu_rcpt_to_list(eid_t message_id, const TPROPVAL_ARRAY &props,
    std::vector<std::string> &list, bool resend) try
{
	char username[UADDR_SIZE];
	if (resend && !mapi_p1(props))
		return ecSuccess;
	/*
	if (!b_submit && xp_is_in_charge(rcpt))
		return ecSuccess;
	*/
	auto str = props.get<const char>(PR_SMTP_ADDRESS);
	if (str != nullptr && *str != '\0') {
		list.emplace_back(str);
		return ecSuccess;
	}
	auto addrtype = props.get<const char>(PR_ADDRTYPE);
	auto emaddr   = props.get<const char>(PR_EMAIL_ADDRESS);
	std::string es_result;
	if (addrtype != nullptr) {
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr, g_org_name,
		           cu_id2user, es_result);
		if (ret == ecSuccess) {
			list.emplace_back(std::move(es_result));
			return ecSuccess;
		} else if (ret != ecNullObject) {
			return ret;
		}
	}
	auto ret = cvt_entryid_to_smtpaddr(props.get<const BINARY>(PR_ENTRYID),
	           g_org_name, cu_id2user, es_result);
	if (ret == ecSuccess)
		list.emplace_back(username);
	return ret == ecNullObject || ret == ecUnknownUser ? ecInvalidRecips : ret;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1122: ENOMEM");
	return ecServerOOM;
}

BOOL cu_send_message(store_object *pstore, message_object *msg, BOOL b_submit)
{
	uint64_t message_id = msg->get_id();
	void *pvalue;
	BOOL b_result;
	EID_ARRAY ids;
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
		return FALSE;
	auto parent_id = *static_cast<uint64_t *>(pvalue);
	if (!exmdb_client::read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
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
	auto num = pmsgctnt->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (num == nullptr)
		return FALSE;
	bool b_resend = *num & MSGFLAG_RESEND;
	const tarray_set *prcpts = pmsgctnt->children.prcpts;
	if (prcpts == nullptr)
		return FALSE;
	if (prcpts->count == 0)
		mlog(LV_INFO, "I-1504: Store %s attempted to send message %llxh to 0 recipients",
		        pstore->get_account(), LLU{message_id});

	std::vector<std::string> rcpt_list;
	for (auto &rcpt : *prcpts)
		if (cu_rcpt_to_list(message_id, rcpt, rcpt_list,
		    b_resend) != ecSuccess)
			return false;

	if (rcpt_list.size() > 0) {
		auto body_type = get_override_format(*pmsgctnt);
		common_util_set_dir(pstore->get_dir());
		/* try to avoid TNEF message */
		MAIL imail;
		if (!oxcmail_export(pmsgctnt, false, body_type,
		    &imail, common_util_alloc, common_util_get_propids,
		    common_util_get_propname))
			return FALSE;	

		imail.set_header("X-Mailer", ZCORE_UA);
		if (zcore_backfill_transporthdr) {
			std::unique_ptr<MESSAGE_CONTENT, mc_delete> rmsg(oxcmail_import("utf-8",
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
			mlog(LV_ERR, "E-1194: cu_send_mail: %s", mapi_strerror(ret));
			return FALSE;
		}
	}
	auto flag = pmsgctnt->proplist.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagSentMailSvrEID);
	auto ptarget = pmsgctnt->proplist.get<BINARY>(PR_TARGET_ENTRYID);
	if (NULL != ptarget) {
		if (!cu_entryid_to_mid(*ptarget,
		    &b_private, &account_id, &folder_id, &new_id))
			return FALSE;	
		if (!exmdb_client::clear_submit(pstore->get_dir(), message_id, false))
			return FALSE;
		if (!exmdb_client::movecopy_message(pstore->get_dir(),
		    pstore->account_id, cpid, message_id, folder_id, new_id,
		    TRUE, &b_result))
			return FALSE;
		return TRUE;
	} else if (b_delete) {
		exmdb_client_delete_message(pstore->get_dir(),
			pstore->account_id, cpid, parent_id, message_id,
			TRUE, &b_result);
		return TRUE;
	}
	if (!exmdb_client::clear_submit(pstore->get_dir(), message_id, false))
		return FALSE;
	ids.count = 1;
	ids.pids = &message_id;
	ptarget = pmsgctnt->proplist.get<BINARY>(PR_SENTMAIL_ENTRYID);
	if (ptarget == nullptr || !cu_entryid_to_fid(*ptarget,
	    &b_private, &account_id, &folder_id))
		folder_id = rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS);
	return exmdb_client::movecopy_messages(pstore->get_dir(),
	       pstore->account_id, cpid, false, STORE_OWNER_GRANTED,
	       parent_id, folder_id, false, &ids, &b_partial);
}

void common_util_notify_receipt(const char *username, int type,
    MESSAGE_CONTENT *pbrief) try
{
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str == nullptr)
		return;
	std::vector<std::string> rcpt_list = {str};
	MAIL imail;
	auto bounce_type = type == NOTIFY_RECEIPT_READ ?
	                   "BOUNCE_NOTIFY_READ" : "BOUNCE_NOTIFY_NON_READ";
	if (!exch_bouncer_make(system_services_get_user_displayname,
	    system_services_get_user_lang, username, pbrief, bounce_type, &imail))
		return;
	imail.set_header("X-Mailer", ZCORE_UA);
	auto ret = cu_send_mail(imail, g_smtp_url.c_str(),
	           username, rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "E-1193: cu_send_mail: %xh\n", ret);
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
	if (ext_pull.g_store_eid(pstore_entryid) != EXT_ERR_SUCCESS)
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

BINARY *common_util_to_store_entryid(store_object *pstore)
{
	EXT_PUSH ext_push;
	char tmp_buff[1024];
	STORE_ENTRYID store_entryid = {};
	
	store_entryid.flags = 0;
	store_entryid.version = 0;
	store_entryid.flag = 0;
	store_entryid.wrapped_flags = 0;
	store_entryid.pserver_name = deconst(pstore->get_account());
	if (pstore->b_private) {
		store_entryid.wrapped_provider_uid = g_muidStorePrivate;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_TAKE_OWNERSHIP;
		if (!common_util_username_to_essdn(pstore->get_account(),
		    tmp_buff, std::size(tmp_buff)))
			return NULL;	
	} else {
		store_entryid.wrapped_provider_uid = g_muidStorePublic;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_PUBLIC;
		auto pinfo = zs_get_info();
		if (!common_util_username_to_essdn(pinfo->get_username(),
		    tmp_buff, std::size(tmp_buff)))
			return NULL;	
	}
	store_entryid.pmailbox_dn = tmp_buff;
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(1024);
	if (pbin->pb == nullptr ||
	    !ext_push.init(pbin->pv, 1024, EXT_FLAG_UTF16) ||
	    ext_push.p_store_eid(store_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
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
		    ext_push.p_store_eid(*src.pstore_eid) != EXT_ERR_SUCCESS)
			return NULL;	
		dst->store_eid.cb = ext_push.m_offset;
		dst->folder_eid = *static_cast<BINARY *>(src.pfolder_eid);
	} else {
		auto pbin = common_util_to_store_entryid(pstore);
		if (pbin == nullptr)
			return NULL;
		dst->store_eid = *pbin;
		pbin = cu_fid_to_entryid(pstore, static_cast<SVREID *>(src.pfolder_eid)->folder_id);
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
	if (cu_mid_to_entryid(pstore, src.template_folder_id,
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
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zs_get_info();
	auto username = src_store->b_private ? nullptr : pinfo->get_username();
	if (!exmdb_client::read_message(src_store->get_dir(), username,
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
	if (!exmdb_client::allocate_cn(dst_store->get_dir(), &change_num))
		return ecError;
	propval.proptag = PidTagChangeNumber;
	propval.pvalue = &change_num;
	common_util_set_propvals(&pmsgctnt->proplist, &propval);
	auto pbin = cu_xid_to_bin({src_store->guid(), change_num});
	if (pbin == nullptr)
		return ecError;
	propval.proptag = PR_CHANGE_KEY;
	propval.pvalue = pbin;
	common_util_set_propvals(&pmsgctnt->proplist, &propval);
	auto pbin1 = pmsgctnt->proplist.get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval.pvalue = common_util_pcl_append(pbin1, pbin);
	if (propval.pvalue == nullptr)
		return ecError;
	common_util_set_propvals(&pmsgctnt->proplist, &propval);
	ec_error_t e_result = ecError;
	if (!exmdb_client::write_message(dst_store->get_dir(),
	    dst_store->get_account(), pinfo->cpid, folder_id1,
	    pmsgctnt, &e_result) || e_result != ecSuccess)
		return e_result;
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
	TAGGED_PROPVAL propval;
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
	propval.proptag = PR_FOLDER_TYPE;
	propval.pvalue = &tmp_type;
	tmp_type = FOLDER_GENERIC;
	common_util_set_propvals(pproplist, &propval);
	propval.proptag = PidTagParentFolderId;
	propval.pvalue = &parent_id;
	common_util_set_propvals(pproplist, &propval);
	if (!exmdb_client::allocate_cn(pstore->get_dir(), &change_num))
		return ecError;
	propval.proptag = PidTagChangeNumber;
	propval.pvalue = &change_num;
	common_util_set_propvals(pproplist, &propval);
	auto pbin = cu_xid_to_bin({pstore->guid(), change_num});
	if (pbin == nullptr)
		return ecMAPIOOM;
	propval.proptag = PR_CHANGE_KEY;
	propval.pvalue = pbin;
	common_util_set_propvals(pproplist, &propval);
	auto pbin1 = pproplist->get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval.pvalue = common_util_pcl_append(pbin1, pbin);
	if (propval.pvalue == nullptr)
		return ecMAPIOOM;
	common_util_set_propvals(pproplist, &propval);
	auto pinfo = zs_get_info();
	ec_error_t err = ecSuccess;
	if (!exmdb_client::create_folder(pstore->get_dir(), pinfo->cpid,
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
	exmdb_client::update_folder_permission(pstore->get_dir(),
		*pfolder_id, FALSE, 1, &permission_row);
	return ecSuccess;
}

static EID_ARRAY *common_util_load_folder_messages(store_object *pstore,
    uint64_t folder_id, const char *username)
{
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	PROPTAG_ARRAY proptags;
	EID_ARRAY *pmessage_ids;
	
	if (!exmdb_client::load_content_table(pstore->get_dir(), CP_ACP,
	    folder_id, username, TABLE_FLAG_NONOTIFICATIONS,
	    nullptr, nullptr, &table_id, &row_count))
		return NULL;	
	uint32_t tmp_proptag = PidTagMid;
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	if (!exmdb_client::query_table(pstore->get_dir(), nullptr, CP_ACP,
	    table_id, &proptags, 0, row_count, &tmp_set))
		return NULL;	
	exmdb_client::unload_table(pstore->get_dir(), table_id);
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
	TAGGED_PROPVAL propval;
	EID_ARRAY *pmessage_ids;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (!exmdb_client::get_folder_all_proptags(src_store->get_dir(),
	    folder_id, &tmp_proptags))
		return ecError;
	if (!exmdb_client::get_folder_properties(src_store->get_dir(), CP_ACP,
	    folder_id, &tmp_proptags, &tmp_propvals))
		return ecError;
	if (NULL != new_name) {
		propval.proptag = PR_DISPLAY_NAME;
		propval.pvalue = deconst(new_name);
		common_util_set_propvals(&tmp_propvals, &propval);
	}
	auto err = cu_create_folder(dst_store, folder_id1, &tmp_propvals, &new_fid);
	if (err != ecSuccess)
		return err;
	auto pinfo = zs_get_info();
	const char *username = nullptr;
	if (!src_store->owner_mode()) {
		username = pinfo->get_username();
		if (!exmdb_client::get_folder_perm(src_store->get_dir(),
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
	if (!exmdb_client::load_hierarchy_table(src_store->get_dir(), folder_id,
	    username, TABLE_FLAG_NONOTIFICATIONS, nullptr,
	    &table_id, &row_count))
		return ecError;
	uint32_t tmp_proptag = PidTagFolderId;
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &tmp_proptag;
	if (!exmdb_client::query_table(src_store->get_dir(), nullptr, CP_ACP,
	    table_id, &tmp_proptags, 0, row_count, &tmp_set))
		return ecError;
	exmdb_client::unload_table(src_store->get_dir(), table_id);
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

BOOL common_util_message_to_rfc822(store_object *pstore, uint64_t inst_id, BINARY *peml_bin)
{
	int size;
	void *ptr;
	TAGGED_PROPVAL *ppropval;
	MESSAGE_CONTENT msgctnt{}, *pmsgctnt = &msgctnt;
	
	auto pinfo = zs_get_info();
	cpid_t cpid = pinfo == nullptr ? CP_UTF8 : pinfo->cpid;
	if (!exmdb_client::read_message_instance(pstore->get_dir(),
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
	MAIL imail;
	if (!oxcmail_export(pmsgctnt, false, body_type, &imail,
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
}

static void zc_unwrap_smime(MAIL &ma) try
{
	auto part = ma.get_head();
	if (part == nullptr ||
	    strcasecmp(part->content_type, "multipart/signed") != 0)
		return;
	part = part->get_child();
	if (part == nullptr)
		return;
	auto partlen = part->get_length();
	if (partlen < 0)
		return;
	size_t len = partlen;
	std::unique_ptr<char[], stdlib_delete> ctbuf(me_alloc<char>(len));
	if (ctbuf == nullptr)
		throw std::bad_alloc();
	if (!part->read_head(ctbuf.get(), &len))
		return;
	size_t written_so_far = len;
	len = partlen - len;
	if (!part->read_content(&ctbuf[written_so_far], &len))
		return;
	written_so_far += len;
	MAIL m2;
	if (!m2.load_from_str_move(ctbuf.get(), written_so_far))
		return;
	m2.buffer = ctbuf.release();
	ma = std::move(m2);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1996: ENOMEM");
}

MESSAGE_CONTENT *cu_rfc822_to_message(store_object *pstore,
    unsigned int mxf_flags, /* effective-moved-from */ BINARY *peml_bin)
{
	char charset[32], tmzone[64];
	
	auto pinfo = zs_get_info();
	MAIL imail;
	if (!imail.load_from_str_move(peml_bin->pc, peml_bin->cb))
		return NULL;
	if (mxf_flags & MXF_UNWRAP_SMIME_CLEARSIGNED)
		zc_unwrap_smime(imail);
	auto c = lang_to_charset(pinfo->get_lang());
	if (c != nullptr && *c != '\0')
		gx_strlcpy(charset, c, std::size(charset));
	else
		strcpy(charset, g_default_charset);
	if (!system_services_get_timezone(pinfo->get_username(), tmzone,
	    std::size(tmzone)) || tmzone[0] == '\0')
		strcpy(tmzone, common_util_get_default_timezone());
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
	if (!exmdb_client::read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	common_util_set_dir(pstore->get_dir());
	if (!oxcical_export(pmsgctnt, ical, g_org_name,
	    common_util_alloc, common_util_get_propids, cu_id2user)) {
		mlog(LV_DEBUG, "D-2202: oxcical_export %s:%llxh failed",
			pstore->get_dir(), LLU{message_id});
		return FALSE;
	}
	std::string tmp_buff;
	if (ical.serialize(tmp_buff) != ecSuccess)
		return FALSE;	
	pical_bin->cb = tmp_buff.size();
	pical_bin->pc = common_util_dup(tmp_buff.c_str());
	return pical_bin->pc != nullptr ? TRUE : FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2183: ENOMEM");
	return false;
}

message_ptr cu_ical_to_message(store_object *pstore, const BINARY *pical_bin) try
{
	ical ical;
	char tmzone[64];
	
	auto pinfo = zs_get_info();
	if (!system_services_get_timezone(pinfo->get_username(), tmzone,
	    std::size(tmzone)) || tmzone[0] == '\0')
		strcpy(tmzone, common_util_get_default_timezone());
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
	char tmzone[64];
	if (!system_services_get_timezone(info->get_username(), tmzone,
	    std::size(tmzone)) || tmzone[0] == '\0')
		gx_strlcpy(tmzone, common_util_get_default_timezone(), std::size(tmzone));

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
	if (!exmdb_client::read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	common_util_set_dir(pstore->get_dir());
	vcard vcard;
	if (!oxvcard_export(pmsgctnt, vcard, common_util_get_propids))
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

BINARY *cu_read_storenamedprop(const char *dir, const GUID &guid,
    const char *name, uint16_t proptype)
{
	if (*dir == '\0')
		return nullptr;
	const PROPERTY_NAME xn = {MNID_STRING, guid, 0, deconst(name)};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!exmdb_client::get_named_propids(dir, false, &name_req, &name_rsp) ||
	    name_rsp.count != name_req.count || name_rsp.ppropid[0] == 0)
		return nullptr;
	uint32_t proptag = PROP_TAG(proptype, name_rsp.ppropid[0]);
	const PROPTAG_ARRAY tags = {1, deconst(&proptag)};
	TPROPVAL_ARRAY values{};
	if (!exmdb_client::get_store_properties(dir, CP_ACP, &tags, &values))
		return nullptr;
	return values.get<BINARY>(proptag);
}

errno_t cu_write_storenamedprop(const char *dir, const GUID &guid,
    const char *name, uint16_t proptype, const void *buf, size_t size)
{
	if (*dir == '\0')
		return EINVAL;
	const PROPERTY_NAME xn = {MNID_STRING, guid, 0, deconst(name)};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!exmdb_client::get_named_propids(dir, true, &name_req, &name_rsp) ||
	    name_rsp.count != name_req.count || name_rsp.ppropid[0] == 0)
		return EINVAL;
	BINARY bin;
	bin.cb = size;
	bin.pv = deconst(buf);
	TAGGED_PROPVAL pv = {PROP_TAG(proptype, name_rsp.ppropid[0]), &bin};
	TPROPVAL_ARRAY values = {1, &pv};
	PROBLEM_ARRAY prob;
	if (!exmdb_client::set_store_properties(dir, CP_ACP, &values, &prob))
		return EINVAL;
	return 0;
}

ec_error_t cu_id2user(int id, std::string &user) try
{
	char ubuf[UADDR_SIZE];
	if (!system_services_get_username_from_id(id, ubuf, std::size(ubuf)))
		return ecError;
	user = ubuf;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
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
