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
#include <gromox/mapidefs.h>
#include <gromox/mime_pool.hpp>
#include <gromox/oxcical.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/oxvcard.hpp>
#include <gromox/pcl.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#include "bounce_producer.hpp"
#include "common_util.h"
#include "exmdb_client.h"
#include "objects.hpp"
#include "store_object.h"
#include "system_services.hpp"
#include "zarafa_server.h"

using namespace std::string_literals;
using namespace gromox;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

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
using ENVIRONMENT_CONTEXT = env_context;

struct LANGMAP_ITEM {
	char lang[32];
	char i18n[32];
};

}

unsigned int g_max_rcpt, g_max_message, g_max_mail_len;
unsigned int g_max_rule_len, g_max_extrule_len;
static int g_mime_num;
static uint16_t g_smtp_port;
static char g_smtp_ip[40];
static char g_org_name[256];
static char g_hostname[UDOM_SIZE];
static std::shared_ptr<MIME_POOL> g_mime_pool;
static thread_local const char *g_dir_key;
static thread_local unsigned int g_env_refcount;
static thread_local std::unique_ptr<env_context> g_env_key;
static char g_freebusy_path[256];
static char g_default_charset[32];
static char g_submit_command[1024];

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

bool cu_extract_delegate(message_object *pmessage, char *username, size_t ulen)
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
		username[0] = '\0';
		return TRUE;
	}
	auto str = tmp_propvals.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
	if (str != nullptr) {
		if (strcasecmp(str, "EX") == 0) {
			str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr)
				return common_util_essdn_to_username(str,
				       username, ulen);
		} else if (strcasecmp(str, "SMTP") == 0) {
			str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr) {
				gx_strlcpy(username, str, ulen);
				return TRUE;
			}
		}
	}
	str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr) {
		gx_strlcpy(username, str, ulen);
		return TRUE;
	}
	auto bin = tmp_propvals.get<const BINARY>(PR_SENT_REPRESENTING_ENTRYID);
	if (bin != nullptr)
		return common_util_entryid_to_username(bin, username, ulen);
	username[0] = '\0';
	return TRUE;
}

/**
 * Check whether @account (secretary) is allowed to represent @maildir
 * (this is the filesystem variant of cu_get_delegate_perm_AA.)
 * @send_as:	whether to evaluate either the Send-As or Send-On-Behalf list
 */
bool cu_test_delegate_perm_MD(const char *account,
    const char *maildir, bool send_as) try
{
	std::vector<std::string> delegate_list;
	auto path = maildir + std::string(send_as ? "/config/sendas.txt" : "/config/delegates.txt");
	auto ret = read_file_by_line(path.c_str(), delegate_list);
	if (ret != 0 && ret != ENOENT) {
		fprintf(stderr, "W-2057: %s: %s\n", path.c_str(), strerror(errno));
		return FALSE;
	}
	for (const auto &d : delegate_list)
		if (strcasecmp(d.c_str(), account) == 0)
			return TRUE;
	return FALSE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2056: ENOMEM\n");
	return false;
}

/**
 * Check whether @account (secretary) is allowed to represent @account_repr.
 * @send_as:	whether to evaluate either the Send-As or Send-On-Behalf list
 */
bool cu_test_delegate_perm_AA(const char *account,
    const char *account_representing, bool send_as)
{
	char maildir[256];	
	
	if (strcasecmp(account, account_representing) == 0)
		return TRUE;
	if (!system_services_get_maildir(account_representing,
	    maildir, arsizeof(maildir)))
		return FALSE;
	return cu_get_delegate_perm_MD(account, maildir, send_as);
}

/**
 * @account:	"secretary account"
 * @maildir:	"boss account"
 *
 * Return value(s):
 * - rv false: Only send as yourself
 * - rv true, send_as false: Send-On-Behalf
 * - rv true, send_as true: Send-As
 */
bool cu_get_delegate_perm_MD(const char *account, const char *maildir, bool &send_as)
{
	if (cu_test_delegate_perm_MD(account, maildir, true)) {
		send_as = true;
		return true;
	}
	if (cu_test_delegate_perm_MD(account, maildir, false)) {
		send_as = false;
		return true;
	}
	return false;
}

bool cu_get_delegate_perm_AA(const char *account, const char *repr, bool &send_as)
{
	if (cu_test_delegate_perm_AA(account, repr, true)) {
		send_as = true;
		return true;
	}
	if (cu_test_delegate_perm_AA(account, repr, false)) {
		send_as = false;
		return true;
	}
	return false;
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
	int i, j;
	
	for (j=0; j<pproptags_subtractor->count; j++) {
		for (i=0; i<pproptags_minuend->count; i++) {
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

BOOL common_util_essdn_to_username(const char *pessdn,
    char *username, size_t ulen)
{
	char *pat;
	int tmp_len;
	int user_id;
	const char *plocal;
	char tmp_essdn[1024];
	
	tmp_len = sprintf(tmp_essdn,
			"/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=",
			g_org_name);
	if (strncasecmp(pessdn, tmp_essdn, tmp_len) != 0 ||
	    pessdn[tmp_len+16] != '-')
		return FALSE;
	plocal = pessdn + tmp_len + 17;
	user_id = decode_hex_int(pessdn + tmp_len + 8);
	if (!system_services_get_username_from_id(user_id, username, ulen))
		return FALSE;
	pat = strchr(username, '@');
	if (pat == nullptr)
		return FALSE;
	return strncasecmp(username, plocal, pat - username) == 0 ? TRUE : false;
}

BOOL common_util_essdn_to_uid(const char *pessdn, int *puid)
{
	int tmp_len;
	char tmp_essdn[1024];
	
	tmp_len = sprintf(tmp_essdn,
			"/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=",
			g_org_name);
	if (strncasecmp(pessdn, tmp_essdn, tmp_len) != 0 ||
	    pessdn[tmp_len+16] != '-')
		return FALSE;
	*puid = decode_hex_int(pessdn + tmp_len + 8);
	return TRUE;
}

BOOL common_util_essdn_to_ids(const char *pessdn,
	int *pdomain_id, int *puser_id)
{
	int tmp_len;
	char tmp_essdn[1024];
	
	tmp_len = sprintf(tmp_essdn,
			"/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=",
			g_org_name);
	if (strncasecmp(pessdn, tmp_essdn, tmp_len) != 0 ||
	    pessdn[tmp_len+16] != '-')
		return FALSE;
	*pdomain_id = decode_hex_int(pessdn + tmp_len);
	*puser_id = decode_hex_int(pessdn + tmp_len + 8);
	return TRUE;	
}

BOOL common_util_username_to_essdn(const char *username, char *pessdn, size_t dnmax)
{
	int user_id;
	int domain_id;
	char *pdomain;
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];
	
	gx_strlcpy(tmp_name, username, GX_ARRAY_SIZE(tmp_name));
	pdomain = strchr(tmp_name, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	*pdomain = '\0';
	pdomain ++;
	if (!system_services_get_user_ids(username, &user_id, &domain_id, nullptr))
		return FALSE;
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, dnmax, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
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

void common_util_init(const char *org_name, const char *hostname,
	const char *default_charset, int mime_num,
    unsigned int max_rcpt, unsigned int max_message, unsigned int max_mail_len,
    unsigned int max_rule_len, const char *smtp_ip, uint16_t smtp_port,
	const char *freebusy_path, const char *submit_command)
{
	gx_strlcpy(g_org_name, org_name, GX_ARRAY_SIZE(g_org_name));
	gx_strlcpy(g_hostname, hostname, GX_ARRAY_SIZE(g_hostname));
	gx_strlcpy(g_default_charset, default_charset, GX_ARRAY_SIZE(g_default_charset));
	g_mime_num = mime_num;
	g_max_rcpt = max_rcpt;
	g_max_message = max_message;
	g_max_mail_len = max_mail_len;
	g_max_rule_len = g_max_extrule_len = max_rule_len;
	gx_strlcpy(g_smtp_ip, smtp_ip, GX_ARRAY_SIZE(g_smtp_ip));
	g_smtp_port = smtp_port;
	gx_strlcpy(g_freebusy_path, freebusy_path, GX_ARRAY_SIZE(g_freebusy_path));
	gx_strlcpy(g_submit_command, submit_command, GX_ARRAY_SIZE(g_submit_command));
}

int common_util_run(const char *data_path)
{
	g_mime_pool = MIME_POOL::create(g_mime_num, 16,
	              "zcore_mime_pool (zcore.cfg:g_mime_num)");
	if (NULL == g_mime_pool) {
		printf("[common_util]: Failed to init MIME pool\n");
		return -1;
	}
	if (!oxcmail_init_library(g_org_name, system_services_get_user_ids,
		system_services_get_username_from_id)) {
		printf("[common_util]: Failed to init oxcmail library\n");
		return -2;
	}
	return 0;
}

const char* common_util_get_hostname()
{
	return g_hostname;
}

const char* common_util_get_freebusy_path()
{
	return g_freebusy_path;
}

BOOL common_util_build_environment() try
{
	if (++g_env_refcount > 1)
		return TRUE;
	g_env_key = std::make_unique<env_context>();
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1977: ENOMEM\n");
	return false;
}

void common_util_free_environment()
{
	if (--g_env_refcount > 0)
		return;
	if (g_env_key == nullptr)
		fprintf(stderr, "W-1908: T%lu: g_env_key already unset\n", gx_gettid());
	else
		g_env_key.reset();
}

void* common_util_alloc(size_t size)
{
	auto pctx = g_env_key.get();
	if (pctx == nullptr) {
		fprintf(stderr, "E-1909: T%lu: g_env_key is unset, allocator is unset\n", gx_gettid());
		return NULL;
	}
	return pctx->allocator.alloc(size);
}

void common_util_set_clifd(int clifd)
{
	auto pctx = g_env_key.get();
	if (pctx == nullptr)
		fprintf(stderr, "E-1810: T%lu: g_env_key is unset, cannot set clifd\n", gx_gettid());
	else
		pctx->clifd = clifd;
}

int common_util_get_clifd()
{
	auto pctx = g_env_key.get();
	if (pctx != nullptr)
		return pctx->clifd;
	fprintf(stderr, "E-1811: T%lu: g_env_key is unset, clifd is unset\n", gx_gettid());
	return -1;
}

char* common_util_dup(const char *pstr)
{
	int len;
	
	len = strlen(pstr) + 1;
	auto pstr1 = cu_alloc<char>(len);
	if (pstr1 == nullptr)
		return NULL;
	memcpy(pstr1, pstr, len);
	return pstr1;
}

static BINARY* common_util_dup_binary(const BINARY *pbin)
{
	auto pbin1 = cu_alloc<BINARY>();
	if (pbin1 == nullptr)
		return NULL;
	pbin1->cb = pbin->cb;
	if (0 == pbin->cb) {
		pbin1->pb = NULL;
		return pbin1;
	}
	pbin1->pv = common_util_alloc(pbin->cb);
	if (pbin1->pv == nullptr)
		return NULL;
	memcpy(pbin1->pv, pbin->pv, pbin->cb);
	return pbin1;
}

ZNOTIFICATION* common_util_dup_znotification(
	ZNOTIFICATION *pnotification, BOOL b_temp)
{
	OBJECT_ZNOTIFICATION *pobj_notify;
	OBJECT_ZNOTIFICATION *pobj_notify1;
	NEWMAIL_ZNOTIFICATION *pnew_notify;
	NEWMAIL_ZNOTIFICATION *pnew_notify1;
	ZNOTIFICATION *pnotification1 = !b_temp ? me_alloc<ZNOTIFICATION>() : cu_alloc<ZNOTIFICATION>();
	
	if (pnotification1 == nullptr)
		return NULL;
	pnotification1->event_type = pnotification->event_type;
	if (EVENT_TYPE_NEWMAIL == pnotification->event_type) {
		pnew_notify1 = (NEWMAIL_ZNOTIFICATION*)
			pnotification->pnotification_data;
		if (!b_temp) {
			pnew_notify = me_alloc<NEWMAIL_ZNOTIFICATION>();
			if (NULL == pnew_notify) {
				free(pnotification1);
				return NULL;
			}
		} else {
			pnew_notify = cu_alloc<NEWMAIL_ZNOTIFICATION>();
			if (pnew_notify == nullptr)
				return NULL;
		}
		memset(pnew_notify, 0, sizeof(NEWMAIL_ZNOTIFICATION));
		pnotification1->pnotification_data = pnew_notify;
		pnew_notify->entryid.cb = pnew_notify1->entryid.cb;
		if (!b_temp) {
			pnew_notify->entryid.pv = malloc(pnew_notify->entryid.cb);
			if (pnew_notify->entryid.pv == nullptr) {
				pnew_notify->entryid.cb = 0;
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pnew_notify->entryid.pv = common_util_alloc(pnew_notify->entryid.cb);
			if (pnew_notify->entryid.pv == nullptr) {
				pnew_notify->entryid.cb = 0;
				return NULL;
			}
		}
		memcpy(pnew_notify->entryid.pv, pnew_notify1->entryid.pv,
			pnew_notify->entryid.cb);
		pnew_notify->parentid.cb = pnew_notify1->parentid.cb;
		if (!b_temp) {
			pnew_notify->parentid.pv = malloc(pnew_notify->parentid.cb);
			if (pnew_notify->parentid.pv == nullptr) {
				pnew_notify->parentid.cb = 0;
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pnew_notify->parentid.pv = common_util_alloc(pnew_notify->parentid.cb);
			if (pnew_notify->parentid.pv == nullptr) {
				pnew_notify->parentid.cb = 0;
				return NULL;
			}
		}
		memcpy(pnew_notify->parentid.pv, pnew_notify1->parentid.pv,
			pnew_notify->parentid.cb);
		pnew_notify->flags = pnew_notify1->flags;
		if (!b_temp) {
			pnew_notify->message_class = strdup(pnew_notify1->message_class);
			if (NULL == pnew_notify->message_class) {
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pnew_notify->message_class = common_util_dup(
							pnew_notify1->message_class);
			if (pnew_notify->message_class == nullptr)
				return NULL;
		}
		pnew_notify->message_flags = pnew_notify1->message_flags;
		return pnotification1;
	}
	pobj_notify1 = (OBJECT_ZNOTIFICATION *)
	               pnotification->pnotification_data;
	if (!b_temp) {
		pobj_notify = me_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			free(pnotification1);
			return NULL;
		}
	} else {
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return NULL;
		}
	}
	memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
	pnotification1->pnotification_data = pobj_notify;
	pobj_notify->object_type = pobj_notify1->object_type;
	if (NULL != pobj_notify1->pentryid) {
		if (!b_temp) {
			pobj_notify->pentryid = static_cast<BINARY *>(propval_dup(PT_BINARY,
			                        pobj_notify1->pentryid));
			if (NULL == pobj_notify->pentryid) {
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pobj_notify->pentryid = common_util_dup_binary(
			                        pobj_notify1->pentryid);
			if (pobj_notify->pentryid == nullptr)
				return NULL;
		}
	}
	if (NULL != pobj_notify1->pparentid) {
		if (!b_temp) {
			pobj_notify->pparentid = static_cast<BINARY *>(propval_dup(PT_BINARY,
			                         pobj_notify1->pparentid));
			if (NULL == pobj_notify->pparentid) {
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pobj_notify->pparentid = common_util_dup_binary(
			                         pobj_notify1->pparentid);
			if (pobj_notify->pparentid == nullptr)
				return NULL;
		}
	}
	if (NULL != pobj_notify1->pold_entryid) {
		if (!b_temp) {
			pobj_notify->pold_entryid = static_cast<BINARY *>(propval_dup(PT_BINARY,
			                            pobj_notify1->pold_entryid));
			if (NULL == pobj_notify->pold_entryid) {
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pobj_notify->pold_entryid = common_util_dup_binary(
			                            pobj_notify1->pold_entryid);
			if (pobj_notify->pold_entryid == nullptr)
				return NULL;
		}
	}
	if (NULL != pobj_notify->pold_parentid) {
		if (!b_temp) {
			pobj_notify->pold_parentid = static_cast<BINARY *>(propval_dup(PT_BINARY,
			                             pobj_notify1->pold_parentid));
			if (NULL == pobj_notify->pold_parentid) {
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pobj_notify->pold_parentid = common_util_dup_binary(
			                             pobj_notify1->pold_parentid);
			if (pobj_notify->pold_parentid == nullptr)
				return NULL;
		}
	}
	if (NULL != pobj_notify->pproptags) {
		if (!b_temp) {
			pobj_notify1->pproptags = proptag_array_dup(
			                          pobj_notify->pproptags);
			if (NULL == pobj_notify1->pproptags) {
				common_util_free_znotification(pnotification1);
				return NULL;
			}
		} else {
			pobj_notify1->pproptags = cu_alloc<PROPTAG_ARRAY>();
			if (pobj_notify1->pproptags == nullptr)
				return NULL;
			pobj_notify1->pproptags->count =
				pobj_notify->pproptags->count;
			pobj_notify1->pproptags->pproptag = cu_alloc<uint32_t>(pobj_notify->pproptags->count);
			if (pobj_notify1->pproptags->pproptag == nullptr)
				return NULL;
			memcpy(pobj_notify1->pproptags->pproptag,
				pobj_notify->pproptags->pproptag, sizeof(
				uint32_t) * pobj_notify->pproptags->count);
		}
	}
	return pnotification1;
}

void common_util_free_znotification(ZNOTIFICATION *pnotification)
{
	OBJECT_ZNOTIFICATION *pobj_notify;
	NEWMAIL_ZNOTIFICATION *pnew_notify;
	
	if (EVENT_TYPE_NEWMAIL == pnotification->event_type) {
		pnew_notify = (NEWMAIL_ZNOTIFICATION*)
			pnotification->pnotification_data;
		if (pnew_notify->entryid.pb != nullptr)
			free(pnew_notify->entryid.pb);
		if (pnew_notify->parentid.pb != nullptr)
			free(pnew_notify->parentid.pb);
		if (pnew_notify->message_class != nullptr)
			free(pnew_notify->message_class);
		free(pnew_notify);
	} else {
		pobj_notify = (OBJECT_ZNOTIFICATION*)
			pnotification->pnotification_data;
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

BOOL common_util_addressbook_entryid_to_username(BINARY entryid_bin,
    char *username, size_t ulen)
{
	EXT_PULL ext_pull;
	EMSAB_ENTRYID tmp_entryid;

	ext_pull.init(entryid_bin.pb, entryid_bin.cb, common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_abk_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;
	return common_util_essdn_to_username(tmp_entryid.px500dn, username, ulen);
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

static BOOL common_util_entryid_to_username_internal(const BINARY *pbin,
    EXT_BUFFER_ALLOC alloc, char *username, size_t ulen)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	FLATUID provider_uid;
	
	if (pbin->cb < 20)
		return FALSE;
	ext_pull.init(pbin->pb, pbin->cb, alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_uint32(&flags) != EXT_ERR_SUCCESS || flags != 0 ||
	    ext_pull.g_guid(&provider_uid) != EXT_ERR_SUCCESS)
		return FALSE;
	/* Tail functions will use EXT_PULL::*_eid, which parse a full EID */
	ext_pull.m_offset = 0;
	if (provider_uid == muidEMSAB)
		return emsab_to_email(ext_pull, common_util_essdn_to_username,
		       username, ulen) ? TRUE : false;
	if (provider_uid == muidOOP)
		return oneoff_to_parts(ext_pull, nullptr, 0, username, ulen) ? TRUE : false;
	return FALSE;
}

BOOL common_util_entryid_to_username(const BINARY *pbin,
    char *username, size_t ulen)
{
	return common_util_entryid_to_username_internal(pbin,
	       common_util_alloc, username, ulen);
}

BINARY* common_util_username_to_addressbook_entryid(
	const char *username)
{
	char x500dn[1024];
	EXT_PUSH ext_push;
	EMSAB_ENTRYID tmp_entryid;
	
	if (!common_util_username_to_essdn(username, x500dn, GX_ARRAY_SIZE(x500dn)))
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
	int status;
	int user_id;
	int domain_id;
	char *pdomain;
	char x500dn[1024];
	EXT_PUSH ext_push;
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];
	ONEOFF_ENTRYID oneoff_entry;
	auto dtypx = DT_MAILUSER;
	
	if (system_services_get_user_ids(username, &user_id, &domain_id, &dtypx)) {
		gx_strlcpy(tmp_name, username, GX_ARRAY_SIZE(tmp_name));
		pdomain = strchr(tmp_name, '@');
		if (pdomain == nullptr)
			return FALSE;
		*pdomain = '\0';
		encode_hex_int(user_id, hex_string);
		encode_hex_int(domain_id, hex_string2);
		snprintf(x500dn, 1024, "/o=%s/ou=Exchange Administrative "
				"Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
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
	oneoff_entry.ctrl_flags = CTRL_FLAG_NORICH | CTRL_FLAG_UNICODE;
	oneoff_entry.pdisplay_name = pdisplay_name != nullptr && *pdisplay_name != '\0' ?
	                             deconst(pdisplay_name) : deconst(username);
	oneoff_entry.paddress_type = deconst("SMTP");
	oneoff_entry.pmail_address = deconst(username);
	if (!ext_push.init(pbin->pv, 1280, EXT_FLAG_UTF16))
		return false;
	status = ext_push.p_oneoff_eid(oneoff_entry);
	if (EXT_ERR_CHARCNV == status) {
		oneoff_entry.ctrl_flags = CTRL_FLAG_NORICH;
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

BOOL common_util_from_folder_entryid(BINARY bin,
	BOOL *pb_private, int *pdb_id, uint64_t *pfolder_id)
{
	BOOL b_found;
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
		auto pinfo = zarafa_server_get_info();
		if (pinfo == nullptr || *pdb_id != pinfo->domain_id)
			return FALSE;
		if (!exmdb_client::get_mapping_replid(pinfo->get_homedir(),
		    tmp_entryid.database_guid, &b_found, &replid) || !b_found)
			return FALSE;
		*pfolder_id = rop_util_make_eid(replid,
					tmp_entryid.global_counter);
		return TRUE;
	}
	default:
		return FALSE;
	}
}

BOOL common_util_from_message_entryid(BINARY bin, BOOL *pb_private,
	int *pdb_id, uint64_t *pfolder_id, uint64_t *pmessage_id)
{
	BOOL b_found;
	uint16_t replid;
	EXT_PULL ext_pull;
	MESSAGE_ENTRYID tmp_entryid;
	
	ext_pull.init(bin.pb, bin.cb, common_util_alloc, 0);
	if (ext_pull.g_msg_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;	
	if (0 != memcmp(&tmp_entryid.folder_database_guid,
		&tmp_entryid.message_database_guid, sizeof(GUID))) {
		return FALSE;
	}
	switch (tmp_entryid.message_type) {
	case EITLT_PRIVATE_MESSAGE:
		*pb_private = TRUE;
		*pdb_id = rop_util_get_user_id(tmp_entryid.folder_database_guid);
		if (-1 == *pdb_id) {
			return FALSE;
		}
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
		auto pinfo = zarafa_server_get_info();
		if (NULL == pinfo || *pdb_id != pinfo->domain_id) {
			return FALSE;
		}
		if (!exmdb_client::get_mapping_replid(pinfo->get_homedir(),
		    tmp_entryid.folder_database_guid, &b_found, &replid) ||
		    !b_found)
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

BINARY *common_util_to_folder_entryid(store_object *pstore, uint64_t folder_id)
{
	BOOL b_found;
	BINARY tmp_bin;
	uint16_t replid;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (pstore->b_private) {
		tmp_bin.cb = 0;
		tmp_bin.pv = &tmp_entryid.provider_uid;
		rop_util_guid_to_binary(pstore->mailbox_guid, &tmp_bin);
		tmp_entryid.database_guid = rop_util_make_user_guid(pstore->account_id);
		tmp_entryid.folder_type = EITLT_PRIVATE_FOLDER;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		replid = rop_util_get_replid(folder_id);
		if (1 != replid) {
			if (!exmdb_client::get_mapping_guid(pstore->get_dir(),
			    replid, &b_found, &tmp_entryid.database_guid))
				return NULL;	
			if (!b_found)
				return NULL;
		} else {
			tmp_entryid.database_guid = rop_util_make_domain_guid(pstore->account_id);
		}
		tmp_entryid.folder_type = EITLT_PUBLIC_FOLDER;
	}
	tmp_entryid.global_counter = rop_util_get_gc_array(folder_id);
	tmp_entryid.pad[0] = 0;
	tmp_entryid.pad[1] = 0;
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 256, 0) ||
	    ext_push.p_folder_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BINARY *common_util_calculate_folder_sourcekey(store_object *pstore,
    uint64_t folder_id)
{
	BOOL b_found;
	uint16_t replid;
	EXT_PUSH ext_push;
	LONG_TERM_ID longid;
	
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = 22;
	pbin->pv = common_util_alloc(22);
	if (pbin->pv == nullptr)
		return NULL;
	if (pstore->b_private) {
		longid.guid = rop_util_make_user_guid(pstore->account_id);
	} else {
		replid = rop_util_get_replid(folder_id);
		if (1 == replid) {
			longid.guid = rop_util_make_domain_guid(pstore->account_id);
		} else {
			if (!exmdb_client::get_mapping_guid(pstore->get_dir(),
			    replid, &b_found, &longid.guid))
				return NULL;	
			if (!b_found)
				return NULL;
		}	
	}
	longid.global_counter = rop_util_get_gc_array(folder_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != EXT_ERR_SUCCESS)
		return NULL;
	return pbin;
}

BINARY *common_util_to_message_entryid(store_object *pstore,
	uint64_t folder_id, uint64_t message_id)
{
	BOOL b_found;
	BINARY tmp_bin;
	uint16_t replid;
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (pstore->b_private) {
		tmp_bin.cb = 0;
		tmp_bin.pv = &tmp_entryid.provider_uid;
		rop_util_guid_to_binary(pstore->mailbox_guid, &tmp_bin);
		tmp_entryid.folder_database_guid = rop_util_make_user_guid(pstore->account_id);
		tmp_entryid.message_type = EITLT_PRIVATE_MESSAGE;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		replid = rop_util_get_replid(folder_id);
		if (1 != replid) {
			if (!exmdb_client::get_mapping_guid(pstore->get_dir(),
			    replid, &b_found, &tmp_entryid.folder_database_guid))
				return NULL;	
			if (!b_found)
				return NULL;
		} else {
			tmp_entryid.folder_database_guid = rop_util_make_domain_guid(pstore->account_id);
		}
		tmp_entryid.message_type = EITLT_PUBLIC_MESSAGE;
	}
	tmp_entryid.message_database_guid = tmp_entryid.folder_database_guid;
	tmp_entryid.folder_global_counter = rop_util_get_gc_array(folder_id);
	tmp_entryid.message_global_counter = rop_util_get_gc_array(message_id);
	tmp_entryid.pad1[0] = 0;
	tmp_entryid.pad1[1] = 0;
	tmp_entryid.pad2[0] = 0;
	tmp_entryid.pad2[1] = 0;
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 256, 0) ||
	    ext_push.p_msg_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

int cu_calc_msg_access(store_object *pstore, const char *user,
    uint64_t folder_id, uint64_t message_id, uint32_t &tag_access)
{
	BOOL b_owner = false;
	uint32_t permission = 0;

	tag_access = 0;
	if (pstore->owner_mode()) {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		goto PERMISSION_CHECK;
	}
	if (!exmdb_client::check_folder_permission(pstore->get_dir(),
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
	return 0;
}

BINARY *common_util_calculate_message_sourcekey(store_object *pstore,
    uint64_t message_id)
{
	EXT_PUSH ext_push;
	LONG_TERM_ID longid;
	
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
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
	if (NULL == pbin) {
		return NULL;
	}
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
	
	if (pbin->cb < 17 || pbin->cb > 24) {
		return FALSE;
	}
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	return ext_pull.g_xid(pbin->cb, pxid) == EXT_ERR_SUCCESS ? TRUE : false;
}

BINARY* common_util_guid_to_binary(GUID guid)
{
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
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
	if (NULL == pbin) {
		return NULL;
	}
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
	if (NULL == ptmp_bin) {
		return NULL;
	}
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
	if (-1 == fd) {
		return FALSE;
	}
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

static BOOL common_util_send_command(int sockd,
	const char *command, int command_len)
{
	int write_len;

	write_len = write(sockd, command, command_len);
    if (write_len != command_len) {
		return FALSE;
	}
	return TRUE;
}

static int common_util_get_response(int sockd,
	char *response, int response_len, BOOL expect_3xx)
{
	int read_len;

	memset(response, 0, response_len);
	read_len = read(sockd, response, response_len);
	if (-1 == read_len || 0 == read_len) {
		return SMTP_TIME_OUT;
	}
	if ('\n' == response[read_len - 1] && '\r' == response[read_len - 2]){
		/* remove /r/n at the end of response */
		read_len -= 2;
	}
	response[read_len] = '\0';
	if (!expect_3xx && response[0] == '2' &&
	    HX_isdigit(response[1]) && HX_isdigit(response[2]))
		return SMTP_SEND_OK;
	else if (expect_3xx && response[0] == '3' &&
	    HX_isdigit(response[1]) && HX_isdigit(response[2]))
		return SMTP_SEND_OK;
	else if (response[0] == '4')
		return SMTP_TEMP_ERROR;
	else if (response[0] == '5')
		return SMTP_PERMANENT_ERROR;
	return SMTP_UNKOWN_RESPONSE;
}

static void log_err(const char *format, ...)
{
	va_list ap;
	char log_buf[2048];
	
	auto pinfo = zarafa_server_get_info();
	if (NULL == pinfo) {
		return;
	}
	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	system_services_log_info(LV_ERR, "user=%s  %s", pinfo->get_username(), log_buf);
}

static BOOL cu_send_mail(MAIL *pmail, const char *sender,
    const std::vector<std::string> &rcpt_list)
{
	int res_val;
	int command_len;
	char last_command[1024];
	char last_response[1024];
	
	MAIL dot_encoded(pmail->pmime_pool);
	if (pmail->check_dot()) {
		if (!pmail->transfer_dot(&dot_encoded, true))
			return false;
		pmail = &dot_encoded;
	}
	int sockd = gx_inet_connect(g_smtp_ip, g_smtp_port, 0);
	if (sockd < 0) {
		log_err("Cannot connect to SMTP server [%s]:%hu: %s",
			g_smtp_ip, g_smtp_port, strerror(-sockd));
		return FALSE;
	}
	/* read welcome information of MTA */
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		log_err("Timeout with SMTP server [%s]:%hu",
			g_smtp_ip, g_smtp_port);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        /* send quit command to server */
        common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		log_err("Failed to connect to SMTP. "
			"Server response is \"%s\".", last_response);
		return FALSE;
	}

	/* send helo xxx to server */
	snprintf(last_command, 1024, "helo %s\r\n", g_hostname);
	command_len = strlen(last_command);
	if (!common_util_send_command(sockd, last_command, command_len)) {
		close(sockd);
		log_err("Failed to send \"HELO\" command");
		return FALSE;
	}
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		log_err("Timeout with SMTP server [%s]:%hu", g_smtp_ip, g_smtp_port);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		/* send quit command to server */
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		log_err("SMTP server responded \"%s\" "
			"after sending \"HELO\" command", last_response);
		return FALSE;
	}

	command_len = sprintf(last_command, "mail from:<%s>\r\n", sender);
	if (!common_util_send_command(sockd, last_command, command_len)) {
		close(sockd);
		log_err("Failed to send \"MAIL FROM\" command");
		return FALSE;
	}
	/* read mail from response information */
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		log_err("Timeout with SMTP server [%s]:%hu", g_smtp_ip, g_smtp_port);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
		/* send quit command to server */
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		log_err("SMTP server responded \"%s\" "
			"after sending \"MAIL FROM\" command", last_response);
		return FALSE;
	}

	for (const auto &eaddr : rcpt_list) {
		auto have_at = strchr(eaddr.c_str(), '@') != nullptr;
		command_len = sprintf(last_command, have_at ? "rcpt to:<%s>\r\n" :
		              "rcpt to:<%s@none>\r\n", eaddr.c_str());
		if (!common_util_send_command(sockd, last_command, command_len)) {
			close(sockd);
			log_err("Failed to send \"RCPT TO\" command");
			return FALSE;
		}
		/* read rcpt to response information */
		res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
		switch (res_val) {
		case SMTP_TIME_OUT:
			close(sockd);
			log_err("Timeout with SMTP server [%s]:%hu", g_smtp_ip, g_smtp_port);
			return FALSE;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			common_util_send_command(sockd, "quit\r\n", 6);
			close(sockd);
			log_err("SMTP server responded \"%s\" "
				"after sending \"RCPT TO\" command", last_response);
			return FALSE;
		}		
	}
	/* send data */
	strcpy(last_command, "data\r\n");
	command_len = strlen(last_command);
	if (!common_util_send_command(sockd, last_command, command_len)) {
		close(sockd);
		log_err("Sender %s: failed to send \"DATA\" command", sender);
		return FALSE;
	}

	/* read data response information */
	res_val = common_util_get_response(sockd, last_response, 1024, TRUE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		log_err("Sender %s: Timeout with SMTP server [%s]:%hu",
			sender, g_smtp_ip, g_smtp_port);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		log_err("Sender %s: SMTP server responded \"%s\" "
				"after sending \"data\" command", sender, last_response);
		return FALSE;
	}

	pmail->set_header("X-Mailer", "gromox-zcore " PACKAGE_VERSION);
	if (!pmail->to_file(sockd) ||
	    !common_util_send_command(sockd, ".\r\n", 3)) {
		close(sockd);
		log_err("Sender %s: Failed to send mail content", sender);
		return FALSE;
	}
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		log_err("Sender %s: Timeout with SMTP server [%s]:%hu", sender, g_smtp_ip, g_smtp_port);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:	
        common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		log_err("Sender %s: SMTP server responded \"%s\" "
					"after sending mail content", sender, last_response);
		return FALSE;
	case SMTP_SEND_OK:
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		log_err("outgoing SMTP [%s]:%hu: from=<%s> OK",
		        g_smtp_ip, g_smtp_port, sender);
		return TRUE;
	}
	return false;
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
	if (!exmdb_client::get_named_propnames(
		common_util_get_dir(), &propids, &propnames)) {
		return FALSE;
	}
	*pppropname = propnames.count != 1 ? nullptr : propnames.ppropname;
	return TRUE;
}

BOOL common_util_send_message(store_object *pstore,
	uint64_t message_id, BOOL b_submit)
{
	void *pvalue;
	BOOL b_result;
	EID_ARRAY ids;
	BOOL b_private;
	BOOL b_partial;
	int account_id;
	uint64_t new_id;
	uint64_t parent_id;
	uint64_t folder_id;
	TARRAY_SET *prcpts;
	TAGGED_PROPVAL *ppropval;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zarafa_server_get_info();
	uint32_t cpid = pinfo == nullptr ? 1252 : pinfo->cpid;
	if (!exmdb_client_get_message_property(pstore->get_dir(), nullptr, 0,
	    message_id, PidTagParentFolderId, &pvalue) || pvalue == nullptr)
		return FALSE;
	parent_id = *(uint64_t*)pvalue;
	if (!exmdb_client::read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	if (!pmsgctnt->proplist.has(PR_INTERNET_CPID)) {
		ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 1);
		if (NULL == ppropval) {
			return FALSE;
		}
		memcpy(ppropval, pmsgctnt->proplist.ppropval,
			sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
		ppropval[pmsgctnt->proplist.count].proptag = PR_INTERNET_CPID;
		ppropval[pmsgctnt->proplist.count++].pvalue = &cpid;
		pmsgctnt->proplist.ppropval = ppropval;
	}
	auto num = pmsgctnt->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (num == nullptr)
		return FALSE;
	BOOL b_resend = (*num & MSGFLAG_RESEND) ? TRUE : false;
	prcpts = pmsgctnt->children.prcpts;
	if (NULL == prcpts) {
		return FALSE;
	}
	if (prcpts->count == 0)
		fprintf(stderr, "I-1504: Store %s attempted to send message %llxh to 0 recipients\n",
		        pstore->get_account(), static_cast<unsigned long long>(message_id));

	std::vector<std::string> rcpt_list;
	for (size_t i = 0; i < prcpts->count; ++i) {
		if (b_resend) {
			auto rcpttype = prcpts->pparray[i]->get<const uint32_t>(PR_RECIPIENT_TYPE);
			if (rcpttype == nullptr)
				return FALSE;
			if (!(*rcpttype & MAPI_P1))
				continue;	
		}
		/*
		if (!b_submit) {
			auto resp = prcpts->pparray[i]->get<const uint32_t>(PR_RESPONSIBILITY);
			if (resp == nullptr || *resp != 0)
				continue;
		}
		*/
		auto str = prcpts->pparray[i]->get<const char>(PR_SMTP_ADDRESS);
		if (str != nullptr && *str != '\0') {
			rcpt_list.emplace_back(str);
			continue;
		}
		auto addrtype = prcpts->pparray[i]->get<const char>(PR_ADDRTYPE);
		if (addrtype == nullptr) {
 CONVERT_ENTRYID:
			auto entryid = prcpts->pparray[i]->get<const BINARY>(PR_ENTRYID);
			if (entryid == nullptr)
				return FALSE;
			char username[UADDR_SIZE];
			if (!common_util_entryid_to_username(entryid,
			    username, std::size(username)))
				return FALSE;	
		} else if (strcasecmp(addrtype, "SMTP") == 0) {
			str = prcpts->pparray[i]->get<char>(PR_EMAIL_ADDRESS);
			if (str == nullptr)
				return FALSE;
			rcpt_list.emplace_back(str);
		} else if (strcasecmp(addrtype, "EX") == 0) {
			auto emaddr = prcpts->pparray[i]->get<const char>(PR_EMAIL_ADDRESS);
			if (emaddr == nullptr)
				goto CONVERT_ENTRYID;
			char username[UADDR_SIZE];
			if (!common_util_essdn_to_username(emaddr,
			    username, std::size(username)))
				goto CONVERT_ENTRYID;
			rcpt_list.emplace_back(username);
		} else {
			goto CONVERT_ENTRYID;
		}
	}
	if (rcpt_list.size() > 0) {
		auto body_type = get_override_format(*pmsgctnt);
		common_util_set_dir(pstore->get_dir());
		/* try to avoid TNEF message */
		MAIL imail;
		if (!oxcmail_export(pmsgctnt, false, body_type, g_mime_pool,
		    &imail, common_util_alloc, common_util_get_propids,
		    common_util_get_propname))
			return FALSE;	
		if (!cu_send_mail(&imail, pstore->get_account(), rcpt_list))
			return FALSE;
	}
	auto flag = pmsgctnt->proplist.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagSentMailSvrEID);
	auto ptarget = pmsgctnt->proplist.get<BINARY>(PR_TARGET_ENTRYID);
	if (NULL != ptarget) {
		if (!common_util_from_message_entryid(*ptarget,
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
	if (ptarget == nullptr || !common_util_from_folder_entryid(*ptarget,
	    &b_private, &account_id, &folder_id))
		folder_id = rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS);
	return exmdb_client::movecopy_messages(pstore->get_dir(),
	       pstore->account_id, cpid, false, nullptr, parent_id, folder_id,
		FALSE, &ids, &b_partial);
}

void common_util_notify_receipt(const char *username, int type,
    MESSAGE_CONTENT *pbrief) try
{
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str == nullptr)
		return;
	std::vector<std::string> rcpt_list = {str};
	MAIL imail(g_mime_pool);
	int bounce_type = type == NOTIFY_RECEIPT_READ ? BOUNCE_NOTIFY_READ : BOUNCE_NOTIFY_NON_READ;
	if (!bounce_producer_make(username, pbrief, bounce_type, &imail))
		return;
	cu_send_mail(&imail, username, rcpt_list);
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2038: ENOMEM\n");
}

static MOVECOPY_ACTION* common_util_convert_from_zmovecopy(
	ZMOVECOPY_ACTION *pmovecopy)
{
	int db_id;
	int user_id;
	BOOL b_private;
	SVREID *psvreid;
	EXT_PULL ext_pull;
	
	auto pmovecopy1 = cu_alloc<MOVECOPY_ACTION>();
	if (NULL == pmovecopy1) {
		return NULL;
	}
	auto pstore_entryid = cu_alloc<STORE_ENTRYID>();
	if (NULL == pstore_entryid) {
		return NULL;
	}
	ext_pull.init(pmovecopy->store_eid.pb, pmovecopy->store_eid.cb,
		common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_store_eid(pstore_entryid) != EXT_ERR_SUCCESS)
		return NULL;
	if (!common_util_essdn_to_uid(pstore_entryid->pmailbox_dn, &user_id))
		return NULL;	
	auto pinfo = zarafa_server_get_info();
	if (user_id != pinfo->user_id) {
		pmovecopy1->same_store = 0;
		pmovecopy1->pstore_eid = pstore_entryid;
		pmovecopy1->pfolder_eid = &pmovecopy->folder_eid;
	} else {
		pmovecopy1->same_store = 1;
		pmovecopy1->pstore_eid = NULL;
		psvreid = cu_alloc<SVREID>();
		if (NULL == psvreid) {
			return NULL;
		}
		psvreid->pbin = NULL;
		if (!common_util_from_folder_entryid(pmovecopy->folder_eid,
		    &b_private, &db_id, &psvreid->folder_id))
			return NULL;	
		psvreid->message_id = 0;
		psvreid->instance = 0;
		pmovecopy1->pfolder_eid = psvreid;
	}
	return pmovecopy1;
}

static REPLY_ACTION* common_util_convert_from_zreply(ZREPLY_ACTION *preply)
{
	int db_id;
	BOOL b_private;
	
	auto preply1 = cu_alloc<REPLY_ACTION>();
	if (NULL == preply1) {
		return NULL;
	}
	if (!common_util_from_message_entryid(preply->message_eid, &b_private,
	    &db_id, &preply1->template_folder_id, &preply1->template_message_id))
		return NULL;	
	preply1->template_guid = preply->template_guid;
	return preply1;
}

BOOL common_util_convert_from_zrule(TPROPVAL_ARRAY *ppropvals)
{
	int i;
	
	auto pactions = ppropvals->get<RULE_ACTIONS>(PR_RULE_ACTIONS);
	if (pactions == nullptr)
		return TRUE;
	for (i=0; i<pactions->count; i++) {
		switch (pactions->pblock[i].type) {
		case OP_MOVE:
		case OP_COPY:
			pactions->pblock[i].pdata =
				common_util_convert_from_zmovecopy(
				static_cast<ZMOVECOPY_ACTION *>(pactions->pblock[i].pdata));
			if (NULL == pactions->pblock[i].pdata) {
				return FALSE;
			}
			break;
		case OP_REPLY:
		case OP_OOF_REPLY:
			pactions->pblock[i].pdata =
				common_util_convert_from_zreply(
				static_cast<ZREPLY_ACTION *>(pactions->pblock[i].pdata));
			if (NULL == pactions->pblock[i].pdata) {
				return FALSE;
			}
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
	if (pstore->b_private) {
		store_entryid.wrapped_provider_uid = g_muidStorePrivate;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_TAKE_OWNERSHIP;
		store_entryid.pserver_name = deconst(pstore->get_account());
		if (!common_util_username_to_essdn(pstore->get_account(),
		    tmp_buff, GX_ARRAY_SIZE(tmp_buff)))
			return NULL;	
	} else {
		store_entryid.wrapped_provider_uid = g_muidStorePublic;
		store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_PUBLIC;
		store_entryid.pserver_name = g_hostname;
		auto pinfo = zarafa_server_get_info();
		if (!common_util_username_to_essdn(pinfo->get_username(),
		    tmp_buff, arsizeof(tmp_buff)))
			return NULL;	
	}
	store_entryid.pmailbox_dn = tmp_buff;
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(1024);
	if (pbin->pb == nullptr ||
	    !ext_push.init(pbin->pv, 1024, EXT_FLAG_UTF16) ||
	    ext_push.p_store_eid(store_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

static ZMOVECOPY_ACTION *common_util_convert_to_zmovecopy(store_object *pstore,
    MOVECOPY_ACTION *pmovecopy)
{
	BINARY *pbin;
	EXT_PUSH ext_push;
	
	auto pmovecopy1 = cu_alloc<ZMOVECOPY_ACTION>();
	if (NULL == pmovecopy1) {
		return NULL;
	}
	if (0 == pmovecopy->same_store) {
		pmovecopy1->store_eid.pv = common_util_alloc(1024);
		if (pmovecopy1->store_eid.pv == nullptr ||
		    !ext_push.init(pmovecopy1->store_eid.pv, 1024, EXT_FLAG_UTF16) ||
		    ext_push.p_store_eid(*pmovecopy->pstore_eid) != EXT_ERR_SUCCESS)
			return NULL;	
		pmovecopy1->store_eid.cb = ext_push.m_offset;
		pmovecopy1->folder_eid = *(BINARY*)pmovecopy->pfolder_eid;
	} else {
		pbin = common_util_to_store_entryid(pstore);
		if (NULL == pbin) {
			return NULL;
		}
		pmovecopy1->store_eid = *pbin;
		pbin = common_util_to_folder_entryid(
			pstore, ((SVREID*)pmovecopy->pfolder_eid)->folder_id);
		if (NULL == pbin) {
			return NULL;
		}
		pmovecopy1->folder_eid = *pbin;
	}
	return pmovecopy1;
}

static ZREPLY_ACTION *common_util_convert_to_zreply(store_object *pstore,
    REPLY_ACTION *preply)
{
	auto preply1 = cu_alloc<ZREPLY_ACTION>();
	if (NULL == preply1) {
		return NULL;
	}
	if (common_util_to_message_entryid(pstore, preply->template_folder_id,
	    preply->template_message_id) == nullptr)
		return NULL;	
	preply1->template_guid = preply->template_guid;
	return preply1;
}

BOOL common_util_convert_to_zrule_data(store_object *pstore, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	
	auto pactions = ppropvals->get<RULE_ACTIONS>(PR_RULE_ACTIONS);
	if (pactions == nullptr)
		return TRUE;
	for (i=0; i<pactions->count; i++) {
		switch (pactions->pblock[i].type) {
		case OP_MOVE:
		case OP_COPY:
			pactions->pblock[i].pdata =
				common_util_convert_to_zmovecopy(
				pstore, static_cast<MOVECOPY_ACTION *>(pactions->pblock[i].pdata));
			if (NULL == pactions->pblock[i].pdata) {
				return FALSE;
			}
			break;
		case OP_REPLY:
		case OP_OOF_REPLY:
			pactions->pblock[i].pdata =
				common_util_convert_to_zreply(
				pstore, static_cast<REPLY_ACTION *>(pactions->pblock[i].pdata));
			if (NULL == pactions->pblock[i].pdata) {
				return FALSE;
			}
			break;
		}
	}
	return TRUE;
}

gxerr_t common_util_remote_copy_message(store_object *pstore,
    uint64_t message_id, store_object *pstore1, uint64_t folder_id1)
{
	uint64_t change_num;
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zarafa_server_get_info();
	auto username = pstore->b_private ? nullptr : pinfo->get_username();
	if (!exmdb_client::read_message(pstore->get_dir(), username,
	    pinfo->cpid, message_id, &pmsgctnt))
		return GXERR_CALL_FAILED;
	if (NULL == pmsgctnt) {
		return GXERR_SUCCESS;
	}
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
	if (!exmdb_client::allocate_cn(pstore->get_dir(), &change_num))
		return GXERR_CALL_FAILED;
	propval.proptag = PidTagChangeNumber;
	propval.pvalue = &change_num;
	common_util_set_propvals(&pmsgctnt->proplist, &propval);
	auto pbin = cu_xid_to_bin({pstore->guid(), change_num});
	if (NULL == pbin) {
		return GXERR_CALL_FAILED;
	}
	propval.proptag = PR_CHANGE_KEY;
	propval.pvalue = pbin;
	common_util_set_propvals(&pmsgctnt->proplist, &propval);
	auto pbin1 = pmsgctnt->proplist.get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval.pvalue = common_util_pcl_append(pbin1, pbin);
	if (NULL == propval.pvalue) {
		return GXERR_CALL_FAILED;
	}
	common_util_set_propvals(&pmsgctnt->proplist, &propval);
	gxerr_t e_result = GXERR_CALL_FAILED;
	if (!exmdb_client::write_message(pstore1->get_dir(),
	    pstore1->get_account(), pinfo->cpid, folder_id1,
	    pmsgctnt, &e_result) || e_result != GXERR_SUCCESS)
		return e_result;
	return GXERR_SUCCESS;
}

static BOOL common_util_create_folder(store_object *pstore, uint64_t parent_id,
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
		return FALSE;
	propval.proptag = PR_FOLDER_TYPE;
	propval.pvalue = &tmp_type;
	tmp_type = FOLDER_GENERIC;
	common_util_set_propvals(pproplist, &propval);
	propval.proptag = PidTagParentFolderId;
	propval.pvalue = &parent_id;
	common_util_set_propvals(pproplist, &propval);
	if (!exmdb_client::allocate_cn(pstore->get_dir(), &change_num))
		return FALSE;
	propval.proptag = PidTagChangeNumber;
	propval.pvalue = &change_num;
	common_util_set_propvals(pproplist, &propval);
	auto pbin = cu_xid_to_bin({pstore->guid(), change_num});
	if (NULL == pbin) {
		return FALSE;
	}
	propval.proptag = PR_CHANGE_KEY;
	propval.pvalue = pbin;
	common_util_set_propvals(pproplist, &propval);
	auto pbin1 = pproplist->get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval.pvalue = common_util_pcl_append(pbin1, pbin);
	if (NULL == propval.pvalue) {
		return FALSE;
	}
	common_util_set_propvals(pproplist, &propval);
	auto pinfo = zarafa_server_get_info();
	if (!exmdb_client::create_folder_by_properties(pstore->get_dir(),
	    pinfo->cpid, pproplist, pfolder_id) || *pfolder_id == 0)
		return FALSE;
	if (pstore->owner_mode())
		return TRUE;
	pentryid = common_util_username_to_addressbook_entryid(pinfo->get_username());
	if (pentryid == nullptr)
		return TRUE;
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
	return TRUE;
}

static EID_ARRAY *common_util_load_folder_messages(store_object *pstore,
    uint64_t folder_id, const char *username)
{
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	PROPTAG_ARRAY proptags;
	EID_ARRAY *pmessage_ids;
	
	if (!exmdb_client::load_content_table(pstore->get_dir(), 0, folder_id,
	    username, TABLE_FLAG_NONOTIFICATIONS,
	    nullptr, nullptr, &table_id, &row_count))
		return NULL;	
	uint32_t tmp_proptag = PidTagMid;
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	if (!exmdb_client::query_table(pstore->get_dir(), nullptr, 0, table_id,
	    &proptags, 0, row_count, &tmp_set))
		return NULL;	
	exmdb_client::unload_table(pstore->get_dir(), table_id);
	pmessage_ids = cu_alloc<EID_ARRAY>();
	if (NULL == pmessage_ids) {
		return NULL;
	}
	pmessage_ids->count = 0;
	pmessage_ids->pids = cu_alloc<uint64_t>(tmp_set.count);
	if (NULL == pmessage_ids->pids) {
		return NULL;
	}
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto pmid = tmp_set.pparray[i]->get<uint64_t>(PidTagMid);
		if (NULL == pmid) {
			return NULL;
		}
		pmessage_ids->pids[pmessage_ids->count++] = *pmid;
	}
	return pmessage_ids;
}

gxerr_t common_util_remote_copy_folder(store_object *pstore, uint64_t folder_id,
    store_object *pstore1, uint64_t folder_id1, const char *new_name)
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
	
	if (!exmdb_client::get_folder_all_proptags(pstore->get_dir(),
	    folder_id, &tmp_proptags))
		return GXERR_CALL_FAILED;
	if (!exmdb_client::get_folder_properties(pstore->get_dir(), 0,
	    folder_id, &tmp_proptags, &tmp_propvals))
		return GXERR_CALL_FAILED;
	if (NULL != new_name) {
		propval.proptag = PR_DISPLAY_NAME;
		propval.pvalue = deconst(new_name);
		common_util_set_propvals(&tmp_propvals, &propval);
	}
	if (!common_util_create_folder(pstore1, folder_id1, &tmp_propvals, &new_fid))
		return GXERR_CALL_FAILED;
	auto pinfo = zarafa_server_get_info();
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		username = pinfo->get_username();
		if (!exmdb_client::check_folder_permission(pstore->get_dir(),
		    folder_id, username, &permission))
			return GXERR_CALL_FAILED;
		if (!(permission & (frightsReadAny | frightsOwner)))
			return GXERR_CALL_FAILED;
	}
	pmessage_ids = common_util_load_folder_messages(
						pstore, folder_id, username);
	if (NULL == pmessage_ids) {
		return GXERR_CALL_FAILED;
	}
	for (size_t i = 0; i < pmessage_ids->count; ++i) {
		gxerr_t err = common_util_remote_copy_message(pstore,
		              pmessage_ids->pids[i], pstore1, new_fid);
		if (err != GXERR_SUCCESS)
			return err;
	}
	username = pstore->owner_mode() ? nullptr : pinfo->get_username();
	if (!exmdb_client::load_hierarchy_table(pstore->get_dir(), folder_id,
	    username, TABLE_FLAG_NONOTIFICATIONS, nullptr,
	    &table_id, &row_count))
		return GXERR_CALL_FAILED;
	uint32_t tmp_proptag = PidTagFolderId;
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &tmp_proptag;
	if (!exmdb_client::query_table(pstore->get_dir(), nullptr, 0, table_id,
	    &tmp_proptags, 0, row_count, &tmp_set))
		return GXERR_CALL_FAILED;
	exmdb_client::unload_table(pstore->get_dir(), table_id);
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto pfolder_id = tmp_set.pparray[i]->get<uint64_t>(PidTagFolderId);
		if (NULL == pfolder_id) {
			return GXERR_CALL_FAILED;
		}
		gxerr_t err = common_util_remote_copy_folder(pstore,
		              *pfolder_id, pstore1, new_fid, nullptr);
		if (err != GXERR_SUCCESS)
			return err;
	}
	return GXERR_SUCCESS;
}

BOOL common_util_message_to_rfc822(store_object *pstore,
	uint64_t message_id, BINARY *peml_bin)
{
	int size;
	void *ptr;
	void *pvalue;
	TAGGED_PROPVAL *ppropval;
	MESSAGE_CONTENT *pmsgctnt;
	
	if (exmdb_client_get_message_property(pstore->get_dir(), nullptr, 0,
	    message_id, PidTagMidString, &pvalue) && pvalue != nullptr) try {
		auto eml_path = pstore->get_dir() + "/eml/"s +
		                static_cast<const char *>(pvalue);
		return common_util_load_file(eml_path.c_str(), peml_bin);
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1495: ENOMEM\n");
		return false;
	}
	auto pinfo = zarafa_server_get_info();
	uint32_t cpid = pinfo == nullptr ? 1252 : pinfo->cpid;
	if (!exmdb_client::read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	if (!pmsgctnt->proplist.has(PR_INTERNET_CPID)) {
		ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 1);
		if (NULL == ppropval) {
			return FALSE;
		}
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
	if (!oxcmail_export(pmsgctnt, false, body_type, g_mime_pool, &imail,
	    common_util_alloc, common_util_get_propids, common_util_get_propname))
		return FALSE;	
	auto mail_len = imail.get_length();
	if (mail_len < 0) {
		return false;
	}
	alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1,
		"zcu_msgtorfc822", "(dynamic)");
	STREAM tmp_stream(&pallocator);
	if (!imail.serialize(&tmp_stream)) {
		return FALSE;
	}
	imail.clear();
	peml_bin->pv = common_util_alloc(mail_len + 128);
	if (peml_bin->pv == nullptr) {
		return FALSE;
	}

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
	auto ctbuf = std::make_unique<char[]>(len);
	if (!part->read_head(ctbuf.get(), &len))
		return;
	size_t written_so_far = len;
	len = partlen - len;
	if (!part->read_content(&ctbuf[written_so_far], &len))
		return;
	written_so_far += len;
	MAIL m2(g_mime_pool);
	if (!m2.retrieve(ctbuf.get(), written_so_far))
		return;
	ma = std::move(m2);
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1996: ENOMEM\n");
}

MESSAGE_CONTENT *cu_rfc822_to_message(store_object *pstore,
    unsigned int mxf_flags, const BINARY *peml_bin)
{
	char charset[32], tmzone[64];
	
	auto pinfo = zarafa_server_get_info();
	MAIL imail(g_mime_pool);
	if (!imail.retrieve(peml_bin->pc, peml_bin->cb))
		return NULL;
	if (mxf_flags & MXF_UNWRAP_SMIME_CLEARSIGNED)
		zc_unwrap_smime(imail);
	if (!system_services_lang_to_charset(pinfo->get_lang(), charset) ||
	    charset[0] == '\0')
		strcpy(charset, g_default_charset);
	if (!system_services_get_timezone(pinfo->get_username(), tmzone,
	    arsizeof(tmzone)) || tmzone[0] == '\0')
		strcpy(tmzone, common_util_get_default_timezone());
	common_util_set_dir(pstore->get_dir());
	auto pmsgctnt = oxcmail_import(charset, tmzone, &imail,
	                common_util_alloc, common_util_get_propids_create);
	return pmsgctnt;
}

BOOL common_util_message_to_ical(store_object *pstore,
	uint64_t message_id, BINARY *pical_bin)
{
	ICAL ical;
	char tmp_buff[1024*1024];
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zarafa_server_get_info();
	uint32_t cpid = pinfo == nullptr ? 1252 : pinfo->cpid;
	if (!exmdb_client::read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	if (ical.init() < 0)
		return false;
	common_util_set_dir(pstore->get_dir());
	if (!oxcical_export(pmsgctnt, &ical,
		common_util_alloc, common_util_get_propids,
		common_util_entryid_to_username_internal,
		common_util_essdn_to_username))
		return FALSE;
	if (!ical.serialize(tmp_buff, arsizeof(tmp_buff)))
		return FALSE;	
	pical_bin->cb = strlen(tmp_buff);
	pical_bin->pc = common_util_dup(tmp_buff);
	return pical_bin->pc != nullptr ? TRUE : FALSE;
}

message_ptr cu_ical_to_message(store_object *pstore, const BINARY *pical_bin)
{
	ICAL ical;
	char tmzone[64];
	
	auto pinfo = zarafa_server_get_info();
	if (!system_services_get_timezone(pinfo->get_username(), tmzone,
	    arsizeof(tmzone)) || tmzone[0] == '\0')
		strcpy(tmzone, common_util_get_default_timezone());
	auto pbuff = cu_alloc<char>(pical_bin->cb + 1);
	if (NULL == pbuff) {
		return nullptr;
	}
	memcpy(pbuff, pical_bin->pb, pical_bin->cb);
	pbuff[pical_bin->cb] = '\0';
	if (ical.init() < 0 || !ical.retrieve(pbuff))
		return NULL;
	common_util_set_dir(pstore->get_dir());
	return oxcical_import_single(tmzone, &ical, common_util_alloc,
	       common_util_get_propids_create, common_util_username_to_entryid);
}

ec_error_t cu_ical_to_message2(store_object *store, char *ical_data,
    std::vector<message_ptr> &msgvec)
{
	auto info = zarafa_server_get_info();
	char tmzone[64];
	if (!system_services_get_timezone(info->get_username(), tmzone,
	    arsizeof(tmzone)) || tmzone[0] == '\0')
		gx_strlcpy(tmzone, common_util_get_default_timezone(), std::size(tmzone));

	ICAL icobj;
	if (icobj.init() < 0 || !icobj.retrieve(ical_data))
		return ecError;
	common_util_set_dir(store->get_dir());
	return oxcical_import_multi(tmzone, &icobj, common_util_alloc,
	       common_util_get_propids_create,
	       common_util_username_to_entryid, msgvec);
}

BOOL common_util_message_to_vcf(message_object *pmessage, BINARY *pvcf_bin)
{
	auto pstore = pmessage->get_store();
	auto message_id = pmessage->get_id();
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zarafa_server_get_info();
	uint32_t cpid = pinfo == nullptr ? 1252 : pinfo->cpid;
	if (!exmdb_client::read_message(pstore->get_dir(), nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return FALSE;
	common_util_set_dir(pstore->get_dir());
	vcard vcard;
	if (!oxvcard_export(pmsgctnt, vcard, common_util_get_propids))
		return FALSE;
	pvcf_bin->pv = common_util_alloc(VCARD_MAX_BUFFER_LEN);
	if (pvcf_bin->pv == nullptr) {
		return FALSE;
	}
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
	if (NULL == pbuff) {
		return nullptr;
	}
	memcpy(pbuff, pvcf_bin->pb, pvcf_bin->cb);
	pbuff[pvcf_bin->cb] = '\0';
	vcard vcard;
	auto ret = vcard.retrieve_single(pbuff);
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
	auto ret = vcard_retrieve_multi(vcf_data, cardvec);
	if (ret != ecSuccess)
		return ret;
	common_util_set_dir(store->get_dir());
	msgvec.reserve(msgvec.size() + cardvec.size());
	for (const auto &vcard : cardvec) {
		message_ptr mc(oxvcard_import(&vcard, common_util_get_propids_create));
		if (mc == nullptr)
			return ecError;
		msgvec.push_back(std::move(mc));
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2048: ENOMEM\n");
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
