// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iconv.h>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/mime_pool.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/proc_common.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/socket.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "logon_object.h"

using namespace gromox;

enum {
	SMTP_SEND_OK = 0,
	SMTP_CANNOT_CONNECT,
	SMTP_CONNECT_ERROR,
	SMTP_TIME_OUT,
	SMTP_TEMP_ERROR,
	SMTP_UNKOWN_RESPONSE,
	SMTP_PERMANENT_ERROR
};

unsigned int g_max_rcpt, g_max_message, g_max_mail_len;
unsigned int g_max_rule_len, g_max_extrule_len;
static uint16_t g_smtp_port;
static char g_smtp_ip[40], g_emsmdb_org_name[256];
static int g_average_blocks;
static std::shared_ptr<MIME_POOL> g_mime_pool;
static thread_local const char *g_dir_key;
static char g_submit_command[1024];
static alloc_limiter<file_block> g_file_allocator{"emsmdb.g_file_allocator.d"};

#define E(s) decltype(common_util_ ## s) common_util_ ## s;
E(get_maildir)
E(get_homedir)
E(get_user_displayname)
E(check_mlist_include)
E(get_user_lang)
E(get_timezone)
E(get_username_from_id)
E(get_id_from_username)
E(get_user_ids)
E(get_domain_ids)
E(check_same_org)
E(get_homedir_by_id)
E(get_id_from_maildir)
E(get_id_from_homedir)
E(add_timer)
E(cancel_timer)
#undef E

static void mlog2(unsigned int level, const char *format, ...) __attribute__((format(printf, 2, 3)));

void* common_util_alloc(size_t size)
{
	return ndr_stack_alloc(NDR_STACK_IN, size);
}

ssize_t common_util_mb_from_utf8(uint32_t cpid, const char *src,
    char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	char temp_charset[256];
	
	auto charset = cpid_to_cset(cpid);
	if (NULL == charset) {
		return -1;
	}
	sprintf(temp_charset, "%s//IGNORE",
		replace_iconv_charset(charset));
	conv_id = iconv_open(temp_charset, "UTF-8");
	if (conv_id == (iconv_t)-1)
		return -1;
	auto pin = deconst(src);
	auto pout = dst;
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	iconv(conv_id, &pin, &in_len, &pout, &len);
	iconv_close(conv_id);
	return out_len - len;
}

ssize_t common_util_mb_to_utf8(uint32_t cpid, const char *src,
    char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;

	cpid_cstr_compatible(cpid);
	auto charset = cpid_to_cset(cpid);
	if (NULL == charset) {
		return -1;
	}
	conv_id = iconv_open("UTF-8//IGNORE",
		replace_iconv_charset(charset));
	if (conv_id == (iconv_t)-1)
		return -1;
	auto pin = deconst(src);
	auto pout = dst;
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	iconv(conv_id, &pin, &in_len, &pout, &len);	
	iconv_close(conv_id);
	return out_len - len;
}

static char* common_util_dup_mb_to_utf8(
	uint32_t cpid, const char *src)
{
	cpid_cstr_compatible(cpid);
	auto len = mb_to_utf8_len(src);
	auto pdst = cu_alloc<char>(len);
	if (NULL == pdst) {
		return NULL;
	}
	if (common_util_mb_to_utf8(cpid, src, pdst, len) < 0) {
		return NULL;
	}
	return pdst;
}

/* only for being invoked under rop environment */
ssize_t common_util_convert_string(bool to_utf8, const char *src,
    char *dst, size_t len)
{
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return -1;
	return to_utf8 ? common_util_mb_to_utf8(pinfo->cpid, src, dst, len) :
	       common_util_mb_from_utf8(pinfo->cpid, src, dst, len);
}

void common_util_obfuscate_data(uint8_t *data, uint32_t size)
{
	uint32_t i;

	for (i=0; i<size; i++) {
		data[i] ^= 0xA5;
	}
}

BOOL common_util_essdn_to_username(const char *pessdn,
    char *username, size_t ulen)
{
	char *pat;
	int user_id;
	const char *plocal;
	char tmp_essdn[1024];
	
	auto tmp_len = gx_snprintf(tmp_essdn, GX_ARRAY_SIZE(tmp_essdn),
			"/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=",
	               g_emsmdb_org_name);
	if (0 != strncasecmp(pessdn, tmp_essdn, tmp_len)) {
		return FALSE;
	}
	if ('-' != pessdn[tmp_len + 16]) {
		return FALSE;
	}
	plocal = pessdn + tmp_len + 17;
	user_id = decode_hex_int(pessdn + tmp_len + 8);
	if (!common_util_get_username_from_id(user_id, username, ulen))
		return FALSE;
	pat = strchr(username, '@');
	if (NULL == pat) {
		return FALSE;
	}
	if (0 != strncasecmp(username, plocal, pat - username)) {
		return FALSE;
	}
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
	*pdomain++ = '\0';
	if (!common_util_get_user_ids(username, &user_id, &domain_id, nullptr))
		return FALSE;
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, dnmax, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
		g_emsmdb_org_name, hex_string2, hex_string, tmp_name);
	HX_strupper(pessdn);
	return TRUE;
}

BOOL common_util_essdn_to_public(const char *pessdn, char *domainname)
{
	//TODO
	return FALSE;
}

BOOL common_util_public_to_essdn(const char *username, char *pessdn, size_t dnmax)
{
	//TODO
	return FALSE;
}

const char* common_util_essdn_to_domain(const char *pessdn)
{
	int tmp_len;
	char tmp_essdn[1024];
	
	tmp_len = sprintf(tmp_essdn,
		"/o=%s/ou=Exchange Administrative Group "
		"(FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn="
		"f98430ae-22ad-459a-afba-68c972eefc56@", g_emsmdb_org_name);
	if (0 != strncasecmp(pessdn, tmp_essdn, tmp_len)) {
		return NULL;
	}
	return pessdn + tmp_len;
}

void common_util_domain_to_essdn(const char *pdomain, char *pessdn, size_t dnmax)
{
	snprintf(pessdn, dnmax, "/o=%s/ou=Exchange Administrative Group "
		"(FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn="
		"f98430ae-22ad-459a-afba-68c972eefc56@%s", g_emsmdb_org_name, pdomain);
}

BOOL common_util_entryid_to_username(const BINARY *pbin,
    char *username, size_t ulen)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	FLATUID provider_uid;
	
	if (pbin->cb < 20) {
		return FALSE;
	}
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
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

void common_util_get_domain_server(const char *account_name, char *pserver)
{
	sprintf(pserver, "f98430ae-22ad-459a-afba-68c972eefc56@%s", account_name);
}

BINARY* common_util_username_to_addressbook_entryid(const char *username)
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
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(1280);
	if (pbin->pv == nullptr ||
	    !ext_push.init(pbin->pv, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BINARY* common_util_public_to_addressbook_entryid(const char *domainname)
{
	char x500dn[1024];
	EXT_PUSH ext_push;
	EMSAB_ENTRYID tmp_entryid;
	
	if (!common_util_public_to_essdn(domainname, x500dn, GX_ARRAY_SIZE(x500dn)))
		return NULL;
	tmp_entryid.flags = 0;
	tmp_entryid.version = 1;
	tmp_entryid.type = DT_MAILUSER;
	tmp_entryid.px500dn = x500dn;
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(1280);
	if (pbin->pv == nullptr ||
	    !ext_push.init(pbin->pv, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;	
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BINARY *cu_fid_to_entryid(logon_object *plogon, uint64_t folder_id)
{
	BOOL b_found;
	BINARY tmp_bin;
	uint16_t replid;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (plogon->is_private()) {
		tmp_bin.cb = 0;
		tmp_bin.pv = &tmp_entryid.provider_uid;
		rop_util_guid_to_binary(plogon->mailbox_guid, &tmp_bin);
		tmp_entryid.database_guid = rop_util_make_user_guid(plogon->account_id);
		tmp_entryid.folder_type = EITLT_PRIVATE_FOLDER;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		replid = rop_util_get_replid(folder_id);
		if (1 != replid) {
			if (!exmdb_client::get_mapping_guid(plogon->get_dir(),
			    replid, &b_found, &tmp_entryid.database_guid))
				return NULL;	
			if (!b_found)
				return NULL;
		} else {
			tmp_entryid.database_guid = rop_util_make_domain_guid(plogon->account_id);
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

BINARY *cu_fid_to_sk(logon_object *plogon, uint64_t folder_id)
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
	if (plogon->is_private()) {
		longid.guid = rop_util_make_user_guid(plogon->account_id);
	} else {
		replid = rop_util_get_replid(folder_id);
		if (1 == replid) {
			longid.guid = rop_util_make_domain_guid(plogon->account_id);
		} else {
			if (!exmdb_client::get_mapping_guid(plogon->get_dir(),
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

BINARY *cu_mid_to_entryid(logon_object *plogon,
	uint64_t folder_id, uint64_t message_id)
{
	BOOL b_found;
	BINARY tmp_bin;
	uint16_t replid;
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	if (plogon->is_private()) {
		tmp_bin.cb = 0;
		tmp_bin.pv = &tmp_entryid.provider_uid;
		rop_util_guid_to_binary(plogon->mailbox_guid, &tmp_bin);
		tmp_entryid.folder_database_guid = rop_util_make_user_guid(plogon->account_id);
		tmp_entryid.message_type = EITLT_PRIVATE_MESSAGE;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		replid = rop_util_get_replid(folder_id);
		if (1 != replid) {
			if (!exmdb_client::get_mapping_guid(plogon->get_dir(),
			    replid, &b_found, &tmp_entryid.folder_database_guid))
				return NULL;	
			if (!b_found)
				return NULL;
		} else {
			tmp_entryid.folder_database_guid = rop_util_make_domain_guid(plogon->account_id);
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

BINARY *cu_mid_to_sk(logon_object *plogon, uint64_t message_id)
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
	longid.guid = plogon->guid();
	longid.global_counter = rop_util_get_gc_array(message_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != EXT_ERR_SUCCESS)
		return NULL;
	return pbin;
}

BOOL cu_entryid_to_fid(logon_object *plogon, const BINARY *pbin,
    uint64_t *pfolder_id)
{
	BOOL b_found;
	uint16_t replid;
	EXT_PULL ext_pull;
	FOLDER_ENTRYID tmp_entryid;
	
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_folder_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;	
	switch (tmp_entryid.folder_type) {
	case EITLT_PRIVATE_FOLDER: {
		if (!plogon->is_private())
			return FALSE;
		auto tmp_guid = rop_util_make_user_guid(plogon->account_id);
		if (tmp_guid != tmp_entryid.database_guid)
			return FALSE;	
		*pfolder_id = rop_util_make_eid(1,
				tmp_entryid.global_counter);
		return TRUE;
	}
	case EITLT_PUBLIC_FOLDER: {
		if (plogon->is_private())
			return FALSE;
		auto tmp_guid = rop_util_make_domain_guid(plogon->account_id);
		if (tmp_guid == tmp_entryid.database_guid) {
			*pfolder_id = rop_util_make_eid(1,
					tmp_entryid.global_counter);
			return TRUE;
		}
		if (!exmdb_client::get_mapping_replid(plogon->get_dir(),
		    tmp_entryid.database_guid, &b_found, &replid) ||
		    !b_found)
			return FALSE;
		*pfolder_id = rop_util_make_eid(replid,
					tmp_entryid.global_counter);
		return TRUE;
	}
	default:
		return FALSE;
	}
}

BOOL cu_entryid_to_mid(logon_object *plogon, const BINARY *pbin,
    uint64_t *pfolder_id, uint64_t *pmessage_id)
{
	BOOL b_found;
	uint16_t replid;
	EXT_PULL ext_pull;
	MESSAGE_ENTRYID tmp_entryid;
	
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_msg_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;	
	if (tmp_entryid.folder_database_guid != tmp_entryid.message_database_guid)
		return FALSE;
	switch (tmp_entryid.message_type) {
	case EITLT_PRIVATE_MESSAGE: {
		if (!plogon->is_private())
			return FALSE;
		auto tmp_guid = rop_util_make_user_guid(plogon->account_id);
		if (tmp_guid != tmp_entryid.folder_database_guid)
			return FALSE;	
		*pfolder_id = rop_util_make_eid(1,
			tmp_entryid.folder_global_counter);
		*pmessage_id = rop_util_make_eid(1,
			tmp_entryid.message_global_counter);
		return TRUE;
	}
	case EITLT_PUBLIC_MESSAGE: {
		if (plogon->is_private())
			return FALSE;
		auto tmp_guid = rop_util_make_domain_guid(plogon->account_id);
		if (tmp_guid == tmp_entryid.folder_database_guid) {
			*pfolder_id = rop_util_make_eid(1,
				tmp_entryid.folder_global_counter);
			*pmessage_id = rop_util_make_eid(1,
				tmp_entryid.message_global_counter);
			return TRUE;
		}
		if (!exmdb_client::get_mapping_replid(plogon->get_dir(),
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

BOOL common_util_pcl_compare(const BINARY *pbin_pcl1,
	const BINARY *pbin_pcl2, uint32_t *presult)
{
	PCL a, b;
	if (!a.deserialize(pbin_pcl1) || !b.deserialize(pbin_pcl2))
		return FALSE;
	*presult = a.compare(b);
	return TRUE;
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

BINARY* common_util_pcl_merge(const BINARY *pbin_pcl1,
	const BINARY *pbin_pcl2)
{
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	PCL ppcl1;
	if (!ppcl1.deserialize(pbin_pcl1))
		return NULL;
	PCL ppcl2;
	if (!ppcl2.deserialize(pbin_pcl2))
		return NULL;
	if (!ppcl1.merge(std::move(ppcl2)))
		return NULL;
	auto ptmp_bin = ppcl1.serialize();
	ppcl1.clear();
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

BINARY* common_util_to_folder_replica(
	const LONG_TERM_ID *plongid, const char *essdn)
{
	EXT_PUSH ext_push;
	
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(1024);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 1024, 0) ||
	    ext_push.p_uint32(0) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(0) != EXT_ERR_SUCCESS ||
	    ext_push.p_longterm(*plongid) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(1) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(1) != EXT_ERR_SUCCESS ||
	    ext_push.p_str(essdn) != EXT_ERR_SUCCESS)
		return NULL;
	pbin->cb = ext_push.m_offset;
	return pbin;
}


GUID common_util_get_mapping_guid(BOOL b_private, int account_id)
{
	account_id *= -1;
	return b_private ? rop_util_make_user_guid(account_id) :
	       rop_util_make_domain_guid(account_id);
}

BOOL common_util_mapping_replica(BOOL to_guid,
	void *pparam, uint16_t *preplid, GUID *pguid)
{
	BOOL b_found;
	auto plogon = static_cast<logon_object *>(pparam);
	auto dir = plogon->get_dir();

	if (to_guid) {
		if (plogon->is_private()) {
			if (1 != *preplid) {
				return FALSE;
			}
			*pguid = rop_util_make_user_guid(plogon->account_id);
		} else {
			if (1 == *preplid) {
				*pguid = rop_util_make_domain_guid(plogon->account_id);
			} else if (!exmdb_client::get_mapping_guid(dir,
			    *preplid, &b_found, pguid) || !b_found) {
				return FALSE;
			}
		}
	} else {
		if (plogon->is_private()) {
			auto tmp_guid = rop_util_make_user_guid(plogon->account_id);
			if (tmp_guid != *pguid)
				return FALSE;
			*preplid = 1;
		} else {
			auto tmp_guid = rop_util_make_domain_guid(plogon->account_id);
			if (tmp_guid == *pguid)
				*preplid = 1;
			else if (!exmdb_client::get_mapping_replid(dir,
			    *pguid, &b_found, preplid) || !b_found)
				return FALSE;
		}
	}
	return TRUE;
}

void cu_set_propval(TPROPVAL_ARRAY *parray, uint32_t tag, const void *data)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (parray->ppropval[i].proptag == tag) {
			parray->ppropval[i].pvalue = deconst(data);
			return;
		}
	}
	parray->ppropval[parray->count].proptag = tag;
	parray->ppropval[parray->count++].pvalue = deconst(data);
}

void common_util_remove_propvals(
	TPROPVAL_ARRAY *parray, uint32_t proptag)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (proptag == parray->ppropval[i].proptag) {
			parray->count --;
			if (i < parray->count) {
				memmove(parray->ppropval + i, parray->ppropval + i + 1,
					(parray->count - i) * sizeof(TAGGED_PROPVAL));
			}
			return;
		}
	}
}

BOOL common_util_retag_propvals(TPROPVAL_ARRAY *parray,
    uint32_t original_proptag, uint32_t new_proptag)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (parray->ppropval[i].proptag == original_proptag) {
			parray->ppropval[i].proptag = new_proptag;
			return TRUE;
		}
	}
	return FALSE;
}

void common_util_reduce_proptags(PROPTAG_ARRAY *pproptags_minuend,
	const PROPTAG_ARRAY *pproptags_subtractor)
{
	int i, j;
	
	for (j=0; j<pproptags_subtractor->count; j++) {
		for (i=0; i<pproptags_minuend->count; i++) {
			if (pproptags_subtractor->pproptag[j] ==
				pproptags_minuend->pproptag[i]) {
				pproptags_minuend->count --;
				if (i < pproptags_minuend->count) {
					memmove(pproptags_minuend->pproptag + i,
						pproptags_minuend->pproptag + i + 1,
						(pproptags_minuend->count - i) *
						sizeof(uint32_t));
				}
				break;
			}
		}
	}
}

PROPTAG_ARRAY* common_util_trim_proptags(const PROPTAG_ARRAY *pproptags)
{
	int i;
	
	auto ptmp_proptags = cu_alloc<PROPTAG_ARRAY>();
	if (NULL == ptmp_proptags) {
		return NULL;
	}
	ptmp_proptags->pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (ptmp_proptags->pproptag == nullptr)
		return NULL;
	ptmp_proptags->count = 0;
	for (i=0; i<pproptags->count; i++) {
		if (PROP_TYPE(pproptags->pproptag[i]) == PT_OBJECT)
			continue;
		ptmp_proptags->pproptag[ptmp_proptags->count++] = pproptags->pproptag[i];
	}
	return ptmp_proptags;
}

BOOL common_util_propvals_to_row(
	const TPROPVAL_ARRAY *ppropvals,
	const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *prow)
{
	int i;
	static const uint32_t errcode = ecNotFound;
	
	for (i=0; i<pcolumns->count; i++) {
		if (!ppropvals->has(pcolumns->pproptag[i]))
			break;	
	}
	prow->flag = i < pcolumns->count ? PROPERTY_ROW_FLAG_FLAGGED : PROPERTY_ROW_FLAG_NONE;
	prow->pppropval = cu_alloc<void *>(pcolumns->count);
	if (NULL == prow->pppropval) {
		return FALSE;
	}
	for (i=0; i<pcolumns->count; i++) {
		prow->pppropval[i] = ppropvals->getval(pcolumns->pproptag[i]);
		if (prow->flag != PROPERTY_ROW_FLAG_FLAGGED)
			continue;
		auto pflagged_val = cu_alloc<FLAGGED_PROPVAL>();
		if (NULL == pflagged_val) {
			return FALSE;
		}
		if (NULL == prow->pppropval[i]) {
			pflagged_val->flag = FLAGGED_PROPVAL_FLAG_ERROR;
			pflagged_val->pvalue = ppropvals->getval(CHANGE_PROP_TYPE(pcolumns->pproptag[i], PT_ERROR));
			if (NULL == pflagged_val->pvalue) {
				pflagged_val->pvalue = deconst(&errcode);
			}
		} else {
			pflagged_val->flag = FLAGGED_PROPVAL_FLAG_AVAILABLE;
			pflagged_val->pvalue = prow->pppropval[i];
		}
		prow->pppropval[i] = pflagged_val;
	}
	return TRUE;
}

BOOL common_util_convert_unspecified(uint32_t cpid,
	BOOL b_unicode, TYPED_PROPVAL *ptyped)
{
	if (b_unicode) {
		if (ptyped->type != PT_STRING8)
			return TRUE;
		auto tmp_len = mb_to_utf8_len(static_cast<char *>(ptyped->pvalue));
		auto pvalue = common_util_alloc(tmp_len);
		if (NULL == pvalue) {
			return FALSE;
		}
		if (common_util_mb_to_utf8(cpid, static_cast<char *>(ptyped->pvalue),
		    static_cast<char *>(pvalue), tmp_len) < 0)
			return FALSE;	
		ptyped->pvalue = pvalue;
		return TRUE;
	}
	if (ptyped->type != PT_UNICODE)
		return TRUE;
	auto tmp_len = utf8_to_mb_len(static_cast<char *>(ptyped->pvalue));
	auto pvalue = common_util_alloc(tmp_len);
	if (NULL == pvalue) {
		return FALSE;
	}
	if (common_util_mb_from_utf8(cpid, static_cast<char *>(ptyped->pvalue),
	    static_cast<char *>(pvalue), tmp_len) < 0)
		return FALSE;
	ptyped->pvalue = pvalue;
	return TRUE;
}

BOOL common_util_propvals_to_row_ex(uint32_t cpid,
	BOOL b_unicode, const TPROPVAL_ARRAY *ppropvals,
	const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *prow)
{
	int i;
	static const uint32_t errcode = ecNotFound;
	
	for (i=0; i<pcolumns->count; i++) {
		if (!ppropvals->has(pcolumns->pproptag[i]))
			break;	
	}
	prow->flag = i < pcolumns->count ? PROPERTY_ROW_FLAG_FLAGGED : PROPERTY_ROW_FLAG_NONE;
	prow->pppropval = cu_alloc<void *>(pcolumns->count);
	if (NULL == prow->pppropval) {
		return FALSE;
	}
	for (i=0; i<pcolumns->count; i++) {
		prow->pppropval[i] = ppropvals->getval(pcolumns->pproptag[i]);
		if (NULL != prow->pppropval[i] &&
		    PROP_TYPE(pcolumns->pproptag[i]) == PT_UNSPECIFIED) {
			if (!common_util_convert_unspecified(cpid, b_unicode,
			    static_cast<TYPED_PROPVAL *>(prow->pppropval[i])))
				return FALSE;
		}
		if (prow->flag != PROPERTY_ROW_FLAG_FLAGGED)
			continue;
		auto pflagged_val = cu_alloc<FLAGGED_PROPVAL>();
		if (NULL == pflagged_val) {
			return FALSE;
		}
		if (NULL == prow->pppropval[i]) {
			pflagged_val->flag = FLAGGED_PROPVAL_FLAG_ERROR;
			pflagged_val->pvalue = ppropvals->getval(CHANGE_PROP_TYPE(pcolumns->pproptag[i], PT_ERROR));
			if (NULL == pflagged_val->pvalue) {
				pflagged_val->pvalue = deconst(&errcode);
			}
		} else {
			pflagged_val->flag = FLAGGED_PROPVAL_FLAG_AVAILABLE;
			pflagged_val->pvalue = prow->pppropval[i];
		}
		prow->pppropval[i] = pflagged_val;
	}
	return TRUE;
}

BOOL common_util_row_to_propvals(
	const PROPERTY_ROW *prow, const PROPTAG_ARRAY *pcolumns,
	TPROPVAL_ARRAY *ppropvals)
{
	int i;
	
	for (i=0; i<pcolumns->count; i++) {
		void *pvalue;
		if (PROPERTY_ROW_FLAG_NONE == prow->flag) {
			pvalue = prow->pppropval[i];
		} else {
			auto p = static_cast<FLAGGED_PROPVAL *>(prow->pppropval[i]);
			if (p->flag != FLAGGED_PROPVAL_FLAG_AVAILABLE)
				continue;	
			pvalue = p->pvalue;
		}
		cu_set_propval(ppropvals, pcolumns->pproptag[i], pvalue);
	}
	return TRUE;
}

static BOOL common_util_propvals_to_recipient(uint32_t cpid,
	TPROPVAL_ARRAY *ppropvals, const PROPTAG_ARRAY *pcolumns,
	RECIPIENT_ROW *prow)
{
	memset(prow, 0, sizeof(RECIPIENT_ROW));
	prow->flags |= RECIPIENT_ROW_FLAG_UNICODE;
	auto flag = ppropvals->get<const uint8_t>(PR_RESPONSIBILITY);
	if (flag != nullptr && *flag != 0)
		prow->flags |= RECIPIENT_ROW_FLAG_RESPONSIBLE;
	flag = ppropvals->get<const uint8_t>(PR_SEND_RICH_INFO);
	if (flag != nullptr && *flag != 0)
		prow->flags |= RECIPIENT_ROW_FLAG_NONRICH;
	prow->ptransmittable_name = ppropvals->get<char>(PR_TRANSMITABLE_DISPLAY_NAME);
	if (NULL == prow->ptransmittable_name) {
		auto name = ppropvals->get<const char>(PR_TRANSMITABLE_DISPLAY_NAME_A);
		if (name != nullptr)
			prow->ptransmittable_name = common_util_dup_mb_to_utf8(cpid, name);
	}
	prow->pdisplay_name = ppropvals->get<char>(PR_DISPLAY_NAME);
	if (NULL == prow->pdisplay_name) {
		auto name = ppropvals->get<const char>(PR_DISPLAY_NAME_A);
		if (name != nullptr)
			prow->pdisplay_name = common_util_dup_mb_to_utf8(cpid, name);
	}
	if (NULL != prow->ptransmittable_name && NULL != prow->pdisplay_name &&
		0 == strcasecmp(prow->pdisplay_name, prow->ptransmittable_name)) {
		prow->flags |= RECIPIENT_ROW_FLAG_SAME;
		prow->ptransmittable_name = NULL;
	}
	if (NULL != prow->ptransmittable_name) {
		prow->flags |= RECIPIENT_ROW_FLAG_TRANSMITTABLE;
	}
	if (NULL != prow->pdisplay_name) {
		prow->flags |= RECIPIENT_ROW_FLAG_DISPLAY;
	}
	prow->psimple_name = ppropvals->get<char>(PR_EMS_AB_DISPLAY_NAME_PRINTABLE);
	if (NULL == prow->psimple_name) {
		auto name = ppropvals->get<const char>(PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A);
		if (name != nullptr)
			prow->psimple_name = common_util_dup_mb_to_utf8(cpid, name);
	}
	if (NULL != prow->psimple_name) {
		prow->flags |= RECIPIENT_ROW_FLAG_SIMPLE;
	}
	auto addrtype = ppropvals->get<const char>(PR_ADDRTYPE);
	if (addrtype != nullptr) {
		if (strcasecmp(addrtype, "EX") == 0) {
			prow->flags |= RECIPIENT_ROW_TYPE_X500DN;
			static constexpr uint8_t dummy_zero = 0;
			prow->pprefix_used = deconst(&dummy_zero);
			auto disptype = ppropvals->get<const uint32_t>(PR_DISPLAY_TYPE);
			if (disptype == nullptr) {
				prow->display_type = DT_MAILUSER;
			} else {
				prow->display_type = *disptype;
				if (prow->display_type >= DT_ROOM)
					prow->display_type = DT_MAILUSER;
			}
			prow->have_display_type = true;
			prow->px500dn = ppropvals->get<char>(PR_EMAIL_ADDRESS);
			if (NULL == prow->px500dn) {
				return FALSE;
			}
		} else if (strcasecmp(addrtype, "SMTP") == 0) {
			prow->flags |= RECIPIENT_ROW_TYPE_SMTP |
							RECIPIENT_ROW_FLAG_EMAIL;
			prow->pmail_address = ppropvals->get<char>(PR_EMAIL_ADDRESS);
			if (NULL == prow->pmail_address) {
				prow->pmail_address = ppropvals->get<char>(PR_SMTP_ADDRESS);
				if (NULL == prow->pmail_address) {
					return FALSE;
				}
			}
		} else {
			prow->flags |= RECIPIENT_ROW_FLAG_EMAIL |
					RECIPIENT_ROW_FLAG_OUTOFSTANDARD;
			prow->paddress_type = deconst(addrtype);
			prow->pmail_address = ppropvals->get<char>(PR_EMAIL_ADDRESS);
			if (NULL == prow->pmail_address) {
				return FALSE;
			}
		}
	}
	prow->count = pcolumns->count;
	return common_util_propvals_to_row(ppropvals, pcolumns, &prow->properties);
}

static BOOL common_util_recipient_to_propvals(uint32_t cpid,
	RECIPIENT_ROW *prow, const PROPTAG_ARRAY *pcolumns,
	TPROPVAL_ARRAY *ppropvals)
{
	static constexpr uint8_t persist_true = true, persist_false = false;
	PROPTAG_ARRAY tmp_columns;
	BOOL b_unicode = (prow->flags & RECIPIENT_ROW_FLAG_UNICODE) ? TRUE : false;
	
	cu_set_propval(ppropvals, PR_RESPONSIBILITY, (prow->flags & RECIPIENT_ROW_FLAG_RESPONSIBLE) ? &persist_true : &persist_false);
	cu_set_propval(ppropvals, PR_SEND_RICH_INFO, (prow->flags & RECIPIENT_ROW_FLAG_NONRICH) ? &persist_true : &persist_false);
	if (NULL != prow->ptransmittable_name) {
		void *pvalue;
		if (b_unicode) {
			pvalue = prow->ptransmittable_name;
		} else {
			pvalue = common_util_dup_mb_to_utf8(cpid,
								prow->ptransmittable_name);
			if (pvalue == nullptr)
				return FALSE;
		}
		cu_set_propval(ppropvals, PR_TRANSMITABLE_DISPLAY_NAME, pvalue);
	}
	if (NULL != prow->pdisplay_name) {
		auto pvalue = b_unicode ? prow->pdisplay_name :
		              common_util_dup_mb_to_utf8(cpid, prow->pdisplay_name);
		if (pvalue != nullptr)
			cu_set_propval(ppropvals, PR_DISPLAY_NAME, pvalue);
	}
	if (NULL != prow->pmail_address) {
		void *pvalue;
		if (b_unicode) {
			pvalue = prow->pmail_address;
		} else {
			pvalue = common_util_dup_mb_to_utf8(
								cpid, prow->pmail_address);
			if (pvalue == nullptr)
				return FALSE;
		}
		cu_set_propval(ppropvals, PR_EMAIL_ADDRESS, pvalue);
	}
	switch (prow->flags & 0x0007) {
	case RECIPIENT_ROW_TYPE_NONE:
		if (NULL != prow->paddress_type) {
			cu_set_propval(ppropvals, PR_ADDRTYPE, prow->paddress_type);
		}
		break;
	case RECIPIENT_ROW_TYPE_X500DN:
		if (NULL == prow->px500dn) {
			return FALSE;
		}
		cu_set_propval(ppropvals, PR_ADDRTYPE, "EX");
		cu_set_propval(ppropvals, PR_EMAIL_ADDRESS, prow->px500dn);
		break;
	case RECIPIENT_ROW_TYPE_SMTP:
		cu_set_propval(ppropvals, PR_ADDRTYPE, "SMTP");
		break;
	default:
		/* we do not support other address types */
		return FALSE;
	}
	tmp_columns.count = prow->count;
	tmp_columns.pproptag = pcolumns->pproptag;
	if (!common_util_row_to_propvals(&prow->properties, &tmp_columns, ppropvals))
		return FALSE;	
	auto str = ppropvals->get<const char>(PR_DISPLAY_NAME);
	if (str == nullptr || *str == '\0' || strcmp(str, "''") == 0 ||
	    strcmp(str, "\"\"") == 0) {
		str = ppropvals->get<char>(PR_RECIPIENT_DISPLAY_NAME);
		if (str == nullptr)
			str = ppropvals->get<char>(PR_SMTP_ADDRESS);
		if (str == nullptr)
			str = "Undisclosed-Recipients";
		cu_set_propval(ppropvals, PR_DISPLAY_NAME, str);
	}
	return TRUE;
}

BOOL common_util_propvals_to_openrecipient(uint32_t cpid,
	TPROPVAL_ARRAY *ppropvals, const PROPTAG_ARRAY *pcolumns,
	OPENRECIPIENT_ROW *prow)
{
	auto pvalue = ppropvals->get<uint32_t>(PR_RECIPIENT_TYPE);
	prow->recipient_type = pvalue == nullptr ? MAPI_ORIG : *pvalue;
	prow->reserved = 0;
	prow->cpid = cpid;
	return common_util_propvals_to_recipient(cpid,
		ppropvals, pcolumns, &prow->recipient_row);
}

BOOL common_util_propvals_to_readrecipient(uint32_t cpid,
	TPROPVAL_ARRAY *ppropvals, const PROPTAG_ARRAY *pcolumns,
	READRECIPIENT_ROW *prow)
{
	auto pvalue = ppropvals->get<uint32_t>(PR_ROWID);
	if (NULL == pvalue) {
		return FALSE;
	}
	prow->row_id = *pvalue;
	pvalue = ppropvals->get<uint32_t>(PR_RECIPIENT_TYPE);
	prow->recipient_type = pvalue == nullptr ? MAPI_ORIG : *pvalue;
	prow->reserved = 0;
	prow->cpid = cpid;
	return common_util_propvals_to_recipient(cpid,
		ppropvals, pcolumns, &prow->recipient_row);
}

BOOL common_util_modifyrecipient_to_propvals(
	 uint32_t cpid, const MODIFYRECIPIENT_ROW *prow,
	const PROPTAG_ARRAY *pcolumns, TPROPVAL_ARRAY *ppropvals)
{
	TAGGED_PROPVAL propval;
	
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(16 + pcolumns->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	propval.proptag = PR_ROWID;
	propval.pvalue = deconst(&prow->row_id);
	common_util_set_propvals(ppropvals, &propval);
	propval.proptag = PR_RECIPIENT_TYPE;
	auto rcpttype = cu_alloc<uint32_t>();
	propval.pvalue = rcpttype;
	if (NULL == propval.pvalue) {
		return FALSE;
	}
	*rcpttype = prow->recipient_type;
	common_util_set_propvals(ppropvals, &propval);
	if (NULL == prow->precipient_row) {
		return TRUE;
	}
	return common_util_recipient_to_propvals(cpid,
			prow->precipient_row, pcolumns, ppropvals);
}

static void common_util_convert_proptag(BOOL to_unicode, uint32_t *pproptag)
{
	if (to_unicode) {
		if (PROP_TYPE(*pproptag) == PT_STRING8)
			*pproptag = CHANGE_PROP_TYPE(*pproptag, PT_UNICODE);
		else if (PROP_TYPE(*pproptag) == PT_MV_STRING8)
			*pproptag = CHANGE_PROP_TYPE(*pproptag, PT_MV_UNICODE);
	} else {
		if (PROP_TYPE(*pproptag) == PT_UNICODE)
			*pproptag = CHANGE_PROP_TYPE(*pproptag, PT_STRING8);
		else if (PROP_TYPE(*pproptag) == PT_MV_UNICODE)
			*pproptag = CHANGE_PROP_TYPE(*pproptag, PT_MV_STRING8);
	}
}

/* only for being invoked in rop environment */
BOOL common_util_convert_tagged_propval(
	BOOL to_unicode, TAGGED_PROPVAL *ppropval)
{
	if (to_unicode) {
		switch (PROP_TYPE(ppropval->proptag)) {
		case PT_STRING8: {
			auto len = mb_to_utf8_len(static_cast<char *>(ppropval->pvalue));
			auto pstring = cu_alloc<char>(len);
			if (NULL == pstring) {
				return FALSE;
			}
			if (common_util_convert_string(true,
			    static_cast<char *>(ppropval->pvalue), pstring, len) < 0) {
				return FALSE;	
			}
			ppropval->pvalue = pstring;
			common_util_convert_proptag(TRUE, &ppropval->proptag);
			break;
		}
		case PT_MV_STRING8: {
			auto sa = static_cast<STRING_ARRAY *>(ppropval->pvalue);
			for (size_t i = 0; i < sa->count; ++i) {
				auto len = mb_to_utf8_len(sa->ppstr[i]);
				auto pstring = cu_alloc<char>(len);
				if (NULL == pstring) {
					return FALSE;
				}
				if (common_util_convert_string(true,
				    sa->ppstr[i], pstring, len) < 0)
					return FALSE;	
				sa->ppstr[i] = pstring;
			}
			common_util_convert_proptag(TRUE, &ppropval->proptag);
			break;
		}
		case PT_SRESTRICTION:
			if (!common_util_convert_restriction(TRUE,
			    static_cast<RESTRICTION *>(ppropval->pvalue)))
				return FALSE;	
			break;
		case PT_ACTIONS:
			if (!common_util_convert_rule_actions(TRUE,
			    static_cast<RULE_ACTIONS *>(ppropval->pvalue)))
				return FALSE;	
			break;
		}
	} else {
		switch (PROP_TYPE(ppropval->proptag)) {
		case PT_UNICODE: {
			auto len = utf8_to_mb_len(static_cast<char *>(ppropval->pvalue));
			auto pstring = cu_alloc<char>(len);
			if (NULL == pstring) {
				return FALSE;
			}
			if (common_util_convert_string(false,
			    static_cast<char *>(ppropval->pvalue), pstring, len) < 0)
				return FALSE;	
			ppropval->pvalue = pstring;
			common_util_convert_proptag(FALSE, &ppropval->proptag);
			break;
		}
		case PT_MV_UNICODE: {
			auto sa = static_cast<STRING_ARRAY *>(ppropval->pvalue);
			for (size_t i = 0; i < sa->count; ++i) {
				auto len = utf8_to_mb_len(sa->ppstr[i]);
				auto pstring = cu_alloc<char>(len);
				if (NULL == pstring) {
					return FALSE;
				}
				if (common_util_convert_string(false,
				    sa->ppstr[i], pstring, len) < 0)
					return FALSE;	
				sa->ppstr[i] = pstring;
			}
			common_util_convert_proptag(FALSE, &ppropval->proptag);
			break;
		}
		case PT_SRESTRICTION:
			if (!common_util_convert_restriction(FALSE,
			    static_cast<RESTRICTION *>(ppropval->pvalue)))
				return FALSE;	
			break;
		case PT_ACTIONS:
			if (!common_util_convert_rule_actions(FALSE,
			    static_cast<RULE_ACTIONS *>(ppropval->pvalue)))
				return FALSE;	
			break;
		}
	}
	return TRUE;
}

/* only for being invoked in rop environment */
BOOL common_util_convert_restriction(BOOL to_unicode, RESTRICTION *pres)
{
	switch (pres->rt) {
	case RES_AND:
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!common_util_convert_restriction(to_unicode, &pres->andor->pres[i]))
				return FALSE;	
		break;
	case RES_NOT:
		if (!common_util_convert_restriction(to_unicode, &pres->xnot->res))
			return FALSE;	
		break;
	case RES_CONTENT:
		if (!common_util_convert_tagged_propval(to_unicode, &pres->cont->propval))
			return FALSE;	
		common_util_convert_proptag(to_unicode, &pres->cont->proptag);
		break;
	case RES_PROPERTY:
		if (!common_util_convert_tagged_propval(to_unicode, &pres->prop->propval))
			return FALSE;	
		common_util_convert_proptag(to_unicode, &pres->prop->proptag);
		break;
	case RES_PROPCOMPARE:
		common_util_convert_proptag(to_unicode, &pres->pcmp->proptag1);
		common_util_convert_proptag(to_unicode, &pres->pcmp->proptag2);
		break;
	case RES_BITMASK:
		common_util_convert_proptag(to_unicode, &pres->bm->proptag);
		break;
	case RES_SIZE:
		common_util_convert_proptag(to_unicode, &pres->size->proptag);
		break;
	case RES_EXIST:
		common_util_convert_proptag(to_unicode, &pres->exist->proptag);
		break;
	case RES_SUBRESTRICTION:
		if (!common_util_convert_restriction(to_unicode, &pres->sub->res))
			return FALSE;	
		break;
	case RES_COMMENT:
	case RES_ANNOTATION: {
		auto rcom = pres->comment;
		for (size_t i = 0; i < rcom->count; ++i)
			if (!common_util_convert_tagged_propval(to_unicode, &rcom->ppropval[i]))
				return FALSE;	
		if (rcom->pres != nullptr)
			if (!common_util_convert_restriction(to_unicode, rcom->pres))
				return FALSE;	
		break;
	}
	case RES_COUNT:
		if (!common_util_convert_restriction(to_unicode, &pres->count->sub_res))
			return FALSE;	
		break;
	default:
		return TRUE;
	}
	return TRUE;
}

static BOOL common_util_convert_recipient_block(
	BOOL to_unicode, RECIPIENT_BLOCK *prcpt)
{
	int i;
	
	for (i=0; i<prcpt->count; i++) {
		if (!common_util_convert_tagged_propval(to_unicode, &prcpt->ppropval[i]))
			return FALSE;	
	}
	return TRUE;
}

static BOOL common_util_convert_forwarddelegate_action(
	BOOL to_unicode, FORWARDDELEGATE_ACTION *pfwd)
{
	int i;
	
	for (i=0; i<pfwd->count; i++) {
		if (!common_util_convert_recipient_block(to_unicode, &pfwd->pblock[i]))
			return FALSE;	
	}
	return TRUE;
}

static BOOL common_util_convert_action_block(
	BOOL to_unicode, ACTION_BLOCK *pblock)
{
	switch (pblock->type) {
	case OP_MOVE:
	case OP_COPY:
		break;
	case OP_REPLY:
	case OP_OOF_REPLY:
		break;
	case OP_DEFER_ACTION:
		break;
	case OP_BOUNCE:
		break;
	case OP_FORWARD:
	case OP_DELEGATE:
		if (!common_util_convert_forwarddelegate_action(to_unicode,
		    static_cast<FORWARDDELEGATE_ACTION *>(pblock->pdata)))
			return FALSE;	
		break;
	case OP_TAG:
		if (!common_util_convert_tagged_propval(to_unicode,
		    static_cast<TAGGED_PROPVAL *>(pblock->pdata)))
			return FALSE;	
		break;
	case OP_DELETE:
		break;
	case OP_MARK_AS_READ:
		break;
	}
	return TRUE;
}

BOOL common_util_convert_rule_actions(BOOL to_unicode, RULE_ACTIONS *pactions)
{
	int i;
	
	for (i=0; i<pactions->count; i++) {
		if (!common_util_convert_action_block(to_unicode, &pactions->pblock[i]))
			return FALSE;	
	}
	return TRUE;
}

void common_util_notify_receipt(const char *username, int type,
    MESSAGE_CONTENT *pbrief) try
{
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str == nullptr)
		return;
	std::vector<std::string> rcpt_list;
	rcpt_list.emplace_back(str);
	MAIL imail(g_mime_pool);
	auto bounce_type = type == NOTIFY_RECEIPT_READ ?
	                   "BOUNCE_NOTIFY_READ" : "BOUNCE_NOTIFY_NON_READ";
	if (!emsmdb_bouncer_make(username, pbrief, bounce_type, &imail))
		return;
	if (cu_send_mail(&imail, username, rcpt_list) != ecSuccess)
		/* ignore */;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2035: ENOMEM");
}

BOOL common_util_save_message_ics(logon_object *plogon,
	uint64_t message_id, PROPTAG_ARRAY *pchanged_proptags)
{
	int i;
	uint32_t tmp_index;
	uint32_t *pgroup_id;
	uint64_t change_num;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[2];
	auto dir = plogon->get_dir();
	
	if (!exmdb_client::allocate_cn(dir, &change_num))
		return FALSE;	
	tmp_propvals.count = 2;
	tmp_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PidTagChangeNumber;
	propval_buff[0].pvalue = &change_num;
	propval_buff[1].proptag = PR_CHANGE_KEY;
	propval_buff[1].pvalue = cu_xid_to_bin({plogon->guid(), change_num});
	if (NULL == propval_buff[1].pvalue) {
		return FALSE;
	}
	if (!exmdb_client::set_message_properties(dir, nullptr, 0,
	    message_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (!exmdb_client::get_message_group_id(dir, message_id, &pgroup_id))
		return FALSE;	
	const property_groupinfo *pgpinfo;
	if (NULL == pgroup_id) {
		pgpinfo = plogon->get_last_property_groupinfo();
		if (NULL == pgpinfo) {
			return FALSE;
		}
		if (!exmdb_client::set_message_group_id(dir,
		    message_id, pgpinfo->group_id))
			return FALSE;	
	}  else {
		pgpinfo = plogon->get_property_groupinfo(*pgroup_id);
		if (NULL == pgpinfo) {
			return FALSE;
		}
	}
	/* memory format of PROPTAG_ARRAY is identical to LONG_ARRAY */
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> pindices(proptag_array_init());
	if (NULL == pindices) {
		return FALSE;
	}
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> pungroup_proptags(proptag_array_init());
	if (NULL == pungroup_proptags) {
		return FALSE;
	}
	if (!pgpinfo->get_partial_index(PR_CHANGE_KEY, &tmp_index)) {
		if (!proptag_array_append(pungroup_proptags.get(), PR_CHANGE_KEY))
			return FALSE;
	} else {
		if (!proptag_array_append(pindices.get(), tmp_index))
			return FALSE;
	}
	if (NULL != pchanged_proptags) {
		for (i=0; i<pchanged_proptags->count; i++) {
			if (!pgpinfo->get_partial_index(pchanged_proptags->pproptag[i], &tmp_index)) {
				if (!proptag_array_append(pungroup_proptags.get(),
				    pchanged_proptags->pproptag[i])) {
					return FALSE;
				}
			} else {
				if (!proptag_array_append(pindices.get(), tmp_index))
					return FALSE;
			}
		}
		
	}
	return exmdb_client::save_change_indices(dir, message_id,
	       change_num, pindices.get(), pungroup_proptags.get());
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

ec_error_t cu_send_mail(MAIL *pmail, const char *sender,
    const std::vector<std::string> &rcpt_list)
{
	int res_val;
	int command_len;
	char last_command[1024];
	char last_response[1024];
	
	MAIL dot_encoded(pmail->pmime_pool);
	if (pmail->check_dot()) {
		if (!pmail->transfer_dot(&dot_encoded, true))
			return ecError;
		pmail = &dot_encoded;
	}
	int sockd = gx_inet_connect(g_smtp_ip, g_smtp_port, 0);
	if (sockd < 0) {
		mlog2(LV_ERR, "Cannot connect to SMTP server [%s]:%hu: %s",
			g_smtp_ip, g_smtp_port, strerror(-sockd));
		return ecNetwork;
	}
	/* read welcome information of MTA */
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		mlog2(LV_ERR, "Timeout with SMTP server [%s]:%hu",
			g_smtp_ip, g_smtp_port);
		return ecNetwork;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        /* send quit command to server */
        common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		mlog2(LV_ERR, "Failed to connect to SMTP. "
			"Server response is \"%s\"", last_response);
		return ecNetwork;
	}

	/* send helo xxx to server */
	snprintf(last_command, 1024, "helo %s\r\n", get_host_ID());
	command_len = strlen(last_command);
	if (!common_util_send_command(sockd, last_command, command_len)) {
		close(sockd);
		mlog2(LV_ERR, "Failed to send \"HELO\" command");
		return ecNetwork;
	}
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		mlog2(LV_ERR, "Timeout with SMTP "
			"server [%s]:%hu", g_smtp_ip, g_smtp_port);
		return ecNetwork;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		/* send quit command to server */
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		mlog2(LV_ERR, "SMTP server responded with \"%s\" "
			"after sending \"HELO\" command", last_response);
		return ecNetwork;
	}

	command_len = sprintf(last_command, "mail from:<%s>\r\n", sender);
	if (!common_util_send_command(sockd, last_command, command_len)) {
		close(sockd);
		mlog2(LV_ERR, "Failed to send \"MAIL FROM\" command");
		return ecNetwork;
	}
	/* read mail from response information */
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		mlog2(LV_ERR, "Timeout with SMTP server [%s]:%hu",
			g_smtp_ip, g_smtp_port);
		return ecNetwork;
	case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
		/* send quit command to server */
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		mlog2(LV_ERR, "SMTP server responded \"%s\" "
			"after sending \"MAIL FROM\" command", last_response);
		return ecNetwork;
	}

	for (const auto &eaddr : rcpt_list) {
		bool have_at = strchr(eaddr.c_str(), '@') != nullptr;
		command_len = sprintf(last_command, have_at ? "rcpt to:<%s>\r\n" :
		              "rcpt to:<%s@none>\r\n", eaddr.c_str());
		if (!common_util_send_command(sockd, last_command, command_len)) {
			close(sockd);
			mlog2(LV_ERR, "Failed to send \"RCPT TO\" command");
			return ecNetwork;
		}
		/* read rcpt to response information */
		res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
		switch (res_val) {
		case SMTP_TIME_OUT:
			close(sockd);
			mlog2(LV_ERR, "Timeout with SMTP server [%s]:%hu",
				g_smtp_ip, g_smtp_port);
			return ecNetwork;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			common_util_send_command(sockd, "quit\r\n", 6);
			close(sockd);
			mlog2(LV_ERR, "SMTP server responded with \"%s\" "
				"after sending \"RCPT TO\" command", last_response);
			return ecNetwork;
		}						
	}
	/* send data */
	strcpy(last_command, "data\r\n");
	command_len = strlen(last_command);
	if (!common_util_send_command(sockd, last_command, command_len)) {
		close(sockd);
		mlog2(LV_ERR, "Sender %s: Failed "
			"to send \"DATA\" command", sender);
		return ecNetwork;
	}

	/* read data response information */
	res_val = common_util_get_response(sockd, last_response, 1024, TRUE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		mlog2(LV_ERR, "Sender %s: Timeout with SMTP server [%s]:%hu",
			sender, g_smtp_ip, g_smtp_port);
		return ecNetwork;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		mlog2(LV_ERR, "Sender %s: SMTP server responded \"%s\" "
			"after sending \"DATA\" command", sender, last_response);
		return ecNetwork;
	}

	pmail->set_header("X-Mailer", "gromox-emsmdb " PACKAGE_VERSION);
	if (!pmail->to_file(sockd) ||
	    !common_util_send_command(sockd, ".\r\n", 3)) {
		close(sockd);
		mlog2(LV_ERR, "Sender %s: Failed to send mail content", sender);
		return ecNetwork;
	}
	res_val = common_util_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		mlog2(LV_ERR, "Sender %s: Timeout with SMTP server [%s]:%hu",
			sender, g_smtp_ip, g_smtp_port);
		return ecNetwork;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:	
        common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		mlog2(LV_ERR, "Sender %s: SMTP server responded \"%s\" "
					"after sending mail content", sender, last_response);
		return ecNetwork;
	case SMTP_SEND_OK:
		common_util_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		mlog2(LV_NOTICE, "emsmdb: outgoing SMTP [%s]:%hu: from=<%s> OK",
		        g_smtp_ip, g_smtp_port, sender);
		return ecSuccess;
	}
	return ecSuccess;
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
	return exmdb_client::get_named_propids(common_util_get_dir(), false,
	       ppropnames, ppropids);
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

ec_error_t cu_send_message(logon_object *plogon, uint64_t message_id, bool b_submit)
{
	MAIL imail;
	void *pvalue;
	BOOL b_result;
	EID_ARRAY ids;
	BOOL b_partial;
	uint64_t new_id;
	uint64_t folder_id;
	TARRAY_SET *prcpts;
	MESSAGE_CONTENT *pmsgctnt;
	using LLU = unsigned long long;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto dir = plogon->get_dir();
	uint32_t cpid = pinfo == nullptr ? 1252 : pinfo->cpid;
	if (!exmdb_client::get_message_property(dir, nullptr, 0,
	    message_id, PidTagParentFolderId, &pvalue) || pvalue == nullptr) {
		mlog2(LV_ERR, "E-1289: Cannot get parent folder_id of mid:%llu",
		        LLU{rop_util_get_gc_value(message_id)});
		return ecNotFound;
	}
	auto parent_id = *static_cast<uint64_t *>(pvalue);
	if (!exmdb_client::read_message(dir, nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr) {
		mlog2(LV_ERR, "E-1288: Failed to read mid:%llu from exmdb",
		        LLU{rop_util_get_gc_value(message_id)});
		return ecRpcFailed;
	}
	if (!pmsgctnt->proplist.has(PR_INTERNET_CPID)) {
		auto ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 1);
		if (NULL == ppropval) {
			return ecServerOOM;
		}
		memcpy(ppropval, pmsgctnt->proplist.ppropval,
			sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
		ppropval[pmsgctnt->proplist.count].proptag = PR_INTERNET_CPID;
		ppropval[pmsgctnt->proplist.count++].pvalue = &cpid;
		pmsgctnt->proplist.ppropval = ppropval;
	}
	auto message_flags = pmsgctnt->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (message_flags == nullptr) {
		mlog2(LV_ERR, "E-1287: Failed to get message_flag of mid:%llu",
		        LLU{rop_util_get_gc_value(message_id)});
		return ecError;
	}
	BOOL b_resend = (*message_flags & MSGFLAG_RESEND) ? TRUE : false;
	prcpts = pmsgctnt->children.prcpts;
	if (NULL == prcpts) {
		mlog2(LV_ERR, "E-1286: Missing recipients for message mid:%llu",
		        LLU{rop_util_get_gc_value(message_id)});
		return MAPI_E_NO_RECIPIENTS;
	}

	std::vector<std::string> rcpt_list;
	for (size_t i = 0; i < prcpts->count; ++i) {
		if (b_resend) {
			auto rcpttype = prcpts->pparray[i]->get<const uint32_t>(PR_RECIPIENT_TYPE);
			if (rcpttype == nullptr)
				continue;
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
			if (entryid == nullptr) {
				mlog2(LV_ERR, "E-1285: Cannot get recipient entryid while sending mid:%llu",
				        LLU{rop_util_get_gc_value(message_id)});
				return ecInvalidRecips;
			}
			char username[UADDR_SIZE];
			if (!common_util_entryid_to_username(entryid,
			    username, GX_ARRAY_SIZE(username))) {
				mlog2(LV_ERR, "E-1284: Cannot convert recipient entryid to SMTP address while sending mid:%llu",
				        LLU{rop_util_get_gc_value(message_id)});
				return ecInvalidRecips;
			}
			rcpt_list.emplace_back(username);
		} else if (strcasecmp(addrtype, "SMTP") == 0) {
			str = prcpts->pparray[i]->get<char>(PR_EMAIL_ADDRESS);
			if (str == nullptr) {
				mlog2(LV_ERR, "E-1283: Cannot get email address of recipient of SMTP address type while sending mid:%llu",
				        LLU{rop_util_get_gc_value(message_id)});
				return ecInvalidRecips;
			}
			rcpt_list.emplace_back(str);
		} else if (strcasecmp(addrtype, "EX") == 0) {
			auto emaddr = prcpts->pparray[i]->get<const char>(PR_EMAIL_ADDRESS);
			if (emaddr == nullptr)
				goto CONVERT_ENTRYID;
			char username[UADDR_SIZE];
			if (!common_util_essdn_to_username(emaddr,
			    username, GX_ARRAY_SIZE(username)))
				goto CONVERT_ENTRYID;
			rcpt_list.emplace_back(username);
		} else {
			goto CONVERT_ENTRYID;
		}
	}
	if (rcpt_list.size() == 0) {
		mlog2(LV_ERR, "E-1282: Empty converted recipients list while sending mid:%llu",
		        LLU{rop_util_get_gc_value(message_id)});
		return MAPI_E_NO_RECIPIENTS;
	}
	auto body_type = get_override_format(*pmsgctnt);
	common_util_set_dir(dir);
	/* try to avoid TNEF message */
	if (!oxcmail_export(pmsgctnt, false, body_type, g_mime_pool, &imail,
	    common_util_alloc, common_util_get_propids, common_util_get_propname)) {
		mlog2(LV_ERR, "E-1281: Failed to export to RFC5322 mail while sending mid:%llu",
		        LLU{rop_util_get_gc_value(message_id)});
		return ecError;	
	}
	auto ret = cu_send_mail(&imail, plogon->get_account(), rcpt_list);
	if (ret != ecSuccess) {
		mlog2(LV_ERR, "E-1280: Failed to send mid:%llu via SMTP",
		        LLU{rop_util_get_gc_value(message_id)});
		return ret;
	}
	imail.clear();
	
	/*
	 * Mail is out, but we may still encounter errors during
	 * postprocessing. The send routine really should not report a terminal
	 * error to the user at this point. :-/
	 */
	auto flag = pmsgctnt->proplist.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagSentMailSvrEID);
	auto ptarget = pmsgctnt->proplist.get<BINARY>(PR_TARGET_ENTRYID);
	if (NULL != ptarget) {
		if (!cu_entryid_to_mid(plogon,
		    ptarget, &folder_id, &new_id)) {
			mlog2(LV_WARN, "W-1279: Failed to retrieve target entryid while sending mid:%llu",
			        LLU{rop_util_get_gc_value(message_id)});
			return ecWarnWithErrors;	
		}
		if (!exmdb_client::clear_submit(dir, message_id, false)) {
			mlog2(LV_WARN, "W-1278: Failed to clear submit flag while sending mid:%llu",
			        LLU{rop_util_get_gc_value(message_id)});
			return ecWarnWithErrors;
		}
		if (!exmdb_client::movecopy_message(dir, plogon->account_id,
		    cpid, message_id, folder_id, new_id, TRUE, &b_result)) {
			mlog2(LV_WARN, "W-1277: Failed to move to target folder while sending mid:%llu",
			        LLU{rop_util_get_gc_value(message_id)});
			return ecWarnWithErrors;
		}
		return ecSuccess;
	} else if (b_delete) {
		exmdb_client::delete_message(dir, plogon->account_id, cpid,
			parent_id, message_id, TRUE, &b_result);
		return ecSuccess;
	}
	if (!exmdb_client::clear_submit(dir, message_id, false)) {
		mlog2(LV_WARN, "W-1276: Failed to clear submit flag while sending mid:%llu",
		        LLU{rop_util_get_gc_value(message_id)});
		return ecWarnWithErrors;
	}
	ids.count = 1;
	ids.pids = &message_id;
	ptarget = pmsgctnt->proplist.get<BINARY>(PR_SENTMAIL_ENTRYID);
	if (ptarget == nullptr ||
	    !cu_entryid_to_fid(plogon, ptarget, &folder_id))
		folder_id = rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS);
	if (!exmdb_client::movecopy_messages(dir, plogon->account_id, cpid,
	    false, nullptr, parent_id, folder_id, false, &ids, &b_partial)) {
		mlog2(LV_WARN, "W-1275: Failed to move to \"Sent\" folder while sending mid:%llu",
		        LLU{rop_util_get_gc_value(message_id)});
		return ecWarnWithErrors;
	}
	return ecSuccess;
}

alloc_limiter<file_block> *common_util_get_allocator()
{
	return &g_file_allocator;
}

void common_util_init(const char *org_name, int average_blocks,
    unsigned int max_rcpt, unsigned int max_message, unsigned int max_mail_len,
	unsigned int max_rule_len, const char *smtp_ip, uint16_t smtp_port,
	const char *submit_command)
{
	gx_strlcpy(g_emsmdb_org_name, org_name, arsizeof(g_emsmdb_org_name));
	g_average_blocks = average_blocks;
	g_max_rcpt = max_rcpt;
	g_max_message = max_message;
	g_max_mail_len = max_mail_len;
	g_max_rule_len = g_max_extrule_len = max_rule_len;
	gx_strlcpy(g_smtp_ip, smtp_ip, GX_ARRAY_SIZE(g_smtp_ip));
	g_smtp_port = smtp_port;
	gx_strlcpy(g_submit_command, submit_command, GX_ARRAY_SIZE(g_submit_command));
}

int common_util_run()
{
	int mime_num;
	int context_num;
	
	context_num = get_context_num();

#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "emsmdb: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(common_util_get_username_from_id, "get_username_from_id");
	E(common_util_get_maildir, "get_maildir");
	E(common_util_get_homedir, "get_homedir");
	E(common_util_get_user_displayname, "get_user_displayname");
	E(common_util_check_mlist_include, "check_mlist_include");
	E(common_util_get_user_lang, "get_user_lang");
	E(common_util_get_timezone, "get_timezone");
	E(common_util_get_id_from_username, "get_id_from_username");
	E(common_util_get_user_ids, "get_user_ids");
	E(common_util_get_domain_ids, "get_domain_ids");
	E(common_util_check_same_org, "check_same_org");
	E(common_util_get_homedir_by_id, "get_homedir_by_id");
	E(common_util_get_id_from_maildir, "get_id_from_maildir");
	E(common_util_get_id_from_homedir, "get_id_from_homedir");
	E(common_util_add_timer, "add_timer");
	E(common_util_cancel_timer, "cancel_timer");
#undef E

	if (!oxcmail_init_library(g_emsmdb_org_name,
		common_util_get_user_ids, common_util_get_username_from_id)) {
		mlog(LV_ERR, "emsmdb: failed to init oxcmail library");
		return -2;
	}
	g_file_allocator = alloc_limiter<file_block>(g_average_blocks * context_num,
	                   "emsmdb_file_allocator", "http.cfg:context_num");
	mime_num = 16*context_num;
	if (mime_num < 1024) {
		mime_num = 1024;
	} else if (mime_num > 16*1024) {
		mime_num = 16*1024;
	}
	g_mime_pool = MIME_POOL::create(mime_num, 16,
	              "emsmdb_mime_pool (http.cfg:context_num)");
	if (NULL == g_mime_pool) {
		mlog(LV_ERR, "emsmdb: failed to init MIME pool");
		return -4;
	}
	return 0;
}

void common_util_stop()
{
	g_mime_pool.reset();
}

const char* common_util_get_submit_command()
{
	return g_submit_command;
}

std::shared_ptr<MIME_POOL> common_util_get_mime_pool()
{
	return g_mime_pool;
}

static void mlog2(unsigned int level, const char *format, ...)
{
	va_list ap;
	char log_buf[2048];
	
	auto rpc_info = get_rpc_info();
	if (NULL == rpc_info.username) {
		return;
	}
	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	mlog(level, "user=%s host=%s  %s",
		rpc_info.username, rpc_info.client_ip, log_buf);
}
