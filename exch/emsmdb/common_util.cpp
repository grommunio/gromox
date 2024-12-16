// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
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
#include <vmime/message.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/proc_common.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "logon_object.hpp"
#include "message_object.hpp"
#include "../bounce_exch.cpp"

using namespace gromox;

using LLU = unsigned long long;

unsigned int emsmdb_backfill_transporthdr;

namespace emsmdb {

unsigned int g_max_rcpt, g_max_message, g_max_mail_len;
unsigned int g_max_rule_len, g_max_extrule_len;
static std::string g_smtp_url;
char g_emsmdb_org_name[256];
static thread_local const char *g_dir_key;
static char g_submit_command[1024];
static constexpr char EMSMDB_UA[] = PACKAGE_NAME "-emsmdb " PACKAGE_VERSION;

#define E(s) decltype(common_util_ ## s) common_util_ ## s;
E(add_timer)
E(cancel_timer)
#undef E

static void mlog2(unsigned int level, const char *format, ...) __attribute__((format(printf, 2, 3)));

void* common_util_alloc(size_t size)
{
	return ndr_stack_alloc(NDR_STACK_IN, size);
}

ssize_t common_util_mb_from_utf8(cpid_t cpid, const char *src,
    char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	char temp_charset[256];
	
	auto charset = cpid_to_cset(cpid);
	if (charset == nullptr)
		return -1;
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

ssize_t common_util_mb_to_utf8(cpid_t cpid, const char *src,
    char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;

	cpid_cstr_compatible(cpid);
	auto charset = cpid_to_cset(cpid);
	if (charset == nullptr)
		return -1;
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

static char *common_util_dup_mb_to_utf8(cpid_t cpid, const char *src)
{
	cpid_cstr_compatible(cpid);
	auto len = mb_to_utf8_len(src);
	auto pdst = cu_alloc<char>(len);
	if (pdst == nullptr)
		return NULL;
	return common_util_mb_to_utf8(cpid, src, pdst, len) >= 0 ? pdst : nullptr;
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
	for (uint32_t i = 0; i < size; ++i)
		data[i] ^= 0xA5;
}

BINARY *cu_username_to_oneoff(const char *username, const char *dispname)
{
	ONEOFF_ENTRYID e{};

	e.ctrl_flags    = MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_UNICODE;
	e.pdisplay_name = dispname != nullptr && *dispname != '\0' ?
	                  deconst(dispname) : deconst(username);
	e.paddress_type = deconst("SMTP");
	e.pmail_address = deconst(username);
	auto bin = cu_alloc<BINARY>();
	if (bin == nullptr)
		return nullptr;
	bin->pv = common_util_alloc(1280);
	if (bin->pv == nullptr)
		return nullptr;
	EXT_PUSH push;
	if (!push.init(bin->pv, 1280, EXT_FLAG_UTF16))
		return nullptr;
	if (push.p_oneoff_eid(e) != pack_result::success)
		return nullptr;
	bin->cb = push.m_offset;
	return bin;
}

BINARY* common_util_username_to_addressbook_entryid(const char *username)
{
	std::string eidbuf;
	
	if (cvt_username_to_abkeid(username, g_emsmdb_org_name, DT_MAILUSER,
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

static void *cu_fid_to_entryid_1(const logon_object *plogon,
    uint64_t folder_id, void *output, size_t *outmax)
{
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	tmp_bin.cb = 0;
	tmp_bin.pv = &tmp_entryid.provider_uid;
	rop_util_guid_to_binary(plogon->mailbox_guid, &tmp_bin);
	if (replid_to_replguid(*plogon, rop_util_get_replid(folder_id),
	    tmp_entryid.database_guid) != ecSuccess)
		return nullptr;
	tmp_entryid.folder_type = plogon->is_private() ?
	                          EITLT_PRIVATE_FOLDER : EITLT_PUBLIC_FOLDER;
	tmp_entryid.global_counter = rop_util_get_gc_array(folder_id);
	tmp_entryid.pad[0] = 0;
	tmp_entryid.pad[1] = 0;
	if (!ext_push.init(output, *outmax, 0) ||
	    ext_push.p_folder_eid(tmp_entryid) != pack_result::ok)
		return nullptr;
	*outmax = ext_push.m_offset;
	return output;
}

BINARY *cu_fid_to_entryid(const logon_object *plogon, uint64_t folder_id)
{
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	size_t z = 256;
	pbin->pv = common_util_alloc(z);
	if (pbin->pv == nullptr ||
	    cu_fid_to_entryid_1(plogon, folder_id, pbin->pv, &z) == nullptr)
		return NULL;	
	pbin->cb = z;
	return pbin;
}

/* The caller can check for .size() < 4 to detect errors */
std::string cu_fid_to_entryid_s(const logon_object *plogon, uint64_t folder_id) try
{
	std::string out;
	size_t z = 256;
	out.resize(z);
	if (cu_fid_to_entryid_1(plogon, folder_id, out.data(), &z) == nullptr)
		return {};
	out.resize(z);
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2246: ENOMEM");
	return {};
}

BINARY *cu_fid_to_sk(const logon_object *plogon, uint64_t folder_id)
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
	if (replid_to_replguid(*plogon, rop_util_get_replid(folder_id),
	    longid.guid) != ecSuccess)
		return nullptr;
	longid.global_counter = rop_util_get_gc_array(folder_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != EXT_ERR_SUCCESS)
		return NULL;
	return pbin;
}

BINARY *cu_mid_to_entryid(const logon_object *plogon,
	uint64_t folder_id, uint64_t message_id)
{
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	tmp_bin.cb = 0;
	tmp_bin.pv = &tmp_entryid.provider_uid;
	rop_util_guid_to_binary(plogon->mailbox_guid, &tmp_bin);
	if (replid_to_replguid(*plogon, rop_util_get_replid(folder_id),
	    tmp_entryid.folder_database_guid) != ecSuccess)
		return nullptr;
	if (replid_to_replguid(*plogon, rop_util_get_replid(message_id),
	    tmp_entryid.message_database_guid) != ecSuccess)
		return nullptr;
	tmp_entryid.message_type = plogon->is_private() ?
	                           EITLT_PRIVATE_MESSAGE : EITLT_PUBLIC_MESSAGE;
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

BINARY *cu_mid_to_sk(const logon_object *plogon, uint64_t message_id)
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
	longid.guid = plogon->guid();
	longid.global_counter = rop_util_get_gc_array(message_id);
	if (!ext_push.init(pbin->pv, 22, 0) ||
	    ext_push.p_guid(longid.guid) != EXT_ERR_SUCCESS ||
	    ext_push.p_bytes(longid.global_counter.ab, 6) != EXT_ERR_SUCCESS)
		return NULL;
	return pbin;
}

BOOL cu_entryid_to_fid(const logon_object *plogon, const BINARY *pbin,
    uint64_t *pfolder_id)
{
	uint16_t replid;
	EXT_PULL ext_pull;
	FOLDER_ENTRYID tmp_entryid;
	
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_folder_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;	
	if (replguid_to_replid(*plogon, tmp_entryid.database_guid,
	    replid) != ecSuccess)
		return false;
	switch (tmp_entryid.folder_type) {
	case EITLT_PRIVATE_FOLDER:
	case EITLT_PUBLIC_FOLDER:
		*pfolder_id = rop_util_make_eid(replid, tmp_entryid.global_counter);
		return TRUE;
	default:
		return FALSE;
	}
}

BOOL cu_entryid_to_mid(const logon_object *plogon, const BINARY *pbin,
    uint64_t *pfolder_id, uint64_t *pmessage_id)
{
	uint16_t freplid, mreplid;
	EXT_PULL ext_pull;
	MESSAGE_ENTRYID tmp_entryid;
	
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_msg_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;	
	if (replguid_to_replid(*plogon, tmp_entryid.folder_database_guid,
	    freplid) != ecSuccess)
		return false;
	if (replguid_to_replid(*plogon, tmp_entryid.message_database_guid,
	    mreplid) != ecSuccess)
		return false;
	switch (tmp_entryid.message_type) {
	case EITLT_PRIVATE_MESSAGE:
	case EITLT_PUBLIC_MESSAGE:
		*pfolder_id  = rop_util_make_eid(freplid, tmp_entryid.folder_global_counter);
		*pmessage_id = rop_util_make_eid(mreplid, tmp_entryid.message_global_counter);
		return TRUE;
	default:
		return FALSE;
	}
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

BINARY* common_util_pcl_merge(const BINARY *pbin_pcl1,
	const BINARY *pbin_pcl2)
{
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
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

ec_error_t replguid_to_replid(const logon_object &logon,
    const GUID &guid, uint16_t &replid)
{
	if (guid == GUID_NULL) {
		replid = 0;
		return ecInvalidParam;
	} else if (guid == exc_replid2) {
		replid = 2;
		return ecSuccess;
	} else if (guid == exc_replid3) {
		replid = 3;
		return ecSuccess;
	} else if (guid == exc_replid4) {
		replid = 4;
		return ecSuccess;
	} else if (guid == logon.mailbox_guid) {
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
		if (!mysql_adaptor_check_same_org(dom_id, logon.domain_id))
			return ecInvalidParam;
	}
	ec_error_t ret = ecSuccess;
	if (!exmdb_client::get_mapping_replid(logon.get_dir(),
	    guid, &replid, &ret))
		return ecError;
	return ret;
}

/*
 * Replid 1 is hardwired to the Database GUID (specced somewhere).
 *
 * XXX: The translation from/to replids 1-5 is done with code, because the data
 * is not yet served by the database.
 *
 * Replids 2, 3, 4 are reserved in case we need to reproduce (more of the)
 * EXC behavior at some later point.
 */
ec_error_t replid_to_replguid(const logon_object &logon, uint16_t replid,
    GUID &guid)
{
	auto dir = logon.get_dir();
	BOOL b_found = false;
	if (replid == 1)
		guid = logon.is_private() ?
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
	else if (!exmdb_client::get_mapping_guid(dir, replid, &b_found, &guid))
		return ecError;
	else if (!b_found)
		return ecNotFound;
	return ecSuccess;
}

BOOL common_util_mapping_replica(BOOL to_guid,
	void *pparam, uint16_t *preplid, GUID *pguid)
{
	auto plogon = static_cast<logon_object *>(pparam);
	auto ret = to_guid ? replid_to_replguid(*plogon, *preplid, *pguid) :
	           replguid_to_replid(*plogon, *pguid, *preplid);
	return ret == ecSuccess ? TRUE : false;
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
	parray->emplace_back(tag, data);
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

PROPTAG_ARRAY* common_util_trim_proptags(const PROPTAG_ARRAY *pproptags)
{
	auto ptmp_proptags = cu_alloc<PROPTAG_ARRAY>();
	if (ptmp_proptags == nullptr)
		return NULL;
	ptmp_proptags->pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (ptmp_proptags->pproptag == nullptr)
		return NULL;
	ptmp_proptags->count = 0;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (PROP_TYPE(tag) == PT_OBJECT)
			continue;
		ptmp_proptags->pproptag[ptmp_proptags->count++] = tag;
	}
	return ptmp_proptags;
}

BOOL common_util_propvals_to_row(
	const TPROPVAL_ARRAY *ppropvals,
	const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *prow)
{
	int i;
	static constexpr uint32_t errcode = ecNotFound, enotsup = ecNotSupported;
	
	for (i = 0; i < pcolumns->count; ++i)
		if (!ppropvals->has(pcolumns->pproptag[i]))
			break;	
	prow->flag = i < pcolumns->count ? PROPERTY_ROW_FLAG_FLAGGED : PROPERTY_ROW_FLAG_NONE;
	prow->pppropval = cu_alloc<void *>(pcolumns->count);
	if (prow->pppropval == nullptr)
		return FALSE;
	for (i=0; i<pcolumns->count; i++) {
		const auto tag = pcolumns->pproptag[i];
		auto val = ppropvals->getval(tag);
		prow->pppropval[i] = deconst(val);
		if (prow->flag != PROPERTY_ROW_FLAG_FLAGGED)
			continue;
		auto pflagged_val = cu_alloc<FLAGGED_PROPVAL>();
		if (pflagged_val == nullptr)
			return FALSE;
		prow->pppropval[i] = pflagged_val;
		if (val != nullptr) {
			pflagged_val->flag = FLAGGED_PROPVAL_FLAG_AVAILABLE;
			pflagged_val->pvalue = deconst(val);
			continue;
		}
		/*
		 * The table protocol has two different ways to report empty
		 * cells. OXCDATA §2.11.5 has a hint. Unavailable is defined as
		 * "The PropertyValue field is not present." Error on the other
		 * hand is defined as "[...] why the property value is not
		 * present". Since one can always make up a reason, this is why
		 * only the Error variant is only ever seen/used in practice.
		 */
		pflagged_val->flag = FLAGGED_PROPVAL_FLAG_ERROR;
		val = ppropvals->getval(CHANGE_PROP_TYPE(tag, PT_ERROR));
		pflagged_val->pvalue = deconst(val);
		if (val != nullptr)
			continue;
		/*
		 * OXCTABL v21 specifies no requirement on the number of
		 * MVI_FLAG properties in the column set. Nor does it specify
		 * that the sortorder shall contain those MVI_FLAG properties.
		 *
		 * EXC2019 however will reject ropQueryRows when the sortorder
		 * is lacking an MVI_FLAG property that *is* in the column set.
		 * EXC2019 also rejects ropSortTable if the sortorder contains
		 * more than one MVI_FLAG property.
		 *
		 * Gromox will allow ropQueryRows, and db_engine simply won't
		 * yield data for that column (@ppropvals). This gives us the
		 * opportunity to signal ecNotSupported for only the affected
		 * columns and still return other data.
		 */
		pflagged_val->pvalue = deconst((tag & MVI_FLAG) == MVI_FLAG ? &enotsup : &errcode);
	}
	return TRUE;
}

BOOL common_util_convert_unspecified(cpid_t cpid,
	BOOL b_unicode, TYPED_PROPVAL *ptyped)
{
	if (b_unicode) {
		if (ptyped->type != PT_STRING8)
			return TRUE;
		auto tmp_len = mb_to_utf8_len(static_cast<char *>(ptyped->pvalue));
		auto pvalue = common_util_alloc(tmp_len);
		if (pvalue == nullptr)
			return FALSE;
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
	if (pvalue == nullptr)
		return FALSE;
	if (common_util_mb_from_utf8(cpid, static_cast<char *>(ptyped->pvalue),
	    static_cast<char *>(pvalue), tmp_len) < 0)
		return FALSE;
	ptyped->pvalue = pvalue;
	return TRUE;
}

BOOL common_util_propvals_to_row_ex(cpid_t cpid,
	BOOL b_unicode, const TPROPVAL_ARRAY *ppropvals,
	const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *prow)
{
	static const uint32_t errcode = ecNotFound;
	unsigned int i;
	
	for (i = 0; i < pcolumns->count; ++i)
		if (!ppropvals->has(pcolumns->pproptag[i]))
			break;	
	prow->flag = i < pcolumns->count ? PROPERTY_ROW_FLAG_FLAGGED : PROPERTY_ROW_FLAG_NONE;
	prow->pppropval = cu_alloc<void *>(pcolumns->count);
	if (prow->pppropval == nullptr)
		return FALSE;
	for (i=0; i<pcolumns->count; i++) {
		prow->pppropval[i] = deconst(ppropvals->getval(pcolumns->pproptag[i]));
		if (prow->pppropval[i] != nullptr &&
		    PROP_TYPE(pcolumns->pproptag[i]) == PT_UNSPECIFIED &&
		    !common_util_convert_unspecified(cpid, b_unicode,
		    static_cast<TYPED_PROPVAL *>(prow->pppropval[i])))
			return FALSE;
		if (prow->flag != PROPERTY_ROW_FLAG_FLAGGED)
			continue;
		auto pflagged_val = cu_alloc<FLAGGED_PROPVAL>();
		if (pflagged_val == nullptr)
			return FALSE;
		if (NULL == prow->pppropval[i]) {
			pflagged_val->flag = FLAGGED_PROPVAL_FLAG_ERROR;
			pflagged_val->pvalue = deconst(ppropvals->getval(CHANGE_PROP_TYPE(pcolumns->pproptag[i], PT_ERROR)));
			if (pflagged_val->pvalue == nullptr)
				pflagged_val->pvalue = deconst(&errcode);
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

static BOOL common_util_propvals_to_recipient(cpid_t cpid,
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
	if (prow->ptransmittable_name != nullptr)
		prow->flags |= RECIPIENT_ROW_FLAG_TRANSMITTABLE;
	if (prow->pdisplay_name != nullptr)
		prow->flags |= RECIPIENT_ROW_FLAG_DISPLAY;
	prow->psimple_name = ppropvals->get<char>(PR_EMS_AB_DISPLAY_NAME_PRINTABLE);
	if (NULL == prow->psimple_name) {
		auto name = ppropvals->get<const char>(PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A);
		if (name != nullptr)
			prow->psimple_name = common_util_dup_mb_to_utf8(cpid, name);
	}
	if (prow->psimple_name != nullptr)
		prow->flags |= RECIPIENT_ROW_FLAG_SIMPLE;
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
			if (prow->px500dn == nullptr)
				return FALSE;
		} else if (strcasecmp(addrtype, "SMTP") == 0) {
			prow->flags |= RECIPIENT_ROW_TYPE_SMTP |
							RECIPIENT_ROW_FLAG_EMAIL;
			prow->pmail_address = ppropvals->get<char>(PR_EMAIL_ADDRESS);
			if (NULL == prow->pmail_address) {
				prow->pmail_address = ppropvals->get<char>(PR_SMTP_ADDRESS);
				if (prow->pmail_address == nullptr)
					return FALSE;
			}
		} else {
			prow->flags |= RECIPIENT_ROW_FLAG_EMAIL |
					RECIPIENT_ROW_FLAG_OUTOFSTANDARD;
			prow->paddress_type = deconst(addrtype);
			prow->pmail_address = ppropvals->get<char>(PR_EMAIL_ADDRESS);
			if (prow->pmail_address == nullptr)
				return FALSE;
		}
	}
	prow->count = pcolumns->count;
	return common_util_propvals_to_row(ppropvals, pcolumns, &prow->properties);
}

static BOOL common_util_recipient_to_propvals(cpid_t cpid,
	RECIPIENT_ROW *prow, const PROPTAG_ARRAY *pcolumns,
	TPROPVAL_ARRAY *ppropvals)
{
	static constexpr uint8_t persist_true = true, persist_false = false;
	BOOL b_unicode = (prow->flags & RECIPIENT_ROW_FLAG_UNICODE) ? TRUE : false;
	
	cu_set_propval(ppropvals, PR_RESPONSIBILITY, (prow->flags & RECIPIENT_ROW_FLAG_RESPONSIBLE) ? &persist_true : &persist_false);
	cu_set_propval(ppropvals, PR_SEND_RICH_INFO, (prow->flags & RECIPIENT_ROW_FLAG_NONRICH) ? &persist_true : &persist_false);
	if (NULL != prow->ptransmittable_name) {
		void *pvalue;
		if (b_unicode) {
			pvalue = prow->ptransmittable_name;
		} else {
			pvalue = common_util_dup_mb_to_utf8(cpid, prow->ptransmittable_name);
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
			pvalue = common_util_dup_mb_to_utf8(cpid, prow->pmail_address);
			if (pvalue == nullptr)
				return FALSE;
		}
		cu_set_propval(ppropvals, PR_EMAIL_ADDRESS, pvalue);
	}
	switch (prow->flags & 0x0007) {
	case RECIPIENT_ROW_TYPE_NONE:
		if (prow->paddress_type != nullptr)
			cu_set_propval(ppropvals, PR_ADDRTYPE, prow->paddress_type);
		break;
	case RECIPIENT_ROW_TYPE_X500DN:
		if (prow->px500dn == nullptr)
			return FALSE;
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

	const PROPTAG_ARRAY tmp_columns = {prow->count, pcolumns->pproptag};
	if (!common_util_row_to_propvals(&prow->properties, &tmp_columns, ppropvals))
		return FALSE;	
	auto str = ppropvals->get<const char>(PR_DISPLAY_NAME);
	if (str != nullptr && *str != '\0' && strcmp(str, "''") != 0 &&
	    strcmp(str, "\"\"") != 0)
		return TRUE;
	str = ppropvals->get<char>(PR_RECIPIENT_DISPLAY_NAME);
	if (str == nullptr)
		str = ppropvals->get<char>(PR_SMTP_ADDRESS);
	if (str == nullptr)
		str = "Undisclosed-Recipients";
	cu_set_propval(ppropvals, PR_DISPLAY_NAME, str);
	return TRUE;
}

BOOL common_util_propvals_to_openrecipient(cpid_t cpid,
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

BOOL common_util_propvals_to_readrecipient(cpid_t cpid,
	TPROPVAL_ARRAY *ppropvals, const PROPTAG_ARRAY *pcolumns,
	READRECIPIENT_ROW *prow)
{
	auto pvalue = ppropvals->get<uint32_t>(PR_ROWID);
	if (pvalue == nullptr)
		return FALSE;
	prow->row_id = *pvalue;
	pvalue = ppropvals->get<uint32_t>(PR_RECIPIENT_TYPE);
	prow->recipient_type = pvalue == nullptr ? MAPI_ORIG : *pvalue;
	prow->reserved = 0;
	prow->cpid = cpid;
	return common_util_propvals_to_recipient(cpid,
		ppropvals, pcolumns, &prow->recipient_row);
}

BOOL common_util_modifyrecipient_to_propvals(cpid_t cpid,
    const MODIFYRECIPIENT_ROW *prow, const PROPTAG_ARRAY *pcolumns,
    TPROPVAL_ARRAY *ppropvals)
{
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(16 + pcolumns->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	cu_set_propval(ppropvals, PR_ROWID, deconst(&prow->row_id));
	auto rcpttype = cu_alloc<uint32_t>();
	if (rcpttype == nullptr)
		return FALSE;
	*rcpttype = prow->recipient_type;
	cu_set_propval(ppropvals, PR_RECIPIENT_TYPE, rcpttype);
	if (prow->precipient_row == nullptr)
		return TRUE;
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
			if (pstring == nullptr)
				return FALSE;
			if (common_util_convert_string(true,
			    static_cast<char *>(ppropval->pvalue), pstring, len) < 0)
				return FALSE;	
			ppropval->pvalue = pstring;
			common_util_convert_proptag(TRUE, &ppropval->proptag);
			break;
		}
		case PT_MV_STRING8: {
			auto sa = static_cast<STRING_ARRAY *>(ppropval->pvalue);
			for (size_t i = 0; i < sa->count; ++i) {
				auto len = mb_to_utf8_len(sa->ppstr[i]);
				auto pstring = cu_alloc<char>(len);
				if (pstring == nullptr)
					return FALSE;
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
			if (pstring == nullptr)
				return FALSE;
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
				if (pstring == nullptr)
					return FALSE;
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
	for (auto &prop : *prcpt)
		if (!common_util_convert_tagged_propval(to_unicode, &prop))
			return FALSE;	
	return TRUE;
}

static BOOL common_util_convert_forwarddelegate_action(
	BOOL to_unicode, FORWARDDELEGATE_ACTION *pfwd)
{
	for (auto &a : *pfwd)
		if (!common_util_convert_recipient_block(to_unicode, &a))
			return FALSE;	
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
	for (auto &a : *pactions)
		if (!common_util_convert_action_block(to_unicode, &a))
			return FALSE;	
	return TRUE;
}

ec_error_t ems_send_mail(MAIL *m, const char *sender, const std::vector<std::string> &rcpts)
{
	m->set_header("X-Mailer", EMSMDB_UA);
	return cu_send_mail(*m, g_smtp_url.c_str(), sender, rcpts);
}

ec_error_t ems_send_vmail(vmime::shared_ptr<vmime::message> m,
    const char *sender, const std::vector<std::string> &rcpts)
{
	m->getHeader()->getField("X-Mailer")->setValue(EMSMDB_UA);
	return cu_send_vmail(std::move(m), g_smtp_url.c_str(), sender, rcpts);
}

void common_util_notify_receipt(const char *username, int type,
    MESSAGE_CONTENT *pbrief) try
{
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str == nullptr)
		return;
	std::vector<std::string> rcpt_list;
	rcpt_list.emplace_back(str);
	auto bounce_type = type == NOTIFY_RECEIPT_READ ?
	                   "BOUNCE_NOTIFY_READ" : "BOUNCE_NOTIFY_NON_READ";
	vmime::shared_ptr<vmime::message> imail;
	if (!exch_bouncer_make(mysql_adaptor_get_user_displayname,
	    mysql_adaptor_meta, username, pbrief, bounce_type, imail))
		return;
	auto ret = ems_send_vmail(std::move(imail), username, rcpt_list);
	if (ret != ecSuccess)
		mlog2(LV_ERR, "E-1189: ems_send_mail: %s", mapi_strerror(ret));
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2035: ENOMEM");
}

BOOL common_util_save_message_ics(logon_object *plogon,
	uint64_t message_id, PROPTAG_ARRAY *pchanged_proptags)
{
	uint32_t tmp_index;
	uint32_t *pgroup_id;
	uint64_t change_num;
	PROBLEM_ARRAY tmp_problems;
	auto dir = plogon->get_dir();
	
	if (!exmdb_client::allocate_cn(dir, &change_num))
		return FALSE;	
	const TAGGED_PROPVAL propval_buff[] = {
		{PidTagChangeNumber, &change_num},
		{PR_CHANGE_KEY, cu_xid_to_bin({plogon->guid(), change_num})},
	};
	if (propval_buff[1].pvalue == nullptr)
		return FALSE;
	const TPROPVAL_ARRAY tmp_propvals = {std::size(propval_buff), deconst(propval_buff)};
	if (!exmdb_client::set_message_properties(dir, nullptr, CP_ACP,
	    message_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (!exmdb_client::get_message_group_id(dir, message_id, &pgroup_id))
		return FALSE;	
	const property_groupinfo *pgpinfo;
	if (NULL == pgroup_id) {
		pgpinfo = plogon->get_last_property_groupinfo();
		if (pgpinfo == nullptr)
			return FALSE;
		if (!exmdb_client::set_message_group_id(dir,
		    message_id, pgpinfo->group_id))
			return FALSE;	
	}  else {
		pgpinfo = plogon->get_property_groupinfo(*pgroup_id);
		if (pgpinfo == nullptr)
			return FALSE;
	}
	/* memory format of PROPTAG_ARRAY is identical to LONG_ARRAY */
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> pindices(proptag_array_init());
	if (pindices == nullptr)
		return FALSE;
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> pungroup_proptags(proptag_array_init());
	if (pungroup_proptags == nullptr)
		return FALSE;
	if (!pgpinfo->get_partial_index(PR_CHANGE_KEY, &tmp_index)) {
		if (!proptag_array_append(pungroup_proptags.get(), PR_CHANGE_KEY))
			return FALSE;
	} else {
		if (!proptag_array_append(pindices.get(), tmp_index))
			return FALSE;
	}
	if (NULL != pchanged_proptags) {
		for (unsigned int i = 0; i < pchanged_proptags->count; ++i) {
			const auto tag = pchanged_proptags->pproptag[i];
			if (!pgpinfo->get_partial_index(tag, &tmp_index)) {
				if (!proptag_array_append(pungroup_proptags.get(), tag))
					return FALSE;
			} else {
				if (!proptag_array_append(pindices.get(), tmp_index))
					return FALSE;
			}
		}
		
	}
	return exmdb_client::save_change_indices(dir, message_id,
	       change_num, pindices.get(), pungroup_proptags.get());
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
	uint16_t propid, PROPERTY_NAME **pppropname) try
{
	PROPNAME_ARRAY propnames;
	
	if (!exmdb_client::get_named_propnames(common_util_get_dir(),
	    {propid}, &propnames) || propnames.size() != 1)
		return FALSE;
	*pppropname = propnames.ppropname;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2234: ENOMEM");
	return false;
}

static bool mapi_p1(const TPROPVAL_ARRAY &props)
{
	auto t = props.get<const uint32_t>(PR_RECIPIENT_TYPE);
	return t != nullptr && *t & MAPI_P1;
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
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr,
		           g_emsmdb_org_name, cu_id2user, es_result);
		if (ret == ecSuccess) {
			list.emplace_back(std::move(es_result));
			return ecSuccess;
		} else if (ret != ecNullObject) {
			return ret;
		}
	}
	auto ret = cvt_entryid_to_smtpaddr(props.get<const BINARY>(PR_ENTRYID),
	           g_emsmdb_org_name, cu_id2user, es_result);
	if (ret == ecSuccess)
		list.emplace_back(std::move(es_result));
	return ret == ecNullObject || ret == ecUnknownUser ? ecInvalidRecips : ret;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1123: ENOMEM");
	return ecServerOOM;
}

ec_error_t cu_send_message(logon_object *plogon, message_object *msg,
    bool b_submit) try
{
	uint64_t message_id = msg->get_id();
	MAIL imail;
	void *pvalue;
	BOOL b_result;
	BOOL b_partial;
	uint64_t new_id;
	uint64_t folder_id;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto dir = plogon->get_dir();
	auto log_id = dir + ":m"s + std::to_string(rop_util_get_gc_value(message_id));
	cpid_t cpid = pinfo == nullptr ? static_cast<cpid_t>(1252) : pinfo->cpid;
	if (!exmdb_client::get_message_property(dir, nullptr, CP_ACP,
	    message_id, PidTagParentFolderId, &pvalue) || pvalue == nullptr) {
		mlog2(LV_ERR, "E-1289: exrpc get_message_property %s failed", log_id.c_str());
		return ecNotFound;
	}
	auto parent_id = *static_cast<uint64_t *>(pvalue);
	if (!exmdb_client::read_message(dir, nullptr, cpid,
	    message_id, &pmsgctnt) || pmsgctnt == nullptr) {
		mlog2(LV_ERR, "E-1288: exrpc read_message %s failed", log_id.c_str());
		return ecRpcFailed;
	}
	if (!pmsgctnt->proplist.has(PR_INTERNET_CPID)) {
		auto ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 1);
		if (ppropval == nullptr)
			return ecServerOOM;
		memcpy(ppropval, pmsgctnt->proplist.ppropval,
			sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
		ppropval[pmsgctnt->proplist.count].proptag = PR_INTERNET_CPID;
		ppropval[pmsgctnt->proplist.count++].pvalue = &cpid;
		pmsgctnt->proplist.ppropval = ppropval;
	}
	auto message_flags = pmsgctnt->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (message_flags == nullptr) {
		mlog2(LV_ERR, "E-1287: no PR_MESSAGE_FLAGS in %s", log_id.c_str());
		return ecError;
	}
	bool b_resend = *message_flags & MSGFLAG_RESEND;
	const tarray_set *prcpts = pmsgctnt->children.prcpts;
	if (NULL == prcpts) {
		mlog2(LV_ERR, "E-1286: Tried to send %s but message has 0 recipients", log_id.c_str());
		return MAPI_E_NO_RECIPIENTS;
	}

	std::vector<std::string> rcpt_list;
	for (const auto &rcpt : *prcpts) {
		auto ret = cu_rcpt_to_list(message_id, rcpt, rcpt_list, b_resend);
		if (ret != ecSuccess)
			return ret;
	}
	if (rcpt_list.size() == 0) {
		mlog2(LV_ERR, "E-1282: Empty converted recipients list attempting to send %s", log_id.c_str());
		return MAPI_E_NO_RECIPIENTS;
	}
	auto body_type = get_override_format(*pmsgctnt);
	common_util_set_dir(dir);
	/* try to avoid TNEF message */
	if (!oxcmail_export(pmsgctnt, log_id.c_str(), false, body_type, &imail,
	    common_util_alloc, common_util_get_propids, common_util_get_propname)) {
		mlog2(LV_ERR, "E-1281: oxcmail_export %s failed", log_id.c_str());
		return ecError;	
	}

	imail.set_header("X-Mailer", EMSMDB_UA);
	if (emsmdb_backfill_transporthdr) {
		std::unique_ptr<MESSAGE_CONTENT, mc_delete> rmsg(oxcmail_import("utf-8",
			"UTC", &imail, common_util_alloc, common_util_get_propids));
		if (rmsg != nullptr) {
			for (auto tag : {PR_TRANSPORT_MESSAGE_HEADERS, PR_TRANSPORT_MESSAGE_HEADERS_A}) {
				auto th = rmsg->proplist.get<const char>(tag);
				if (th == nullptr)
					continue;
				TAGGED_PROPVAL tp  = {tag, deconst(th)};
				TPROPVAL_ARRAY tpa = {1, &tp};
				PROBLEM_ARRAY pa{};
				if (!msg->set_properties(&tpa, &pa))
					break;
				/* Unclear if permitted to save (specs say nothing) */
				msg->save();
				break;
			}
		}
	}

	auto ret = ems_send_mail(&imail, plogon->get_account(), rcpt_list);
	if (ret != ecSuccess) {
		mlog2(LV_ERR, "E-1280: failed to send %s via SMTP: %s",
			log_id.c_str(), mapi_strerror(ret));
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
			mlog2(LV_WARN, "W-1279: PR_TARGET_ENTRYID inconvertible in %s", log_id.c_str());
			return ecWarnWithErrors;	
		}
		if (!exmdb_client::clear_submit(dir, message_id, false)) {
			mlog2(LV_WARN, "W-1278: exrpc clear_submit %s failed", log_id.c_str());
			return ecWarnWithErrors;
		}
		if (!exmdb_client::movecopy_message(dir, cpid, message_id,
		    folder_id, new_id, TRUE, &b_result)) {
			mlog2(LV_WARN, "W-1277: exrpc movecopy_message %s failed", log_id.c_str());
			return ecWarnWithErrors;
		}
		return ecSuccess;
	} else if (b_delete) {
		exmdb_client::delete_message(dir, plogon->account_id, cpid,
			parent_id, message_id, TRUE, &b_result);
		return ecSuccess;
	}
	if (!exmdb_client::clear_submit(dir, message_id, false)) {
		mlog2(LV_WARN, "W-1276: exrpc clear_submit %s failed", log_id.c_str());
		return ecWarnWithErrors;
	}

	ptarget = pmsgctnt->proplist.get<BINARY>(PR_SENTMAIL_ENTRYID);
	if (ptarget == nullptr ||
	    !cu_entryid_to_fid(plogon, ptarget, &folder_id))
		folder_id = rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS);

	const EID_ARRAY ids = {1, &message_id};
	if (!exmdb_client::movecopy_messages(dir, cpid,
	    false, STORE_OWNER_GRANTED, parent_id, folder_id, false,
	    &ids, &b_partial)) {
		mlog2(LV_WARN, "W-1275: exrpc movecopy_message %s failed", log_id.c_str());
		return ecWarnWithErrors;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2553: ENOMEM");
	return ecServerOOM;
}

void common_util_init(const char *org_name, unsigned int max_rcpt,
    unsigned int max_message, unsigned int max_mail_len,
    unsigned int max_rule_len, std::string &&smtp_url,
    const char *submit_command)
{
	gx_strlcpy(g_emsmdb_org_name, org_name, std::size(g_emsmdb_org_name));
	g_max_rcpt = max_rcpt;
	g_max_message = max_message;
	g_max_mail_len = max_mail_len;
	g_max_rule_len = g_max_extrule_len = max_rule_len;
	g_smtp_url = std::move(smtp_url);
	gx_strlcpy(g_submit_command, submit_command, std::size(g_submit_command));
}

int common_util_run()
{
#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "emsmdb: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)
	E(common_util_add_timer, "add_timer");
	E(common_util_cancel_timer, "cancel_timer");
#undef E

	if (!oxcmail_init_library(g_emsmdb_org_name, mysql_adaptor_get_user_ids,
	    mysql_adaptor_get_domain_ids, mysql_adaptor_get_username_from_id)) {
		mlog(LV_ERR, "emsmdb: failed to init oxcmail library");
		return -2;
	}
	return 0;
}

const char* common_util_get_submit_command()
{
	return g_submit_command;
}

static void mlog2(unsigned int level, const char *format, ...)
{
	va_list ap;
	char log_buf[2048];
	
	auto rpc_info = get_rpc_info();
	if (rpc_info.username == nullptr)
		return;
	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	mlog(level, "user=%s host=[%s]  %s",
		rpc_info.username, rpc_info.client_ip, log_buf);
}

ec_error_t cu_id2user(int id, std::string &user) try
{
	char ubuf[UADDR_SIZE];
	if (!mysql_adaptor_get_username_from_id(id, ubuf, std::size(ubuf)))
		return ecError;
	user = ubuf;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

}
