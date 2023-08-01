// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2023 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <fcntl.h>
#include <iconv.h>
#include <memory>
#include <new>
#include <pthread.h>
#include <string>
#include <string_view>
#include <unistd.h>
#ifdef HAVE_XXHASH
	/* xxh3 must come first in 0.7.0, or everything breaks apart */
#	include <xxh3.h>
#	include <xxhash.h>
#endif
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/pcl.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#define S2A(x) reinterpret_cast<const char *>(x)

using XUI = unsigned int;
using LLD = long long;
using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

namespace {

class fhash {
	public:
	fhash(std::string_view);
	const std::string &str() const { return cid; }
	const char *c_str() const { return cid.c_str(); }

	private:
	void hexify(const unsigned char *, unsigned int);
	std::string cid;
};

struct prepared_statements {
	xstmt msg_norm, msg_str, rcpt_norm, rcpt_str;
};

}

static char g_exmdb_org_name[256];
static unsigned int g_max_msg, g_cid_use_xxhash = 1;
thread_local unsigned int g_inside_flush_instance;
thread_local sqlite3 *g_sqlite_for_oxcmail;
static thread_local prepared_statements *g_opt_key;
static thread_local const char *g_opt_key_src;
unsigned int g_max_rule_num, g_max_extrule_num;
unsigned int g_cid_compression = 0; /* disabled(0), specific_level(n) */
static std::atomic<unsigned int> g_sequence_id;

#define E(s) decltype(common_util_ ## s) common_util_ ## s;
E(get_username_from_id)
E(get_user_displayname)
E(check_mlist_include)
E(get_user_lang)
E(get_timezone)
E(get_maildir)
E(get_homedir)
E(get_id_from_username)
E(get_user_ids)
E(get_domain_ids)
E(get_id_from_maildir)
E(get_id_from_homedir)
E(get_mime_pool)
E(get_handle)
#undef E
decltype(ems_send_mail) ems_send_mail;

static bool cu_eval_subobj_restriction(sqlite3 *, cpid_t, uint64_t msgid, uint32_t proptag, const RESTRICTION *);
static bool gp_prepare_anystr(sqlite3 *, mapi_object_type, uint64_t, uint32_t, xstmt &, sqlite3_stmt *&);
static bool gp_prepare_mvstr(sqlite3 *, mapi_object_type, uint64_t, uint32_t, xstmt &, sqlite3_stmt *&);
static bool gp_prepare_default(sqlite3 *, mapi_object_type, uint64_t, uint32_t, xstmt &, sqlite3_stmt *&);
static void *gp_fetch(sqlite3 *, sqlite3_stmt *, uint16_t, cpid_t);

void cu_set_propval(TPROPVAL_ARRAY *parray, uint32_t tag, const void *data)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (parray->ppropval[i].proptag != tag)
			continue;
		parray->ppropval[i].pvalue = deconst(data);
		return;
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

BOOL common_util_essdn_to_username(const char *pessdn,
    char *username, size_t ulen)
{
	char *pat;
	const char *plocal;
	char tmp_essdn[1024];
	
	auto tmp_len = gx_snprintf(tmp_essdn, std::size(tmp_essdn),
			"/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=",
	               g_exmdb_org_name);
	if (strncasecmp(pessdn, tmp_essdn, tmp_len) != 0)
		return FALSE;
	if (pessdn[tmp_len+16] != '-')
		return FALSE;
	plocal = pessdn + tmp_len + 17;
	unsigned int user_id = decode_hex_int(&pessdn[tmp_len+8]);
	if (!common_util_get_username_from_id(user_id, username, ulen))
		return FALSE;
	pat = strchr(username, '@');
	if (pat == nullptr)
		return FALSE;
	if (strncasecmp(username, plocal, pat - username) != 0)
		return FALSE;
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
	if (!common_util_get_user_ids(username, &user_id, &domain_id, nullptr))
		return FALSE;
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, dnmax, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
		g_exmdb_org_name, hex_string2, hex_string, tmp_name);
	HX_strupper(pessdn);
	return TRUE;
}
	
void common_util_pass_service(const char *name, void *func)
{
#define E(v, ptr) do { if (strcmp(name, (v)) == 0) { (ptr) = reinterpret_cast<decltype(ptr)>(func); return; } } while (false)
	E("ems_send_mail", ems_send_mail);
	E("get_mime_pool", common_util_get_mime_pool);
	E("get_handle", common_util_get_handle);
#undef E
}

void common_util_init(const char *org_name, uint32_t max_msg,
	unsigned int max_rule_num, unsigned int max_ext_rule_num)
{
	gx_strlcpy(g_exmdb_org_name, org_name, std::size(g_exmdb_org_name));
	g_max_msg = max_msg;
	g_max_rule_num = max_rule_num;
	g_max_extrule_num = max_ext_rule_num;
}

void common_util_build_tls()
{
	g_inside_flush_instance = false;
	g_sqlite_for_oxcmail = nullptr;
	g_opt_key = nullptr;
	g_opt_key_src = nullptr;
}

unsigned int common_util_sequence_ID()
{
	return ++g_sequence_id;
}

/* can directly be called in local rpc thread without
	invoking exmdb_server::build_environment before! */
void* common_util_alloc(size_t size)
{
	auto pctx = exmdb_server::get_alloc_context();
	if (pctx != nullptr)
		return pctx->alloc(size);
	return ndr_stack_alloc(NDR_STACK_IN, size);
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

char *common_util_convert_copy(BOOL to_utf8, cpid_t cpid, const char *pstring)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	char temp_charset[256];
	
	if (to_utf8)
		cpid_cstr_compatible(cpid);
	auto charset = cpid_to_cset(cpid);
	if (charset == nullptr)
		charset = "windows-1252";
	in_len = strlen(pstring) + 1;
	out_len = 2*in_len;
	auto pstr_out = cu_alloc<char>(out_len);
	if (pstr_out == nullptr)
		return NULL;
	if (to_utf8) {
		conv_id = iconv_open("UTF-8//IGNORE", charset);
		if (conv_id == (iconv_t)-1)
			conv_id = iconv_open("UTF-8//IGNORE", "windows-1252");
	} else {
		sprintf(temp_charset, "%s//IGNORE", charset);
		conv_id = iconv_open(temp_charset, "UTF-8");
		if (conv_id == (iconv_t)-1)
			conv_id = iconv_open("windows-1252//IGNORE", "UTF-8");
	}
	if (conv_id == (iconv_t)-1) {
		free(pstr_out);
		return NULL;
	}
	auto pin = deconst(pstring);
	auto pout = pstr_out;
	memset(pstr_out, 0, out_len);
	iconv(conv_id, &pin, &in_len, &pout, &out_len);
	iconv_close(conv_id);
	return pstr_out;
}

STRING_ARRAY *common_util_convert_copy_string_array(BOOL to_utf8,
    cpid_t cpid, const STRING_ARRAY *parray)
{
	auto parray1 = cu_alloc<STRING_ARRAY>();
	if (parray1 == nullptr)
		return NULL;
	parray1->count = parray->count;
	if (0 != parray->count) {
		parray1->ppstr = cu_alloc<char *>(parray->count);
		if (parray1->ppstr == nullptr)
			return NULL;
	} else {
		parray1->ppstr = NULL;
	}
	for (size_t i = 0; i < parray->count; ++i) {
		parray1->ppstr[i] = common_util_convert_copy(
					to_utf8, cpid, parray->ppstr[i]);
		if (parray1->ppstr[i] == nullptr)
			return NULL;
	}
	return parray1;
}

BOOL common_util_allocate_eid(sqlite3 *psqlite, uint64_t *peid)
{
	uint64_t cur_eid;
	uint64_t max_eid;
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_CURRENT_EID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	cur_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	*peid = cur_eid + 1;
	snprintf(sql_string, std::size(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_MAXIMUM_EID);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	max_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (cur_eid >= max_eid) {
		pstmt = gx_sql_prep(psqlite, "SELECT MAX(range_end) FROM allocated_eids");
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		cur_eid = sqlite3_column_int64(pstmt, 0);
		max_eid = cur_eid + ALLOCATED_EID_RANGE;
		pstmt.finalize();
		snprintf(sql_string, std::size(sql_string), "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lld, 1)",
		        LLU{cur_eid + 1}, LLU{max_eid}, LLD{time(nullptr)});
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, std::size(sql_string), "UPDATE configurations SET"
			" config_value=%llu WHERE config_id=%u",
			LLU{max_eid}, CONFIG_ID_MAXIMUM_EID);
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	} else {
		cur_eid ++;
	}
	snprintf(sql_string, std::size(sql_string), "UPDATE configurations SET"
		" config_value=%llu WHERE config_id=%u",
		LLU{cur_eid}, CONFIG_ID_CURRENT_EID);
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

BOOL common_util_allocate_eid_from_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t *peid)
{
	uint64_t cur_eid;
	uint64_t max_eid;
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT cur_eid, max_eid "
	          "FROM folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	*peid = sqlite3_column_int64(pstmt, 0);
	max_eid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	cur_eid = *peid + 1;
	if (cur_eid > max_eid) {
		pstmt = gx_sql_prep(psqlite, "SELECT MAX(range_end) FROM allocated_eids");
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		*peid = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		max_eid = *peid + ALLOCATED_EID_RANGE;
		cur_eid = *peid + 1;
		snprintf(sql_string, std::size(sql_string), "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %llu, 1)", LLU{cur_eid},
			LLU{max_eid}, LLD{time(nullptr)});
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	snprintf(sql_string, std::size(sql_string), "UPDATE folders SET cur_eid=%llu,"
		" max_eid=%llu WHERE folder_id=%llu", LLU{cur_eid},
		LLU{max_eid}, LLU{folder_id});
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

BOOL common_util_allocate_cn(sqlite3 *psqlite, uint64_t *pcn)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT config_value FROM "
				"configurations WHERE config_id=%u",
				CONFIG_ID_LAST_CHANGE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint64_t last_cn = pstmt.step() == SQLITE_ROW ?
	                   sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_cn ++;
	snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
				"configurations VALUES (%u, ?)",
				CONFIG_ID_LAST_CHANGE_NUMBER);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_cn);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	*pcn = last_cn;
	return TRUE;
}

BOOL common_util_allocate_folder_art(sqlite3 *psqlite, uint32_t *part)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint32_t last_art = pstmt.step() == SQLITE_ROW ?
	                    sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_art ++;
	snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
				"configurations VALUES (%u, ?)",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_art);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	*part = last_art;
	return TRUE;
}

BOOL common_util_check_allocated_eid(sqlite3 *psqlite,
	uint64_t eid_val, BOOL *pb_result)
{
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT range_begin,"
				" range_end FROM allocated_eids WHERE "
				"range_begin<=%llu AND range_end>=%llu",
				LLU{eid_val}, LLU{eid_val});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_result = pstmt.step() == SQLITE_ROW ? TRUE : false;
	return TRUE;
}

BOOL common_util_allocate_cid(sqlite3 *psqlite, uint64_t *pcid)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT config_value FROM "
		"configurations WHERE config_id=%u", CONFIG_ID_LAST_CID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint64_t last_cid = pstmt.step() == SQLITE_ROW ?
	                    sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_cid ++;
	snprintf(sql_string, std::size(sql_string), "REPLACE INTO configurations"
					" VALUES (%u, ?)", CONFIG_ID_LAST_CID);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_cid);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	*pcid = last_cid;
	return TRUE;
}

BOOL common_util_begin_message_optimize(sqlite3 *psqlite, const char *src)
{
	if (g_opt_key != nullptr) {
		mlog(LV_ERR, "E-1229: cannot satisfy nested common_util_begin_message_optimize call (previous: %s, new: %s)",
			znul(g_opt_key_src), znul(src));
		return TRUE;
	}
	std::unique_ptr<prepared_statements> op(new(std::nothrow) prepared_statements);
	if (op == nullptr)
		return FALSE;
	op->msg_norm = gx_sql_prep(psqlite, "SELECT propval"
	               " FROM message_properties WHERE "
	               "message_id=? AND proptag=?");
	if (op->msg_norm == nullptr)
		return FALSE;
	op->msg_str = gx_sql_prep(psqlite, "SELECT proptag, "
	              "propval FROM message_properties WHERE "
	              "message_id=? AND proptag IN (?,?)");
	if (op->msg_str == nullptr)
		return FALSE;
	op->rcpt_norm = gx_sql_prep(psqlite, "SELECT propval "
	                "FROM recipients_properties WHERE "
	                "recipient_id=? AND proptag=?");
	if (op->rcpt_norm == nullptr)
		return FALSE;
	op->rcpt_str = gx_sql_prep(psqlite, "SELECT proptag, propval"
	               " FROM recipients_properties WHERE recipient_id=?"
	               " AND proptag IN (?,?)");
	if (op->rcpt_str == nullptr)
		return FALSE;
	g_opt_key = op.release();
	g_opt_key_src = src;
	return TRUE;
}

void common_util_end_message_optimize()
{
	auto op = g_opt_key;
	if (op == nullptr)
		return;
	g_opt_key = nullptr;
	g_opt_key_src = nullptr;
	delete op;
}

static sqlite3_stmt *
cu_get_optimize_stmt(mapi_object_type table_type, bool b_normal)
{
	if (table_type != MAPI_MESSAGE && table_type != MAPI_MAILUSER)
		return NULL;	
	auto op = g_opt_key;
	if (op == nullptr)
		return NULL;
	if (table_type == MAPI_MESSAGE)
		return b_normal ? op->msg_norm : op->msg_str;
	return b_normal ? op->rcpt_norm : op->rcpt_str;
}

/**
 * A property can only have one type, so do some filtering in case the database
 * has gunk. (We implicitly depend on PT_UNICODE > PT_STRING8 being the case to
 * prefer Unicode over 8-bit strings.)
 *
 * Prerequisites:
 * Elements in first..last with the same PROP_ID(x) are adjacent.
 */
template<typename F> static F coalesce_propid(F first, F last)
{
	for (auto it = first; it != last; ) {
		auto nx = std::next(it);
		auto rm = nx != last && PROP_ID(*it) == PROP_ID(*nx);
		if (!rm)
			*first++ = *it;
		it = nx;
	}
	return first;
}

BOOL cu_get_proptags(mapi_object_type table_type, uint64_t id, sqlite3 *psqlite,
    std::vector<uint32_t> &tags) try
{
	/*
	 * All computed/synthesized tags should appear in these tag lists (XXX:
	 * but needs more research to which extent), because this function is
	 * used to feed rop_getallproptags (IMAPIProp::GetPropList) and
	 * exmdb_server::read_message, so it's not just for the default columns
	 * of content tables.
	 */
	static constexpr uint32_t folder_tags[] = {
		PR_ASSOC_CONTENT_COUNT, PR_CONTENT_COUNT,
		PR_MESSAGE_SIZE_EXTENDED, PR_ASSOC_MESSAGE_SIZE_EXTENDED,
		PR_NORMAL_MESSAGE_SIZE_EXTENDED, PR_FOLDER_CHILD_COUNT,
		PR_FOLDER_TYPE, PR_CONTENT_UNREAD, PR_SUBFOLDERS, PR_HAS_RULES,
		PR_FOLDER_PATHNAME, PR_LOCAL_COMMIT_TIME, PidTagFolderId,
		PidTagChangeNumber, PR_FOLDER_FLAGS,
	};
	static constexpr uint32_t msg_tags[] = {
		PidTagMid, PR_MESSAGE_SIZE, PR_ASSOCIATED, PidTagChangeNumber,
		PR_READ, PR_HASATTACH, PR_MESSAGE_FLAGS, PR_DISPLAY_TO,
		PR_DISPLAY_CC, PR_DISPLAY_BCC, PR_MESSAGE_CLASS,
	};
	static constexpr uint32_t rcpt_tags[] = {
		/*
		 * We could also synthesize PR_OBJECT_TYPE, PR_DISPLAY_TYPE,
		 * though their presence seems to be not strictly necessary.
		 */
		PR_RECIPIENT_TYPE, PR_DISPLAY_NAME, PR_ADDRTYPE, PR_EMAIL_ADDRESS,
	};
	BOOL b_subject;
	char sql_string[128];
	tags.clear();
	tags.reserve(std::size(folder_tags) + 1);

	switch (table_type) {
	case MAPI_STORE:
		gx_strlcpy(sql_string, "SELECT proptag FROM store_properties", std::size(sql_string));
		tags.push_back(PR_INTERNET_ARTICLE_NUMBER);
		break;
	case MAPI_FOLDER:
		snprintf(sql_string, std::size(sql_string), "SELECT proptag FROM "
		        "folder_properties WHERE folder_id=%llu", LLU{id});
		tags.insert(tags.end(), std::begin(folder_tags), std::end(folder_tags));
		break;
	case MAPI_MESSAGE:
		snprintf(sql_string, std::size(sql_string), "SELECT proptag FROM "
		        "message_properties WHERE message_id=%llu AND proptag NOT IN (0x0e05001e,0x0e05001f)", LLU{id});
		tags.insert(tags.end(), std::begin(msg_tags), std::end(msg_tags));
		break;
	case MAPI_MAILUSER:
		snprintf(sql_string, std::size(sql_string), "SELECT proptag FROM "
		        "recipients_properties WHERE recipient_id=%llu", LLU{id});
		tags.insert(tags.end(), std::begin(rcpt_tags), std::end(rcpt_tags));
		break;
	case MAPI_ATTACH:
		snprintf(sql_string, std::size(sql_string), "SELECT proptag FROM "
		        "attachment_properties WHERE attachment_id=%llu", LLU{id});
		tags.push_back(PR_RECORD_KEY);
		break;
	default:
		assert(!"Unknown table_type");
		return false;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	b_subject = FALSE;
	while (pstmt.step() == SQLITE_ROW && tags.size() < 0xfff0) {
		auto tag = pstmt.col_uint64(0);
		if (PROP_ID(tag) == PROP_ID(PR_NULL))
			continue;
		if (table_type == MAPI_MESSAGE && !b_subject) {
			if (tag == PR_NORMALIZED_SUBJECT ||
			    tag == PR_SUBJECT_PREFIX) {
				b_subject = TRUE;
				tags.push_back(tag);
				tag = PR_SUBJECT;
			} else if (tag == PR_NORMALIZED_SUBJECT_A ||
			    tag == PR_SUBJECT_PREFIX_A) {
				b_subject = TRUE;
				tags.push_back(tag);
				tag = PR_SUBJECT_A;
			}
		}
		tags.push_back(tag);
	}
	pstmt.finalize();
	std::sort(tags.begin(), tags.end());
	tags.erase(coalesce_propid(tags.begin(), tags.end()), tags.end());
	if (table_type == MAPI_MAILUSER) {
		auto i = std::find(tags.begin(), tags.end(), PR_ENTRYID);
		if (i != tags.end())
			tags.erase(i);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1161: ENOMEM");
	return false;
}

static BINARY* common_util_get_mailbox_guid(sqlite3 *psqlite)
{
	GUID tmp_guid;
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%d",
				CONFIG_ID_MAILBOX_GUID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return NULL;
	if (!tmp_guid.from_str(pstmt.col_text(0)))
		return NULL;
	pstmt.finalize();
	auto ptmp_bin = cu_alloc<BINARY>();
	if (ptmp_bin == nullptr)
		return NULL;
	ptmp_bin->pv = common_util_alloc(16);
	if (ptmp_bin->pv == nullptr)
		return NULL;
	ptmp_bin->cb = 0;
	rop_util_guid_to_binary(tmp_guid, ptmp_bin);
	return ptmp_bin;
}

static uint32_t common_util_get_store_state(sqlite3 *psqlite)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%d",
				CONFIG_ID_SEARCH_STATE);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || pstmt.step() != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

BOOL common_util_get_mapping_guid(sqlite3 *psqlite,
	uint16_t replid, BOOL *pb_found, GUID *pguid)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT replguid FROM "
		"replca_mapping WHERE replid=%d", (int)replid);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*pb_found = FALSE;
		return TRUE;
	}
	if (!pguid->from_str(pstmt.col_text(0))) {
		mlog(LV_ERR, "E-1621: illegal GUID in dataset");
		return false;
	}
	*pb_found = TRUE;
	return TRUE;
}

static uint32_t common_util_calculate_childcount(
	uint32_t folder_id, sqlite3 *psqlite)
{
	uint32_t count;
	char sql_string[80];
	
	count = 0;
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM "
	          "folders WHERE parent_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	while (pstmt.step() == SQLITE_ROW) {
		count += common_util_calculate_childcount(
			sqlite3_column_int64(pstmt, 0), psqlite);
		count ++;
	}
	return count;
}

static BOOL common_util_check_subfolders(
	sqlite3 *psqlite, uint32_t folder_id)
{
	char sql_string[80];
	
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM"
	         " folders WHERE parent_id=%llu AND is_deleted=0", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && pstmt.step() == SQLITE_ROW ? TRUE : false;
}

static char *common_util_calculate_folder_path(uint32_t folder_id,
    sqlite3 *psqlite) try
{
	uint64_t tmp_fid;
	char sql_string[128];
	std::string path;
	
	tmp_fid = folder_id;
	auto b_private = exmdb_server::is_private();
	while (true) {
		snprintf(sql_string, std::size(sql_string), "SELECT propval FROM"
				" folder_properties WHERE proptag=%u AND "
		        "folder_id=%llu", PR_DISPLAY_NAME, LLU{tmp_fid});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return NULL;
		auto dnlen = sqlite3_column_bytes(pstmt, 0);
		if (dnlen == 0 || dnlen > 255 || path.size() + dnlen + 1 >= 4096)
			return nullptr;
		auto dispname = pstmt.col_text(0);
		if (dispname == nullptr)
			return nullptr;
		path.insert(0, dispname);
		path.insert(0, "\\");
		if ((b_private && tmp_fid == PRIVATE_FID_ROOT) ||
		    (!b_private && tmp_fid == PUBLIC_FID_ROOT))
			break;
		snprintf(sql_string, std::size(sql_string), "SELECT parent_id FROM "
		          "folders WHERE folder_id=%llu", LLU{tmp_fid});
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return NULL;
		tmp_fid = sqlite3_column_int64(pstmt, 0);
	}
	return common_util_dup(path.c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1155: ENOMEM");
	return nullptr;
}

BOOL common_util_check_msgcnt_overflow(sqlite3 *psqlite)
{
	char sql_string[64];
	
	if (g_max_msg == 0)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT "
		"count(message_id) FROM messages");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return false;
	auto c = pstmt.col_uint64(0);
	mlog(LV_DEBUG, "D-1681: %llu messages <=> max_store_message_count %u",
		LLU{c}, g_max_msg);
	return c >= g_max_msg ? TRUE : false;
}

BOOL cu_check_msgsize_overflow(sqlite3 *psqlite, uint32_t qtag)
{
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[2];
	
	proptags.count = 2;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = qtag;
	proptag_buff[1] = PR_MESSAGE_SIZE_EXTENDED;
	if (!cu_get_properties(MAPI_STORE, 0, CP_ACP, psqlite,
	    &proptags, &propvals))
		return FALSE;
	/* Another checking point is in midb, CKFL */
	auto ptotal = propvals.get<uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	auto qv_kb = propvals.get<uint32_t>(qtag);
	if (ptotal == nullptr || qv_kb == nullptr)
		return false;
	auto qvbytes = static_cast<uint64_t>(*qv_kb) * 1024;
	mlog(LV_DEBUG, "D-1680: storesize %llu <=> quota(%xh) %llu bytes",
		LLU{*ptotal}, XUI{qtag}, LLU{qvbytes});
	return *ptotal >= qvbytes;
}

static uint32_t cu_get_store_msgcount(sqlite3 *psqlite, unsigned int flags)
{
	char sql_string[70];
	
	snprintf(sql_string, std::size(sql_string),
	         "SELECT COUNT(*) FROM messages WHERE is_associated=%u AND is_deleted=%u",
	         !!(flags & TABLE_FLAG_ASSOCIATED),
	         !!(flags & TABLE_FLAG_SOFTDELETES));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || pstmt.step() != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

static uint32_t common_util_get_store_article_number(sqlite3 *psqlite)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || pstmt.step() != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

static uint32_t cu_folder_count(sqlite3 *psqlite, uint64_t folder_id,
    unsigned int flags = 0)
{
	uint32_t folder_type;
	char sql_string[168];
	const bool del   = flags & TABLE_FLAG_SOFTDELETES;
	const bool assoc = flags & TABLE_FLAG_ASSOCIATED;
	
	if (common_util_get_folder_type(psqlite, folder_id, &folder_type) &&
	    folder_type == FOLDER_SEARCH)
		snprintf(sql_string, std::size(sql_string),
		         "SELECT COUNT(*) FROM messages AS m "
		         "JOIN search_result AS s ON s.folder_id=%llu "
		         "AND s.message_id=m.message_id AND m.is_deleted=%u "
		         "AND m.is_associated=%u",
		         LLU{folder_id}, del, assoc);
	else
		snprintf(sql_string, std::size(sql_string),
		         "SELECT COUNT(*) FROM messages AS m "
		         "WHERE parent_fid=%llu AND is_deleted=%u AND "
		         "is_associated=%u",
		         LLU{folder_id}, del, assoc);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || pstmt.step() != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

uint32_t cu_folder_unread_count(sqlite3 *psqlite, uint64_t folder_id,
    unsigned int flags)
{
	uint32_t folder_type;
	char sql_string[192];
	const bool del   = flags & TABLE_FLAG_SOFTDELETES;
	const bool assoc = flags & TABLE_FLAG_ASSOCIATED;
	
	if (exmdb_server::is_private()) {
		if (common_util_get_folder_type(psqlite, folder_id, &folder_type) &&
		    folder_type == FOLDER_SEARCH)
			snprintf(sql_string, std::size(sql_string),
			         "SELECT COUNT(*) FROM messages AS m "
			         "JOIN search_result AS s ON s.folder_id=%llu "
			         "AND s.message_id=m.message_id AND m.read_state=0 "
			         "AND m.is_deleted=%u AND m.is_associated=%u",
			         LLU{folder_id}, del, assoc);
		else
			snprintf(sql_string, std::size(sql_string),
			         "SELECT COUNT(*) FROM messages AS m "
			         "WHERE parent_fid=%llu AND read_state=0 "
			         "AND is_deleted=%u AND is_associated=%u",
			         LLU{folder_id}, del, assoc);
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		return pstmt == nullptr || pstmt.step() != SQLITE_ROW ? 0 :
		       sqlite3_column_int64(pstmt, 0);
	}
	auto username = exmdb_pf_read_per_user ? exmdb_server::get_public_username() : "";
	if (username == nullptr)
		return 0;
	snprintf(sql_string, std::size(sql_string),
	         "SELECT COUNT(*) FROM messages AS m WHERE parent_fid=%llu "
	         "AND is_deleted=%u AND is_associated=%u",
	         LLU{folder_id}, del, assoc);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return 0;
	auto count = pstmt.col_uint64(0);
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string),
	         "SELECT COUNT(*) FROM read_states AS rs JOIN messages AS m "
	         "ON rs.username=? AND m.parent_fid=%llu "
	         "AND m.message_id=rs.message_id AND m.is_deleted=%u "
	         "AND m.is_associated=%u", LLU{folder_id}, del, assoc);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	if (pstmt.step() != SQLITE_ROW)
		return 0;
	auto have_read = pstmt.col_uint64(0);
	if (have_read > count)
		mlog(LV_WARN, "W-1665: fid %llxh inconsistent read states for %s: %lld > %lld",
		        LLU{folder_id}, username, LLU{have_read}, LLU{count});
	return count - std::min(count, have_read);
}

static uint64_t common_util_get_folder_message_size(
	sqlite3 *psqlite, uint64_t folder_id, BOOL b_normal,
	BOOL b_associated)
{
	uint32_t folder_type;
	char sql_string[256];
	
	if (common_util_get_folder_type(psqlite, folder_id, &folder_type) &&
	    folder_type == FOLDER_SEARCH) {
		if (b_normal && b_associated)
			snprintf(sql_string, std::size(sql_string), "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id",
				LLU{folder_id});
		else if (b_normal)
			snprintf(sql_string, std::size(sql_string), "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id"
				" AND messages.is_associated=0", LLU{folder_id});
		else if (b_associated)
			snprintf(sql_string, std::size(sql_string), "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id"
				" AND messages.is_associated=1", LLU{folder_id});
		else
			return 0;
	} else {
		if (b_normal && b_associated)
			snprintf(sql_string, std::size(sql_string), "SELECT sum(message_size) "
			          "FROM messages WHERE parent_fid=%llu", LLU{folder_id});
		else if (b_normal)
			snprintf(sql_string, std::size(sql_string), "SELECT sum(message_size) "
						"FROM messages WHERE parent_fid=%llu AND "
						"is_associated=0", LLU{folder_id});
						
		else if (b_associated)
			snprintf(sql_string, std::size(sql_string), "SELECT sum(message_size) "
						"FROM messages WHERE parent_fid=%llu AND "
						"is_associated=1", LLU{folder_id});
		else
			return 0;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || pstmt.step() != SQLITE_ROW ? 0 :
	       gx_sql_col_uint64(pstmt, 0);
}

BOOL common_util_get_folder_type(sqlite3 *psqlite, uint64_t folder_id,
    uint32_t *pfolder_type, const char *dir)
{
	char sql_string[128];
	
	if (!exmdb_server::is_private()) {
		*pfolder_type = folder_id == PUBLIC_FID_ROOT ? FOLDER_ROOT : FOLDER_GENERIC;
		return TRUE;
	}
	if (PRIVATE_FID_ROOT == folder_id) {
		*pfolder_type = FOLDER_ROOT;
		return TRUE;
	}
	snprintf(sql_string, std::size(sql_string), "SELECT is_search "
	         "FROM folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW)
		/*
		 * Could be if db_engine_proc_dynamic_event was just
		 * looking at a folder a moment ago that then was
		 * deleted.
		 */
		return FALSE;
	*pfolder_type = sqlite3_column_int64(pstmt, 0) == 0 ? FOLDER_GENERIC : FOLDER_SEARCH;
	return TRUE;
}

static BOOL common_util_check_folder_rules(
	sqlite3 *psqlite, uint64_t folder_id)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM "
	          "rules WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && pstmt.step() == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) > 0 ? TRUE : false;
}

static uint32_t common_util_get_folder_flags(
	sqlite3 *psqlite, uint64_t folder_id)
{
	BOOL b_included;
	uint32_t folder_type;
	uint32_t folder_flags;
	
	folder_flags = 0;
	if (common_util_get_folder_type(psqlite, folder_id, &folder_type))
		folder_flags |= folder_type == FOLDER_SEARCH ? FOLDER_FLAGS_SEARCH : FOLDER_FLAGS_NORMAL;
	if (common_util_check_folder_rules(psqlite, folder_id))
		folder_flags |= FOLDER_FLAGS_RULES;
	if (exmdb_server::is_private()) {
		if (common_util_check_descendant(psqlite, folder_id,
		    PRIVATE_FID_IPMSUBTREE, &b_included) && b_included)
			folder_flags |= FOLDER_FLAGS_IPM;
	} else {
		if (common_util_check_descendant(psqlite, folder_id,
		    PUBLIC_FID_IPMSUBTREE, &b_included) && b_included)
			folder_flags |= FOLDER_FLAGS_IPM;
	}
	return folder_flags;
}

static uint64_t common_util_get_message_size(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT message_size FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || pstmt.step() != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

uint64_t common_util_get_folder_parent_fid(
	sqlite3 *psqlite, uint64_t folder_id)
{
	uint64_t parent_fid;
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT parent_id FROM "
	          "folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return 0;
	parent_fid = sqlite3_column_int64(pstmt, 0);
	return parent_fid != 0 ? parent_fid : folder_id;
}

static uint64_t common_util_get_folder_changenum(
	sqlite3 *psqlite, uint64_t folder_id)
{
	uint64_t change_num;
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT change_number FROM "
	          "folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return 0;
	change_num = sqlite3_column_int64(pstmt, 0);
	return rop_util_make_eid_ex(1, change_num);
}

BOOL common_util_get_folder_by_name(
	sqlite3 *psqlite, uint64_t parent_id,
	const char *str_name, uint64_t *pfolder_id)
{
	uint64_t tmp_val;
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id "
	          "FROM folders WHERE parent_id=%llu", LLU{parent_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT propval "
		"FROM folder_properties WHERE folder_id=?"
	        " AND proptag=%u", PR_DISPLAY_NAME);
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	*pfolder_id = 0;
	while (pstmt.step() == SQLITE_ROW) {
		tmp_val = sqlite3_column_int64(pstmt, 0);
		sqlite3_bind_int64(pstmt1, 1, tmp_val);
		if (gx_sql_step(pstmt1) == SQLITE_ROW &&
		    strcasecmp(str_name, pstmt1.col_text(0)) == 0) {
			*pfolder_id = tmp_val;
			break;
		}
		sqlite3_reset(pstmt1);
	}
	return TRUE;
}

static BINARY *cu_fid_to_entryid(sqlite3 *psqlite, uint64_t folder_id)
{
	BOOL b_found;
	uint16_t replid;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	auto account_id = exmdb_server::get_account_id();
	if (account_id < 0)
		return NULL;
	tmp_entryid.flags = 0;
	if (exmdb_server::is_private()) {
		auto pbin = common_util_get_mailbox_guid(psqlite);
		if (pbin == nullptr)
			return NULL;
		memcpy(&tmp_entryid.provider_uid, pbin->pb, 16);
		tmp_entryid.database_guid =
			rop_util_make_user_guid(account_id);
		tmp_entryid.folder_type = EITLT_PRIVATE_FOLDER;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		replid = folder_id >> 48;
		if (replid == 0)
			tmp_entryid.database_guid =
				rop_util_make_domain_guid(account_id);
		else if (!common_util_get_mapping_guid(psqlite, replid,
		    &b_found, &tmp_entryid.database_guid) || !b_found)
			return NULL;
		tmp_entryid.folder_type = EITLT_PUBLIC_FOLDER;
	}
	tmp_entryid.global_counter = rop_util_value_to_gc(folder_id);
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

static BINARY *cu_mid_to_entryid(sqlite3 *psqlite, uint64_t message_id)
{
	EXT_PUSH ext_push;
	uint64_t folder_id;
	MESSAGE_ENTRYID tmp_entryid;
	
	if (!common_util_get_message_parent_folder(psqlite, message_id, &folder_id))
		return NULL;	
	auto account_id = exmdb_server::get_account_id();
	if (account_id < 0)
		return NULL;
	tmp_entryid.flags = 0;
	if (exmdb_server::is_private()) {
		auto pbin = common_util_get_mailbox_guid(psqlite);
		if (pbin == nullptr)
			return NULL;
		memcpy(&tmp_entryid.provider_uid, pbin->pb, 16);
		tmp_entryid.folder_database_guid =
			rop_util_make_user_guid(account_id);
		tmp_entryid.message_type = EITLT_PRIVATE_MESSAGE;
	} else {
		tmp_entryid.provider_uid = pbLongTermNonPrivateGuid;
		tmp_entryid.folder_database_guid =
			rop_util_make_domain_guid(account_id);
		tmp_entryid.message_type = EITLT_PUBLIC_MESSAGE;
	}
	tmp_entryid.message_database_guid = tmp_entryid.folder_database_guid;
	tmp_entryid.folder_global_counter = rop_util_value_to_gc(folder_id);
	tmp_entryid.message_global_counter = rop_util_value_to_gc(message_id);
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

BOOL common_util_check_message_associated(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT is_associated FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && pstmt.step() == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static BOOL common_util_check_message_named_properties(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT proptag"
				" FROM message_properties WHERE "
				"message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW)
		if (sqlite3_column_int64(pstmt, 0) & 0x8000)
			return TRUE;
	return FALSE;
}

static BOOL common_util_check_message_has_attachments(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM "
	          "attachments WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && pstmt.step() == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static BOOL common_util_check_message_read(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	if (!exmdb_server::is_private()) {
		auto username = exmdb_pf_read_per_user ? exmdb_server::get_public_username() : "";
		if (username == nullptr)
			return FALSE;
		snprintf(sql_string, std::size(sql_string), "SELECT message_id"
				" FROM read_states WHERE username=? AND "
				"message_id=%llu", LLU{message_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		return pstmt.step() == SQLITE_ROW ? TRUE : false;
	}
	snprintf(sql_string, std::size(sql_string), "SELECT read_state FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && pstmt.step() == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static uint64_t common_util_get_message_changenum(
	sqlite3 *psqlite, uint64_t message_id)
{
	uint64_t change_num;
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT change_number FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return 0;
	change_num = sqlite3_column_int64(pstmt, 0);
	return rop_util_make_eid_ex(1, change_num);
}

BOOL common_util_get_message_flags(sqlite3 *psqlite,
	uint64_t message_id, BOOL b_native,
	uint32_t **ppmessage_flags)
{
	auto pstmt = cu_get_optimize_stmt(MAPI_MESSAGE, true);
	xstmt own_stmt;
	if (NULL != pstmt) {
		sqlite3_reset(pstmt);
	} else {
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM message_properties WHERE message_id=?"
		           " AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
	}
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_int64(pstmt, 2, PR_MESSAGE_FLAGS);
	uint32_t message_flags = gx_sql_step(pstmt) == SQLITE_ROW ?
	                         sqlite3_column_int64(pstmt, 0) : 0;
	message_flags &= ~(MSGFLAG_READ | MSGFLAG_HASATTACH | MSGFLAG_FROMME |
	                 MSGFLAG_ASSOCIATED | MSGFLAG_RN_PENDING | MSGFLAG_NRN_PENDING);
	if (!b_native) {
		if (common_util_check_message_read(psqlite, message_id))
			message_flags |= MSGFLAG_READ;
		if (common_util_check_message_has_attachments(psqlite, message_id))
			message_flags |= MSGFLAG_HASATTACH;
		if (common_util_check_message_associated(psqlite, message_id))
			message_flags |= MSGFLAG_ASSOCIATED;
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PR_READ_RECEIPT_REQUESTED);
		if (gx_sql_step(pstmt) == SQLITE_ROW)
			if (sqlite3_column_int64(pstmt, 0) != 0)
				message_flags |= MSGFLAG_RN_PENDING;
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
		if (gx_sql_step(pstmt) == SQLITE_ROW)
			if (sqlite3_column_int64(pstmt, 0) != 0)
				message_flags |= MSGFLAG_NRN_PENDING;
	}
	own_stmt.finalize();
	*ppmessage_flags = cu_alloc<uint32_t>();
	if (*ppmessage_flags == nullptr)
		return FALSE;
	**ppmessage_flags = message_flags;
	return TRUE;
}

static void* common_util_get_message_parent_display(
	sqlite3 *psqlite, uint64_t message_id)
{
	void *pvalue;
	uint64_t folder_id;
	
	if (!common_util_get_message_parent_folder(psqlite, message_id, &folder_id))
		return NULL;	
	if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP,
	    psqlite, PR_DISPLAY_NAME, &pvalue))
		return NULL;	
	return pvalue;
}

/**
 * The idea here is that, when PR_SUBJECT is read, it is always synthesized
 * from its constituent parts (PR_SUBJECT_PREFIX, PR_NORMALIZED_SUBJECT).
 * Conversely, writes to PR_SUBJECT are intercepted and split up.
 */
static BOOL common_util_get_message_subject(sqlite3 *psqlite, cpid_t cpid,
    uint64_t message_id, uint32_t proptag, void **ppvalue)
{
	const char *psubject_prefix, *pnormalized_subject;
	
	psubject_prefix = NULL;
	pnormalized_subject = NULL;
	auto pstmt = cu_get_optimize_stmt(MAPI_MESSAGE, true);
	xstmt own_stmt;
	if (NULL != pstmt) {
		sqlite3_reset(pstmt);
	} else {
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM message_properties WHERE message_id=?"
		           " AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
	}
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_int64(pstmt, 2, PR_NORMALIZED_SUBJECT);
	if (gx_sql_step(pstmt) == SQLITE_ROW) {
		pnormalized_subject = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
		if (pnormalized_subject == nullptr)
			return FALSE;
	} else {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PR_NORMALIZED_SUBJECT_A);
		if (gx_sql_step(pstmt) == SQLITE_ROW)
			pnormalized_subject =
				common_util_convert_copy(TRUE, cpid,
				S2A(sqlite3_column_text(pstmt, 0)));
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_int64(pstmt, 2, PR_SUBJECT_PREFIX);
	if (gx_sql_step(pstmt) == SQLITE_ROW) {
		psubject_prefix = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
		if (psubject_prefix == nullptr)
			return FALSE;
	} else {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PR_SUBJECT_PREFIX_A);
		if (gx_sql_step(pstmt) == SQLITE_ROW)
			psubject_prefix =
				common_util_convert_copy(TRUE, cpid,
				S2A(sqlite3_column_text(pstmt, 0)));
	}
	own_stmt.finalize();
	if (pnormalized_subject == nullptr)
		pnormalized_subject = "";
	if (psubject_prefix == nullptr)
		psubject_prefix = "";
	auto pvalue = cu_alloc<char>(strlen(pnormalized_subject) + strlen(psubject_prefix) + 1);
	if (pvalue == nullptr)
		return FALSE;
	strcpy(pvalue, psubject_prefix);
	strcat(pvalue, pnormalized_subject);
	if (PROP_TYPE(proptag) == PT_UNICODE)
		*ppvalue = common_util_dup(pvalue);
	else
		*ppvalue = common_util_convert_copy(FALSE, cpid, pvalue);
	return TRUE;
}
	
static BOOL common_util_get_message_display_recipients(sqlite3 *psqlite,
    cpid_t cpid, uint64_t message_id, uint32_t proptag, void **ppvalue) try
{
	void *pvalue;
	uint64_t rcpt_id;
	char sql_string[256];
	std::string dr;
	uint32_t recipient_type = 0;
	static const uint8_t fake_empty = 0;
	
	switch (proptag) {
	case PR_DISPLAY_TO:
	case PR_DISPLAY_TO_A:
		recipient_type = MAPI_TO;
		break;
	case PR_DISPLAY_CC:
	case PR_DISPLAY_CC_A:
		recipient_type = MAPI_CC;
		break;
	case PR_DISPLAY_BCC:
	case PR_DISPLAY_BCC_A:
		recipient_type = MAPI_BCC;
		break;
	}
	snprintf(sql_string, std::size(sql_string), "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		rcpt_id = sqlite3_column_int64(pstmt, 0);
		if (!cu_get_property(MAPI_MAILUSER, rcpt_id, CP_ACP, psqlite,
		    PR_RECIPIENT_TYPE, &pvalue))
			return FALSE;
		if (pvalue == nullptr || *static_cast<uint32_t *>(pvalue) != recipient_type)
			continue;
		if (!cu_get_property(MAPI_MAILUSER,
		    rcpt_id, cpid, psqlite, PR_DISPLAY_NAME, &pvalue))
			return FALSE;	
		if (pvalue == nullptr && !cu_get_property(MAPI_MAILUSER,
		    rcpt_id, cpid, psqlite, PR_SMTP_ADDRESS, &pvalue))
			return FALSE;
		if (pvalue == nullptr)
			continue;
		if (!dr.empty())
			dr += "; ";
		dr += static_cast<const char *>(pvalue);
	}
	pstmt.finalize();
	if (dr.empty()) {
		*ppvalue = deconst(&fake_empty);
		return TRUE;
	}
	*ppvalue = PROP_TYPE(proptag) == PT_UNICODE ? common_util_dup(dr.c_str()) :
	           common_util_convert_copy(false, cpid, dr.c_str());
	return *ppvalue != nullptr ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1159: ENOMEM");
	return false;
}

std::string cu_cid_path(const char *dir, const char *id, unsigned int type) try
{
	if (dir == nullptr)
		dir = exmdb_server::get_dir();
	auto path = dir + "/cid/"s + id;
	if (type == 2)
		path += ".zst";
	else if (type == 1)
		path += ".v1z";
	return path;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1608: ENOMEM");
	return {};
}

static void *cu_get_object_text_v0(const char *dir, const char *cid, uint32_t, uint32_t, cpid_t);

static void *cu_get_object_text_vx(const char *dir, const char *cid,
    uint32_t proptag, uint32_t db_proptag, cpid_t cpid, unsigned int type)
{
	BINARY dxbin{};
	errno = gx_decompress_file(cu_cid_path(dir, cid, type).c_str(), dxbin,
	        common_util_alloc, [](void *, size_t z) { return common_util_alloc(z); });
	if (errno != 0)
		return nullptr;

	if (PROP_TYPE(proptag) == PT_BINARY || PROP_TYPE(proptag) == PT_OBJECT) {
		auto bin = cu_alloc<BINARY>();
		if (bin == nullptr)
			return nullptr;
		*bin = std::move(dxbin);
		return bin;
	} else if (type == 1 && PROP_TYPE(db_proptag) == PT_UNICODE) {
		if (dxbin.cb < 4)
			return nullptr;
		dxbin.pc += 4;
	}
	if (proptag == db_proptag)
		/* Requested proptag already matches the type found in the DB */
		return dxbin.pv;
	return common_util_convert_copy(PROP_TYPE(proptag) == PT_STRING8 ? TRUE : false,
	       cpid, dxbin.pc);
}

static void *cu_get_object_text(sqlite3 *psqlite,
    cpid_t cpid, uint64_t message_id, uint32_t proptag) try
{
	char sql_string[128];
	
	auto dir = exmdb_server::get_dir();
	if (dir == nullptr)
		return NULL;
	if (proptag == PR_BODY || proptag == PR_BODY_A)
		snprintf(sql_string, std::size(sql_string), "SELECT proptag, propval "
		         "FROM message_properties WHERE message_id=%llu AND"
		         " proptag IN (%u,%u)",
		         LLU{message_id}, PR_BODY, PR_BODY_A);
	else if (proptag == PR_TRANSPORT_MESSAGE_HEADERS ||
	    proptag == PR_TRANSPORT_MESSAGE_HEADERS_A)
		snprintf(sql_string, std::size(sql_string), "SELECT proptag, propval "
		         "FROM message_properties WHERE message_id=%llu AND"
		         " proptag IN (%u,%u)",
		         LLU{message_id}, PR_TRANSPORT_MESSAGE_HEADERS,
		         PR_TRANSPORT_MESSAGE_HEADERS_A);
	else if (proptag == PR_HTML || proptag == PR_RTF_COMPRESSED)
		snprintf(sql_string, std::size(sql_string), "SELECT proptag, propval FROM "
		         "message_properties WHERE message_id=%llu AND "
		         "proptag=%u", LLU{message_id}, XUI{proptag});
	else if (proptag == PR_ATTACH_DATA_BIN || proptag == PR_ATTACH_DATA_OBJ)
		snprintf(sql_string, std::size(sql_string), "SELECT proptag, propval FROM "
		         "attachment_properties WHERE attachment_id=%llu"
		         " AND proptag=%u", LLU{message_id}, XUI{proptag});
	else
		return nullptr;

	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return nullptr;
	uint32_t proptag1 = sqlite3_column_int64(pstmt, 0);
	std::string cid = pstmt.col_text(1);
	pstmt.finalize();

	if (strchr(cid.c_str(), '/') != nullptr) {
		/* v3 */
		auto blk = cu_get_object_text_vx(dir, cid.c_str(), proptag, proptag1, cpid, 0);
		if (blk != nullptr)
			return blk;
		return nullptr;
	}
	auto blk = cu_get_object_text_vx(dir, cid.c_str(), proptag, proptag1, cpid, 2);
	if (blk != nullptr)
		return blk;
	if (errno != ENOENT)
		return nullptr;
	blk = cu_get_object_text_vx(dir, cid.c_str(), proptag, proptag1, cpid, 1);
	if (blk != nullptr)
		return blk;
	if (errno != ENOENT)
		return nullptr;
	return cu_get_object_text_v0(dir, cid.c_str(), proptag, proptag1, cpid);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2387: ENOMEM");
	return nullptr;
}

static void *cu_get_object_text_v0(const char *dir, const char *cid,
    uint32_t proptag, uint32_t proptag1, cpid_t cpid)
{
	wrapfd fd = open(cu_cid_path(dir, cid, 0).c_str(), O_RDONLY);
	struct stat node_stat;
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
		return nullptr;
	if (!S_ISREG(node_stat.st_mode)) {
		errno = ENOENT;
		return nullptr;
	}
#if defined(HAVE_POSIX_FADVISE)
	if (posix_fadvise(fd.get(), 0, node_stat.st_size, POSIX_FADV_SEQUENTIAL) != 0)
		/* ignore */;
#endif
	/*
	 * Tack on a NUL for the sake of string functions which may process
	 * pbuff down the road.
	 */
	auto pbuff = cu_alloc<char>(node_stat.st_size + 1);
	if (NULL == pbuff) {
		mlog(LV_ERR, "E-1626: ENOMEM");
		return NULL;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size)
		return NULL;
	pbuff[node_stat.st_size] = 0;
	if (PROP_TYPE(proptag) == PT_BINARY || PROP_TYPE(proptag) == PT_OBJECT) {
		auto bin = cu_alloc<BINARY>();
		if (bin == nullptr)
			return nullptr;
		bin->cb = node_stat.st_size;
		bin->pv = pbuff;
		return bin;
	}
	if (PROP_TYPE(proptag1) == PT_UNICODE)
		pbuff += sizeof(uint32_t);
	if (proptag == proptag1)
		/* Requested proptag already matches the type found in the DB */
		return pbuff;
	return common_util_convert_copy(PROP_TYPE(proptag) == PT_STRING8 ? TRUE : false,
	       cpid, pbuff);
}

BOOL cu_get_property(mapi_object_type table_type, uint64_t id,
    cpid_t cpid, sqlite3 *psqlite, uint32_t proptag, void **ppvalue)
{
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	
	proptags.count = 1;
	proptags.pproptag = &proptag;
	if (!cu_get_properties(table_type,
	    id, cpid, psqlite, &proptags, &propvals))
		return FALSE;
	*ppvalue = propvals.count == 0 ? nullptr : propvals.ppropval[0].pvalue;
	return TRUE;
}

namespace {
enum GP_RESULT { GP_ADV, GP_UNHANDLED, GP_SKIP, GP_ERR };
}

static GP_RESULT gp_storeprop(uint32_t tag, TAGGED_PROPVAL &pv, sqlite3 *db)
{
	uint32_t *v = nullptr;
	switch (tag) {
	case PR_STORE_STATE:
	case PR_CONTENT_COUNT:
	case PR_ASSOC_CONTENT_COUNT:
	case PR_INTERNET_ARTICLE_NUMBER:
	case PR_DELETED_MSG_COUNT:
	case PR_DELETED_ASSOC_MSG_COUNT:
		v = cu_alloc<uint32_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		break;
	default:
		return GP_UNHANDLED;
	}
	switch (tag) {
	case PR_STORE_STATE: *v = common_util_get_store_state(db); break;
	case PR_CONTENT_COUNT: *v = cu_get_store_msgcount(db, 0); break;
	case PR_ASSOC_CONTENT_COUNT: *v = cu_get_store_msgcount(db, TABLE_FLAG_ASSOCIATED); break;
	case PR_DELETED_MSG_COUNT: *v = cu_get_store_msgcount(db, TABLE_FLAG_SOFTDELETES); break;
	case PR_DELETED_ASSOC_MSG_COUNT: *v = cu_get_store_msgcount(db, TABLE_FLAG_ASSOCIATED | TABLE_FLAG_SOFTDELETES); break;
	case PR_INTERNET_ARTICLE_NUMBER: *v = common_util_get_store_article_number(db); break;
	}
	return GP_ADV;
}

static GP_RESULT gp_folderprop(uint32_t tag, TAGGED_PROPVAL &pv,
    sqlite3 *db, uint64_t id)
{
	uint32_t *v = nullptr;
	uint64_t *w = nullptr;
	switch (tag) {
	case PR_FOLDER_FLAGS:
	case PR_CONTENT_COUNT:
	case PR_ASSOC_CONTENT_COUNT:
	case PR_FOLDER_CHILD_COUNT:
	case PR_CONTENT_UNREAD:
	case PR_FOLDER_TYPE:
	case PR_MESSAGE_SIZE:
	case PR_ASSOC_MESSAGE_SIZE:
	case PR_NORMAL_MESSAGE_SIZE:
		v = cu_alloc<uint32_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		break;
	case PidTagFolderId:
	case PidTagChangeNumber:
	case PR_MESSAGE_SIZE_EXTENDED:
	case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
	case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
		w = cu_alloc<uint64_t>();
		pv.pvalue = w;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		break;
	case PR_ENTRYID:
		pv.pvalue = cu_fid_to_entryid(db, id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	case PidTagParentFolderId: {
		w = cu_alloc<uint64_t>();
		pv.pvalue = w;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		auto tmp_id = common_util_get_folder_parent_fid(db, id);
		if (tmp_id == 0)
			return GP_SKIP;
		*w = rop_util_make_eid_ex(1, tmp_id);
		return GP_ADV;
	}
	case PR_PARENT_ENTRYID: {
		auto tmp_id = common_util_get_folder_parent_fid(db, id);
		if (tmp_id == 0)
			return GP_SKIP;
		pv.pvalue = cu_fid_to_entryid(db, tmp_id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	}
	case PR_SUBFOLDERS: {
		auto u = cu_alloc<uint8_t>();
		pv.pvalue = u;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*u = !!common_util_check_subfolders(db, id);
		return GP_ADV;
	}
	case PR_HAS_RULES: {
		auto u = cu_alloc<uint8_t>();
		pv.pvalue = u;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*u = !!common_util_check_folder_rules(db, id);
		return GP_ADV;
	}
	case PR_FOLDER_PATHNAME:
		pv.pvalue = common_util_calculate_folder_path(id, db);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	default:
		return GP_UNHANDLED;
	}
	switch (tag) {
	case PR_FOLDER_FLAGS: *v = common_util_get_folder_flags(db, id); break;
	case PR_CONTENT_COUNT: *v = cu_folder_count(db, id); break;
	case PR_ASSOC_CONTENT_COUNT: *v = cu_folder_count(db, id, TABLE_FLAG_ASSOCIATED); break;
	case PR_CONTENT_UNREAD: *v = cu_folder_unread_count(db, id); break;
	case PR_FOLDER_CHILD_COUNT: *v = common_util_calculate_childcount(id, db); break;
	case PR_MESSAGE_SIZE: *v = std::min(common_util_get_folder_message_size(db, id, TRUE, TRUE), static_cast<uint64_t>(INT32_MAX)); break;
	case PR_MESSAGE_SIZE_EXTENDED: *w = common_util_get_folder_message_size(db, id, TRUE, TRUE); break;
	case PR_ASSOC_MESSAGE_SIZE: *v = std::min(common_util_get_folder_message_size(db, id, false, TRUE), static_cast<uint64_t>(INT32_MAX)); break;
	case PR_ASSOC_MESSAGE_SIZE_EXTENDED: *w = common_util_get_folder_message_size(db, id, false, TRUE); break;
	case PR_NORMAL_MESSAGE_SIZE: *v = std::min(common_util_get_folder_message_size(db, id, TRUE, false), static_cast<uint64_t>(INT32_MAX)); break;
	case PR_NORMAL_MESSAGE_SIZE_EXTENDED: *w = common_util_get_folder_message_size(db, id, TRUE, false); break;
	case PidTagFolderId: *w = rop_util_nfid_to_eid(id); break;
	case PidTagChangeNumber: *w = common_util_get_folder_changenum(db, id); break;
	case PR_FOLDER_TYPE: return common_util_get_folder_type(db, id, v) ? GP_ADV : GP_ERR;
	}
	return GP_ADV;
}

static GP_RESULT gp_msgprop(uint32_t tag, TAGGED_PROPVAL &pv, sqlite3 *db,
    uint64_t id, cpid_t cpid)
{
	switch (tag) {
	case PR_ENTRYID:
		pv.pvalue = cu_mid_to_entryid(db, id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	case PR_PARENT_ENTRYID: {
		uint64_t tmp_id;
		if (!common_util_get_message_parent_folder(db, id, &tmp_id) || tmp_id == 0)
			return GP_ERR;
		pv.pvalue = cu_fid_to_entryid(db, tmp_id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	}
	case PidTagFolderId:
	case PidTagParentFolderId: {
		uint64_t tmp_id;
		if (!common_util_get_message_parent_folder(db, id, &tmp_id) || tmp_id == 0)
			return GP_ERR;
		auto v = cu_alloc<uint64_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = rop_util_make_eid_ex(1, tmp_id);
		return GP_ADV;
	}
	case PR_INSTANCE_SVREID: {
		uint64_t tmp_id;
		if (!common_util_get_message_parent_folder(db, id, &tmp_id) || tmp_id == 0)
			return GP_ERR;
		auto se = cu_alloc<SVREID>();
		pv.pvalue = se;
		if (se == nullptr)
			return GP_ERR;
		se->pbin = nullptr;
		se->folder_id = rop_util_make_eid_ex(1, tmp_id);
		se->message_id = rop_util_make_eid_ex(1, id);
		se->instance = 0;
		return GP_ADV;
	}
	case PR_PARENT_DISPLAY:
		pv.pvalue = common_util_get_message_parent_display(db, id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	case PR_PARENT_DISPLAY_A: {
		auto pstring = static_cast<char *>(common_util_get_message_parent_display(db, id));
		if (pstring == nullptr)
			return GP_ERR;
		pv.pvalue = common_util_convert_copy(false, cpid, pstring);
		return pv.pvalue != nullptr ? GP_ADV : GP_UNHANDLED;
	}
	case PR_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = common_util_get_message_size(db, id);
		return GP_ADV;
	}
	case PR_ASSOCIATED: {
		auto v = cu_alloc<uint8_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = !!common_util_check_message_associated(db, id);
		return GP_ADV;
	}
	case PidTagChangeNumber: {
		auto v = cu_alloc<uint64_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = common_util_get_message_changenum(db, id);
		return GP_ADV;
	}
	case PR_READ: {
		auto v = cu_alloc<uint8_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = exmdb_pf_read_states == 0 && !exmdb_server::is_private() ?
		     true : !!common_util_check_message_read(db, id);
		return GP_ADV;
	}
	case PR_HAS_NAMED_PROPERTIES: {
		auto v = cu_alloc<uint8_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = !!common_util_check_message_named_properties(db, id);
		return GP_ADV;
	}
	case PR_HASATTACH: {
		auto v = cu_alloc<uint8_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = !!common_util_check_message_has_attachments(db, id);
		return GP_ADV;
	}
	case PidTagMid: {
		auto v = cu_alloc<uint64_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = rop_util_make_eid_ex(1, id);
		return GP_ADV;
	}
	case PR_MESSAGE_FLAGS:
		if (!common_util_get_message_flags(db, id, false,
		    reinterpret_cast<uint32_t **>(&pv.pvalue)))
			return GP_ERR;
		if (exmdb_pf_read_states == 0 && !exmdb_server::is_private())
			*static_cast<uint32_t *>(pv.pvalue) |= MSGFLAG_READ;
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PR_SUBJECT:
	case PR_SUBJECT_A:
		if (!common_util_get_message_subject(db, cpid, id, tag, &pv.pvalue))
			return GP_ERR;
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PR_DISPLAY_TO:
	case PR_DISPLAY_CC:
	case PR_DISPLAY_BCC:
	case PR_DISPLAY_TO_A:
	case PR_DISPLAY_CC_A:
	case PR_DISPLAY_BCC_A:
		if (!common_util_get_message_display_recipients(db, cpid, id, tag, &pv.pvalue))
			return GP_ERR;
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PR_BODY:
	case PR_BODY_A:
	case PR_TRANSPORT_MESSAGE_HEADERS:
	case PR_TRANSPORT_MESSAGE_HEADERS_A:
		pv.pvalue = cu_get_object_text(db, cpid, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PR_HTML:
	case PR_RTF_COMPRESSED:
		pv.pvalue = cu_get_object_text(db, CP_ACP, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PidTagMidString: /* self-defined proptag */
		return common_util_get_mid_string(db, id, reinterpret_cast<char **>(&pv.pvalue)) &&
		       pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_atxprop(uint32_t tag, TAGGED_PROPVAL &pv,
    sqlite3 *db, uint64_t id)
{
	switch (tag) {
	case PR_RECORD_KEY: {
		auto ptmp_bin = cu_alloc<BINARY>();
		if (ptmp_bin == nullptr)
			return GP_ERR;
		ptmp_bin->cb = sizeof(uint64_t);
		auto v = cu_alloc<uint64_t>();
		ptmp_bin->pv = v;
		if (ptmp_bin->pv == nullptr)
			return GP_ERR;
		*v = id;
		pv.pvalue = ptmp_bin;
		return GP_ADV;
	}
	case PR_ATTACH_DATA_BIN:
	case PR_ATTACH_DATA_OBJ:
		pv.pvalue = cu_get_object_text(db, CP_ACP, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_spectableprop(mapi_object_type table_type, uint32_t tag,
    TAGGED_PROPVAL &pv, sqlite3 *db, uint64_t id, cpid_t cpid)
{
	pv.proptag = tag;
	switch (tag) {
	case PR_STORE_RECORD_KEY:
		pv.pvalue = common_util_get_mailbox_guid(db);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	}
	switch (table_type) {
	case MAPI_STORE:    return gp_storeprop(tag, pv, db);
	case MAPI_FOLDER:   return gp_folderprop(tag, pv, db, id);
	case MAPI_MESSAGE:  return gp_msgprop(tag, pv, db, id, cpid);
	case MAPI_MAILUSER: return GP_UNHANDLED;
	case MAPI_ATTACH:   return gp_atxprop(tag, pv, db, id);
	default:
		assert(!"Unknown table_type");
		return GP_UNHANDLED;
	}
}

static GP_RESULT gp_msgprop_synth(uint32_t proptag, TAGGED_PROPVAL &pv)
{
	if (proptag == PR_MESSAGE_CLASS) {
		auto v = cu_alloc<char>(9);
		pv.pvalue = v;
		if (v == nullptr)
			return GP_ERR;
		strcpy(v, "IPM.Note");
		return GP_ADV;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_rcptprop_synth(uint32_t proptag, TAGGED_PROPVAL &pv)
{
	switch (proptag) {
	case PR_RECIPIENT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		pv.pvalue = v;
		if (v == nullptr)
			return GP_ERR;
		*v = MAPI_TO;
		return GP_ADV;
	}
	case PR_DISPLAY_NAME:
	case PR_EMAIL_ADDRESS: {
		auto v = cu_alloc<char>(1);
		pv.pvalue = v;
		if (v == nullptr)
			return GP_ERR;
		*v = '\0';
		pv.proptag = CHANGE_PROP_TYPE(pv.proptag, PT_UNICODE);
		return GP_ADV;
	}
	case PR_ADDRTYPE: {
		auto v = cu_alloc<char>(5);
		pv.pvalue = v;
		if (v == nullptr)
			return GP_ERR;
		strcpy(v, "NONE");
		pv.proptag = CHANGE_PROP_TYPE(pv.proptag, PT_UNICODE);
		return GP_ADV;
	}
	default:
		return GP_UNHANDLED;
	}
}

static GP_RESULT gp_fallbackprop(mapi_object_type table_type, uint32_t proptag,
    TAGGED_PROPVAL &pv)
{
	pv.proptag = proptag;
	if (table_type == MAPI_MESSAGE)
		return gp_msgprop_synth(proptag, pv);
	if (table_type == MAPI_MAILUSER)
		return gp_rcptprop_synth(proptag, pv);
	return GP_UNHANDLED;
}

BOOL cu_get_properties(mapi_object_type table_type, uint64_t id, cpid_t cpid,
    sqlite3 *psqlite, const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	sqlite3_stmt *pstmt = nullptr;
	
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	for (size_t i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (PROP_TYPE(tag) == PT_OBJECT &&
		    (table_type != MAPI_ATTACH || tag != PR_ATTACH_DATA_OBJ))
			continue;
		/* begin of special properties */
		auto &pv = ppropvals->ppropval[ppropvals->count];
		auto ret = gp_spectableprop(table_type, tag,
		           pv, psqlite, id, cpid);
		if (ret == GP_ERR)
			return false;
		if (ret == GP_SKIP)
			continue;
		if (ret == GP_ADV) {
			++ppropvals->count;
			continue;
		}
		/* end of special properties */
		xstmt own_stmt;
		uint16_t proptype = PROP_TYPE(tag);
		if (proptype == PT_UNSPECIFIED || proptype == PT_STRING8 ||
		    proptype == PT_UNICODE) {
			auto bret = gp_prepare_anystr(psqlite, table_type, id, tag, own_stmt, pstmt);
			if (!bret)
				return false;
		} else if (proptype == PT_MV_STRING8) {
			auto bret = gp_prepare_mvstr(psqlite, table_type, id, tag, own_stmt, pstmt);
			if (!bret)
				return false;
		} else {
			auto bret = gp_prepare_default(psqlite, table_type, id, tag, own_stmt, pstmt);
			if (!bret)
				return false;
		}
		if (gx_sql_step(pstmt) != SQLITE_ROW) {
			ret = gp_fallbackprop(table_type, tag, pv);
			if (ret == GP_ERR)
				return false;
			if (ret == GP_ADV) {
				++ppropvals->count;
				continue;
			}
			continue; /* SKIP or UNHANDLED */
		}
		auto pvalue = gp_fetch(psqlite, pstmt, proptype, cpid);
		if (pvalue == nullptr)
			return false;
		ppropvals->emplace_back(tag, pvalue);
	}
	return TRUE;
}

static bool gp_prepare_anystr(sqlite3 *psqlite, mapi_object_type table_type,
    uint64_t id, uint32_t tag, xstmt &own_stmt, sqlite3_stmt *&pstmt)
{
	switch (table_type) {
	case MAPI_STORE:
		own_stmt = gx_sql_prep(psqlite, "SELECT proptag, propval"
		           " FROM store_properties WHERE proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		break;
	case MAPI_FOLDER:
		own_stmt = gx_sql_prep(psqlite, "SELECT proptag,"
		           " propval FROM folder_properties WHERE"
		           " folder_id=? AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		break;
	case MAPI_MESSAGE:
		pstmt = cu_get_optimize_stmt(table_type, false);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT proptag, "
			           "propval FROM message_properties WHERE "
			           "message_id=? AND proptag IN (?,?)");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(tag, PT_STRING8));
		break;
	case MAPI_MAILUSER:
		pstmt = cu_get_optimize_stmt(table_type, false);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT proptag,"
			           " propval FROM recipients_properties WHERE"
			           " recipient_id=? AND proptag IN (?,?)");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(tag, PT_STRING8));
		break;
	case MAPI_ATTACH:
		own_stmt = gx_sql_prep(psqlite, "SELECT proptag, propval"
		           " FROM attachment_properties WHERE attachment_id=?"
		           " AND proptag IN (?,?)");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(tag, PT_STRING8));
		break;
	default:
		assert(!"Unknown table_type");
		return false;
	}
	return true;
}

static bool gp_prepare_mvstr(sqlite3 *psqlite, mapi_object_type table_type,
    uint64_t id, uint32_t tag, xstmt &own_stmt, sqlite3_stmt *&pstmt)
{
	switch (table_type) {
	case MAPI_STORE:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval"
		           " FROM store_properties WHERE proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	case MAPI_FOLDER:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM folder_properties WHERE folder_id=? "
		           "AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	case MAPI_MESSAGE:
		pstmt = cu_get_optimize_stmt(table_type, true);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT propval"
			           " FROM message_properties WHERE "
			           "message_id=? AND proptag=?");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	case MAPI_MAILUSER:
		pstmt = cu_get_optimize_stmt(table_type, true);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT propval "
			           "FROM recipients_properties WHERE "
			           "recipient_id=? AND proptag=?");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	case MAPI_ATTACH:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM attachment_properties WHERE "
		           "attachment_id=? AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	default:
		assert(!"Unknown table_type");
		return false;
	}
	return true;
}

static bool gp_prepare_default(sqlite3 *psqlite, mapi_object_type table_type,
    uint64_t id, uint32_t tag, xstmt &own_stmt, sqlite3_stmt *&pstmt)
{
	switch (table_type) {
	case MAPI_STORE:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM store_properties WHERE proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, tag);
		break;
	case MAPI_FOLDER:
		if (tag == PR_LOCAL_COMMIT_TIME)
			tag = PR_LAST_MODIFICATION_TIME;
		own_stmt = gx_sql_prep(psqlite, "SELECT propval FROM "
		           "folder_properties WHERE folder_id=? AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, tag);
		break;
	case MAPI_MESSAGE:
		pstmt = cu_get_optimize_stmt(table_type, true);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT propval"
			           " FROM message_properties WHERE "
			           "message_id=? AND proptag=?");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, tag);
		break;
	case MAPI_MAILUSER:
		pstmt = cu_get_optimize_stmt(table_type, true);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT propval "
			           "FROM recipients_properties WHERE "
			           "recipient_id=? AND proptag=?");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, tag);
		break;
	case MAPI_ATTACH:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval FROM "
		           "attachment_properties WHERE attachment_id=?"
		           " AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, tag);
		break;
	default:
		assert(!"Unknown table_type");
		return false;
	}
	return true;
}

/**
 * @pstmt:	a statement for which sqlite3_step was already invoked
 *
 * Read the current row from @pstmt (i.e. just one row; no read cursor
 * advancing here).
 */
static void *gp_fetch(sqlite3 *psqlite, sqlite3_stmt *pstmt,
    uint16_t proptype, cpid_t cpid)
{
	EXT_PULL ext_pull;
	void *pvalue;
	switch (proptype) {
	case PT_UNSPECIFIED: {
		auto ptyped = cu_alloc<TYPED_PROPVAL>();
		if (ptyped == nullptr)
			return nullptr;
		ptyped->type = PROP_TYPE(sqlite3_column_int64(pstmt, 0));
		ptyped->pvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 1)));
		if (ptyped->pvalue == nullptr)
			return nullptr;
		return ptyped;
	}
	case PT_STRING8:
		if (proptype == PROP_TYPE(sqlite3_column_int64(pstmt, 0)))
			pvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 1)));
		else
			pvalue = common_util_convert_copy(FALSE, cpid,
				 S2A(sqlite3_column_text(pstmt, 1)));
		break;
	case PT_UNICODE:
		if (proptype == PROP_TYPE(sqlite3_column_int64(pstmt, 0)))
			pvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 1)));
		else
			pvalue = common_util_convert_copy(TRUE, cpid,
				 S2A(sqlite3_column_text(pstmt, 1)));
		break;
	case PT_FLOAT: {
		auto v = cu_alloc<float>();
		if (v == nullptr)
			return nullptr;
		*v = sqlite3_column_double(pstmt, 0);
		return v;
	}
	case PT_DOUBLE:
	case PT_APPTIME: {
		auto v = cu_alloc<double>();
		if (v == nullptr)
			return nullptr;
		*v = sqlite3_column_double(pstmt, 0);
		return v;
	}
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME: {
		auto v = cu_alloc<uint64_t>();
		if (v == nullptr)
			return nullptr;
		*v = sqlite3_column_int64(pstmt, 0);
		return v;
	}
	case PT_SHORT: {
		auto v = cu_alloc<uint16_t>();
		if (v == nullptr)
			return nullptr;
		*v = sqlite3_column_int64(pstmt, 0);
		return v;
	}
	case PT_LONG: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return nullptr;
		*v = sqlite3_column_int64(pstmt, 0);
		return v;
	}
	case PT_BOOLEAN: {
		auto v = cu_alloc<uint8_t>();
		if (v == nullptr)
			return nullptr;
		*v = sqlite3_column_int64(pstmt, 0);
		return v;
	}
	case PT_CLSID: {
		auto v = cu_alloc<GUID>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_guid(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_SVREID: {
		auto v = cu_alloc<SVREID>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_svreid(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_SRESTRICTION: {
		auto v = cu_alloc<RESTRICTION>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_restriction(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_ACTIONS: {
		auto v = cu_alloc<RULE_ACTIONS>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_rule_actions(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_OBJECT:
	case PT_BINARY: {
		auto bv = cu_alloc<BINARY>();
		if (bv == nullptr)
			return nullptr;
		bv->cb = sqlite3_column_bytes(pstmt, 0);
		bv->pv = common_util_alloc(bv->cb);
		if (bv->pv == nullptr)
			return nullptr;
		auto blob = sqlite3_column_blob(pstmt, 0);
		if (bv->cb != 0 || blob != nullptr)
			memcpy(bv->pv, blob, bv->cb);
		return bv;
	}
	case PT_MV_SHORT: {
		auto v = cu_alloc<SHORT_ARRAY>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_uint16_a(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_MV_LONG: {
		auto v = cu_alloc<LONG_ARRAY>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_uint32_a(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		auto v = cu_alloc<LONGLONG_ARRAY>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_uint64_a(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_MV_FLOAT: {
		auto ar = cu_alloc<FLOAT_ARRAY>();
		if (ar == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0), sqlite3_column_bytes(pstmt, 0), common_util_alloc, 0);
		if (ext_pull.g_float_a(ar) != EXT_ERR_SUCCESS)
			return nullptr;
		return ar;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		auto ar = cu_alloc<DOUBLE_ARRAY>();
		if (ar == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0), sqlite3_column_bytes(pstmt, 0), common_util_alloc, 0);
		if (ext_pull.g_double_a(ar) != EXT_ERR_SUCCESS)
			return nullptr;
		return ar;
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto sa = cu_alloc<STRING_ARRAY>();
		if (sa == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_wstr_a(sa) != EXT_ERR_SUCCESS)
			return nullptr;
		if (proptype != PT_MV_STRING8)
			return sa;
		for (size_t j = 0; j < sa->count; ++j) {
			auto pstring = common_util_convert_copy(false, cpid, sa->ppstr[j]);
			if (pstring == nullptr)
				return nullptr;
			sa->ppstr[j] = pstring;
		}
		return sa;
	}
	case PT_MV_CLSID: {
		auto v = cu_alloc<GUID_ARRAY>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_guid_a(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	case PT_MV_BINARY: {
		auto v = cu_alloc<BINARY_ARRAY>();
		if (v == nullptr)
			return nullptr;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_pull.g_bin_a(v) != EXT_ERR_SUCCESS)
			return nullptr;
		return v;
	}
	default:
		assert(false);
		return nullptr;
	}
	return pvalue;
}

static void common_util_set_folder_changenum(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t change_num)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "UPDATE folders SET change_number=%llu"
	        " WHERE folder_id=%llu", LLU{change_num}, LLU{folder_id});
	gx_sql_exec(psqlite, sql_string);
}

static void common_util_set_message_changenum(sqlite3 *psqlite,
	uint64_t message_id, uint64_t change_num)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "UPDATE messages SET change_number=%llu"
	        " WHERE message_id=%llu", LLU{change_num}, LLU{message_id});
	gx_sql_exec(psqlite, sql_string);
}

void common_util_set_message_read(sqlite3 *psqlite,
	uint64_t message_id, uint8_t is_read)
{
	char sql_string[128];
	
	if (is_read)
		snprintf(sql_string, std::size(sql_string), "UPDATE message_properties "
			"SET propval=propval|%u WHERE message_id=%llu"
			" AND proptag=%u", MSGFLAG_EVERREAD,
		        LLU{message_id}, PR_MESSAGE_FLAGS);
	else
		snprintf(sql_string, std::size(sql_string), "UPDATE message_properties "
			"SET propval=propval&(~%u) WHERE message_id=%llu"
			" AND proptag=%u", MSGFLAG_EVERREAD,
		        LLU{message_id}, PR_MESSAGE_FLAGS);
	gx_sql_exec(psqlite, sql_string);
	if (exmdb_server::is_private()) {
		if (!is_read)
			snprintf(sql_string, std::size(sql_string), "UPDATE messages SET "
				"read_state=0 WHERE message_id=%llu", LLU{message_id});
		else
			snprintf(sql_string, std::size(sql_string), "UPDATE messages SET "
				"read_state=1 WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(psqlite, sql_string);
		return;
	}
	auto username = exmdb_pf_read_per_user ? exmdb_server::get_public_username() : "";
	if (username == nullptr)
		return;
	if (is_read)
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
			"read_states VALUES (%llu, ?)", LLU{message_id});
	else
		snprintf(sql_string, std::size(sql_string), "DELETE FROM "
			"read_states WHERE message_id=%llu AND "
			"username=?", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return;
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	auto ret = pstmt.step();
	if (ret != SQLITE_DONE)
		mlog(LV_WARN, "W-1274: %s", sqlite3_errstr(ret));
}

static BOOL cu_update_object_cid(sqlite3 *psqlite, mapi_object_type table_type,
    uint64_t object_id, uint32_t proptag, const char *cid)
{
	char sql_string[256];
	
	if (table_type == MAPI_MESSAGE)
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO message_properties"
		         " VALUES (%llu, %u, ?)", LLU{object_id}, XUI{proptag});
	else if (table_type == MAPI_ATTACH)
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO attachment_properties"
		          " VALUES (%llu, %u, ?)", LLU{object_id}, XUI{proptag});
	else
		return false;
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, cid, -1, SQLITE_STATIC);
	return pstmt.step() == SQLITE_DONE ? TRUE : false;
}

/**
 * Determine the length of the message prefix, up to three alphanumeric Unicode
 * characters - though we do not recognize combining characters and thus no
 * NFD/NKFD. Returns the number of bytes.
 */
static int subj_pfxlen(const char *s) try
{
	/* Note we do not recognize NFD/NKFD. Oh well. */
	auto ustr  = iconvtext(s, strlen(s), "UTF-8", "wchar_t");
	auto units = ustr.size() / sizeof(wchar_t);
	wchar_t uc[6]{};
	if (units > std::size(uc))
		units = std::size(uc);
	memcpy(uc, ustr.data(), units * sizeof(wchar_t));
	if (uc[0] == L'\0' || !iswalnum(uc[0]))
		return 0;
	if (uc[1] == L':' && iswspace(uc[2]))
		return strchr(s, ':') - s + 2;
	if (!iswalnum(uc[1]))
		return 0;
	if (uc[2] == L':' && iswspace(uc[3]))
		return strchr(s, ':') - s + 2;
	if (!iswalnum(uc[2]))
		return 0;
	if (uc[3] == L':' && iswspace(uc[4]))
		return strchr(s, ':') - s + 2;
	return 0;
} catch (const std::bad_alloc &) {
	return -1;
}

bool cu_rebuild_subjects(const char *&subj, const char *&pfx, const char *&norm)
{
	if (pfx == nullptr && norm != nullptr) {
		/* Build PR_SUBJECT_PREFIX from PR_SUBJECT-PR_NORMALIZED_SUBJECT. */
		auto sz = strlen(subj);
		auto nz = strlen(norm);
		if (sz < nz || strcmp(&subj[sz-nz], norm) != 0)
			return true;
		auto pfxlen = sz - nz;
		auto newpfx = cu_alloc<char>(pfxlen + 1);
		if (newpfx == nullptr)
			return false;
		strncpy(newpfx, subj, pfxlen);
		newpfx[pfxlen] = '\0';
		pfx = newpfx;
		return true;
	} else if (pfx != nullptr && norm == nullptr &&
	    strncmp(subj, pfx, strlen(pfx)) == 0) {
		/* Build PR_NORMALIZED_SUBJECT from PR_SUBJECT-PR_SUBJECT_PREFIX. */
		auto p = subj + strlen(pfx);
		while (isspace(static_cast<unsigned char>(*p)))
			++p;
		norm = p;
		return true;
	}
	auto pfxlen = subj_pfxlen(subj);
	auto newpfx = cu_alloc<char>(pfxlen + 1);
	if (newpfx == nullptr)
		return false;
	memcpy(newpfx, subj, pfxlen);
	newpfx[pfxlen] = '\0';
	pfx  = newpfx;
	norm = &subj[pfxlen];
	return true;
}

/* A duplicate implementation is in xns_set_msg_subj. */
static BOOL common_util_set_message_subject(cpid_t cpid, uint64_t message_id,
    xstmt &pstmt, const TPROPVAL_ARRAY &props, size_t subj_id)
{
	auto &stag   = props.ppropval[subj_id].proptag;
	/* No support for mixed STRING8/UNICODE */
	auto pfxtag  = CHANGE_PROP_TYPE(PR_SUBJECT_PREFIX, PROP_TYPE(stag));
	auto normtag = CHANGE_PROP_TYPE(PR_NORMALIZED_SUBJECT, PROP_TYPE(stag));
	auto pfx  = props.get<const char>(pfxtag);
	auto norm = props.get<const char>(normtag);
	if (pfx != nullptr && norm != nullptr)
		/* Decomposition not needed; parts are complete. */
		return TRUE;

	auto subj = static_cast<const char *>(props.ppropval[subj_id].pvalue);
	if (!cu_rebuild_subjects(subj, pfx, norm))
		return false;
	auto lm = [&](uint32_t tag, const char *value) {
	if (PROP_TYPE(tag) == PT_UNICODE) {
		pstmt.bind_int64(1, tag);
		pstmt.bind_text(2, value);
	} else if (cpid != CP_ACP) {
		auto s = common_util_convert_copy(TRUE, cpid, value);
		if (s == nullptr)
			return FALSE;
		pstmt.bind_int64(1, tag);
		pstmt.bind_text(2, value);
	} else {
		pstmt.bind_int64(1, tag);
		pstmt.bind_text(2, value);
	}
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	return TRUE;
	};
	if (pfx != nullptr && !lm(pfxtag, pfx))
		return false;
	if (norm != nullptr && !lm(normtag, norm))
		return false;
	return TRUE;
}

fhash::fhash(const std::string_view data)
{
	if (g_cid_use_xxhash) {
#ifdef HAVE_XXHASH
		XXH128_canonical_t canon;
		XXH128_canonicalFromHash(&canon, XXH3_128bits(data.data(), data.size()));
		cid = "Y-00/000000000000000000000000000000";
		hexify(reinterpret_cast<const unsigned char *>(canon.digest), 16);
		return;
#endif
	}
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int outsize = 0;
	auto ret = EVP_Digest(reinterpret_cast<const unsigned char *>(data.data()),
	           data.size(), digest, &outsize, EVP_sha3_256(), nullptr);
	if (ret < 1)
		return;
	cid = "S-00/00000000000000000000000000000000000000000000000000000000000000";
	hexify(digest, 32);
}

void fhash::hexify(const unsigned char *digest, unsigned int bytes)
{
	static constexpr char digits[] = "0123456789abcdef";
	unsigned int z = 2;
	cid[z++] = digits[(digest[0] & 0xF0) >> 4];
	cid[z++] = digits[digest[0] & 0x0F];
	cid[z++] = '/';
	for (unsigned int i = 1; i < bytes && z < cid.size(); ++i) {
		cid[z++] = digits[(digest[i] & 0xF0) >> 4];
		cid[z++] = digits[digest[i] & 0x0F];
	}
}

/**
 * @data:	[in] attachment/body
 * @cid:	[out] generated CID string for the database
 * @path:	[out] generated path
 */
static errno_t cu_cid_writeout(const char *maildir, std::string_view data,
    std::string &cid, std::string &path) try
{
	fhash hval(data);
	if (maildir == nullptr)
		maildir = exmdb_server::get_dir();
	path = maildir + "/cid/"s + hval.str();
	cid  = hval.str();
	std::unique_ptr<char[], stdlib_delete> extradir(HX_dirname(path.c_str()));
	if (extradir == nullptr)
		return ENOMEM;
	auto ret = HX_mkdir(extradir.get(), S_IRUGO | S_IWUGO | S_IXUGO);
	if (ret < 0) {
		mlog(LV_ERR, "E-2388: mkdir %s: %s", extradir.get(), strerror(-ret));
		return -ret;
	}

	/* See if the object already exists. (Skip compression.) */
	wrapfd check_fd = open(path.c_str(), O_RDONLY);
	struct stat sb;
	if (check_fd.get() >= 0 && fstat(check_fd.get(), &sb) == 0 &&
	    sb.st_size > 0)
		return 0;
	check_fd.close_rd();

	gromox::tmpfile tmf;
	ret = tmf.open_linkable(maildir, O_RDWR | O_TRUNC);
	if (ret < 0) {
		mlog(LV_ERR, "E-2308: open(%s)[%s]: %s", maildir, tmf.m_path.c_str(), strerror(-ret));
		return -ret;
	}
	/*
	 * zstd already has some form of uncompressability detection
	 * (huf_compress.c), so we do not have to implement our own. Besides,
	 * even if the overall compressibility in a file is low, there may
	 * still be a block where it is comparatively high.
	 */
	auto err = gx_compress_tofd(data, tmf, g_cid_compression);
	if (err != 0)
		return err;
	/*
	 * If another thread created a writeout in the meantime, we will now
	 * overwrite it. Since the contents are the same, that has no ill
	 * effect (POSIX guarantees atomicity). But it is somewhat inefficient,
	 * because now the filesystem will writeout our thread's second copy
	 * and ditch the blocks from the first copy, which is pointless churn.
	 * It is not too terrible, considering this can only happen for newly
	 * instantiated @paths.
	 */
	return tmf.link_to(path.c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2305: ENOMEM");
	return ENOMEM;
}

static BOOL common_util_set_message_body(sqlite3 *psqlite, cpid_t cpid,
    uint64_t message_id, const TAGGED_PROPVAL *ppropval)
{
	void *pvalue;
	uint32_t proptag;
	
	if (ppropval->proptag == PR_BODY_A) {
		if (cpid == CP_ACP) {
			proptag = PR_BODY_A;
			pvalue = ppropval->pvalue;
		} else {
			proptag = PR_BODY;
			pvalue = common_util_convert_copy(TRUE, cpid, static_cast<char *>(ppropval->pvalue));
			if (pvalue == nullptr)
				return FALSE;
		}
	} else if (ppropval->proptag == PR_TRANSPORT_MESSAGE_HEADERS_A) {
		if (cpid == CP_ACP) {
			proptag = PR_TRANSPORT_MESSAGE_HEADERS_A;
			pvalue = ppropval->pvalue;
		} else {
			proptag = PR_TRANSPORT_MESSAGE_HEADERS;
			pvalue = common_util_convert_copy(TRUE, cpid, static_cast<char *>(ppropval->pvalue));
			if (pvalue == nullptr)
				return FALSE;
		}
	} else if (ppropval->proptag == PR_BODY_W) {
		proptag = PR_BODY_W;
		pvalue = ppropval->pvalue;
	} else if (ppropval->proptag == PR_TRANSPORT_MESSAGE_HEADERS) {
		proptag = PR_TRANSPORT_MESSAGE_HEADERS;
		pvalue = ppropval->pvalue;
	} else {
		return FALSE;
	}
	auto dir = exmdb_server::get_dir();
	if (dir == nullptr)
		return FALSE;
	std::string cid, path;
	if (cu_cid_writeout(dir, static_cast<const char *>(pvalue), cid, path) != 0)
		return false;
	if (!cu_update_object_cid(psqlite, MAPI_MESSAGE, message_id, proptag, cid.c_str()))
		return TRUE;
	return TRUE;
}

static BOOL cu_set_object_cid_value(sqlite3 *psqlite, mapi_object_type table_type,
    uint64_t message_id, const TAGGED_PROPVAL *ppropval)
{
	if (table_type == MAPI_MESSAGE) {
		if (ppropval->proptag != PR_HTML &&
		    ppropval->proptag != PR_RTF_COMPRESSED)
			return false;
	} else if (table_type == MAPI_ATTACH) {
		if (ppropval->proptag != PR_ATTACH_DATA_BIN &&
		    ppropval->proptag != PR_ATTACH_DATA_OBJ)
			return false;
	} else {
		return false;
	}
	auto dir = exmdb_server::get_dir();
	if (dir == nullptr)
		return FALSE;
	auto bv = static_cast<BINARY *>(ppropval->pvalue);
	std::string cid, path;
	if (cu_cid_writeout(dir, std::string_view(bv->pc, bv->cb), cid, path) != 0)
		return false;
	if (!cu_update_object_cid(psqlite, table_type, message_id,
	    ppropval->proptag, cid.c_str()))
		return FALSE;
	return TRUE;
}

BOOL cu_set_property(mapi_object_type table_type, uint64_t id, cpid_t cpid,
    sqlite3 *psqlite, uint32_t tag, const void *data, BOOL *pb_result)
{
	PROBLEM_ARRAY tmp_problems;
	const TAGGED_PROPVAL tp = {tag, deconst(data)};
	const TPROPVAL_ARRAY tmp_propvals = {1, deconst(&tp)};
	if (!cu_set_properties(table_type,
	    id, cpid, psqlite, &tmp_propvals, &tmp_problems))
		return FALSE;
	*pb_result = tmp_problems.count == 1 ? false : TRUE;
	return TRUE;
}

BOOL cu_set_properties(mapi_object_type table_type, uint64_t id, cpid_t cpid,
    sqlite3 *psqlite, const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
{
	int s_result;
	char *pstring;
	uint64_t tmp_id;
	uint16_t proptype;
	char sql_string[256];
	uint8_t temp_buff[256];
	STRING_ARRAY *pstrings;
	STRING_ARRAY tmp_strings;
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	switch (table_type) {
	case MAPI_STORE:
		strcpy(sql_string, "REPLACE INTO store_properties VALUES (?, ?)");
		break;
	case MAPI_FOLDER:
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
		          "folder_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	case MAPI_MESSAGE:
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
		          "message_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	case MAPI_MAILUSER:
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
		          "recipients_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	case MAPI_ATTACH:
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
		          "attachment_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	default:
		assert(!"Unknown table_type");
		return false;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (size_t i = 0; i < ppropvals->count; ++i) {
		if (PROP_ID(ppropvals->ppropval[i].proptag) == PROP_ID(PR_NULL)) {
			pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecInvalidParam);
			mlog(LV_DEBUG, "D-1220: cu_set_properties called with PR_NULL");
			continue;
		}
		if (PROP_TYPE(ppropvals->ppropval[i].proptag) == PT_OBJECT &&
		    (table_type != MAPI_ATTACH ||
		    ppropvals->ppropval[i].proptag != PR_ATTACH_DATA_OBJ)) {
			pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecError);
			continue;
		}
		switch (table_type) {
		case MAPI_STORE:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_STORE_STATE:
			case PR_MESSAGE_SIZE:
			case PR_CONTENT_COUNT:
			case PR_STORE_RECORD_KEY:
			case PR_ASSOC_MESSAGE_SIZE:
			case PR_NORMAL_MESSAGE_SIZE:
			case PR_MESSAGE_SIZE_EXTENDED:
			case PR_INTERNET_ARTICLE_NUMBER:
			case PR_ASSOC_CONTENT_COUNT:
			case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
			case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
				pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecAccessDenied);
				continue;
			}
			break;
		case MAPI_FOLDER:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_ENTRYID:
			case PidTagFolderId:
			case PidTagParentFolderId:
			case PR_FOLDER_FLAGS:
			case PR_SUBFOLDERS:
			case PR_CONTENT_COUNT:
			case PR_ASSOC_CONTENT_COUNT:
			case PR_FOLDER_CHILD_COUNT:
			case PR_CONTENT_UNREAD:
			case PR_FOLDER_TYPE:
			case PR_HAS_RULES:
			case PR_FOLDER_PATHNAME:
			case PR_PARENT_SOURCE_KEY:
			case PR_MESSAGE_SIZE_EXTENDED:
			case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
			case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
				pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecAccessDenied);
				continue;
			case PidTagChangeNumber:
				common_util_set_folder_changenum(psqlite, id,
					rop_util_get_gc_value(*static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)));
				continue;
			case PR_DISPLAY_NAME:
			case PR_DISPLAY_NAME_A:
				if (ppropvals->ppropval[i].proptag == PR_DISPLAY_NAME_A) {
					pstring = common_util_convert_copy(TRUE,
					          cpid, static_cast<char *>(ppropvals->ppropval[i].pvalue));
					if (pstring == nullptr)
						break;
				} else {
					pstring = static_cast<char *>(ppropvals->ppropval[i].pvalue);
				}
				tmp_id = common_util_get_folder_parent_fid(psqlite, id);
				if (tmp_id == 0 && tmp_id == id)
					break;
				if (!common_util_get_folder_by_name(psqlite,
				    tmp_id, pstring, &tmp_id))
					break;
				if (tmp_id == 0 || tmp_id == id)
					break;
				pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecDuplicateName);
				continue;
			}
			break;
		case MAPI_MESSAGE:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_ENTRYID:
			case PidTagFolderId:
			case PidTagParentFolderId:
			case PR_INSTANCE_SVREID:
			case PR_PARENT_SOURCE_KEY:
			case PR_HAS_NAMED_PROPERTIES:
			case PidTagMid:
			case PR_MESSAGE_SIZE:
			case PR_ASSOCIATED:
			case PR_HASATTACH:
			case PR_DISPLAY_TO:
			case PR_DISPLAY_CC:
			case PR_DISPLAY_BCC:
			case PR_DISPLAY_TO_A:
			case PR_DISPLAY_CC_A:
			case PR_DISPLAY_BCC_A:
			case PidTagMidString: /* self-defined proptag */
				pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecAccessDenied);
				continue;
			case PidTagChangeNumber:
				common_util_set_message_changenum(psqlite, id,
					rop_util_get_gc_value(*static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)));
				continue;
			case PR_READ:
				common_util_set_message_read(psqlite, id,
					*static_cast<uint8_t *>(ppropvals->ppropval[i].pvalue));
				continue;
			case PR_MESSAGE_FLAGS:
				/*
				 * XXX: Why no SQL update?
				 *
				 * """Several of the flags are always
				 * read-only. Some are read/write until the
				 * first call to the IMAPIProp::SaveChanges
				 * method and thereafter become read-only as
				 * far as IMAPIProp::SetProps is concerned."""
				 * (MSDN)
				 */
				*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) &=
					~(MSGFLAG_READ | MSGFLAG_HASATTACH |
					MSGFLAG_FROMME | MSGFLAG_ASSOCIATED |
					MSGFLAG_RN_PENDING | MSGFLAG_NRN_PENDING);
				break;
			case PR_SUBJECT:
			case PR_SUBJECT_A:
				if (!common_util_set_message_subject(cpid,
				    id, pstmt, *ppropvals, i))
					return FALSE;	
				continue;
			case ID_TAG_BODY: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_BODY, cid))
					return FALSE;	
				continue;
			}
			case ID_TAG_BODY_STRING8: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_BODY_A, cid))
					return FALSE;	
				continue;
			}
			case PR_BODY:
			case PR_BODY_A:
			case PR_TRANSPORT_MESSAGE_HEADERS:
			case PR_TRANSPORT_MESSAGE_HEADERS_A:
				if (common_util_set_message_body(psqlite, cpid, id, &ppropvals->ppropval[i]))
					continue;
				pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecError);
				continue;
			case ID_TAG_HTML: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite, table_type,
				    id, PR_HTML, cid))
					return FALSE;	
				continue;
			}
			case ID_TAG_RTFCOMPRESSED: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite, table_type,
				    id, PR_RTF_COMPRESSED, cid))
					return FALSE;	
				continue;
			}
			case PR_HTML:
			case PR_RTF_COMPRESSED:
				if (cu_set_object_cid_value(psqlite,
				    table_type, id, &ppropvals->ppropval[i]))
					continue;
				pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecError);
				continue;
			case ID_TAG_TRANSPORTMESSAGEHEADERS: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite, table_type,
				    id, PR_TRANSPORT_MESSAGE_HEADERS, cid))
					return FALSE;	
				continue;
			}
			case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite, table_type,
				    id, PR_TRANSPORT_MESSAGE_HEADERS_A, cid))
					return FALSE;	
				continue;
			}
			}
			break;
		case MAPI_MAILUSER:
			if (ppropvals->ppropval[i].proptag == PR_ROWID)
				continue;
			break;
		case MAPI_ATTACH:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_RECORD_KEY:
			case PR_ATTACH_NUM:
				continue;
			case ID_TAG_ATTACHDATABINARY: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_ATTACH_DATA_BIN, cid))
					return FALSE;	
				continue;
			}
			case ID_TAG_ATTACHDATAOBJECT: {
				if (!g_inside_flush_instance)
					break;
				auto cid = static_cast<const char *>(ppropvals->ppropval[i].pvalue);
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_ATTACH_DATA_OBJ, cid))
					return FALSE;	
				continue;
			}
			case PR_ATTACH_DATA_BIN:
			case PR_ATTACH_DATA_OBJ:
				if (cu_set_object_cid_value(psqlite,
				    table_type, id, &ppropvals->ppropval[i]))
					continue;
				pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecError);
				continue;
			}
			break;
		default:
			break;
		}
		proptype = PROP_TYPE(ppropvals->ppropval[i].proptag);
		if (cpid != CP_ACP && proptype == PT_STRING8)
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_UNICODE));
		else if (cpid != CP_ACP && proptype == PT_MV_STRING8)
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_MV_UNICODE));
		else
			sqlite3_bind_int64(pstmt, 1, ppropvals->ppropval[i].proptag);
		switch (proptype) {
		case PT_STRING8:
			if (cpid != CP_ACP) {
				pstring = common_util_convert_copy(TRUE, cpid,
				          static_cast<char *>(ppropvals->ppropval[i].pvalue));
				if (pstring == nullptr)
					return FALSE;
			} else {
				pstring = static_cast<char *>(ppropvals->ppropval[i].pvalue);
			}
			sqlite3_bind_text(pstmt, 2, pstring, -1, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		case PT_UNICODE:
			sqlite3_bind_text(pstmt, 2, static_cast<char *>(ppropvals->ppropval[i].pvalue), -1, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		case PT_FLOAT:
			sqlite3_bind_double(pstmt, 2,
				*static_cast<float *>(ppropvals->ppropval[i].pvalue));
			s_result = pstmt.step();
			break;
		case PT_DOUBLE:
		case PT_APPTIME:
			sqlite3_bind_double(pstmt, 2,
				*static_cast<double *>(ppropvals->ppropval[i].pvalue));
			s_result = pstmt.step();
			break;
		case PT_CURRENCY:
		case PT_I8:
		case PT_SYSTIME:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue));
			s_result = pstmt.step();
			break;
		case PT_SHORT:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint16_t *>(ppropvals->ppropval[i].pvalue));
			s_result = pstmt.step();
			break;
		case PT_LONG:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue));
			s_result = pstmt.step();
			break;
		case PT_BOOLEAN:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint8_t *>(ppropvals->ppropval[i].pvalue));
			s_result = pstmt.step();
			break;
		case PT_CLSID: {
			EXT_PUSH ext_push;
			if (!ext_push.init(temp_buff, 16, 0) ||
			    ext_push.p_guid(*static_cast<GUID *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_SVREID: {
			EXT_PUSH ext_push;
			if (!ext_push.init(temp_buff, 256, 0) ||
			    ext_push.p_svreid(*static_cast<SVREID *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_SRESTRICTION: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_restriction(*static_cast<RESTRICTION *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_ACTIONS: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_rule_actions(*static_cast<RULE_ACTIONS *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_OBJECT:
		case PT_BINARY: {
			auto bv = static_cast<BINARY *>(ppropvals->ppropval[i].pvalue);
			if (bv->cb == 0)
				sqlite3_bind_blob(pstmt, 2, &i, 0, SQLITE_STATIC);
			else
				sqlite3_bind_blob(pstmt, 2, bv->pv, bv->cb, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_SHORT: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_uint16_a(*static_cast<SHORT_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_LONG: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_uint32_a(*static_cast<LONG_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_CURRENCY:
		case PT_MV_I8:
		case PT_MV_SYSTIME: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_uint64_a(*static_cast<LONGLONG_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_FLOAT: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_float_a(*static_cast<FLOAT_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_DOUBLE:
		case PT_MV_APPTIME: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_double_a(*static_cast<DOUBLE_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_STRING8: {
			if (cpid != CP_ACP) {
				auto arr = static_cast<const STRING_ARRAY *>(ppropvals->ppropval[i].pvalue);
				tmp_strings.count = arr->count;
				tmp_strings.ppstr = cu_alloc<char *>(tmp_strings.count);
				if (tmp_strings.ppstr == nullptr)
					return FALSE;
				for (size_t j = 0; j < tmp_strings.count; ++j) {
					tmp_strings.ppstr[j] = common_util_convert_copy(
						TRUE, cpid, arr->ppstr[j]);
					if (tmp_strings.ppstr[j] == nullptr)
						return FALSE;
				}
				pstrings = &tmp_strings;
			} else {
				pstrings = static_cast<STRING_ARRAY *>(ppropvals->ppropval[i].pvalue);
			}
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_str_a(*pstrings) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_UNICODE: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_str_a(*static_cast<STRING_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_CLSID: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_guid_a(*static_cast<GUID_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		case PT_MV_BINARY: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_bin_a(*static_cast<BINARY_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = pstmt.step();
			break;
		}
		default:
			pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecNotSupported);
			sqlite3_reset(pstmt);
			continue;
		}
		sqlite3_reset(pstmt);
		if (s_result != SQLITE_DONE)
			pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecError);
	}
	return TRUE;
}

BOOL cu_remove_property(mapi_object_type table_type,
	uint64_t id, sqlite3 *psqlite, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	
	return cu_remove_properties(
		table_type, id, psqlite, &tmp_proptags);
}

BOOL cu_remove_properties(mapi_object_type table_type, uint64_t id,
	sqlite3 *psqlite, const PROPTAG_ARRAY *pproptags)
{
	char sql_string[128];
	
	switch (table_type) {
	case MAPI_STORE:
		gx_strlcpy(sql_string, "DELETE FROM store_properties WHERE proptag=?", std::size(sql_string));
		break;
	case MAPI_FOLDER:
		snprintf(sql_string, std::size(sql_string), "DELETE FROM "
			"folder_properties WHERE folder_id=%llu"
			" AND proptag=?", LLU{id});
		break;
	case MAPI_MESSAGE:
		snprintf(sql_string, std::size(sql_string), "DELETE FROM "
			"message_properties WHERE message_id=%llu"
			" AND proptag=?", LLU{id});
		break;
	case MAPI_ATTACH:
		/* No callers exercise this */
		snprintf(sql_string, std::size(sql_string), "DELETE FROM "
			"attachment_properties WHERE attachment_id=%llu"
			" AND proptag=?", LLU{id});
		break;
	case MAPI_MAILUSER:
		/* No callers exercise this */
		mlog(LV_WARN, "W-1594: %s: unsupported use case", __func__);
		return false;
	default:
		assert(!"Unknown table_type");
		return false;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		switch (table_type) {
		case MAPI_STORE:
			switch (tag) {
			case PR_MESSAGE_SIZE_EXTENDED:
			case PR_ASSOC_CONTENT_COUNT:
			case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
			case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
				continue;
			}
			break;
		case MAPI_FOLDER:
			switch (tag) {
			case PR_DISPLAY_NAME:
			case PR_PREDECESSOR_CHANGE_LIST:
				continue;
			}
			break;
		case MAPI_MESSAGE:
			switch (tag) {
			case PR_MSG_STATUS:
			case PR_PREDECESSOR_CHANGE_LIST:
				continue;
			}
			break;
		default:
			break;
		}
		switch (PROP_TYPE(tag)) {
		case PT_STRING8:
		case PT_UNICODE:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_UNICODE));
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_STRING8));
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_MV_STRING8));
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			break;
		default:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, tag);
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			break;
		}
	}
	return TRUE;
}

static inline const char *rule_tag_to_col(uint32_t tag)
{
	switch (tag) {
	case PR_RULE_SEQUENCE: return "sequence";
	case PR_RULE_STATE: return "state";
	case PR_RULE_NAME: return "name";
	case PR_RULE_PROVIDER: return "provider";
	case PR_RULE_LEVEL: return "level";
	case PR_RULE_USER_FLAGS: return "user_flags";
	case PR_RULE_PROVIDER_DATA: return "provider_data";
	case PR_RULE_CONDITION: return "condition";
	case PR_RULE_ACTIONS: return "actions";
	default: return nullptr;
	}
}

BOOL common_util_get_rule_property(uint64_t rule_id,
	sqlite3 *psqlite, uint32_t proptag, void **ppvalue)
{
	EXT_PULL ext_pull;
	char sql_string[128];
	
	if (auto x = rule_tag_to_col(proptag)) {
		snprintf(sql_string, std::size(sql_string), "SELECT %s "
		         "FROM rules WHERE rule_id=%llu", x, LLU{rule_id});
	} else if (proptag == PR_RULE_ID) {
		auto v = cu_alloc<uint64_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = rop_util_make_eid_ex(1, rule_id);
		return TRUE;
	} else {
		*ppvalue = NULL;
		return TRUE;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW ||
		SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
		*ppvalue = NULL;
		return TRUE;
	}
	switch (proptag) {
	case PR_RULE_SEQUENCE:
	case PR_RULE_STATE:
	case PR_RULE_LEVEL:
	case PR_RULE_USER_FLAGS: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = sqlite3_column_int64(pstmt, 0);
		break;
	}
	case PR_RULE_NAME:
	case PR_RULE_PROVIDER:
		*ppvalue = common_util_dup(pstmt.col_text(0));
		if (*ppvalue == nullptr)
			return FALSE;
		break;
	case PR_RULE_PROVIDER_DATA: {
		auto bv = cu_alloc<BINARY>();
		*ppvalue = bv;
		if (bv == nullptr)
			return FALSE;
		bv->cb = sqlite3_column_bytes(pstmt, 0);
		bv->pv = common_util_alloc(bv->cb);
		if (bv->pv == nullptr)
			return FALSE;
		memcpy(bv->pv, sqlite3_column_blob(pstmt, 0), bv->cb);
		break;
	}
	case PR_RULE_CONDITION: {
		auto v = cu_alloc<RESTRICTION>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0), common_util_alloc, 0);
		if (ext_pull.g_restriction(v) != EXT_ERR_SUCCESS) {
			*ppvalue = NULL;
			return TRUE;
		}
		break;
	}
	case PR_RULE_ACTIONS: {
		auto v = cu_alloc<RULE_ACTIONS>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0), common_util_alloc, 0);
		if (ext_pull.g_rule_actions(v) != EXT_ERR_SUCCESS) {
			*ppvalue = NULL;
			return TRUE;
		}
		break;
	}
	}
	return TRUE;
}

BOOL common_util_get_permission_property(uint64_t member_id,
	sqlite3 *psqlite, uint32_t proptag, void **ppvalue)
{
	char sql_string[128];
	const char *pusername;
	char display_name[256];
	static constexpr BINARY fake_bin{};
	
	switch (proptag) {
	case PR_ENTRYID:
		if (0 == member_id || -1 == (int64_t)member_id) {
			*ppvalue = deconst(&fake_bin);
			return TRUE;
		}
		snprintf(sql_string, std::size(sql_string), "SELECT username FROM"
		          " permissions WHERE member_id=%llu", LLU{member_id});
		break;
	case PR_MEMBER_NAME:
	case PR_SMTP_ADDRESS:
		if (0 == member_id) {
			*ppvalue = deconst("default");
			return TRUE;
		} else if (member_id == UINT64_MAX) {
			*ppvalue = deconst("anonymous");
			return TRUE;
		}
		snprintf(sql_string, std::size(sql_string), "SELECT username FROM"
		          " permissions WHERE member_id=%llu", LLU{member_id});
		break;
	case PR_MEMBER_ID:
		if (0 == member_id || -1 == (int64_t)member_id) {
			auto v = cu_alloc<uint64_t>();
			*ppvalue = v;
			if (v == nullptr)
				return FALSE;
			*v = member_id;
			return TRUE;
		}
		snprintf(sql_string, std::size(sql_string), "SELECT username FROM"
		          " permissions WHERE member_id=%llu", LLU{member_id});
		break;
	case PR_MEMBER_RIGHTS:
		if (member_id == 0)
			snprintf(sql_string, std::size(sql_string), "SELECT config_value "
					"FROM configurations WHERE config_id=%d",
					CONFIG_ID_DEFAULT_PERMISSION);
		else if (member_id == UINT64_MAX)
			snprintf(sql_string, std::size(sql_string), "SELECT config_value "
					"FROM configurations WHERE config_id=%d",
					CONFIG_ID_ANONYMOUS_PERMISSION);
		else
			snprintf(sql_string, std::size(sql_string), "SELECT permission FROM "
			          "permissions WHERE member_id=%llu", LLU{member_id});
		break;
	default:
		*ppvalue = NULL;
		return TRUE;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*ppvalue = NULL;
		return TRUE;
	}
	if (proptag == PR_MEMBER_ID) {
		auto v = cu_alloc<uint64_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		if (SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
			*ppvalue = NULL;
			return TRUE;
		}
		pusername = pstmt.col_text(0);
		if (*pusername == '\0')
			*v = UINT64_MAX;
		else if (strcasecmp(pusername, "default") == 0)
			*v = 0;
		else
			*v = member_id;
		return TRUE;
	}
	if (SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
		*ppvalue = NULL;
		return TRUE;
	}
	switch (proptag) {
	case PR_ENTRYID:
		pusername = pstmt.col_text(0);
		if ('\0' == pusername[0] || 0 == strcasecmp(pusername, "default")) {
			*ppvalue = deconst(&fake_bin);
			return TRUE;
		}
		*ppvalue = common_util_username_to_addressbook_entryid(pusername);
		break;
	case PR_MEMBER_NAME:
	case PR_SMTP_ADDRESS:
		pusername = pstmt.col_text(0);
		if ('\0' == pusername[0]) {
			*ppvalue = deconst("default");
			return TRUE;
		} else if (0 == strcasecmp(pusername, "default")) {
			*ppvalue = deconst("anonymous");
			return TRUE;
		}
		*ppvalue = common_util_dup(proptag == PR_SMTP_ADDRESS ||
		           !common_util_get_user_displayname(pusername,
		           display_name, std::size(display_name)) ||
		           display_name[0] == '\0'?
		               pusername : display_name);
		if (NULL == *ppvalue) {
			*ppvalue = NULL;
			return FALSE;
		}
		break;
	case PR_MEMBER_RIGHTS: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = sqlite3_column_int64(pstmt, 0);
		break;
	}
	}
	return TRUE;
}

BOOL common_util_addressbook_entryid_to_username(const BINARY *pentryid_bin,
     char *username, size_t ulen)
{
	EXT_PULL ext_pull;
	EMSAB_ENTRYID tmp_entryid;

	ext_pull.init(pentryid_bin->pb, pentryid_bin->cb, common_util_alloc, 0);
	if (ext_pull.g_abk_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;
	return common_util_essdn_to_username(tmp_entryid.px500dn, username, ulen);
}

BOOL common_util_addressbook_entryid_to_essdn(const BINARY *pentryid_bin,
    char *pessdn, size_t dnmax)
{
	EXT_PULL ext_pull;
	EMSAB_ENTRYID tmp_entryid;

	ext_pull.init(pentryid_bin->pb, pentryid_bin->cb, common_util_alloc, 0);
	if (ext_pull.g_abk_eid(&tmp_entryid) != EXT_ERR_SUCCESS)
		return FALSE;
	gx_strlcpy(pessdn, tmp_entryid.px500dn, dnmax);
	return TRUE;
}

BOOL common_util_entryid_to_username(const BINARY *pbin,
    char *username, size_t ulen)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	FLATUID provider_uid;
	
	if (pbin->cb < 20)
		return FALSE;
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

BOOL common_util_parse_addressbook_entryid(const BINARY *pbin,
    char *address_type, size_t atsize, char *email_address, size_t emsize)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	FLATUID provider_uid;
	
	if (pbin->cb < 20)
		return FALSE;
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_uint32(&flags) != EXT_ERR_SUCCESS || flags != 0 ||
	    ext_pull.g_guid(&provider_uid) != EXT_ERR_SUCCESS)
		return FALSE;
	/* Tail functions will use EXT_PULL::*_eid, which parse a full EID */
	ext_pull.m_offset = 0;
	if (provider_uid == muidEMSAB)
		return emsab_to_parts(ext_pull, address_type,
		       atsize, email_address, emsize) ? TRUE : false;
	if (provider_uid == muidOOP)
		return oneoff_to_parts(ext_pull, address_type,
		       atsize, email_address, emsize) ? TRUE : false;
	return FALSE;
}

BINARY* common_util_to_private_folder_entryid(
	sqlite3 *psqlite, const char *username,
	uint64_t folder_id)
{
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	auto pbin = common_util_get_mailbox_guid(psqlite);
	if (pbin == nullptr)
		return nullptr;
	memcpy(&tmp_entryid.provider_uid, pbin->pb, 16);
	unsigned int user_id = 0;
	if (!common_util_get_id_from_username(username, &user_id))
		return nullptr;
	tmp_entryid.database_guid = rop_util_make_user_guid(user_id);
	tmp_entryid.folder_type = EITLT_PRIVATE_FOLDER;
	tmp_entryid.global_counter = rop_util_get_gc_array(folder_id);
	tmp_entryid.pad[0] = 0;
	tmp_entryid.pad[1] = 0;
	pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 256, 0) ||
	    ext_push.p_folder_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BINARY* common_util_to_private_message_entryid(
	sqlite3 *psqlite, const char *username,
	uint64_t folder_id, uint64_t message_id)
{
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	auto pbin = common_util_get_mailbox_guid(psqlite);
	if (pbin == nullptr)
		return nullptr;
	memcpy(&tmp_entryid.provider_uid, pbin->pb, 16);
	unsigned int user_id = 0;
	if (!common_util_get_id_from_username(username, &user_id))
		return nullptr;
	tmp_entryid.folder_database_guid = rop_util_make_user_guid(user_id);
	tmp_entryid.message_type = EITLT_PRIVATE_MESSAGE;
	tmp_entryid.message_database_guid = tmp_entryid.folder_database_guid;
	tmp_entryid.folder_global_counter = rop_util_get_gc_array(folder_id);
	tmp_entryid.message_global_counter = rop_util_get_gc_array(message_id);
	tmp_entryid.pad1[0] = 0;
	tmp_entryid.pad1[1] = 0;
	tmp_entryid.pad2[0] = 0;
	tmp_entryid.pad2[1] = 0;
	pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 256, 0) ||
	    ext_push.p_msg_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return NULL;
	pbin->cb = ext_push.m_offset;
	return pbin;
}

BOOL cu_get_folder_permission(sqlite3 *psqlite, uint64_t folder_id,
    const char *username, uint32_t *ppermission)
{
	char sql_string[1024];
	
	*ppermission = rightsNone;
	snprintf(sql_string, 1024, "SELECT permission"
				" FROM permissions WHERE folder_id=%llu AND"
				" username=?", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, username == nullptr ? "" : username, -1, SQLITE_STATIC);
	if (pstmt.step() == SQLITE_ROW) {
		*ppermission = sqlite3_column_int64(pstmt, 0);
		return TRUE;
	}
	if (NULL != username && '\0' != username[0]) {
		snprintf(sql_string, std::size(sql_string), "SELECT username, permission"
		         " FROM permissions WHERE folder_id=%llu", LLU{folder_id});
		auto pstmt1 = gx_sql_prep(psqlite, sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
		while (pstmt1.step() == SQLITE_ROW) {
			if (common_util_check_mlist_include(pstmt1.col_text(0), username)) {
				*ppermission = sqlite3_column_int64(pstmt1, 1);
				return TRUE;
			}
		}
		pstmt1.finalize();
		sqlite3_reset(pstmt);
		sqlite3_bind_text(pstmt, 1, "default", -1, SQLITE_STATIC);
		if (pstmt.step() == SQLITE_ROW) {
			*ppermission = sqlite3_column_int64(pstmt, 0);
			return TRUE;
		}
	}
	pstmt.finalize();
	if (username == nullptr || *username == '\0')
		snprintf(sql_string, std::size(sql_string), "SELECT config_value "
		         "FROM configurations WHERE config_id=%d",
		         CONFIG_ID_ANONYMOUS_PERMISSION);
	else
		snprintf(sql_string, std::size(sql_string), "SELECT config_value "
		         "FROM configurations WHERE config_id=%d",
		         CONFIG_ID_DEFAULT_PERMISSION);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() == SQLITE_ROW)
		*ppermission = sqlite3_column_int64(pstmt, 0);
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

BOOL common_util_check_descendant(sqlite3 *psqlite,
	uint64_t inner_fid, uint64_t outer_fid, BOOL *pb_included)
{
	uint64_t folder_id;
	
	if (inner_fid == outer_fid) {
		*pb_included = TRUE;
		return TRUE;
	}
	folder_id = inner_fid;
	auto b_private = exmdb_server::is_private();
	auto pstmt = gx_sql_prep(psqlite, "SELECT parent_id"
	             " FROM folders WHERE folder_id=?");
	if (pstmt == nullptr)
		return FALSE;
	while (!((b_private && folder_id == PRIVATE_FID_ROOT) ||
	    (!b_private && folder_id == PUBLIC_FID_ROOT))) {
		sqlite3_bind_int64(pstmt, 1, folder_id);
		if (pstmt.step() != SQLITE_ROW) {
			*pb_included = FALSE;
			return TRUE;
		}
		folder_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt);
		if (folder_id == outer_fid) {
			*pb_included = TRUE;
			return TRUE;
		}
	}
	*pb_included = FALSE;
	return TRUE;
}

BOOL common_util_get_message_parent_folder(sqlite3 *psqlite,
	uint64_t message_id, uint64_t *pfolder_id)
{
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT parent_fid FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;	
	*pfolder_id = pstmt.step() != SQLITE_ROW ? 0 :
	              sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

static SVREID *cu_get_msg_parent_svreid(sqlite3 *psqlite, uint64_t message_id)
{
	uint64_t folder_id;
	
	if (!common_util_get_message_parent_folder(psqlite, message_id, &folder_id))
		return NULL;	
	auto s = cu_alloc<SVREID>();
	if (s == nullptr)
		return NULL;
	s->pbin = nullptr;
	s->folder_id = folder_id;
	s->message_id = 0;
	s->instance = 0;
	return s;
}

BOOL common_util_load_search_scopes(sqlite3 *psqlite,
	uint64_t folder_id, LONGLONG_ARRAY *pfolder_ids)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM "
	          "search_scopes WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	pfolder_ids->count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	pfolder_ids->pll = cu_alloc<uint64_t>(pfolder_ids->count);
	if (pfolder_ids->pll == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT included_fid FROM"
	          " search_scopes WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (size_t i = 0; i < pfolder_ids->count && pstmt.step() == SQLITE_ROW; )
		pfolder_ids->pll[i++] = sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

static bool cu_eval_subitem_restriction(sqlite3 *psqlite, cpid_t cpid,
    mapi_object_type table_type, uint64_t id, const RESTRICTION *pres)
{
	void *pvalue;
	void *pvalue1;
	
	switch (pres->rt) {
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (!rcon->comparable())
			return FALSE;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rcon->proptag, &pvalue))
			return FALSE;
		return rcon->eval(pvalue);
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!rprop->comparable())
			return false;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rprop->proptag, &pvalue))
			return FALSE;
		if (pvalue == nullptr || rprop->proptag != PR_ANR)
			return rprop->eval(pvalue);
		return strcasestr(static_cast<char *>(pvalue),
		       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (!rprop->comparable())
			return FALSE;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rprop->proptag1, &pvalue))
			return FALSE;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rprop->proptag2, &pvalue1))
			return FALSE;
		return propval_compare_relop_nullok(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (!rbm->comparable())
			return FALSE;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rbm->proptag, &pvalue))
			return FALSE;
		return rbm->eval(pvalue);
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rsize->proptag, &pvalue))
			return FALSE;
		return rsize->eval(pvalue);
	}
	case RES_EXIST: {
		auto rex = pres->exist;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rex->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		return TRUE;
	}
	case RES_COMMENT:
	case RES_ANNOTATION: {
		auto rcom = pres->comment;
		if (rcom->pres == nullptr)
			return TRUE;
		return cu_eval_subitem_restriction(psqlite, cpid,
		       table_type, id, rcom->pres);
	}
	default:
		return false;
	}
	return FALSE;
}

static bool cu_eval_msgsubs_restriction(sqlite3 *psqlite, cpid_t cpid,
    uint64_t message_id, uint32_t proptag, const RESTRICTION *pres)
{
	uint64_t id;
	uint32_t count;
	mapi_object_type table_type;
	char sql_string[128];
	
	if (proptag == PR_MESSAGE_RECIPIENTS) {
		table_type = MAPI_MAILUSER;
		snprintf(sql_string, std::size(sql_string), "SELECT recipient_id FROM "
				"recipients WHERE message_id=%llu", LLU{message_id});
	} else {
		table_type = MAPI_ATTACH;
		snprintf(sql_string, std::size(sql_string), "SELECT attachment_id FROM"
				" attachments WHERE message_id=%llu", LLU{message_id});
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	count = 0;
	while (pstmt.step() == SQLITE_ROW) {
		id = sqlite3_column_int64(pstmt, 0);
		if (pres->rt == RES_COUNT) {
			if (cu_eval_subitem_restriction(psqlite,
			    cpid, table_type, id,
			    &static_cast<RESTRICTION_COUNT *>(pres->pres)->sub_res))
				count ++;
		} else {
			if (cu_eval_subitem_restriction(psqlite,
			    cpid, table_type, id, pres))
				return TRUE;
		}
	}
	return pres->rt == RES_COUNT && pres->count->count == count;
}

static bool cu_eval_subobj_restriction(sqlite3 *psqlite, cpid_t cpid,
    uint64_t message_id, uint32_t proptag, const RESTRICTION *pres)
{
	switch (pres->rt) {
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (cu_eval_subobj_restriction(psqlite,
			    cpid, message_id, proptag, &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!cu_eval_subobj_restriction(psqlite,
			    cpid, message_id, proptag, &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		return !cu_eval_subobj_restriction(psqlite, cpid,
		       message_id, proptag, &pres->xnot->res);
	case RES_CONTENT:
	case RES_PROPERTY:
	case RES_PROPCOMPARE:
	case RES_BITMASK:
	case RES_SIZE:
	case RES_EXIST:
	case RES_COMMENT:
	case RES_ANNOTATION:
	case RES_COUNT:
		return cu_eval_msgsubs_restriction(
				psqlite, cpid, message_id, proptag, pres);
	default:
		return false;
	}	
	return FALSE;
}

bool cu_eval_folder_restriction(sqlite3 *psqlite,
	uint64_t folder_id, const RESTRICTION *pres)
{
	void *pvalue;
	void *pvalue1;
	
	switch (pres->rt) {
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (cu_eval_folder_restriction(psqlite,
			    folder_id, &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!cu_eval_folder_restriction(psqlite,
			    folder_id, &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		return !cu_eval_folder_restriction(psqlite,
		       folder_id, &pres->xnot->res);
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (!rcon->comparable())
			return FALSE;
		if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
		    rcon->proptag, &pvalue))
			return FALSE;
		return rcon->eval(pvalue);
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!rprop->comparable())
			return false;
		if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
		    rprop->proptag, &pvalue))
			return FALSE;
		if (pvalue == nullptr || rprop->proptag != PR_ANR)
			return rprop->eval(pvalue);
		return strcasestr(static_cast<char *>(pvalue),
		       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (!rprop->comparable())
			return FALSE;
		if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
		    rprop->proptag1, &pvalue))
			return FALSE;
		if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
		    rprop->proptag2, &pvalue1))
			return FALSE;
		return propval_compare_relop_nullok(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (!rbm->comparable())
			return FALSE;
		if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
		    rbm->proptag, &pvalue))
			return FALSE;
		return rbm->eval(pvalue);
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
		    rsize->proptag, &pvalue))
			return FALSE;
		return rsize->eval(pvalue);
	}
	case RES_EXIST:
		if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
		    pres->exist->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		return TRUE;
	case RES_COMMENT:
	case RES_ANNOTATION:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return cu_eval_folder_restriction(psqlite,
		       folder_id, pres->comment->pres);
	default:
		return FALSE;
	}	
	return FALSE;
}

bool cu_eval_msg_restriction(sqlite3 *psqlite,
    cpid_t cpid, uint64_t message_id, const RESTRICTION *pres)
{
	void *pvalue;
	void *pvalue1;
	
	switch (pres->rt) {
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (cu_eval_msg_restriction(psqlite,
			    cpid, message_id, &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!cu_eval_msg_restriction(psqlite,
			    cpid, message_id, &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		return !cu_eval_msg_restriction(psqlite,
		       cpid, message_id, &pres->xnot->res);
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (!rcon->comparable())
			return FALSE;
		if (!cu_get_property(MAPI_MESSAGE,
		    message_id, cpid, psqlite, rcon->proptag, &pvalue))
			return FALSE;
		return rcon->eval(pvalue);
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!rprop->comparable())
			return false;
		switch (rprop->proptag) {
		case PR_PARENT_SVREID:
		case PR_PARENT_ENTRYID:
			pvalue = cu_get_msg_parent_svreid(psqlite, message_id);
			break;
		case PR_ANR: {
			if (!cu_get_property(MAPI_MESSAGE,
			    message_id, cpid, psqlite, rprop->proptag, &pvalue))
				return FALSE;
			if (pvalue == nullptr)
				break;
			return strcasestr(static_cast<char *>(pvalue),
			       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
		}
		default:
			if (!cu_get_property(MAPI_MESSAGE,
			    message_id, cpid, psqlite, rprop->proptag, &pvalue))
				return FALSE;
			break;
		}
		return rprop->eval(pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (!rprop->comparable())
			return FALSE;
		if (!cu_get_property(MAPI_MESSAGE,
		    message_id, cpid, psqlite, rprop->proptag1, &pvalue))
			return FALSE;
		if (!cu_get_property(MAPI_MESSAGE,
		    message_id, cpid, psqlite, rprop->proptag2, &pvalue1))
			return FALSE;
		return propval_compare_relop_nullok(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (!rbm->comparable())
			return FALSE;
		if (!cu_get_property(MAPI_MESSAGE,
		    message_id, cpid, psqlite, rbm->proptag, &pvalue))
			return FALSE;
		return rbm->eval(pvalue);
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!cu_get_property(MAPI_MESSAGE,
		    message_id, cpid, psqlite, rsize->proptag, &pvalue))
			return FALSE;
		return rsize->eval(pvalue);
	}
	case RES_EXIST:
		if (!cu_get_property(MAPI_MESSAGE,
		    message_id, cpid, psqlite, pres->exist->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		return TRUE;
	case RES_SUBRESTRICTION: {
		auto rsub = pres->sub;
		if (rsub->subobject == PR_MESSAGE_RECIPIENTS ||
		    rsub->subobject == PR_MESSAGE_ATTACHMENTS)
			return cu_eval_subobj_restriction(psqlite,
			       cpid, message_id, rsub->subobject,
			       &rsub->res);
		return FALSE;
	}
	case RES_COMMENT:
	case RES_ANNOTATION:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return cu_eval_msg_restriction(psqlite, cpid,
		       message_id, pres->comment->pres);
	case RES_COUNT: {
		auto rcnt = pres->count;
		if (rcnt->count == 0)
			return FALSE;
		if (!cu_eval_msg_restriction(psqlite,
		    cpid, message_id, &rcnt->sub_res))
			return false;
		--rcnt->count;
		return TRUE;
	}
	case RES_NULL:
		return TRUE;
	}	
	return FALSE;
}

BOOL common_util_check_search_result(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist)
{
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM"
				" search_result WHERE folder_id=%llu AND "
				"message_id=%llu", LLU{folder_id}, LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_exist = pstmt.step() == SQLITE_ROW ? TRUE : false;
	return TRUE;
}

BOOL common_util_get_mid_string(sqlite3 *psqlite,
	uint64_t message_id, char **ppmid_string)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT mid_string FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	if (SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
		*ppmid_string = NULL;
		return TRUE;
	}
	*ppmid_string = common_util_dup(pstmt.col_text(0));
	return *ppmid_string != nullptr ? TRUE : false;
}

BOOL common_util_set_mid_string(sqlite3 *psqlite,
	uint64_t message_id, const char *pmid_string)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "UPDATE messages set "
	          "mid_string=? WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, pmid_string, -1, SQLITE_STATIC);
	return pstmt.step() == SQLITE_DONE ? TRUE : false;
}

BOOL common_util_check_message_owner(sqlite3 *psqlite,
	uint64_t message_id, const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EXT_PULL ext_pull;
	char tmp_name[UADDR_SIZE];
	EMSAB_ENTRYID ab_entryid;
	
	if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP, psqlite,
	    PR_CREATOR_ENTRYID, reinterpret_cast<void **>(&pbin)))
		return FALSE;
	if (NULL == pbin) {
		*pb_owner = FALSE;
		return TRUE;
	}
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_abk_eid(&ab_entryid) != EXT_ERR_SUCCESS) {
		*pb_owner = false;
		return TRUE;
	}
	if (!common_util_essdn_to_username(ab_entryid.px500dn,
	    tmp_name, std::size(tmp_name))) {
		*pb_owner = false;
		return TRUE;
	}
	*pb_owner = strcasecmp(username, tmp_name) == 0 ? TRUE : false;
	return TRUE;
}

static BOOL common_util_copy_message_internal(sqlite3 *psqlite, 
	BOOL b_embedded, uint64_t message_id, uint64_t parent_id,
	uint64_t *pdst_mid, BOOL *pb_result, uint64_t *pchange_num,
	uint32_t *pmessage_size)
{
	BOOL b_result;
	uint64_t tmp_id;
	uint64_t tmp_mid;
	uint64_t last_id;
	int is_associated, read_state = 0;
	char tmp_path[256];
	char tmp_path1[256];
	uint64_t change_num;
	char sql_string[512];
	char mid_string[128];
	char mid_string1[128];
	uint32_t message_size;
	auto b_private = exmdb_server::is_private();
	
	if (!b_embedded) {
		if (*pdst_mid == 0 &&
		    !common_util_allocate_eid_from_folder(psqlite, parent_id, pdst_mid))
			return FALSE;
	} else if (!common_util_allocate_eid(psqlite, pdst_mid)) {
		return FALSE;
	}
	if (!common_util_allocate_cn(psqlite, &change_num))
		return FALSE;
	if (pchange_num != nullptr)
		*pchange_num = change_num;
	if (b_private)
		snprintf(sql_string, std::size(sql_string), "SELECT is_associated, message_size,"
			" read_state, mid_string FROM messages WHERE message_id=%llu",
		          LLU{message_id});
	else
		snprintf(sql_string, std::size(sql_string), "SELECT is_associated, "
			"message_size FROM messages WHERE message_id=%llu",
		          LLU{message_id});

	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*pb_result = FALSE;
		return TRUE;
	}
	is_associated = sqlite3_column_int64(pstmt, 0);
	message_size = sqlite3_column_int64(pstmt, 1);
	if (b_private) {
		read_state = sqlite3_column_int64(pstmt, 2);
		if (SQLITE_NULL == sqlite3_column_type(pstmt, 3)) {
			mid_string[0] = '\0';
		} else {
			gx_strlcpy(mid_string1, pstmt.col_text(3), std::size(mid_string1));
			snprintf(mid_string, std::size(mid_string), "%lld.%u.%s",
			         LLD{time(nullptr)}, common_util_sequence_ID(), get_host_ID());
			snprintf(tmp_path, std::size(tmp_path), "%s/eml/%s",
			         exmdb_server::get_dir(), mid_string);
			snprintf(tmp_path1, std::size(tmp_path1), "%s/eml/%s",
			         exmdb_server::get_dir(), mid_string1);
			link(tmp_path1, tmp_path);
			snprintf(tmp_path, std::size(tmp_path), "%s/ext/%s",
			         exmdb_server::get_dir(), mid_string);
			snprintf(tmp_path1, std::size(tmp_path1), "%s/ext/%s",
			         exmdb_server::get_dir(), mid_string1);
			link(tmp_path1, tmp_path);
		}
	}
	if (pmessage_size != nullptr)
		*pmessage_size = message_size;
	pstmt.finalize();
	if (b_embedded) {
		snprintf(sql_string, std::size(sql_string), "INSERT INTO messages (message_id, parent_fid,"
			" parent_attid, is_associated, change_number, message_size) "
			"VALUES (%llu, NULL, %llu, %d, %llu, %u)", LLU{*pdst_mid},
			LLU{parent_id}, 0, LLU{change_num}, message_size);
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	} else if (b_private) {
		snprintf(sql_string, std::size(sql_string), "INSERT INTO messages (message_id, "
		         "parent_fid, parent_attid, is_associated, change_number, "
		         "read_state, message_size, mid_string) VALUES (%llu, %llu,"
		         " NULL, %d, %llu, %d, %u, ?)", LLU{*pdst_mid}, LLU{parent_id},
		         is_associated, LLU{change_num}, read_state, message_size);
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (*mid_string == '\0')
			sqlite3_bind_null(pstmt, 1);
		else
			sqlite3_bind_text(pstmt, 1, mid_string, -1, SQLITE_STATIC);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		pstmt.finalize();
	} else {
		snprintf(sql_string, std::size(sql_string), "INSERT INTO messages (message_id, parent_fid,"
		         " parent_attid, is_associated, change_number, message_size) "
		         "VALUES (%llu, %llu, NULL, %d, %llu, %u)", LLU{*pdst_mid},
		         LLU{parent_id}, is_associated, LLU{change_num}, message_size);
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	snprintf(sql_string, std::size(sql_string), "INSERT INTO message_properties (message_id,"
			" proptag, propval) SELECT %llu, proptag, propval FROM "
			"message_properties WHERE message_id=%llu",
			LLU{*pdst_mid}, LLU{message_id});
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "INSERT INTO recipients"
	          " (message_id) VALUES (%llu)", LLU{*pdst_mid});
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	auto pstmt2 = gx_sql_prep(psqlite, "INSERT INTO recipients_properties "
	              "(recipient_id, proptag, propval) SELECT ?, proptag, "
	              "propval FROM recipients_properties WHERE recipient_id=?");
	if (pstmt2 == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		tmp_id = sqlite3_column_int64(pstmt, 0);
		if (pstmt1.step() != SQLITE_DONE)
			return FALSE;
		last_id = sqlite3_last_insert_rowid(psqlite);
		sqlite3_bind_int64(pstmt2, 1, last_id);
		sqlite3_bind_int64(pstmt2, 2, tmp_id);
		if (pstmt2.step() != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt2);
	}
	pstmt.finalize();
	pstmt1.finalize();
	pstmt2.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT attachment_id FROM"
	          " attachments WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "INSERT INTO attachments"
	          " (message_id) VALUES (%llu)", LLU{*pdst_mid});
	pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	pstmt2 = gx_sql_prep(psqlite, "INSERT INTO attachment_properties "
	         "(attachment_id, proptag, propval) SELECT ?, proptag, "
	         "propval FROM attachment_properties WHERE attachment_id=?");
	if (pstmt2 == nullptr)
		return FALSE;
	auto stm_sel_mid = gx_sql_prep(psqlite, "SELECT message_id"
	              " FROM messages WHERE parent_attid=?");
	if (stm_sel_mid == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		tmp_id = sqlite3_column_int64(pstmt, 0);
		if (pstmt1.step() != SQLITE_DONE)
			return FALSE;
		last_id = sqlite3_last_insert_rowid(psqlite);
		sqlite3_bind_int64(pstmt2, 1, last_id);
		sqlite3_bind_int64(pstmt2, 2, tmp_id);
		if (pstmt2.step() != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt2);
		stm_sel_mid.bind_int64(1, tmp_id);
		if (stm_sel_mid.step() == SQLITE_ROW) {
			if (!common_util_copy_message_internal(psqlite, TRUE,
			    stm_sel_mid.col_int64(0), last_id, &tmp_mid,
			    &b_result, nullptr, nullptr))
				return FALSE;
			if (!b_result) {
				*pb_result = FALSE;
				return TRUE;
			}
		}
		stm_sel_mid.reset();
	}
	*pb_result = TRUE;
	return TRUE;
}

BOOL common_util_copy_message(sqlite3 *psqlite, int account_id,
	uint64_t message_id, uint64_t folder_id, uint64_t *pdst_mid,
	BOOL *pb_result, uint32_t *pmessage_size)
{
	void *pvalue;
	BOOL b_result;
	uint64_t nt_time;
	uint64_t change_num;
	TPROPVAL_ARRAY propvals;
	PROBLEM_ARRAY tmp_problems;
	static const uint32_t fake_uid = 1;
	TAGGED_PROPVAL propval_buff[4];
	
	if (!common_util_copy_message_internal(psqlite,
	    FALSE, message_id, folder_id, pdst_mid, pb_result,
	    &change_num, pmessage_size))
		return FALSE;
	if (!*pb_result)
		return TRUE;
	if (!cu_get_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
	    PR_INTERNET_ARTICLE_NUMBER_NEXT, &pvalue))
		return FALSE;
	if (pvalue == nullptr)
		pvalue = deconst(&fake_uid);
	auto next = *static_cast<uint32_t *>(pvalue) + 1;
	if (!cu_set_property(MAPI_FOLDER, folder_id, CP_ACP, psqlite,
	    PR_INTERNET_ARTICLE_NUMBER_NEXT, &next, &b_result))
		return FALSE;
	propval_buff[0].proptag = PR_CHANGE_KEY;
	propval_buff[0].pvalue = cu_xid_to_bin({
		exmdb_server::is_private() ?
			rop_util_make_user_guid(account_id) :
			rop_util_make_domain_guid(account_id),
		change_num});
	if (propval_buff[0].pvalue == nullptr)
		return FALSE;
	propval_buff[1].proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval_buff[1].pvalue = common_util_pcl_append(nullptr, static_cast<BINARY *>(propval_buff[0].pvalue));
	if (propval_buff[1].pvalue == nullptr)
		return FALSE;
	propval_buff[2].proptag = PR_INTERNET_ARTICLE_NUMBER;
	propval_buff[2].pvalue = pvalue;
	nt_time = rop_util_current_nttime();
	propval_buff[3].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[3].pvalue = &nt_time;
	propvals.count = 4;
	propvals.ppropval = propval_buff;
	return cu_set_properties(MAPI_MESSAGE, *pdst_mid, CP_ACP, psqlite,
	       &propvals, &tmp_problems);
}

BOOL common_util_get_named_propids(sqlite3 *psqlite,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	char sql_string[128];
	
	ppropids->ppropid = cu_alloc<uint16_t>(ppropnames->count);
	if (ppropids->ppropid == nullptr)
		return FALSE;
	ppropids->count = ppropnames->count;
	if (b_create) {
		snprintf(sql_string, std::size(sql_string), "SELECT"
			" count(*) FROM named_properties");
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		/* if there are too many property names in table, stop creating */
		if (sqlite3_column_int64(pstmt, 0) + ppropnames->count >
		    MAXIMUM_PROPNAME_NUMBER)
			/* at some point we may want to return ecNPQuotaExceeded */
			b_create = FALSE;
	}
	auto pstmt = gx_sql_prep(psqlite, "SELECT propid FROM "
	             "named_properties WHERE name_string=?");
	decltype(pstmt) pstmt1;
	if (pstmt == nullptr)
		return FALSE;
	if (b_create) {
		snprintf(sql_string, std::size(sql_string), "INSERT INTO "
			"named_properties (name_string) VALUES (?)");
		pstmt1 = gx_sql_prep(psqlite, sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
	}
	for (size_t i = 0; i < ppropnames->count; ++i) try {
		char guid_string[GUIDSTR_SIZE];
		ppropnames->ppropname[i].guid.to_str(guid_string, std::size(guid_string));
		std::string name_string;
		switch (ppropnames->ppropname[i].kind) {
		case MNID_ID:
			name_string = "GUID="s + guid_string + ",LID=" +
			              std::to_string(ppropnames->ppropname[i].lid);
			break;
		case MNID_STRING:
			if (strlen(ppropnames->ppropname[i].pname) >= 1024) {
				ppropids->ppropid[i] = 0;
				continue;
			}
			name_string = "GUID="s + guid_string + ",NAME=" +
			              ppropnames->ppropname[i].pname;
			break;
		default:
			ppropids->ppropid[i] = 0;
			continue;
		}
		sqlite3_bind_text(pstmt, 1, name_string.c_str(), -1, SQLITE_STATIC);
		if (pstmt.step() == SQLITE_ROW) {
			ppropids->ppropid[i] = sqlite3_column_int64(pstmt, 0);
			sqlite3_reset(pstmt);
			continue;
		}
		sqlite3_reset(pstmt);
		if (b_create) {
			sqlite3_bind_text(pstmt1, 1, name_string.c_str(), -1, SQLITE_STATIC);
			if (pstmt1.step() != SQLITE_DONE)
				return FALSE;
			ppropids->ppropid[i] = sqlite3_last_insert_rowid(psqlite);
			sqlite3_reset(pstmt1);
		} else {
			ppropids->ppropid[i] = 0;
		}
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1503: ENOMEM");
		return false;
	}
	return TRUE;
}

BOOL common_util_get_named_propnames(sqlite3 *psqlite,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	int i;
	char *ptoken;
	char temp_name[1024];
	
	ppropnames->ppropname = cu_alloc<PROPERTY_NAME>(ppropids->count);
	if (ppropnames->ppropname == nullptr)
		return FALSE;
	ppropnames->count = ppropids->count;
	auto pstmt = gx_sql_prep(psqlite, "SELECT name_string "
	             "FROM named_properties WHERE propid=?");
	if (pstmt == nullptr)
		return FALSE;
	for (i=0; i<ppropids->count; i++) {
		sqlite3_bind_int64(pstmt, 1, ppropids->ppropid[i]);
		if (pstmt.step() != SQLITE_ROW) {
			sqlite3_reset(pstmt);
			goto NOT_FOUND_PROPNAME;
		}
		gx_strlcpy(temp_name, pstmt.col_text(0), std::size(temp_name));
		sqlite3_reset(pstmt);
		if (strncasecmp(temp_name, "GUID=", 5) != 0)
			goto NOT_FOUND_PROPNAME;
		ptoken = strchr(temp_name + 5, ',');
		if (ptoken == nullptr)
			goto NOT_FOUND_PROPNAME;
		*ptoken++ = '\0';
		if (!ppropnames->ppropname[i].guid.from_str(temp_name + 5))
			goto NOT_FOUND_PROPNAME;
		if (0 == strncasecmp(ptoken, "LID=", 4)) {
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].lid = strtol(ptoken + 4, nullptr, 0);
			if (ppropnames->ppropname[i].lid == 0)
				goto NOT_FOUND_PROPNAME;
			ppropnames->ppropname[i].pname = NULL;
			continue;
		} else if (0 == strncasecmp(ptoken, "NAME=", 5)) {
			ppropnames->ppropname[i].kind = MNID_STRING;
			HX_strrtrim(ptoken + 5);
			HX_strltrim(ptoken + 5);
			if (ptoken[5] == '\0')
				goto NOT_FOUND_PROPNAME;
			ppropnames->ppropname[i].pname =
					common_util_dup(ptoken + 5);
			if (ppropnames->ppropname[i].pname == nullptr)
				return FALSE;
			ppropnames->ppropname[i].lid = 0;
			continue;
		}
 NOT_FOUND_PROPNAME:
		ppropnames->ppropname[i].kind = KIND_NONE;
		ppropnames->ppropname[i].lid = 0;
		ppropnames->ppropname[i].pname = NULL;
	}
	return TRUE;
}

BOOL common_util_check_folder_id(sqlite3 *psqlite,
	uint64_t folder_id, BOOL *pb_exist)
{
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id "
	          "FROM folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_exist = pstmt.step() != SQLITE_ROW ? false : TRUE;
	return TRUE;
}

BOOL common_util_increase_deleted_count(sqlite3 *psqlite,
	uint64_t folder_id, uint32_t del_count)
{
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "UPDATE folder_properties"
		" SET propval=propval+%u WHERE proptag=%u"
		" AND folder_id=%llu", del_count,
	        PR_DELETED_COUNT_TOTAL, LLU{folder_id});
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

BOOL cu_adjust_store_size(sqlite3 *psqlite, bool subtract,
    uint64_t normal_size, uint64_t fai_size)
{
	auto pstmt = gx_sql_prep(psqlite, subtract ?
	             "UPDATE store_properties SET propval=MAX(0,propval-?) WHERE proptag=?" :
	             "UPDATE store_properties SET propval=propval+? WHERE proptag=?");
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, normal_size + fai_size);
	sqlite3_bind_int64(pstmt, 2, PR_MESSAGE_SIZE_EXTENDED);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	if (0 != normal_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, normal_size);
		sqlite3_bind_int64(pstmt, 2, PR_NORMAL_MESSAGE_SIZE_EXTENDED);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
	}
	if (0 != fai_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, fai_size);
		sqlite3_bind_int64(pstmt, 2, PR_ASSOC_MESSAGE_SIZE_EXTENDED);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
	}
	return TRUE;
}

BOOL cu_rcpts_to_list(TARRAY_SET *prcpts, std::vector<std::string> &plist) try
{
	for (size_t i = 0; i < prcpts->count; ++i) {
		auto str = prcpts->pparray[i]->get<const char>(PR_SMTP_ADDRESS);
		if (str != nullptr) {
			plist.emplace_back(str);
			continue;
		}
		auto addrtype = prcpts->pparray[i]->get<const char>(PR_ADDRTYPE);
		if (addrtype == nullptr) {
 CONVERT_ENTRYID:
			auto entryid = prcpts->pparray[i]->get<const BINARY>(PR_ENTRYID);
			if (entryid == nullptr)
				return FALSE;
			char ua[UADDR_SIZE];
			if (!common_util_entryid_to_username(entryid, ua, UADDR_SIZE))
				return FALSE;
			plist.emplace_back(ua);
		} else if (strcasecmp(addrtype, "SMTP") == 0) {
			str = prcpts->pparray[i]->get<char>(PR_EMAIL_ADDRESS);
			if (str == nullptr)
				goto CONVERT_ENTRYID;
			plist.emplace_back(str);
		} else {
			goto CONVERT_ENTRYID;
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2036: ENOMEM");
	return false;
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

BOOL common_util_bind_sqlite_statement(sqlite3_stmt *pstmt,
	int bind_index, uint16_t proptype, void *pvalue)
{
	EXT_PUSH ext_push;
	char temp_buff[256];
	
	if (pvalue == nullptr)
		return FALSE;
	switch (proptype) {
	case PT_STRING8:
	case PT_UNICODE:
		sqlite3_bind_text(pstmt, bind_index, static_cast<char *>(pvalue), -1, SQLITE_STATIC);
		break;
	case PT_FLOAT:
		sqlite3_bind_double(pstmt, bind_index, *static_cast<float *>(pvalue));
		break;
	case PT_DOUBLE:
	case PT_APPTIME:
		sqlite3_bind_double(pstmt, bind_index, *static_cast<double *>(pvalue));
		break;
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		sqlite3_bind_int64(pstmt, bind_index, *static_cast<uint64_t *>(pvalue));
		break;
	case PT_SHORT:
		sqlite3_bind_int64(pstmt, bind_index, *static_cast<uint16_t *>(pvalue));
		break;
	case PT_LONG:
		sqlite3_bind_int64(pstmt, bind_index, *static_cast<uint32_t *>(pvalue));
		break;
	case PT_BOOLEAN:
		sqlite3_bind_int64(pstmt, bind_index, *static_cast<uint8_t *>(pvalue));
		break;
	case PT_CLSID:
		if (!ext_push.init(temp_buff, 16, 0) ||
		    ext_push.p_guid(*static_cast<GUID *>(pvalue)) != EXT_ERR_SUCCESS)
			return FALSE;
		sqlite3_bind_blob(pstmt, bind_index, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
		break;
	case PT_SVREID:
		if (!ext_push.init(temp_buff, 256, 0) ||
		    ext_push.p_svreid(*static_cast<SVREID *>(pvalue)) != EXT_ERR_SUCCESS)
			return FALSE;
		sqlite3_bind_blob(pstmt, bind_index, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
		break;
	case PT_OBJECT:
	case PT_BINARY: {
		auto bv = static_cast<BINARY *>(pvalue);
		if (bv->cb == 0)
			sqlite3_bind_null(pstmt, bind_index);
		else
			sqlite3_bind_blob(pstmt, bind_index, bv->pv, bv->cb, SQLITE_STATIC);
		break;
	}
	default:
		return FALSE;
	}
	return TRUE;
}

void* common_util_column_sqlite_statement(sqlite3_stmt *pstmt,
	int column_index, uint16_t proptype)
{
	void *pvalue;
	EXT_PULL ext_pull;
	
	if (sqlite3_column_type(pstmt, column_index) == SQLITE_NULL)
		return NULL;
	switch (proptype) {
	case PT_STRING8:
	case PT_UNICODE: {
		auto s = reinterpret_cast<const char *>(sqlite3_column_text(pstmt, column_index));
		if (s == nullptr)
			return NULL;
		return common_util_dup(s);
	}
	case PT_FLOAT: {
		auto v = cu_alloc<float>();
		if (v == nullptr)
			return NULL;
		*v = sqlite3_column_double(pstmt, column_index);
		return v;
	}
	case PT_DOUBLE:
	case PT_APPTIME: {
		auto v = cu_alloc<double>();
		if (v == nullptr)
			return NULL;
		*v = sqlite3_column_double(pstmt, column_index);
		return v;
	}
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME: {
		auto v = cu_alloc<uint64_t>();
		if (v == nullptr)
			return NULL;
		*v = sqlite3_column_int64(pstmt, column_index);
		return v;
	}
	case PT_SHORT: {
		auto v = cu_alloc<uint16_t>();
		if (v == nullptr)
			return NULL;
		*v = sqlite3_column_int64(pstmt, column_index);
		return v;
	}
	case PT_LONG: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return NULL;
		*v = sqlite3_column_int64(pstmt, column_index);
		return v;
	}
	case PT_BOOLEAN: {
		auto v = cu_alloc<uint8_t>();
		if (v == nullptr)
			return NULL;
		*v = sqlite3_column_int64(pstmt, column_index);
		return v;
	}
	case PT_CLSID: {
		auto blob = sqlite3_column_blob(pstmt, column_index);
		if (blob == nullptr)
			return NULL;
		ext_pull.init(blob, sqlite3_column_bytes(pstmt, column_index),
			common_util_alloc, 0);
		auto v = cu_alloc<GUID>();
		if (v == nullptr)
			return NULL;
		if (ext_pull.g_guid(v) != EXT_ERR_SUCCESS)
			return NULL;
		return v;
	}
	case PT_SVREID: {
		auto blob = sqlite3_column_blob(pstmt, column_index);
		if (blob == nullptr)
			return NULL;
		ext_pull.init(blob, sqlite3_column_bytes(pstmt, column_index),
			common_util_alloc, 0);
		auto v = cu_alloc<SVREID>();
		if (v == nullptr)
			return NULL;
		if (ext_pull.g_svreid(v) != EXT_ERR_SUCCESS)
			return NULL;
		return v;
	}
	case PT_OBJECT:
	case PT_BINARY: {
		if (sqlite3_column_bytes(pstmt, column_index) > 512)
			return NULL;
		pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return NULL;
		auto bv = static_cast<BINARY *>(pvalue);
		bv->cb = sqlite3_column_bytes(pstmt, column_index);
		if (bv->cb == 0) {
			bv->pb = NULL;
		} else {
			bv->pv = common_util_alloc(bv->cb);
			if (bv->pv == nullptr)
				return NULL;
			memcpy(bv->pv, sqlite3_column_blob(pstmt, column_index), bv->cb);
		}
		return pvalue;
	}
	}
	return NULL;
}

BOOL common_util_indexing_sub_contents(
	uint32_t step, sqlite3_stmt *pstmt,
	sqlite3_stmt *pstmt1, uint32_t *pidx)
{
	uint64_t row_id;
	
	while (true) {
		(*pidx) ++;
		row_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_bind_int64(pstmt1, 1, *pidx);
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (gx_sql_step(pstmt1) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
		if (step > 0 && 0 != sqlite3_column_int64(pstmt, 1)) {
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, -row_id);
			if (gx_sql_step(pstmt) == SQLITE_ROW &&
			    !common_util_indexing_sub_contents(step - 1, pstmt, pstmt1, pidx))
				return FALSE;
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, row_id);
		if (gx_sql_step(pstmt) != SQLITE_ROW)
			return TRUE;
	}
}

/**
 * Returns the size that contributes to PR_MESSAGE_SIZE.
 *
 * pidtagmessagesize-canonical-property.md (in the office-developer-client-docs
 * git repo) says "approximate number of bytes that are transferred". Because
 * most wire transfers happen in UTF-16, we would need a painstaking conversion
 * first for PT_UNICODE properties.
 *
 * OXPROPS v27 §2.796, OXCMSG v25 §2.2.1.7 however say "Contains the size, in
 * bytes, consumed by the Message object on the server". The object on the
 * server however is UTF-8 and thus consumes a different amount of bytes.
 * OXCFXICS v24 §3.2.5.4, §3.3.5.12, once again, allow approximations.
 *
 * Gromox also uses PR_MESSAGE_SIZE for quota tracking. That is not an exact an
 * exact science either, due to potential compression or potential presence of
 * midb EML copies.
 */
static uint32_t cu_get_cid_length(const char *cid, uint16_t proptype)
{
	auto dir = exmdb_server::get_dir();
	if (strchr(cid, '/') != nullptr) {
		/* v3 */
		auto size = gx_decompressed_size(cu_cid_path(dir, cid, 0).c_str());
		if (size != SIZE_MAX)
			return size <= UINT32_MAX ? size : UINT32_MAX;
		return 0;
	}
	auto size = gx_decompressed_size(cu_cid_path(dir, cid, 2).c_str());
	if (size != SIZE_MAX)
		return size <= UINT32_MAX ? size : UINT32_MAX;
	size = gx_decompressed_size(cu_cid_path(dir, cid, 1).c_str());
	if (size != SIZE_MAX) {
		if (proptype == PT_UNICODE && size >= 4)
			/* Discount leading U8 codepoint count field */
			size -= 4;
		return size <= UINT32_MAX ? size : UINT32_MAX;
	}

	struct stat node_stat;
	if (stat(cu_cid_path(dir, cid, 0).c_str(),
	    &node_stat) != 0)
		return 0;
	/* Le old uncompressed format has a few kinks... */
	if (proptype == PT_UNICODE && node_stat.st_size >= 4)
		/* Discount leading U8 codepoint count field */
		node_stat.st_size -= 4;
	if (static_cast<unsigned long long>(node_stat.st_size) > UINT32_MAX)
		return UINT32_MAX;
	return node_stat.st_size;
}

uint32_t common_util_calculate_message_size(
	const MESSAGE_CONTENT *pmsgctnt)
{
	uint32_t message_size;
	TAGGED_PROPVAL *ppropval;
	ATTACHMENT_CONTENT *pattachment;
	
	/* PR_ASSOCIATED, PidTagMid, PidTagChangeNumber */
	message_size = sizeof(uint8_t) + 2*sizeof(uint64_t);
	for (size_t i = 0; i < pmsgctnt->proplist.count; ++i) {
		ppropval = pmsgctnt->proplist.ppropval + i;
		switch (ppropval->proptag) {
		case PR_ASSOCIATED:
		case PidTagMid:
		case PidTagChangeNumber:
			continue;
		case ID_TAG_BODY:
		case ID_TAG_TRANSPORTMESSAGEHEADERS: {
			auto cid = static_cast<const char *>(ppropval->pvalue);
			message_size += cu_get_cid_length(cid, PT_UNICODE);
			break;
		}
		case ID_TAG_BODY_STRING8:
		case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8: {
			auto cid = static_cast<const char *>(ppropval->pvalue);
			message_size += cu_get_cid_length(cid, PT_STRING8);
			break;
		}
		case ID_TAG_HTML:
		case ID_TAG_RTFCOMPRESSED: {
			auto cid = static_cast<const char *>(ppropval->pvalue);
			message_size += cu_get_cid_length(cid, PT_BINARY);
			break;
		}
		default:
			message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
			break;
		}
	}
	if (NULL != pmsgctnt->children.prcpts) {
		for (size_t i = 0; i < pmsgctnt->children.prcpts->count; ++i) {
			for (size_t j = 0; j < pmsgctnt->children.prcpts->pparray[i]->count; ++j) {
				ppropval = pmsgctnt->children.prcpts->pparray[i]->ppropval + j;
				if (ppropval->proptag == PR_ROWID)
					continue;
				message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
			}
		}
	}
	if (NULL != pmsgctnt->children.pattachments) {
		for (size_t i = 0; i < pmsgctnt->children.pattachments->count; ++i) {
			pattachment = pmsgctnt->children.pattachments->pplist[i];
			for (size_t j = 0; j < pattachment->proplist.count; ++j) {
				ppropval = pattachment->proplist.ppropval + j;
				switch (ppropval->proptag) {
				case PR_ATTACH_NUM:
					continue;
				case ID_TAG_ATTACHDATABINARY:
				case ID_TAG_ATTACHDATAOBJECT: {
					auto cid = static_cast<const char *>(ppropval->pvalue);
					message_size += cu_get_cid_length(cid, PT_BINARY);
					break;
				}
				default:
					message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
				}
			}
			if (pattachment->pembedded != nullptr)
				message_size += common_util_calculate_message_size(pattachment->pembedded);
		}
	}
	return message_size;
}

uint32_t common_util_calculate_attachment_size(
	const ATTACHMENT_CONTENT *pattachment)
{
	int i;
	TAGGED_PROPVAL *ppropval;
	uint32_t attachment_size;
	
	attachment_size = 0;
	for (i=0; i<pattachment->proplist.count; i++) {
		ppropval = pattachment->proplist.ppropval + i;
		switch (ppropval->proptag) {
		case PR_ATTACH_NUM:
			continue;
		case ID_TAG_ATTACHDATABINARY:
		case ID_TAG_ATTACHDATAOBJECT: {
			auto cid = static_cast<const char *>(ppropval->pvalue);
			attachment_size += cu_get_cid_length(cid, PT_BINARY);
			break;
		}
		default:
			attachment_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
		}
	}
	if (pattachment->pembedded != nullptr)
		attachment_size += common_util_calculate_message_size(pattachment->pembedded);
	return attachment_size;
}
