// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iconv.h>
#include <memory>
#include <new>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <libHX/string.h>
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
#include "sfptrids.hpp"
#define S2A(x) reinterpret_cast<const char *>(x)

using XUI = unsigned int;
using LLD = long long;
using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

namespace {
struct prepared_statements {
	xstmt msg_norm, msg_str, rcpt_norm, rcpt_str;
};
}

static char g_exmdb_org_name[256];
static unsigned int g_max_msg;
thread_local unsigned int g_inside_flush_instance;
thread_local sqlite3 *g_sqlite_for_oxcmail;
static thread_local prepared_statements *g_opt_key;
unsigned int g_max_rule_num, g_max_extrule_num;
int g_cid_compression = -1; /* disabled(-1), default_level(0), specific_level(n) */
static std::atomic<unsigned int> g_sequence_id;

#define E(s) decltype(common_util_ ## s) common_util_ ## s;
E(get_user_displayname)
E(check_mlist_include)
E(get_user_lang)
E(get_timezone)
E(get_maildir)
E(get_id_from_username)
E(get_domain_ids)
E(get_id_from_maildir)
E(get_id_from_homedir)
E(get_mime_pool)
E(get_handle)
#undef E
decltype(ems_send_mail) ems_send_mail;

static BOOL (*common_util_get_username_from_id)(int id, char *username, size_t);
static BOOL (*common_util_get_user_ids)(const char *username, int *user_id, int *domain_id, enum display_type *);
static bool cu_eval_subobj_restriction(sqlite3 *, uint32_t cpid, uint64_t msgid, uint32_t proptag, const RESTRICTION *);
static bool gp_prepare_anystr(sqlite3 *, db_table, uint64_t, uint32_t, xstmt &, sqlite3_stmt *&);
static bool gp_prepare_mvstr(sqlite3 *, db_table, uint64_t, uint32_t, xstmt &, sqlite3_stmt *&);
static bool gp_prepare_default(sqlite3 *, db_table, uint64_t, uint32_t, xstmt &, sqlite3_stmt *&);
static void *gp_fetch(sqlite3 *, sqlite3_stmt *, uint16_t, uint32_t);

void common_util_set_propvals(TPROPVAL_ARRAY *parray,
	const TAGGED_PROPVAL *ppropval)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (ppropval->proptag != parray->ppropval[i].proptag)
			continue;
		parray->ppropval[i].pvalue = ppropval->pvalue;
		return;
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
	               g_exmdb_org_name);
	if (strncasecmp(pessdn, tmp_essdn, tmp_len) != 0)
		return FALSE;
	if (pessdn[tmp_len+16] != '-')
		return FALSE;
	plocal = pessdn + tmp_len + 17;
	user_id = decode_hex_int(pessdn + tmp_len + 8);
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
	int user_id;
	int domain_id;
	char *pdomain;
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];
	
	gx_strlcpy(tmp_name, username, GX_ARRAY_SIZE(tmp_name));
	pdomain = strchr(tmp_name, '@');
	if (pdomain == nullptr)
		return FALSE;
	*pdomain++ = '\0';
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
	
void common_util_pass_service(int service_id, void *func)
{
#define E(v, ptr) case (v): (ptr) = reinterpret_cast<decltype(ptr)>(func); break;
	switch (service_id) {
	E(SERVICE_ID_GET_USER_DISPLAYNAME, common_util_get_user_displayname);
	E(SERVICE_ID_CHECK_MLIST_INCLUDE, common_util_check_mlist_include);
	E(SERVICE_ID_GET_USER_LANG, common_util_get_user_lang);
	E(SERVICE_ID_GET_TIMEZONE, common_util_get_timezone);
	E(SERVICE_ID_GET_MAILDIR, common_util_get_maildir);
	E(SERVICE_ID_GET_ID_FFROM_USERNAME, common_util_get_id_from_username);
	E(SERVICE_ID_GET_USERNAME_FROM_ID, common_util_get_username_from_id);
	E(SERVICE_ID_GET_USER_IDS, common_util_get_user_ids);
	E(SERVICE_ID_GET_DOMAIN_IDS, common_util_get_domain_ids);
	E(SERVICE_ID_GET_ID_FROM_MAILDIR, common_util_get_id_from_maildir);
	E(SERVICE_ID_GET_ID_FROM_HOMEDIR, common_util_get_id_from_homedir);
	E(SERVICE_ID_SEND_MAIL, ems_send_mail);
	E(SERVICE_ID_GET_MIME_POOL, common_util_get_mime_pool);
	E(SERVICE_ID_GET_HANDLE, common_util_get_handle);
	}
#undef E
}

void common_util_init(const char *org_name, uint32_t max_msg,
	unsigned int max_rule_num, unsigned int max_ext_rule_num)
{
	gx_strlcpy(g_exmdb_org_name, org_name, arsizeof(g_exmdb_org_name));
	g_max_msg = max_msg;
	g_max_rule_num = max_rule_num;
	g_max_extrule_num = max_ext_rule_num;
}

void common_util_build_tls()
{
	g_inside_flush_instance = false;
	g_sqlite_for_oxcmail = nullptr;
	g_opt_key = nullptr;
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

char* common_util_convert_copy(BOOL to_utf8,
	uint32_t cpid, const char *pstring)
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

STRING_ARRAY *common_util_convert_copy_string_array(
	BOOL to_utf8, uint32_t cpid, const STRING_ARRAY *parray)
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_CURRENT_EID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	cur_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	*peid = cur_eid + 1;
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_MAXIMUM_EID);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	max_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (cur_eid >= max_eid) {
		pstmt = gx_sql_prep(psqlite, "SELECT MAX(range_end) FROM allocated_eids");
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		cur_eid = sqlite3_column_int64(pstmt, 0);
		max_eid = cur_eid + ALLOCATED_EID_RANGE;
		pstmt.finalize();
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lld, 1)",
		        LLU{cur_eid + 1}, LLU{max_eid}, LLD{time(nullptr)});
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE configurations SET"
			" config_value=%llu WHERE config_id=%u",
			LLU{max_eid}, CONFIG_ID_MAXIMUM_EID);
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	} else {
		cur_eid ++;
	}
	snprintf(sql_string, arsizeof(sql_string), "UPDATE configurations SET"
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT cur_eid, max_eid "
	          "FROM folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	*peid = sqlite3_column_int64(pstmt, 0);
	max_eid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	cur_eid = *peid + 1;
	if (cur_eid > max_eid) {
		pstmt = gx_sql_prep(psqlite, "SELECT MAX(range_end) FROM allocated_eids");
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		*peid = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		max_eid = *peid + ALLOCATED_EID_RANGE;
		cur_eid = *peid + 1;
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %llu, 1)", LLU{cur_eid},
			LLU{max_eid}, LLD{time(nullptr)});
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET cur_eid=%llu,"
		" max_eid=%llu WHERE folder_id=%llu", LLU{cur_eid},
		LLU{max_eid}, LLU{folder_id});
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

BOOL common_util_allocate_cn(sqlite3 *psqlite, uint64_t *pcn)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value FROM "
				"configurations WHERE config_id=%u",
				CONFIG_ID_LAST_CHANGE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint64_t last_cn = sqlite3_step(pstmt) == SQLITE_ROW ?
	                   sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_cn ++;
	snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO "
				"configurations VALUES (%u, ?)",
				CONFIG_ID_LAST_CHANGE_NUMBER);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_cn);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	*pcn = last_cn;
	return TRUE;
}

BOOL common_util_allocate_folder_art(sqlite3 *psqlite, uint32_t *part)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint32_t last_art = sqlite3_step(pstmt) == SQLITE_ROW ?
	                    sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_art ++;
	snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO "
				"configurations VALUES (%u, ?)",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_art);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	*part = last_art;
	return TRUE;
}

BOOL common_util_check_allocated_eid(sqlite3 *psqlite,
	uint64_t eid_val, BOOL *pb_result)
{
	char sql_string[256];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT range_begin,"
				" range_end FROM allocated_eids WHERE "
				"range_begin<=%llu AND range_end>=%llu",
				LLU{eid_val}, LLU{eid_val});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_result = sqlite3_step(pstmt) == SQLITE_ROW ? TRUE : false;
	return TRUE;
}

BOOL common_util_allocate_cid(sqlite3 *psqlite, uint64_t *pcid)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value FROM "
		"configurations WHERE config_id=%u", CONFIG_ID_LAST_CID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint64_t last_cid = sqlite3_step(pstmt) == SQLITE_ROW ?
	                    sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_cid ++;
	snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO configurations"
					" VALUES (%u, ?)", CONFIG_ID_LAST_CID);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_cid);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	*pcid = last_cid;
	return TRUE;
}

BOOL common_util_begin_message_optimize(sqlite3 *psqlite)
{
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
	              "message_id=? AND (proptag=? OR proptag=?)");
	if (op->msg_str == nullptr)
		return FALSE;
	op->rcpt_norm = gx_sql_prep(psqlite, "SELECT propval "
	                "FROM recipients_properties WHERE "
	                "recipient_id=? AND proptag=?");
	if (op->rcpt_norm == nullptr)
		return FALSE;
	op->rcpt_str = gx_sql_prep(psqlite, "SELECT proptag, propval"
	               " FROM recipients_properties WHERE recipient_id=?"
	               " AND (proptag=? OR proptag=?)");
	if (op->rcpt_str == nullptr)
		return FALSE;
	g_opt_key = op.release();
	return TRUE;
}

void common_util_end_message_optimize()
{
	auto op = g_opt_key;
	if (op == nullptr)
		return;
	g_opt_key = nullptr;
	delete op;
}

static sqlite3_stmt *cu_get_optimize_stmt(db_table table_type, bool b_normal)
{
	if (table_type != db_table::msg_props &&
	    table_type != db_table::rcpt_props)
		return NULL;	
	auto op = g_opt_key;
	if (op == nullptr)
		return NULL;
	if (table_type == db_table::msg_props)
		return b_normal ? op->msg_norm : op->msg_str;
	return b_normal ? op->rcpt_norm : op->rcpt_str;
}

BOOL cu_get_proptags(db_table table_type, uint64_t id,
	sqlite3 *psqlite, PROPTAG_ARRAY *pproptags)
{
	BOOL b_subject;
	char sql_string[128];
	uint32_t proptags[0x8000];
	size_t i = 0;

	switch (table_type) {
	case db_table::store_props:
		gx_strlcpy(sql_string, "SELECT proptag FROM store_properties", arsizeof(sql_string));
		proptags[i++] = PR_INTERNET_ARTICLE_NUMBER;
		break;
	case db_table::folder_props:
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag FROM "
		        "folder_properties WHERE folder_id=%llu", LLU{id});
		proptags[i++] = PR_ASSOC_CONTENT_COUNT;
		proptags[i++] = PR_CONTENT_COUNT;
		proptags[i++] = PR_MESSAGE_SIZE_EXTENDED;
		proptags[i++] = PR_ASSOC_MESSAGE_SIZE_EXTENDED;
		proptags[i++] = PR_NORMAL_MESSAGE_SIZE_EXTENDED;
		proptags[i++] = PR_FOLDER_CHILD_COUNT;
		proptags[i++] = PR_FOLDER_TYPE;
		proptags[i++] = PR_CONTENT_UNREAD;
		proptags[i++] = PR_SUBFOLDERS;
		proptags[i++] = PR_HAS_RULES;
		proptags[i++] = PR_FOLDER_PATHNAME;
		proptags[i++] = PR_LOCAL_COMMIT_TIME;
		proptags[i++] = PidTagFolderId;
		proptags[i++] = PidTagChangeNumber;
		proptags[i++] = PR_FOLDER_FLAGS;
		break;
	case db_table::msg_props:
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag FROM "
		        "message_properties WHERE message_id=%llu AND proptag NOT IN (0x0e05001e,0x0e05001f)", LLU{id});
		proptags[i++] = PidTagMid;
		proptags[i++] = PR_MESSAGE_SIZE;
		proptags[i++] = PR_ASSOCIATED;
		proptags[i++] = PidTagChangeNumber;
		proptags[i++] = PR_READ;
		proptags[i++] = PR_HASATTACH;
		proptags[i++] = PR_MESSAGE_FLAGS;
		proptags[i++] = PR_DISPLAY_TO;
		proptags[i++] = PR_DISPLAY_CC;
		proptags[i++] = PR_DISPLAY_BCC;
		break;
	case db_table::rcpt_props:
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag FROM "
		        "recipients_properties WHERE recipient_id=%llu", LLU{id});
		break;
	case db_table::atx_props:
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag FROM "
		        "attachment_properties WHERE attachment_id=%llu", LLU{id});
		proptags[i++] = PR_RECORD_KEY;
		break;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	b_subject = FALSE;
	while (sqlite3_step(pstmt) == SQLITE_ROW && i < GX_ARRAY_SIZE(proptags)) {
		proptags[i] = sqlite3_column_int64(pstmt, 0);
		if (table_type == db_table::msg_props &&
		    proptags[i] == PR_MESSAGE_FLAGS)
			continue;
		if (table_type == db_table::msg_props && !b_subject) {
			if ((proptags[i] == PR_NORMALIZED_SUBJECT ||
			    proptags[i] == PR_SUBJECT_PREFIX) &&
			    i + 1 < GX_ARRAY_SIZE(proptags)) {
				b_subject = TRUE;
				i ++;
				proptags[i] = PR_SUBJECT;
			} else if ((proptags[i] == PR_NORMALIZED_SUBJECT_A ||
			    proptags[i] == PR_SUBJECT_PREFIX_A) &&
			    i + 1 < GX_ARRAY_SIZE(proptags)) {
				b_subject = TRUE;
				i ++;
				proptags[i] = PR_SUBJECT_A;
			}
		}
		i ++;
	}
	pstmt.finalize();
	if (table_type == db_table::rcpt_props) {
		if (std::find(proptags, proptags + i, PR_RECIPIENT_TYPE) == proptags + i)
			proptags[i++] = PR_RECIPIENT_TYPE;
		if (std::find(proptags, proptags + i, PR_DISPLAY_NAME) == proptags + i)
			proptags[i++] = PR_DISPLAY_NAME;
		if (std::find(proptags, proptags + i, PR_ADDRTYPE) == proptags + i)
			proptags[i++] = PR_ADDRTYPE;
		if (std::find(proptags, proptags + i, PR_EMAIL_ADDRESS) == proptags + i)
			proptags[i++] = PR_EMAIL_ADDRESS;
	}
	pproptags->count = i;
	pproptags->pproptag = cu_alloc<uint32_t>(i);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, proptags, sizeof(uint32_t)*i);
	return TRUE;
}

static BINARY* common_util_get_mailbox_guid(sqlite3 *psqlite)
{
	GUID tmp_guid;
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%d",
				CONFIG_ID_MAILBOX_GUID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return NULL;
	if (!tmp_guid.from_str(S2A(sqlite3_column_text(pstmt, 0))))
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%d",
				CONFIG_ID_SEARCH_STATE);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

BOOL common_util_get_mapping_guid(sqlite3 *psqlite,
	uint16_t replid, BOOL *pb_found, GUID *pguid)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT replguid FROM "
		"replca_mapping WHERE replid=%d", (int)replid);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		*pb_found = FALSE;
		return TRUE;
	}
	if (!pguid->from_str(S2A(sqlite3_column_text(pstmt, 0)))) {
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
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM "
	          "folders WHERE parent_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM"
	         " folders WHERE parent_id=%llu AND is_deleted=0", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW ? TRUE : false;
}

static char* common_util_calculate_folder_path(
	uint32_t folder_id, sqlite3 *psqlite)
{
	int len;
	int len1;
	uint64_t tmp_fid;
	char sql_string[128], temp_path[4096]{};
	
	len = 0;
	tmp_fid = folder_id;
	auto b_private = exmdb_server::is_private();
	while (true) {
		snprintf(sql_string, arsizeof(sql_string), "SELECT propval FROM"
				" folder_properties WHERE proptag=%u AND "
		        "folder_id=%llu", PR_DISPLAY_NAME, LLU{tmp_fid});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return NULL;
		len1 = sqlite3_column_bytes(pstmt, 0);
		len += len1;
		if (len >= 4096)
			return NULL;
		memcpy(temp_path + 4095 - len, sqlite3_column_text(pstmt, 0), len1);
		pstmt.finalize();
		len ++;
		temp_path[4095-len] = '\\';
		if ((b_private && tmp_fid == PRIVATE_FID_ROOT) ||
		    (!b_private && tmp_fid == PUBLIC_FID_ROOT))
			break;
		snprintf(sql_string, arsizeof(sql_string), "SELECT parent_id FROM "
		          "folders WHERE folder_id=%llu", LLU{tmp_fid});
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return NULL;
		tmp_fid = sqlite3_column_int64(pstmt, 0);
	}
	memmove(temp_path, temp_path + 4095 - len, len);
	return common_util_dup(temp_path);
}

BOOL common_util_check_msgcnt_overflow(sqlite3 *psqlite)
{
	char sql_string[64];
	
	if (g_max_msg == 0)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT "
		"count(message_id) FROM messages");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) >= g_max_msg ? TRUE : false;
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
	if (!cu_get_properties(db_table::store_props,
	    0, 0, psqlite, &proptags, &propvals))
		return FALSE;
	auto ptotal = propvals.get<uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	auto qv_kb = propvals.get<uint32_t>(qtag);
	return ptotal != nullptr && qv_kb != nullptr &&
	       *ptotal >= static_cast<uint64_t>(*qv_kb) * 1024;
}

static uint32_t common_util_get_store_message_count(
	sqlite3 *psqlite, BOOL b_associated)
{
	char sql_string[64];
	
	snprintf(sql_string, arsizeof(sql_string), b_associated ?
	         "SELECT count(*) FROM messages WHERE is_associated=1" :
	         "SELECT count(*) FROM messages WHERE is_associated=0");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

static uint32_t common_util_get_store_article_number(sqlite3 *psqlite)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

static uint32_t common_util_get_folder_count(sqlite3 *psqlite,
	uint64_t folder_id, BOOL b_associated)
{
	uint32_t folder_type;
	char sql_string[256];
	
	if (common_util_get_folder_type(psqlite, folder_id, &folder_type) &&
	    folder_type == FOLDER_SEARCH)
		snprintf(sql_string, GX_ARRAY_SIZE(sql_string), "SELECT count(*)"
			" FROM messages JOIN search_result ON "
			"search_result.folder_id=%llu AND "
			"search_result.message_id=messages.message_id"
			" AND messages.is_associated=%u",
			LLU{folder_id}, !!b_associated);
	else
		snprintf(sql_string, GX_ARRAY_SIZE(sql_string), "SELECT count(*)"
			" FROM messages WHERE parent_fid=%llu "
			"AND is_deleted=0 AND is_associated=%u",
			LLU{folder_id}, !!b_associated);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

uint32_t common_util_get_folder_unread_count(
	sqlite3 *psqlite, uint64_t folder_id)
{
	uint32_t folder_type;
	char sql_string[220];
	
	if (exmdb_server::is_private()) {
		if (common_util_get_folder_type(psqlite, folder_id, &folder_type) &&
		    folder_type == FOLDER_SEARCH)
			gx_snprintf(sql_string, arsizeof(sql_string), "SELECT count(*)"
				" FROM messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id AND "
				"messages.read_state=0 AND messages.is_associated=0",
				LLU{folder_id});
		else
			gx_snprintf(sql_string, arsizeof(sql_string), "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu AND "
				"read_state=0 AND is_associated=0", LLU{folder_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
		       sqlite3_column_int64(pstmt, 0);
	}
	auto username = exmdb_pf_read_per_user ? exmdb_server::get_public_username() : "";
	if (username == nullptr)
		return 0;
	gx_snprintf(sql_string, arsizeof(sql_string), "SELECT count(*) FROM messages WHERE"
				" parent_fid=%llu AND is_deleted=0 AND is_associated=0",
				LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return 0;
	auto count = pstmt.col_uint64(0);
	pstmt.finalize();
	gx_snprintf(sql_string, arsizeof(sql_string), "SELECT count(*) FROM read_states"
				" JOIN messages ON read_states.username=?"
				" AND messages.parent_fid=%llu AND "
				"messages.message_id=read_states.message_id"
				" AND messages.is_deleted=0"
				" AND messages.is_associated=0", LLU{folder_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW)
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
			snprintf(sql_string, arsizeof(sql_string), "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id",
				LLU{folder_id});
		else if (b_normal)
			snprintf(sql_string, arsizeof(sql_string), "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id"
				" AND messages.is_associated=0", LLU{folder_id});
		else if (b_associated)
			snprintf(sql_string, arsizeof(sql_string), "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id"
				" AND messages.is_associated=1", LLU{folder_id});
		else
			return 0;
	} else {
		if (b_normal && b_associated)
			snprintf(sql_string, arsizeof(sql_string), "SELECT sum(message_size) "
			          "FROM messages WHERE parent_fid=%llu", LLU{folder_id});
		else if (b_normal)
			snprintf(sql_string, arsizeof(sql_string), "SELECT sum(message_size) "
						"FROM messages WHERE parent_fid=%llu AND "
						"is_associated=0", LLU{folder_id});
						
		else if (b_associated)
			snprintf(sql_string, arsizeof(sql_string), "SELECT sum(message_size) "
						"FROM messages WHERE parent_fid=%llu AND "
						"is_associated=1", LLU{folder_id});
		else
			return 0;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
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
	snprintf(sql_string, arsizeof(sql_string), "SELECT is_search "
	         "FROM folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (sqlite3_step(pstmt) != SQLITE_ROW)
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(*) FROM "
	          "rules WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT message_size FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

uint64_t common_util_get_folder_parent_fid(
	sqlite3 *psqlite, uint64_t folder_id)
{
	uint64_t parent_fid;
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT parent_id FROM "
	          "folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return 0;
	parent_fid = sqlite3_column_int64(pstmt, 0);
	return parent_fid != 0 ? parent_fid : folder_id;
}

static uint64_t common_util_get_folder_changenum(
	sqlite3 *psqlite, uint64_t folder_id)
{
	uint64_t change_num;
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT change_number FROM "
	          "folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id "
	          "FROM folders WHERE parent_id=%llu", LLU{parent_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT propval "
		"FROM folder_properties WHERE folder_id=?"
	        " AND proptag=%u", PR_DISPLAY_NAME);
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	*pfolder_id = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		tmp_val = sqlite3_column_int64(pstmt, 0);
		sqlite3_bind_int64(pstmt1, 1, tmp_val);
		if (SQLITE_ROW == sqlite3_step(pstmt1)) {
			if (strcasecmp(str_name, S2A(sqlite3_column_text(pstmt1, 0))) == 0) {
				*pfolder_id = tmp_val;
				break;
			}
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT is_associated FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static BOOL common_util_check_message_named_properties(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT proptag"
				" FROM message_properties WHERE "
				"message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (sqlite3_step(pstmt) == SQLITE_ROW)
		if (sqlite3_column_int64(pstmt, 0) & 0x8000)
			return TRUE;
	return FALSE;
}

static BOOL common_util_check_message_has_attachments(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(*) FROM "
	          "attachments WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
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
		snprintf(sql_string, arsizeof(sql_string), "SELECT message_id"
				" FROM read_states WHERE username=? AND "
				"message_id=%llu", LLU{message_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		return sqlite3_step(pstmt) == SQLITE_ROW ? TRUE : false;
	}
	snprintf(sql_string, arsizeof(sql_string), "SELECT read_state FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static uint64_t common_util_get_message_changenum(
	sqlite3 *psqlite, uint64_t message_id)
{
	uint64_t change_num;
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT change_number FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return 0;
	change_num = sqlite3_column_int64(pstmt, 0);
	return rop_util_make_eid_ex(1, change_num);
}

BOOL common_util_get_message_flags(sqlite3 *psqlite,
	uint64_t message_id, BOOL b_native,
	uint32_t **ppmessage_flags)
{
	auto pstmt = cu_get_optimize_stmt(db_table::msg_props, true);
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
	uint32_t message_flags = sqlite3_step(pstmt) == SQLITE_ROW ?
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
		if (sqlite3_step(pstmt) == SQLITE_ROW)
			if (sqlite3_column_int64(pstmt, 0) != 0)
				message_flags |= MSGFLAG_RN_PENDING;
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
		if (sqlite3_step(pstmt) == SQLITE_ROW)
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
	if (!cu_get_property(db_table::folder_props, folder_id, 0,
	    psqlite, PR_DISPLAY_NAME, &pvalue))
		return NULL;	
	return pvalue;
}

static BOOL common_util_get_message_subject(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppvalue)
{
	const char *psubject_prefix, *pnormalized_subject;
	
	psubject_prefix = NULL;
	pnormalized_subject = NULL;
	auto pstmt = cu_get_optimize_stmt(db_table::msg_props, true);
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
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		pnormalized_subject = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
		if (pnormalized_subject == nullptr)
			return FALSE;
	} else {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PR_NORMALIZED_SUBJECT_A);
		if (sqlite3_step(pstmt) == SQLITE_ROW)
			pnormalized_subject =
				common_util_convert_copy(TRUE, cpid,
				S2A(sqlite3_column_text(pstmt, 0)));
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_int64(pstmt, 2, PR_SUBJECT_PREFIX);
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		psubject_prefix = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
		if (psubject_prefix == nullptr)
			return FALSE;
	} else {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PR_SUBJECT_PREFIX_A);
		if (sqlite3_step(pstmt) == SQLITE_ROW)
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
	
static BOOL common_util_get_message_display_recipients(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppvalue)
{
	int offset;
	void *pvalue;
	uint64_t rcpt_id;
	char sql_string[256];
	char tmp_buff[64*1024];
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
	snprintf(sql_string, arsizeof(sql_string), "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	offset = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		rcpt_id = sqlite3_column_int64(pstmt, 0);
		if (!cu_get_property(db_table::rcpt_props,
		    rcpt_id, 0, psqlite, PR_RECIPIENT_TYPE, &pvalue))
			return FALSE;
		if (pvalue == nullptr || *static_cast<uint32_t *>(pvalue) != recipient_type)
			continue;
		if (!cu_get_property(db_table::rcpt_props,
		    rcpt_id, cpid, psqlite, PR_DISPLAY_NAME, &pvalue))
			return FALSE;	
		if (NULL == pvalue) {
			if (!cu_get_property(db_table::rcpt_props,
			    rcpt_id, cpid, psqlite, PR_SMTP_ADDRESS, &pvalue))
				return FALSE;	
		}
		if (pvalue == nullptr)
			continue;
		if (offset == 0)
			offset = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s",
			         static_cast<const char *>(pvalue));
		else
			offset += gx_snprintf(tmp_buff + offset,
			          GX_ARRAY_SIZE(tmp_buff) - offset, "; %s",
			          static_cast<const char *>(pvalue));
	}
	pstmt.finalize();
	if  (0 == offset) {
		*ppvalue = deconst(&fake_empty);
		return TRUE;
	}
	*ppvalue = PROP_TYPE(proptag) == PT_UNICODE ? common_util_dup(tmp_buff) :
	           common_util_convert_copy(false, cpid, tmp_buff);
	return *ppvalue != nullptr ? TRUE : false;
}

std::string cu_cid_path(const char *dir, uint64_t id, unsigned int type) try
{
	if (dir == nullptr)
		dir = exmdb_server::get_dir();
	auto path = dir + "/cid/"s + std::to_string(id);
	if (type == 2)
		path += ".zst";
	else if (type == 1)
		path += ".v1z";
	return path;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1608: ENOMEM");
	return {};
}

static void *cu_get_object_text_v0(const char *, uint64_t, uint32_t, uint32_t, uint32_t);

static void *cu_get_object_text_vx(const char *dir, uint64_t cid,
    uint32_t proptag, uint32_t db_proptag, uint32_t cpid, unsigned int type)
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
	uint32_t cpid, uint64_t message_id, uint32_t proptag)
{
	char sql_string[128];
	
	auto dir = exmdb_server::get_dir();
	if (dir == nullptr)
		return NULL;
	if (proptag == PR_BODY || proptag == PR_BODY_A)
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag, propval "
		         "FROM message_properties WHERE message_id=%llu AND"
		         " proptag IN (%u,%u)",
		         LLU{message_id}, PR_BODY, PR_BODY_A);
	else if (proptag == PR_TRANSPORT_MESSAGE_HEADERS ||
	    proptag == PR_TRANSPORT_MESSAGE_HEADERS_A)
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag, propval "
		         "FROM message_properties WHERE message_id=%llu AND"
		         " proptag IN (%u,%u)",
		         LLU{message_id}, PR_TRANSPORT_MESSAGE_HEADERS,
		         PR_TRANSPORT_MESSAGE_HEADERS_A);
	else if (proptag == PR_HTML || proptag == PR_RTF_COMPRESSED)
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag, propval FROM "
		         "message_properties WHERE message_id=%llu AND "
		         "proptag=%u", LLU{message_id}, XUI{proptag});
	else if (proptag == PR_ATTACH_DATA_BIN || proptag == PR_ATTACH_DATA_OBJ)
		snprintf(sql_string, arsizeof(sql_string), "SELECT proptag, propval FROM "
		         "attachment_properties WHERE attachment_id=%llu"
		         " AND proptag=%u", LLU{message_id}, XUI{proptag});
	else
		return nullptr;

	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return nullptr;
	uint32_t proptag1 = sqlite3_column_int64(pstmt, 0);
	uint64_t cid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();

	/*
	 * Try compressed variant first. Fail any serious errors.
	 * Only when it was not found do check the uncompressed variant.
	 */
	auto blk = cu_get_object_text_vx(dir, cid, proptag, proptag1, cpid, 2);
	if (blk != nullptr)
		return blk;
	if (errno != ENOENT)
		return nullptr;
	blk = cu_get_object_text_vx(dir, cid, proptag, proptag1, cpid, 1);
	if (blk != nullptr)
		return blk;
	if (errno != ENOENT)
		return nullptr;
	return cu_get_object_text_v0(dir, cid, proptag, proptag1, cpid);
}

static void *cu_get_object_text_v0(const char *dir, uint64_t cid,
    uint32_t proptag, uint32_t proptag1, uint32_t cpid)
{
	wrapfd fd = open(cu_cid_path(dir, cid, 0).c_str(), O_RDONLY);
	struct stat node_stat;
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
		return nullptr;
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

BOOL cu_get_property(db_table table_type, uint64_t id,
	uint32_t cpid, sqlite3 *psqlite, uint32_t proptag,
	void **ppvalue)
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
	case PR_CONTENT_COUNT: *v = common_util_get_store_message_count(db, false); break;
	case PR_ASSOC_CONTENT_COUNT: *v = common_util_get_store_message_count(db, TRUE); break;
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
		auto v = cu_alloc<uint64_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		auto tmp_id = common_util_get_folder_parent_fid(db, id);
		if (tmp_id == 0)
			return GP_SKIP;
		*v = rop_util_make_eid_ex(1, tmp_id);
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
		auto v = cu_alloc<uint8_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = !!common_util_check_subfolders(db, id);
		return GP_ADV;
	}
	case PR_HAS_RULES: {
		auto v = cu_alloc<uint8_t>();
		pv.pvalue = v;
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*v = !!common_util_check_folder_rules(db, id);
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
	case PR_CONTENT_COUNT: *v = common_util_get_folder_count(db, id, false); break;
	case PR_ASSOC_CONTENT_COUNT: *v = common_util_get_folder_count(db, id, TRUE); break;
	case PR_CONTENT_UNREAD: *v = common_util_get_folder_unread_count(db, id); break;
	case PR_FOLDER_CHILD_COUNT: *v = common_util_calculate_childcount(id, db); break;
	case PR_MESSAGE_SIZE_EXTENDED: *w = common_util_get_folder_message_size(db, id, TRUE, TRUE); break;
	case PR_ASSOC_MESSAGE_SIZE_EXTENDED: *w = common_util_get_folder_message_size(db, id, false, TRUE); break;
	case PR_NORMAL_MESSAGE_SIZE_EXTENDED: *w = common_util_get_folder_message_size(db, id, TRUE, false); break;
	case PidTagFolderId: *w = rop_util_nfid_to_eid(id); break;
	case PidTagChangeNumber: *w = common_util_get_folder_changenum(db, id); break;
	case PR_FOLDER_TYPE: return common_util_get_folder_type(db, id, v) ? GP_ADV : GP_ERR;
	}
	return GP_ADV;
}

static GP_RESULT gp_msgprop(uint32_t tag, TAGGED_PROPVAL &pv, sqlite3 *db,
    uint64_t id, uint32_t cpid)
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
		pv.pvalue = cu_get_object_text(db, 0, id, tag);
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
		pv.pvalue = cu_get_object_text(db, 0, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_spectableprop(db_table table_type, uint32_t tag,
    TAGGED_PROPVAL &pv, sqlite3 *db, uint64_t id, uint32_t cpid)
{
	pv.proptag = tag;
	switch (tag) {
	case PR_STORE_RECORD_KEY:
		pv.pvalue = common_util_get_mailbox_guid(db);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	}
	switch (table_type) {
	case db_table::store_props:
		return gp_storeprop(tag, pv, db);
	case db_table::folder_props:
		return gp_folderprop(tag, pv, db, id);
	case db_table::msg_props:
		return gp_msgprop(tag, pv, db, id, cpid);
	case db_table::rcpt_props:
		return GP_UNHANDLED;
	case db_table::atx_props:
		return gp_atxprop(tag, pv, db, id);
	default:
		return GP_UNHANDLED;
	}
}

static GP_RESULT gp_rcptprop_synth(sqlite3 *db, uint32_t proptag, xstmt &stm)
{
	switch (proptag) {
	case PR_RECIPIENT_TYPE:
		stm = gx_sql_prep(db, "SELECT 1"); // MAPI_TO
		break;
	case PR_DISPLAY_NAME:
	case PR_EMAIL_ADDRESS:
		stm = gx_sql_prep(db, "SELECT 15, ''"); // PT_UNICODE
		break;
	case PR_ADDRTYPE:
		stm = gx_sql_prep(db, "SELECT 15, 'NONE'");
		break;
	default:
		return GP_UNHANDLED;
	}
	return GP_ADV;
}

static GP_RESULT gp_fallbackprop(sqlite3 *db, db_table table_type, uint32_t proptag, xstmt &stm)
{
	switch (table_type) {
	case db_table::rcpt_props:
		return gp_rcptprop_synth(db, proptag, stm);
	default:
		return GP_UNHANDLED;
	}
}

BOOL cu_get_properties(db_table table_type,
	uint64_t id, uint32_t cpid, sqlite3 *psqlite,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	sqlite3_stmt *pstmt = nullptr;
	
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	for (size_t i = 0; i < pproptags->count; ++i) {
		if (PROP_TYPE(pproptags->pproptag[i]) == PT_OBJECT &&
		    (table_type != db_table::atx_props ||
		    pproptags->pproptag[i] != PR_ATTACH_DATA_OBJ))
			continue;
		/* begin of special properties */
		auto &pv = ppropvals->ppropval[ppropvals->count];
		auto ret = gp_spectableprop(table_type, pproptags->pproptag[i],
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
		uint16_t proptype = PROP_TYPE(pproptags->pproptag[i]);
		if (proptype == PT_UNSPECIFIED || proptype == PT_STRING8 ||
		    proptype == PT_UNICODE) {
			auto bret = gp_prepare_anystr(psqlite, table_type, id, pproptags->pproptag[i], own_stmt, pstmt);
			if (!bret)
				return false;
		} else if (proptype == PT_MV_STRING8) {
			auto bret = gp_prepare_mvstr(psqlite, table_type, id, pproptags->pproptag[i], own_stmt, pstmt);
			if (!bret)
				return false;
		} else {
			auto bret = gp_prepare_default(psqlite, table_type, id, pproptags->pproptag[i], own_stmt, pstmt);
			if (!bret)
				return false;
		}
		if (sqlite3_step(pstmt) != SQLITE_ROW) {
			ret = gp_fallbackprop(psqlite, table_type, pproptags->pproptag[i], own_stmt);
			if (ret == GP_UNHANDLED)
				continue;
			pstmt = own_stmt;
			if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
				continue;
		}
		auto pvalue = gp_fetch(psqlite, pstmt, proptype, cpid);
		if (pvalue == nullptr)
			return false;
		pv.proptag = pproptags->pproptag[i];
		pv.pvalue = pvalue;
		ppropvals->count ++;
	}
	return TRUE;
}

static bool gp_prepare_anystr(sqlite3 *psqlite, db_table table_type, uint64_t id,
    uint32_t tag, xstmt &own_stmt, sqlite3_stmt *&pstmt)
{
	switch (table_type) {
	case db_table::store_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT proptag, propval"
		           " FROM store_properties WHERE proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		break;
	case db_table::folder_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT proptag,"
		           " propval FROM folder_properties WHERE"
		           " folder_id=? AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		break;
	case db_table::msg_props:
		pstmt = cu_get_optimize_stmt(table_type, false);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT proptag, "
			           "propval FROM message_properties WHERE "
			           "message_id=? AND (proptag=? OR proptag=?)");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(tag, PT_STRING8));
		break;
	case db_table::rcpt_props:
		pstmt = cu_get_optimize_stmt(table_type, false);
		if (NULL != pstmt) {
			sqlite3_reset(pstmt);
		} else {
			own_stmt = gx_sql_prep(psqlite, "SELECT proptag,"
			           " propval FROM recipients_properties WHERE"
			           " recipient_id=? AND (proptag=? OR proptag=?)");
			if (own_stmt == nullptr)
				return FALSE;
			pstmt = own_stmt;
		}
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(tag, PT_STRING8));
		break;
	case db_table::atx_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT proptag, propval"
		           " FROM attachment_properties WHERE attachment_id=?"
		           " AND (proptag=? OR proptag=?)");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_UNICODE));
		sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(tag, PT_STRING8));
		break;
	}
	return true;
}

static bool gp_prepare_mvstr(sqlite3 *psqlite, db_table table_type,
    uint64_t id, uint32_t tag, xstmt &own_stmt, sqlite3_stmt *&pstmt)
{
	switch (table_type) {
	case db_table::store_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval"
		           " FROM store_properties WHERE proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	case db_table::folder_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM folder_properties WHERE folder_id=? "
		           "AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	case db_table::msg_props:
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
	case db_table::rcpt_props:
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
	case db_table::atx_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM attachment_properties WHERE "
		           "attachment_id=? AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
		break;
	}
	return true;
}

static bool gp_prepare_default(sqlite3 *psqlite, db_table table_type,
    uint64_t id, uint32_t tag, xstmt &own_stmt, sqlite3_stmt *&pstmt)
{
	switch (table_type) {
	case db_table::store_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval "
		           "FROM store_properties WHERE proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, tag);
		break;
	case db_table::folder_props:
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
	case db_table::msg_props:
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
	case db_table::rcpt_props:
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
	case db_table::atx_props:
		own_stmt = gx_sql_prep(psqlite, "SELECT propval FROM "
		           "attachment_properties WHERE attachment_id=?"
		           " AND proptag=?");
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
		sqlite3_bind_int64(pstmt, 1, id);
		sqlite3_bind_int64(pstmt, 2, tag);
		break;
	}
	return true;
}

static void *gp_fetch(sqlite3 *psqlite, sqlite3_stmt *pstmt,
    uint16_t proptype, uint32_t cpid)
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
	
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET change_number=%llu"
	        " WHERE folder_id=%llu", LLU{change_num}, LLU{folder_id});
	gx_sql_exec(psqlite, sql_string);
}

static void common_util_set_message_changenum(sqlite3 *psqlite,
	uint64_t message_id, uint64_t change_num)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET change_number=%llu"
	        " WHERE message_id=%llu", LLU{change_num}, LLU{message_id});
	gx_sql_exec(psqlite, sql_string);
}

void common_util_set_message_read(sqlite3 *psqlite,
	uint64_t message_id, uint8_t is_read)
{
	char sql_string[128];
	
	if (is_read)
		snprintf(sql_string, arsizeof(sql_string), "UPDATE message_properties "
			"SET propval=propval|%u WHERE message_id=%llu"
			" AND proptag=%u", MSGFLAG_EVERREAD,
		        LLU{message_id}, PR_MESSAGE_FLAGS);
	else
		snprintf(sql_string, arsizeof(sql_string), "UPDATE message_properties "
			"SET propval=propval&(~%u) WHERE message_id=%llu"
			" AND proptag=%u", MSGFLAG_EVERREAD,
		        LLU{message_id}, PR_MESSAGE_FLAGS);
	gx_sql_exec(psqlite, sql_string);
	if (exmdb_server::is_private()) {
		if (!is_read)
			snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET "
				"read_state=0 WHERE message_id=%llu", LLU{message_id});
		else
			snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET "
				"read_state=1 WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(psqlite, sql_string);
		return;
	}
	auto username = exmdb_pf_read_per_user ? exmdb_server::get_public_username() : "";
	if (username == nullptr)
		return;
	if (is_read)
		snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO "
			"read_states VALUES (%llu, ?)", LLU{message_id});
	else
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM "
			"read_states WHERE message_id=%llu AND "
			"username=?", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return;
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	auto ret = sqlite3_step(pstmt);
	if (ret != SQLITE_DONE)
		mlog(LV_WARN, "W-1274: %s", sqlite3_errstr(ret));
}

static BOOL cu_update_object_cid(sqlite3 *psqlite, db_table table_type,
    uint64_t object_id, uint32_t proptag, uint64_t cid)
{
	char sql_string[256];
	
	if (table_type == db_table::msg_props)
		snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO message_properties"
		         " VALUES (%llu, %u, ?)", LLU{object_id}, XUI{proptag});
	else if (table_type == db_table::atx_props)
		snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO attachment_properties"
		          " VALUES (%llu, %u, ?)", LLU{object_id}, XUI{proptag});
	else
		return false;
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, cid);
	return sqlite3_step(pstmt) == SQLITE_DONE ? TRUE : false;
}

static BOOL common_util_set_message_subject(
	uint32_t cpid, uint64_t message_id,
	sqlite3_stmt *pstmt, const TAGGED_PROPVAL *ppropval)
{
	char *pstring;
	
	if (ppropval->proptag == PR_SUBJECT) {
		sqlite3_bind_int64(pstmt, 1, PR_NORMALIZED_SUBJECT);
		sqlite3_bind_text(pstmt, 2, static_cast<char *>(ppropval->pvalue), -1, SQLITE_STATIC);
	} else if (cpid == 0) {
		pstring = common_util_convert_copy(TRUE, cpid, static_cast<char *>(ppropval->pvalue));
		if (pstring == nullptr)
			return FALSE;
		sqlite3_bind_int64(pstmt, 1, PR_NORMALIZED_SUBJECT);
		sqlite3_bind_text(pstmt, 2, pstring, -1, SQLITE_STATIC);
	} else {
		sqlite3_bind_int64(pstmt, 1, PR_NORMALIZED_SUBJECT_A);
		sqlite3_bind_text(pstmt, 2, static_cast<char *>(ppropval->pvalue), -1, SQLITE_STATIC);
	}
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	return TRUE;
}

static BOOL cu_set_msg_body_v0(sqlite3 *, uint64_t, const char *, uint64_t, uint32_t, const char *);

static BOOL cu_set_msg_body_v2(sqlite3 *psqlite, uint64_t message_id,
    const char *dir, uint64_t cid, uint32_t proptag, const char *value)
{
	auto path = cu_cid_path(dir, cid, 2);
	auto remove_file = make_scope_exit([&]() {
		if (::remove(path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1236: remove %s: %s",
			        path.c_str(), strerror(errno));
	});
	auto ret = gx_compress_tofile(value, path.c_str(), g_cid_compression);
	if (ret != 0) {
		mlog(LV_ERR, "E-1235: compress_tofile %s: %s\n",
		     path.c_str(), strerror(ret));
		return false;
	}
	if (!cu_update_object_cid(psqlite, db_table::msg_props, message_id,
	    proptag, cid))
		return TRUE;
	remove_file.release();
	return TRUE;
}

static BOOL common_util_set_message_body(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	const TAGGED_PROPVAL *ppropval)
{
	void *pvalue;
	uint32_t proptag;
	
	if (ppropval->proptag == PR_BODY_A) {
		if (0 == cpid) {
			proptag = PR_BODY_A;
			pvalue = ppropval->pvalue;
		} else {
			proptag = PR_BODY;
			pvalue = common_util_convert_copy(TRUE, cpid, static_cast<char *>(ppropval->pvalue));
			if (pvalue == nullptr)
				return FALSE;
		}
	} else if (ppropval->proptag == PR_TRANSPORT_MESSAGE_HEADERS_A) {
		if (cpid == 0) {
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
	uint64_t cid = 0;
	if (!common_util_allocate_cid(psqlite, &cid))
		return FALSE;
	if (g_cid_compression >= 0)
		return cu_set_msg_body_v2(psqlite, message_id, dir, cid, proptag,
		       static_cast<const char *>(pvalue));
	return cu_set_msg_body_v0(psqlite, message_id, dir, cid, proptag,
	       static_cast<const char *>(pvalue));
}

static BOOL cu_set_msg_body_v0(sqlite3 *psqlite, uint64_t message_id,
    const char *dir, uint64_t cid, uint32_t proptag, const char *value)
{
	auto path = cu_cid_path(dir, cid, 0);
	wrapfd fd = open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0666);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-1627: open %s O_CREAT: %s", path.c_str(), strerror(errno));
		return FALSE;
	}
	auto remove_file = make_scope_exit([&]() {
		if (::remove(path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1382: remove %s: %s",
			        path.c_str(), strerror(errno));
	});
	if (PROP_TYPE(proptag) == PT_UNICODE) {
		/*
		 * Gromox < 1.14 uses this count for computation of
		 * PR_MESSAGE_SIZE. Only needs to be approximate.
		 */
		uint32_t len = cpu_to_le32(std::min(strlen(value) / 2,
		               static_cast<size_t>(UINT32_MAX)));
		if (write(fd.get(), &len, sizeof(len)) != sizeof(len))
			return FALSE;
	}
	auto len = strlen(value);
	auto ret = write(fd.get(), value, len);
	if (ret < 0 || static_cast<size_t>(ret) != len)
		return FALSE;
	/* Give a NUL byte to appease old Gromox < 0.21. */
	if (write(fd.get(), "", 1) != 1 || fd.close_wr() < 0)
		return false;
	if (!cu_update_object_cid(psqlite, db_table::msg_props, message_id, proptag, cid))
		return TRUE;
	remove_file.release();
	return TRUE;
}

static BOOL cu_set_obj_cid_val_v0(sqlite3 *, db_table, uint64_t, const char *, uint64_t, const TAGGED_PROPVAL *);

static BOOL cu_set_obj_cid_val_v2(sqlite3 *psqlite, db_table table_type,
    uint64_t message_id, const char *dir, uint64_t cid,
    const TAGGED_PROPVAL *prop)
{
	auto path = cu_cid_path(dir, cid, 2);
	auto remove_file = make_scope_exit([&]() {
		if (::remove(path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1237: remove %s: %s",
			        path.c_str(), strerror(errno));
	});
	/*
	 * zstd already has some form of uncompressability detection
	 * (huf_compress.c), so we do not have to implement our own. Besides,
	 * even if the overall entropy for a file is high, maybe there still is
	 * a block where it's comparatively low.
	 */
	auto &bv = *static_cast<const BINARY *>(prop->pvalue);
	auto ret = gx_compress_tofile(std::string_view(bv.pc, bv.cb),
	           path.c_str(), g_cid_compression);
	if (ret != 0 || !cu_update_object_cid(psqlite, table_type, message_id,
	    prop->proptag, cid))
		return false;
	remove_file.release();
	return TRUE;
}

static BOOL cu_set_object_cid_value(sqlite3 *psqlite, db_table table_type,
    uint64_t message_id, const TAGGED_PROPVAL *ppropval)
{
	if (table_type == db_table::msg_props) {
		if (ppropval->proptag != PR_HTML &&
		    ppropval->proptag != PR_RTF_COMPRESSED)
			return false;
	} else if (table_type == db_table::atx_props) {
		if (ppropval->proptag != PR_ATTACH_DATA_BIN &&
		    ppropval->proptag != PR_ATTACH_DATA_OBJ)
			return false;
	} else {
		return false;
	}
	auto dir = exmdb_server::get_dir();
	if (dir == nullptr)
		return FALSE;
	uint64_t cid = 0;
	if (!common_util_allocate_cid(psqlite, &cid))
		return FALSE;
	if (g_cid_compression >= 0)
		return cu_set_obj_cid_val_v2(psqlite, table_type, message_id,
		       dir, cid, ppropval);
	return cu_set_obj_cid_val_v0(psqlite, table_type, message_id, dir, cid,
	       ppropval);
}

static BOOL cu_set_obj_cid_val_v0(sqlite3 *psqlite, db_table table_type,
    uint64_t message_id, const char *dir, uint64_t cid,
    const TAGGED_PROPVAL *ppropval)
{
	auto path = cu_cid_path(dir, cid, 0);
	wrapfd fd = open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0666);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-1628: open %s O_CREAT: %s", path.c_str(), strerror(errno));
		return FALSE;
	}
	auto remove_file = make_scope_exit([&]() {
		if (::remove(path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1389: remove %s: %s",
			        path.c_str(), strerror(errno));
	});
	auto bv = static_cast<BINARY *>(ppropval->pvalue);
	auto ret = write(fd.get(), bv->pv, bv->cb);
	if (ret < 0 || static_cast<size_t>(ret) != bv->cb ||
	    fd.close_wr() < 0 || !cu_update_object_cid(psqlite, table_type,
	    message_id, ppropval->proptag, cid))
		return FALSE;
	remove_file.release();
	return TRUE;
}

BOOL cu_set_property(db_table table_type,
	uint64_t id, uint32_t cpid, sqlite3 *psqlite,
	const TAGGED_PROPVAL *ppropval, BOOL *pb_result)
{
	PROBLEM_ARRAY tmp_problems;
	const TPROPVAL_ARRAY tmp_propvals = {1, deconst(ppropval)};
	if (!cu_set_properties(table_type,
	    id, cpid, psqlite, &tmp_propvals, &tmp_problems))
		return FALSE;
	*pb_result = tmp_problems.count == 1 ? false : TRUE;
	return TRUE;
}

BOOL cu_set_properties(db_table table_type,
	uint64_t id, uint32_t cpid, sqlite3 *psqlite,
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
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
	case db_table::store_props:
		strcpy(sql_string, "REPLACE INTO store_properties VALUES (?, ?)");
		break;
	case db_table::folder_props:
		snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO "
		          "folder_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	case db_table::msg_props:
		snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO "
		          "message_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	case db_table::rcpt_props:
		snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO "
		          "recipients_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	case db_table::atx_props:
		snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO "
		          "attachment_properties VALUES (%llu, ?, ?)", LLU{id});
		break;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (size_t i = 0; i < ppropvals->count; ++i) {
		if (PROP_TYPE(ppropvals->ppropval[i].proptag) == PT_OBJECT &&
		    (table_type != db_table::atx_props ||
		    ppropvals->ppropval[i].proptag != PR_ATTACH_DATA_OBJ)) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count++].err = ecError;
			continue;
		}
		switch (table_type) {
		case db_table::store_props:
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
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
				continue;
			}
			break;
		case db_table::folder_props:
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
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
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
				if (common_util_get_folder_by_name(psqlite,
				    tmp_id, pstring, &tmp_id)) {
					if (tmp_id == 0 || tmp_id == id)
						break;
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count++].err = ecDuplicateName;
					continue;
				}
				break;
			}
			break;
		case db_table::msg_props:
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
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
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
				if (!cu_remove_property(db_table::msg_props,
				    id, psqlite, PR_SUBJECT_PREFIX))
					return FALSE;	
				if (!common_util_set_message_subject(cpid,
				    id, pstmt, &ppropvals->ppropval[i]))
					return FALSE;	
				continue;
			case ID_TAG_BODY:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_BODY,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case ID_TAG_BODY_STRING8:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_BODY_A,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case PR_BODY:
			case PR_BODY_A:
			case PR_TRANSPORT_MESSAGE_HEADERS:
			case PR_TRANSPORT_MESSAGE_HEADERS_A:
				if (!common_util_set_message_body(psqlite, cpid, id, &ppropvals->ppropval[i])) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count++].err = ecError;
				}
				continue;
			case ID_TAG_HTML:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite, table_type, id, PR_HTML,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case ID_TAG_RTFCOMPRESSED:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite, table_type, id, PR_RTF_COMPRESSED,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case PR_HTML:
			case PR_RTF_COMPRESSED:
				if (!cu_set_object_cid_value(psqlite,
				    table_type, id, &ppropvals->ppropval[i])) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count++].err = ecError;
				}
				continue;
			case ID_TAG_TRANSPORTMESSAGEHEADERS:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite, table_type,
				    id, PR_TRANSPORT_MESSAGE_HEADERS,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite, table_type,
				    id, PR_TRANSPORT_MESSAGE_HEADERS_A,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			}
			break;
		case db_table::rcpt_props:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_ROWID:
				continue;
			}
			break;
		case db_table::atx_props:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_RECORD_KEY:
			case PR_ATTACH_NUM:
				continue;
			case ID_TAG_ATTACHDATABINARY:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_ATTACH_DATA_BIN,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case ID_TAG_ATTACHDATAOBJECT:
				if (!g_inside_flush_instance)
					break;
				if (!cu_update_object_cid(psqlite,
				    table_type, id, PR_ATTACH_DATA_OBJ,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case PR_ATTACH_DATA_BIN:
			case PR_ATTACH_DATA_OBJ:
				if (!cu_set_object_cid_value(psqlite,
				    table_type, id, &ppropvals->ppropval[i])) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count++].err = ecError;
				}
				continue;
			}
			break;
		}
		proptype = PROP_TYPE(ppropvals->ppropval[i].proptag);
		if (cpid != 0 && proptype == PT_STRING8)
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_UNICODE));
		else if (cpid != 0 && proptype == PT_MV_STRING8)
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_MV_UNICODE));
		else
			sqlite3_bind_int64(pstmt, 1, ppropvals->ppropval[i].proptag);
		switch (proptype) {
		case PT_STRING8:
			if (0 != cpid) {
				pstring = common_util_convert_copy(TRUE, cpid,
				          static_cast<char *>(ppropvals->ppropval[i].pvalue));
				if (pstring == nullptr)
					return FALSE;
			} else {
				pstring = static_cast<char *>(ppropvals->ppropval[i].pvalue);
			}
			sqlite3_bind_text(pstmt, 2, pstring, -1, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_UNICODE:
			sqlite3_bind_text(pstmt, 2, static_cast<char *>(ppropvals->ppropval[i].pvalue), -1, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_FLOAT:
			sqlite3_bind_double(pstmt, 2,
				*static_cast<float *>(ppropvals->ppropval[i].pvalue));
			s_result = sqlite3_step(pstmt);
			break;
		case PT_DOUBLE:
		case PT_APPTIME:
			sqlite3_bind_double(pstmt, 2,
				*static_cast<double *>(ppropvals->ppropval[i].pvalue));
			s_result = sqlite3_step(pstmt);
			break;
		case PT_CURRENCY:
		case PT_I8:
		case PT_SYSTIME:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue));
			s_result = sqlite3_step(pstmt);
			break;
		case PT_SHORT:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint16_t *>(ppropvals->ppropval[i].pvalue));
			s_result = sqlite3_step(pstmt);
			break;
		case PT_LONG:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue));
			s_result = sqlite3_step(pstmt);
			break;
		case PT_BOOLEAN:
			sqlite3_bind_int64(pstmt, 2,
				*static_cast<uint8_t *>(ppropvals->ppropval[i].pvalue));
			s_result = sqlite3_step(pstmt);
			break;
		case PT_CLSID: {
			EXT_PUSH ext_push;
			if (!ext_push.init(temp_buff, 16, 0) ||
			    ext_push.p_guid(*static_cast<GUID *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_SVREID: {
			EXT_PUSH ext_push;
			if (!ext_push.init(temp_buff, 256, 0) ||
			    ext_push.p_svreid(*static_cast<SVREID *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_SRESTRICTION: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_restriction(*static_cast<RESTRICTION *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_ACTIONS: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_rule_actions(*static_cast<RULE_ACTIONS *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_OBJECT:
		case PT_BINARY: {
			auto bv = static_cast<BINARY *>(ppropvals->ppropval[i].pvalue);
			if (bv->cb == 0)
				sqlite3_bind_blob(pstmt, 2, &i, 0, SQLITE_STATIC);
			else
				sqlite3_bind_blob(pstmt, 2, bv->pv, bv->cb, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_SHORT: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_uint16_a(*static_cast<SHORT_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_LONG: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_uint32_a(*static_cast<LONG_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
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
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_FLOAT: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_float_a(*static_cast<FLOAT_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_DOUBLE:
		case PT_MV_APPTIME: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_double_a(*static_cast<DOUBLE_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_STRING8: {
			if (0 != cpid) {
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
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_UNICODE: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_str_a(*static_cast<STRING_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_CLSID: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_guid_a(*static_cast<GUID_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_BINARY: {
			EXT_PUSH ext_push;
			if (!ext_push.init(nullptr, 0, 0) ||
			    ext_push.p_bin_a(*static_cast<BINARY_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS)
				return FALSE;
			sqlite3_bind_blob(pstmt, 2, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		default:
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count++].err = ecNotSupported;
			sqlite3_reset(pstmt);
			continue;
		}
		sqlite3_reset(pstmt);
		if (SQLITE_DONE != s_result) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count++].err = ecError;
		}
	}
	return TRUE;
}

BOOL cu_remove_property(db_table table_type,
	uint64_t id, sqlite3 *psqlite, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	
	return cu_remove_properties(
		table_type, id, psqlite, &tmp_proptags);
}

BOOL cu_remove_properties(db_table table_type, uint64_t id,
	sqlite3 *psqlite, const PROPTAG_ARRAY *pproptags)
{
	int i;
	uint32_t proptag;
	char sql_string[128];
	
	switch (table_type) {
	case db_table::store_props:
		gx_strlcpy(sql_string, "DELETE FROM store_properties WHERE proptag=?", arsizeof(sql_string));
		break;
	case db_table::folder_props:
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM "
			"folder_properties WHERE folder_id=%llu"
			" AND proptag=?", LLU{id});
		break;
	case db_table::msg_props:
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM "
			"message_properties WHERE message_id=%llu"
			" AND proptag=?", LLU{id});
		break;
	case db_table::atx_props:
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM "
			"attachment_properties WHERE attachment_id=%llu"
			" AND proptag=?", LLU{id});
		break;
	default:
		mlog(LV_WARN, "W-1594: %s undiscovered case", __func__);
		return false;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (i=0; i<pproptags->count; i++) {
		switch (table_type) {
		case db_table::store_props:
			switch (pproptags->pproptag[i]) {
			case PR_MESSAGE_SIZE_EXTENDED:
			case PR_ASSOC_CONTENT_COUNT:
			case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
			case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
				continue;
			}
			break;
		case db_table::folder_props:
			switch (pproptags->pproptag[i]) {
			case PR_DISPLAY_NAME:
			case PR_PREDECESSOR_CHANGE_LIST:
				continue;
			}
			break;
		case db_table::msg_props:
			switch (pproptags->pproptag[i]) {
			case PR_MSG_STATUS:
			case PR_PREDECESSOR_CHANGE_LIST:
				continue;
			}
			break;
		default:
			assert(false); /* cannot happen now */
			return false;
		}
		proptag = pproptags->pproptag[i];
		switch (PROP_TYPE(proptag)) {
		case PT_STRING8:
		case PT_UNICODE:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_UNICODE));
			if (sqlite3_step(pstmt) != SQLITE_DONE)
				return FALSE;
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_STRING8));
			if (sqlite3_step(pstmt) != SQLITE_DONE)
				return FALSE;
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_MV_UNICODE));
			if (sqlite3_step(pstmt) != SQLITE_DONE)
				return FALSE;
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_MV_STRING8));
			if (sqlite3_step(pstmt) != SQLITE_DONE)
				return FALSE;
			break;
		default:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, proptag);
			if (sqlite3_step(pstmt) != SQLITE_DONE)
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
		snprintf(sql_string, arsizeof(sql_string), "SELECT %s "
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
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
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
		*ppvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
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
		snprintf(sql_string, arsizeof(sql_string), "SELECT username FROM"
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
		snprintf(sql_string, arsizeof(sql_string), "SELECT username FROM"
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
		snprintf(sql_string, arsizeof(sql_string), "SELECT username FROM"
		          " permissions WHERE member_id=%llu", LLU{member_id});
		break;
	case PR_MEMBER_RIGHTS:
		if (member_id == 0)
			snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
					"FROM configurations WHERE config_id=%d",
					CONFIG_ID_DEFAULT_PERMISSION);
		else if (member_id == UINT64_MAX)
			snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
					"FROM configurations WHERE config_id=%d",
					CONFIG_ID_ANONYMOUS_PERMISSION);
		else
			snprintf(sql_string, arsizeof(sql_string), "SELECT permission FROM "
			          "permissions WHERE member_id=%llu", LLU{member_id});
		break;
	default:
		*ppvalue = NULL;
		return TRUE;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
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
		pusername = S2A(sqlite3_column_text(pstmt, 0));
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
		pusername = S2A(sqlite3_column_text(pstmt, 0));
		if ('\0' == pusername[0] || 0 == strcasecmp(pusername, "default")) {
			*ppvalue = deconst(&fake_bin);
			return TRUE;
		}
		*ppvalue = common_util_username_to_addressbook_entryid(pusername);
		break;
	case PR_MEMBER_NAME:
	case PR_SMTP_ADDRESS:
		pusername = S2A(sqlite3_column_text(pstmt, 0));
		if ('\0' == pusername[0]) {
			*ppvalue = deconst("default");
			return TRUE;
		} else if (0 == strcasecmp(pusername, "default")) {
			*ppvalue = deconst("anonymous");
			return TRUE;
		}
		*ppvalue = common_util_dup(proptag == PR_SMTP_ADDRESS ||
		           !common_util_get_user_displayname(pusername,
		           display_name, arsizeof(display_name)) ||
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
	int user_id;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	auto pbin = common_util_get_mailbox_guid(psqlite);
	if (pbin == nullptr)
		return nullptr;
	memcpy(&tmp_entryid.provider_uid, pbin->pb, 16);
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
	int user_id;
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	auto pbin = common_util_get_mailbox_guid(psqlite);
	if (pbin == nullptr)
		return nullptr;
	memcpy(&tmp_entryid.provider_uid, pbin->pb, 16);
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
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		*ppermission = sqlite3_column_int64(pstmt, 0);
		return TRUE;
	}
	if (NULL != username && '\0' != username[0]) {
		snprintf(sql_string, arsizeof(sql_string), "SELECT username, permission"
		         " FROM permissions WHERE folder_id=%llu", LLU{folder_id});
		auto pstmt1 = gx_sql_prep(psqlite, sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
		while (SQLITE_ROW == sqlite3_step(pstmt1)) {
			if (common_util_check_mlist_include(S2A(sqlite3_column_text(pstmt1, 0)), username) == TRUE) {
				*ppermission = sqlite3_column_int64(pstmt1, 1);
				return TRUE;
			}
		}
		pstmt1.finalize();
		sqlite3_reset(pstmt);
		sqlite3_bind_text(pstmt, 1, "default", -1, SQLITE_STATIC);
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			*ppermission = sqlite3_column_int64(pstmt, 0);
			return TRUE;
		}
	}
	pstmt.finalize();
	if (username == nullptr || *username == '\0')
		snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
		         "FROM configurations WHERE config_id=%d",
		         CONFIG_ID_ANONYMOUS_PERMISSION);
	else
		snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
		         "FROM configurations WHERE config_id=%d",
		         CONFIG_ID_DEFAULT_PERMISSION);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (sqlite3_step(pstmt) == SQLITE_ROW)
		*ppermission = sqlite3_column_int64(pstmt, 0);
	return TRUE;
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
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT parent_fid FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;	
	*pfolder_id = sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(*) FROM "
	          "search_scopes WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	pfolder_ids->count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	pfolder_ids->pll = cu_alloc<uint64_t>(pfolder_ids->count);
	if (pfolder_ids->pll == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT included_fid FROM"
	          " search_scopes WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (size_t i = 0; i < pfolder_ids->count && sqlite3_step(pstmt) == SQLITE_ROW; )
		pfolder_ids->pll[i++] = sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

static bool cu_eval_subitem_restriction(sqlite3 *psqlite,
    uint32_t cpid, db_table table_type, uint64_t id, const RESTRICTION *pres)
{
	int len;
	void *pvalue;
	void *pvalue1;
	uint32_t val_size;
	
	switch (pres->rt) {
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (PROP_TYPE(rcon->proptag) != PT_STRING8 &&
		    PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rcon->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE))
				return strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				       static_cast<char *>(pvalue)) == 0;
			else
				return strcmp(static_cast<char *>(rcon->propval.pvalue),
				       static_cast<char *>(pvalue)) == 0;
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE))
				return strcasestr(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue)) != nullptr;
			else
				return strstr(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue)) != nullptr;
			return FALSE;
		case FL_PREFIX:
			len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE))
				return strncasecmp(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue), len) == 0;
			else
				return strncmp(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue), len) == 0;
			return FALSE;
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rprop->proptag, &pvalue))
			return FALSE;
		if (pvalue == nullptr)
			return propval_compare_relop_nullok(rprop->relop,
			       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
		if (rprop->proptag == PR_ANR) {
			if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
				return FALSE;
			return strcasestr(static_cast<char *>(pvalue),
			       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
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
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rbm->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			return (*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0;
		case BMR_NEZ:
			return (*static_cast<uint32_t *>(pvalue) & rbm->mask) != 0;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!cu_get_property(table_type, id, cpid, psqlite,
		    rsize->proptag, &pvalue))
			return FALSE;
		val_size = pvalue != nullptr ? propval_size(rsize->proptag, pvalue) : 0;
		return propval_compare_relop_nullok(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
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

static bool cu_eval_msgsubs_restriction(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, const RESTRICTION *pres)
{
	uint64_t id;
	uint32_t count;
	db_table table_type;
	char sql_string[128];
	
	if (proptag == PR_MESSAGE_RECIPIENTS) {
		table_type = db_table::rcpt_props;
		snprintf(sql_string, arsizeof(sql_string), "SELECT recipient_id FROM "
				"recipients WHERE message_id=%llu", LLU{message_id});
	} else {
		table_type = db_table::atx_props;
		snprintf(sql_string, arsizeof(sql_string), "SELECT attachment_id FROM"
				" attachments WHERE message_id=%llu", LLU{message_id});
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
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

static bool cu_eval_subobj_restriction(sqlite3 *psqlite, uint32_t cpid,
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
	uint32_t val_size;
	
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
		if (PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		if (!cu_get_property(db_table::folder_props,
		    folder_id, 0, psqlite, rcon->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE))
				return strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				       static_cast<char *>(pvalue)) == 0;
			else
				return strcmp(static_cast<char *>(rcon->propval.pvalue),
				       static_cast<char *>(pvalue)) == 0;
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE))
				return strcasestr(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue)) != nullptr;
			else
				return strstr(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue)) != nullptr;
			return FALSE;
		case FL_PREFIX: {
			auto len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE))
				return strncasecmp(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue), len) == 0;
			else
				return strncmp(static_cast<char *>(pvalue),
				       static_cast<char *>(rcon->propval.pvalue), len) == 0;
			return FALSE;
		}
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!cu_get_property(db_table::folder_props,
		    folder_id, 0, psqlite, rprop->proptag, &pvalue))
			return FALSE;
		if (pvalue == nullptr)
			return propval_compare_relop_nullok(rprop->relop,
			       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
		if (rprop->proptag == PR_ANR) {
			if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
				return FALSE;
			return strcasestr(static_cast<char *>(pvalue),
			       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
			return FALSE;
		if (!cu_get_property(db_table::folder_props,
		    folder_id, 0, psqlite, rprop->proptag1, &pvalue))
			return FALSE;
		if (!cu_get_property(db_table::folder_props,
		    folder_id, 0, psqlite, rprop->proptag2, &pvalue1))
			return FALSE;
		return propval_compare_relop_nullok(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		if (!cu_get_property(db_table::folder_props,
		    folder_id, 0, psqlite, rbm->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			return (*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0;
		case BMR_NEZ:
			return (*static_cast<uint32_t *>(pvalue) & rbm->mask) != 0;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!cu_get_property(db_table::folder_props,
		    folder_id, 0, psqlite, rsize->proptag, &pvalue))
			return FALSE;
		val_size = pvalue != nullptr ? propval_size(rsize->proptag, pvalue) : 0;
		return propval_compare_relop_nullok(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
	}
	case RES_EXIST:
		if (!cu_get_property(db_table::folder_props,
		    folder_id, 0, psqlite, pres->exist->proptag, &pvalue) ||
		    pvalue == nullptr)
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
	uint32_t cpid, uint64_t message_id, const RESTRICTION *pres)
{
	void *pvalue;
	void *pvalue1;
	uint32_t val_size;
	
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
		void *pvalue = nullptr;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		if (PROP_TYPE(rcon->proptag) == PT_BINARY) {
			if (!cu_get_property(db_table::msg_props,
			    message_id, cpid, psqlite, rcon->proptag, &pvalue) ||
			    pvalue == nullptr)
				return FALSE;
			auto &dbval = *static_cast<const BINARY *>(pvalue);
			auto &rsval = *static_cast<const BINARY *>(rcon->propval.pvalue);
			switch (rcon->fuzzy_level & 0xFFFF) {
			case FL_FULLSTRING:
				return dbval.cb == rsval.cb && memcmp(dbval.pv, rsval.pv, rsval.cb) == 0;
			case FL_SUBSTRING:
				return HX_memmem(dbval.pv, dbval.cb, rsval.pv, rsval.cb) != nullptr;
			case FL_PREFIX:
				return dbval.cb >= rsval.cb && memcmp(dbval.pv, rsval.pv, rsval.cb) == 0;
			}
			return false;
		}
		if (PROP_TYPE(rcon->proptag) != PT_STRING8 &&
		    PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (!cu_get_property(db_table::msg_props,
		    message_id, cpid, psqlite, rcon->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		auto dbval = static_cast<const char *>(pvalue);
		auto rsval = static_cast<const char *>(rcon->propval.pvalue);
		auto icase = rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE);
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			return icase ? strcasecmp(dbval, rsval) == 0 :
			       strcmp(dbval, rsval) == 0;
		case FL_SUBSTRING:
			return icase ? strcasestr(dbval, rsval) != nullptr :
			       strstr(dbval, rsval) != nullptr;
		case FL_PREFIX: {
			auto len = strlen(rsval);
			return icase ? strncasecmp(dbval, rsval, len) == 0 :
			       strncmp(dbval, rsval, len) == 0;
		}
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		switch (rprop->proptag) {
		case PR_PARENT_SVREID:
		case PR_PARENT_ENTRYID:
			pvalue = cu_get_msg_parent_svreid(psqlite, message_id);
			if (pvalue == nullptr)
				return FALSE;
			break;
		default:
			if (!cu_get_property(db_table::msg_props,
			    message_id, cpid, psqlite, rprop->proptag, &pvalue))
				return FALSE;
			if (pvalue == nullptr)
				break;
			if (rprop->proptag == PR_ANR) {
				if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
					return FALSE;
				return strcasestr(static_cast<char *>(pvalue),
				       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
			}
			break;
		}
		return propval_compare_relop_nullok(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
			return FALSE;
		if (!cu_get_property(db_table::msg_props,
		    message_id, cpid, psqlite, rprop->proptag1, &pvalue))
			return FALSE;
		if (!cu_get_property(db_table::msg_props,
		    message_id, cpid, psqlite, rprop->proptag2, &pvalue1))
			return FALSE;
		return propval_compare_relop_nullok(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		if (!cu_get_property(db_table::msg_props,
		    message_id, cpid, psqlite, rbm->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			return (*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0;
		case BMR_NEZ:
			return (*static_cast<uint32_t *>(pvalue) & rbm->mask) != 0;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!cu_get_property(db_table::msg_props,
		    message_id, cpid, psqlite, rsize->proptag, &pvalue))
			return FALSE;
		val_size = pvalue != nullptr ? propval_size(rsize->proptag, pvalue) : 0;
		return propval_compare_relop_nullok(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
	}
	case RES_EXIST:
		if (!cu_get_property(db_table::msg_props,
		    message_id, cpid, psqlite, pres->exist->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		return TRUE;
	case RES_SUBRESTRICTION: {
		auto rsub = pres->sub;
		switch (rsub->subobject) {
		case PR_MESSAGE_RECIPIENTS:
			return cu_eval_subobj_restriction(psqlite,
			       cpid, message_id, PR_MESSAGE_RECIPIENTS,
			       &rsub->res);
		case PR_MESSAGE_ATTACHMENTS:
			return cu_eval_subobj_restriction(psqlite,
			       cpid, message_id, PR_MESSAGE_ATTACHMENTS,
			       &rsub->res);
		default:
			return FALSE;
		}
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
		if (cu_eval_msg_restriction(psqlite,
		    cpid, message_id, &rcnt->sub_res)) {
			--rcnt->count;
			return TRUE;
		}
		return FALSE;
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT message_id FROM"
				" search_result WHERE folder_id=%llu AND "
				"message_id=%llu", LLU{folder_id}, LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_exist = sqlite3_step(pstmt) == SQLITE_ROW ? TRUE : false;
	return TRUE;
}

BOOL common_util_get_mid_string(sqlite3 *psqlite,
	uint64_t message_id, char **ppmid_string)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	if (SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
		*ppmid_string = NULL;
		return TRUE;
	}
	*ppmid_string = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
	return *ppmid_string != nullptr ? TRUE : false;
}

BOOL common_util_set_mid_string(sqlite3 *psqlite,
	uint64_t message_id, const char *pmid_string)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "UPDATE messages set "
	          "mid_string=? WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, pmid_string, -1, SQLITE_STATIC);
	return sqlite3_step(pstmt) == SQLITE_DONE ? TRUE : false;
}

BOOL common_util_check_message_owner(sqlite3 *psqlite,
	uint64_t message_id, const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EXT_PULL ext_pull;
	char tmp_name[UADDR_SIZE];
	EMSAB_ENTRYID ab_entryid;
	
	if (!cu_get_property(db_table::msg_props, message_id, 0,
	    psqlite, PR_CREATOR_ENTRYID, reinterpret_cast<void **>(&pbin)))
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
	    tmp_name, GX_ARRAY_SIZE(tmp_name))) {
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
		snprintf(sql_string, arsizeof(sql_string), "SELECT is_associated, message_size,"
			" read_state, mid_string FROM messages WHERE message_id=%llu",
		          LLU{message_id});
	else
		snprintf(sql_string, arsizeof(sql_string), "SELECT is_associated, "
			"message_size FROM messages WHERE message_id=%llu",
		          LLU{message_id});

	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
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
			gx_strlcpy(mid_string1, S2A(sqlite3_column_text(pstmt, 3)), sizeof(mid_string1));
			snprintf(mid_string, arsizeof(mid_string), "%lld.%u.%s",
			         LLD{time(nullptr)}, common_util_sequence_ID(), get_host_ID());
			snprintf(tmp_path, arsizeof(tmp_path), "%s/eml/%s",
			         exmdb_server::get_dir(), mid_string);
			snprintf(tmp_path1, arsizeof(tmp_path1), "%s/eml/%s",
			         exmdb_server::get_dir(), mid_string1);
			link(tmp_path1, tmp_path);
			snprintf(tmp_path, arsizeof(tmp_path), "%s/ext/%s",
			         exmdb_server::get_dir(), mid_string);
			snprintf(tmp_path1, arsizeof(tmp_path1), "%s/ext/%s",
			         exmdb_server::get_dir(), mid_string1);
			link(tmp_path1, tmp_path);
		}
	}
	if (pmessage_size != nullptr)
		*pmessage_size = message_size;
	pstmt.finalize();
	if (b_embedded) {
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO messages (message_id, parent_fid,"
			" parent_attid, is_associated, change_number, message_size) "
			"VALUES (%llu, NULL, %llu, %d, %llu, %u)", LLU{*pdst_mid},
			LLU{parent_id}, 0, LLU{change_num}, message_size);
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	} else if (b_private) {
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO messages (message_id, "
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
		if (sqlite3_step(pstmt) != SQLITE_DONE)
			return FALSE;
		pstmt.finalize();
	} else {
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO messages (message_id, parent_fid,"
		         " parent_attid, is_associated, change_number, message_size) "
		         "VALUES (%llu, %llu, NULL, %d, %llu, %u)", LLU{*pdst_mid},
		         LLU{parent_id}, is_associated, LLU{change_num}, message_size);
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO message_properties (message_id,"
			" proptag, propval) SELECT %llu, proptag, propval FROM "
			"message_properties WHERE message_id=%llu",
			LLU{*pdst_mid}, LLU{message_id});
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO recipients"
	          " (message_id) VALUES (%llu)", LLU{*pdst_mid});
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	auto pstmt2 = gx_sql_prep(psqlite, "INSERT INTO recipients_properties "
	              "(recipient_id, proptag, propval) SELECT ?, proptag, "
	              "propval FROM recipients_properties WHERE recipient_id=?");
	if (pstmt2 == nullptr)
		return FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		tmp_id = sqlite3_column_int64(pstmt, 0);
		if (sqlite3_step(pstmt1) != SQLITE_DONE)
			return FALSE;
		last_id = sqlite3_last_insert_rowid(psqlite);
		sqlite3_bind_int64(pstmt2, 1, last_id);
		sqlite3_bind_int64(pstmt2, 2, tmp_id);
		if (sqlite3_step(pstmt2) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt2);
	}
	pstmt.finalize();
	pstmt1.finalize();
	pstmt2.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT attachment_id FROM"
	          " attachments WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO attachments"
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
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		tmp_id = sqlite3_column_int64(pstmt, 0);
		if (sqlite3_step(pstmt1) != SQLITE_DONE)
			return FALSE;
		last_id = sqlite3_last_insert_rowid(psqlite);
		sqlite3_bind_int64(pstmt2, 1, last_id);
		sqlite3_bind_int64(pstmt2, 2, tmp_id);
		if (sqlite3_step(pstmt2) != SQLITE_DONE)
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
	TAGGED_PROPVAL tmp_propval;
	static const uint32_t fake_uid = 1;
	TAGGED_PROPVAL propval_buff[4];
	
	if (!common_util_copy_message_internal(psqlite,
	    FALSE, message_id, folder_id, pdst_mid, pb_result,
	    &change_num, pmessage_size))
		return FALSE;
	if (!*pb_result)
		return TRUE;
	if (!cu_get_property(db_table::folder_props,
	    folder_id, 0, psqlite, PR_INTERNET_ARTICLE_NUMBER_NEXT, &pvalue))
		return FALSE;
	if (pvalue == nullptr)
		pvalue = deconst(&fake_uid);
	auto next = *static_cast<uint32_t *>(pvalue) + 1;
	tmp_propval.proptag = PR_INTERNET_ARTICLE_NUMBER_NEXT;
	tmp_propval.pvalue = &next;
	if (!cu_set_property(db_table::folder_props,
	    folder_id, 0, psqlite, &tmp_propval, &b_result))
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
	if (!cu_set_properties(db_table::msg_props, *pdst_mid, 0,
	    psqlite, &propvals, &tmp_problems))
		return FALSE;
	return TRUE;
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
		snprintf(sql_string, arsizeof(sql_string), "SELECT"
			" count(*) FROM named_properties");
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
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
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO "
			"named_properties (name_string) VALUES (?)");
		pstmt1 = gx_sql_prep(psqlite, sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
	}
	for (size_t i = 0; i < ppropnames->count; ++i) try {
		char guid_string[GUIDSTR_SIZE];
		ppropnames->ppropname[i].guid.to_str(guid_string, arsizeof(guid_string));
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
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			ppropids->ppropid[i] = sqlite3_column_int64(pstmt, 0);
			sqlite3_reset(pstmt);
			continue;
		}
		sqlite3_reset(pstmt);
		if (b_create) {
			sqlite3_bind_text(pstmt1, 1, name_string.c_str(), -1, SQLITE_STATIC);
			if (sqlite3_step(pstmt1) != SQLITE_DONE)
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
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_reset(pstmt);
			goto NOT_FOUND_PROPNAME;
		}
		gx_strlcpy(temp_name, S2A(sqlite3_column_text(pstmt, 0)), sizeof(temp_name));
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
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id "
	          "FROM folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_exist = sqlite3_step(pstmt) != SQLITE_ROW ? false : TRUE;
	return TRUE;
}

BOOL common_util_increase_deleted_count(sqlite3 *psqlite,
	uint64_t folder_id, uint32_t del_count)
{
	char sql_string[256];
	
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties"
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
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	if (0 != normal_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, normal_size);
		sqlite3_bind_int64(pstmt, 2, PR_NORMAL_MESSAGE_SIZE_EXTENDED);
		if (sqlite3_step(pstmt) != SQLITE_DONE)
			return FALSE;
	}
	if (0 != fai_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, fai_size);
		sqlite3_bind_int64(pstmt, 2, PR_ASSOC_MESSAGE_SIZE_EXTENDED);
		if (sqlite3_step(pstmt) != SQLITE_DONE)
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
		if (sqlite3_step(pstmt1) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
		if (step > 0 && 0 != sqlite3_column_int64(pstmt, 1)) {
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, -row_id);
			if (sqlite3_step(pstmt) == SQLITE_ROW &&
			    !common_util_indexing_sub_contents(step - 1, pstmt, pstmt1, pidx))
				return FALSE;
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, row_id);
		if (sqlite3_step(pstmt) != SQLITE_ROW)
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
static uint32_t cu_get_cid_length(uint64_t cid, uint16_t proptype)
{
	auto dir = exmdb_server::get_dir();
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
		case ID_TAG_TRANSPORTMESSAGEHEADERS:
			message_size += cu_get_cid_length(*static_cast<uint64_t *>(ppropval->pvalue), PT_UNICODE);
			break;
		case ID_TAG_BODY_STRING8:
		case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
			message_size += cu_get_cid_length(*static_cast<uint64_t *>(ppropval->pvalue), PT_STRING8);
			break;
		case ID_TAG_HTML:
		case ID_TAG_RTFCOMPRESSED:
			message_size += cu_get_cid_length(*static_cast<uint64_t *>(ppropval->pvalue), PT_BINARY);
			break;
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
				case ID_TAG_ATTACHDATAOBJECT:
					message_size += cu_get_cid_length(*static_cast<uint64_t *>(ppropval->pvalue), PT_BINARY);
					break;
				default:
					message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
				}
			}
			if (pattachment->pembedded != nullptr)
				message_size += common_util_calculate_message_size(
											pattachment->pembedded);
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
		case ID_TAG_ATTACHDATAOBJECT:
			attachment_size += cu_get_cid_length(*static_cast<uint64_t *>(ppropval->pvalue), PT_BINARY);
			break;
		default:
			attachment_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
		}
	}
	if (pattachment->pembedded != nullptr)
		attachment_size += common_util_calculate_message_size(
										pattachment->pembedded);
	return attachment_size;
}
