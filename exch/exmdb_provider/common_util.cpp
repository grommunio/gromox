// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <new>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/pcl.hpp>
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/ext_buffer.hpp>
#include "common_util.h"
#include "exmdb_server.h"
#include <gromox/alloc_context.hpp>
#include <gromox/database.h>
#include <gromox/fileio.h>
#include <gromox/svc_common.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <cstdio>
#include <iconv.h>
#define UI(x) static_cast<unsigned int>(x)
#define LLD(x) static_cast<long long>(x)
#define LLU(x) static_cast<unsigned long long>(x)
#define S2A(x) reinterpret_cast<const char *>(x)

#define SERVICE_ID_LANG_TO_CHARSET							1
#define SERVICE_ID_CPID_TO_CHARSET							2
#define SERVICE_ID_GET_USER_DISPLAYNAME						3
#define SERVICE_ID_CHECK_MLIST_INCLUDE						4
#define SERVICE_ID_GET_USER_LANG							5
#define SERVICE_ID_GET_TIMEZONE								6
#define SERVICE_ID_GET_MAILDIR								7
#define SERVICE_ID_GET_ID_FFROM_USERNAME					8
#define SERVICE_ID_GET_USERNAME_FROM_ID						9
#define SERVICE_ID_GET_USER_IDS								10
#define SERVICE_ID_GET_DOMAIN_IDS							11
#define SERVICE_ID_GET_ID_FROM_MAILDIR						12
#define SERVICE_ID_GET_ID_FROM_HOMEDIR						13
#define SERVICE_ID_SEND_MAIL								14
#define SERVICE_ID_GET_MIME_POOL							15
#define SERVICE_ID_LOG_INFO									16
#define SERVICE_ID_GET_HANDLE								17

using namespace gromox;

namespace {
struct OPTIMIZE_STMTS {
	xstmt pstmt_msg1; /* normal message property */
	xstmt pstmt_msg2; /* string message property */
	xstmt pstmt_rcpt1; /* normal recipient property */
	xstmt pstmt_rcpt2; /* string recipient property */
};
}

static char g_org_name[256];
static unsigned int g_max_msg;
static pthread_key_t g_var_key;
static pthread_key_t g_opt_key;
static unsigned int g_max_rule_num;
static unsigned int g_max_ext_rule_num;
static std::atomic<int> g_sequence_id{0};

#define E(s) decltype(common_util_ ## s) common_util_ ## s;
E(lang_to_charset)
E(cpid_to_charset)
E(get_user_displayname)
E(check_mlist_include)
E(get_user_lang)
E(get_timezone)
E(get_maildir)
E(get_id_from_username)
E(get_domain_ids)
E(get_id_from_maildir)
E(get_id_from_homedir)
E(send_mail)
E(get_mime_pool)
E(log_info)
E(get_handle)
#undef E

static BOOL (*common_util_get_username_from_id)(int id, char *username, size_t);
static BOOL (*common_util_get_user_ids)(const char *username,
	int *puser_id, int *pdomain_id, int *paddress_type);
static BOOL common_util_evaluate_subobject_restriction(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, const RESTRICTION *pres);

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
	parray->ppropval[parray->count] = *ppropval;
	parray->count ++;
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

void* common_util_get_propvals(
	const TPROPVAL_ARRAY *parray, uint32_t proptag)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (proptag == parray->ppropval[i].proptag) {
			return (void*)parray->ppropval[i].pvalue;
		}
	}
	return NULL;
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
			g_org_name);
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
	int address_type;
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
	if (FALSE == common_util_get_user_ids(username,
		&user_id, &domain_id, &address_type)) {
		return FALSE;
	}
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, dnmax, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
			g_org_name, hex_string2, hex_string, tmp_name);
	HX_strupper(pessdn);
	return TRUE;
}
	
void common_util_pass_service(int service_id, void *func)
{
#define E(v, ptr) case (v): (ptr) = reinterpret_cast<decltype(ptr)>(func); break;
	switch (service_id) {
	E(SERVICE_ID_LANG_TO_CHARSET, common_util_lang_to_charset);
	E(SERVICE_ID_CPID_TO_CHARSET, common_util_cpid_to_charset);
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
	E(SERVICE_ID_SEND_MAIL, common_util_send_mail);
	E(SERVICE_ID_GET_MIME_POOL, common_util_get_mime_pool);
	E(SERVICE_ID_LOG_INFO, common_util_log_info);
	E(SERVICE_ID_GET_HANDLE, common_util_get_handle);
	}
#undef E
}

void common_util_init(const char *org_name, uint32_t max_msg,
	unsigned int max_rule_num, unsigned int max_ext_rule_num)
{
	gx_strlcpy(g_org_name, org_name, GX_ARRAY_SIZE(g_org_name));
	g_max_msg = max_msg;
	g_max_rule_num = max_rule_num;
	g_max_ext_rule_num = max_ext_rule_num;
	pthread_key_create(&g_var_key, NULL);
	pthread_key_create(&g_opt_key, NULL);
}

int common_util_run()
{
	return 0;
}

int common_util_stop()
{
	return 0;
}

void common_util_free()
{
	pthread_key_delete(g_var_key);
	pthread_key_delete(g_opt_key);
}

void common_util_build_tls()
{
	pthread_setspecific(g_var_key, NULL);
	pthread_setspecific(g_opt_key, NULL);
}

void common_util_set_tls_var(const void *pvar)
{
	pthread_setspecific(g_var_key, pvar);
}

const void* common_util_get_tls_var()
{
	return pthread_getspecific(g_var_key);
}

int common_util_sequence_ID()
{
	int old = 0, nu = 0;
	do {
		old = g_sequence_id.load(std::memory_order_relaxed);
		nu  = old != INT_MAX ? old + 1 : 1;
	} while (!g_sequence_id.compare_exchange_weak(old, nu));
	return nu;
}

/* can directly be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
void* common_util_alloc(size_t size)
{
	ALLOC_CONTEXT *pctx;
	
	pctx = exmdb_server_get_alloc_context();
	if (NULL != pctx) {
		return alloc_context_alloc(pctx, size);
	}
	return ndr_stack_alloc(NDR_STACK_IN, size);
}

char* common_util_dup(const char *pstr)
{
	int len;
	
	len = strlen(pstr) + 1;
	auto pstr1 = cu_alloc<char>(len);
	if (NULL == pstr1) {
		return NULL;
	}
	memcpy(pstr1, pstr, len);
	return pstr1;
}

char* common_util_convert_copy(BOOL to_utf8,
	uint32_t cpid, const char *pstring)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;
	char *pin, *pout;
	const char *charset;
	char temp_charset[256];
	
	charset = common_util_cpid_to_charset(cpid);
	if (NULL == charset) {
		charset = "windows-1252";
	}
	in_len = strlen(pstring) + 1;
	out_len = 2*in_len;
	auto pstr_out = cu_alloc<char>(out_len);
	if (NULL == pstr_out) {
		return NULL;
	}
	if (TRUE == to_utf8) {
		conv_id = iconv_open("UTF-8//IGNORE", charset);
		if ((iconv_t)-1 == conv_id) {
			conv_id = iconv_open("UTF-8//IGNORE", "windows-1252");
		}
	} else {
		sprintf(temp_charset, "%s//IGNORE", charset);
		conv_id = iconv_open(temp_charset, "UTF-8");
		if ((iconv_t)-1 == conv_id) {
			conv_id = iconv_open("windows-1252//IGNORE", "UTF-8");
		}
	}
	pin = (char*)pstring;
	pout = pstr_out;
	memset(pstr_out, 0, out_len);
	iconv(conv_id, &pin, &in_len, &pout, &out_len);
	iconv_close(conv_id);
	return pstr_out;
}

STRING_ARRAY *common_util_convert_copy_string_array(
	BOOL to_utf8, uint32_t cpid, const STRING_ARRAY *parray)
{
	auto parray1 = cu_alloc<STRING_ARRAY>();
	if (NULL == parray1) {
		return NULL;
	}
	parray1->count = parray->count;
	if (0 != parray->count) {
		parray1->ppstr = cu_alloc<char *>(parray->count);
		if (NULL == parray1->ppstr) {
			return NULL;
		}
	} else {
		parray1->ppstr = NULL;
	}
	for (size_t i = 0; i < parray->count; ++i) {
		parray1->ppstr[i] = common_util_convert_copy(
					to_utf8, cpid, parray->ppstr[i]);
		if (NULL == parray1->ppstr[i]) {
			return NULL;
		}
	}
	return parray1;
}

BOOL common_util_allocate_eid(sqlite3 *psqlite, uint64_t *peid)
{
	uint64_t cur_eid;
	uint64_t max_eid;
	char sql_string[128];
	
	sprintf(sql_string, "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_CURRENT_EID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	cur_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	*peid = cur_eid + 1;
	sprintf(sql_string, "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_MAXIMUM_EID);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	max_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (cur_eid >= max_eid) {
		sprintf(sql_string, "SELECT "
			"max(range_end) FROM allocated_eids");
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		cur_eid = sqlite3_column_int64(pstmt, 0);
		max_eid = cur_eid + ALLOCATED_EID_RANGE;
		pstmt.finalize();
		sprintf(sql_string, "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lld, 1)",
		        LLU(cur_eid + 1), LLU(max_eid), LLD(time(nullptr)));
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
		sprintf(sql_string, "UPDATE configurations SET"
			" config_value=%llu WHERE config_id=%u",
			LLU(max_eid), CONFIG_ID_MAXIMUM_EID);
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
	} else {
		cur_eid ++;
	}
	sprintf(sql_string, "UPDATE configurations SET"
		" config_value=%llu WHERE config_id=%u",
		LLU(cur_eid), CONFIG_ID_CURRENT_EID);
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	return TRUE;
}

BOOL common_util_allocate_eid_from_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t *peid)
{
	uint64_t cur_eid;
	uint64_t max_eid;
	char sql_string[128];
	
	sprintf(sql_string, "SELECT cur_eid, max_eid "
	          "FROM folders WHERE folder_id=%llu", LLU(folder_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	*peid = sqlite3_column_int64(pstmt, 0);
	max_eid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	cur_eid = *peid + 1;
	if (cur_eid > max_eid) {
		sprintf(sql_string, "SELECT "
			"max(range_end) FROM allocated_eids");
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		*peid = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		max_eid = *peid + ALLOCATED_EID_RANGE;
		cur_eid = *peid + 1;
		sprintf(sql_string, "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %llu, 1)", LLU(cur_eid),
			LLU(max_eid), LLD(time(nullptr)));
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
	}
	sprintf(sql_string, "UPDATE folders SET cur_eid=%llu,"
		" max_eid=%llu WHERE folder_id=%llu", LLU(cur_eid),
		LLU(max_eid), LLU(folder_id));
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	return TRUE;
}

BOOL common_util_allocate_cn(sqlite3 *psqlite, uint64_t *pcn)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT config_value FROM "
				"configurations WHERE config_id=%u",
				CONFIG_ID_LAST_CHANGE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint64_t last_cn = sqlite3_step(pstmt) == SQLITE_ROW ?
	                   sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_cn ++;
	sprintf(sql_string, "REPLACE INTO "
				"configurations VALUES (%u, ?)",
				CONFIG_ID_LAST_CHANGE_NUMBER);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_cn);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		return FALSE;
	}
	*pcn = last_cn;
	return TRUE;
}

BOOL common_util_allocate_folder_art(sqlite3 *psqlite, uint32_t *part)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT config_value "
				"FROM configurations WHERE config_id=%u",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint32_t last_art = sqlite3_step(pstmt) == SQLITE_ROW ?
	                    sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_art ++;
	sprintf(sql_string, "REPLACE INTO "
				"configurations VALUES (%u, ?)",
				CONFIG_ID_LAST_ARTICLE_NUMBER);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_art);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		return FALSE;
	}
	*part = last_art;
	return TRUE;
}

BOOL common_util_check_allocated_eid(sqlite3 *psqlite,
	uint64_t eid_val, BOOL *pb_result)
{
	char sql_string[256];
	
	sprintf(sql_string, "SELECT range_begin,"
				" range_end FROM allocated_eids WHERE "
				"range_begin<=%llu AND range_end>=%llu",
				LLU(eid_val), LLU(eid_val));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_result = sqlite3_step(pstmt) == SQLITE_ROW ? TRUE : false;
	return TRUE;
}

BOOL common_util_allocate_cid(sqlite3 *psqlite, uint64_t *pcid)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT config_value FROM "
		"configurations WHERE config_id=%u", CONFIG_ID_LAST_CID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint64_t last_cid = sqlite3_step(pstmt) == SQLITE_ROW ?
	                    sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	last_cid ++;
	sprintf(sql_string, "REPLACE INTO configurations"
					" VALUES (%u, ?)", CONFIG_ID_LAST_CID);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_cid);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		return FALSE;
	}
	*pcid = last_cid;
	return TRUE;
}

BOOL common_util_begin_message_optimize(sqlite3 *psqlite)
{
	char sql_string[256];
	
	std::unique_ptr<OPTIMIZE_STMTS> popt_stmts(new(std::nothrow) OPTIMIZE_STMTS);
	if (NULL == popt_stmts) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT propval"
				" FROM message_properties WHERE "
				"message_id=? AND proptag=?");
	popt_stmts->pstmt_msg1 = gx_sql_prep(psqlite, sql_string);
	if (popt_stmts->pstmt_msg1 == nullptr) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT proptag, "
			"propval FROM message_properties WHERE "
			"message_id=? AND (proptag=? OR proptag=?)");
	popt_stmts->pstmt_msg2 = gx_sql_prep(psqlite, sql_string);
	if (popt_stmts->pstmt_msg2 == nullptr) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT propval "
				"FROM recipients_properties WHERE "
				"recipient_id=? AND proptag=?");
	popt_stmts->pstmt_rcpt1 = gx_sql_prep(psqlite, sql_string);
	if (popt_stmts->pstmt_rcpt1 == nullptr) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT proptag, propval"
		" FROM recipients_properties WHERE recipient_id=?"
		" AND (proptag=? OR proptag=?)");
	popt_stmts->pstmt_rcpt2 = gx_sql_prep(psqlite, sql_string);
	if (popt_stmts->pstmt_rcpt2 == nullptr) {
		return FALSE;
	}
	pthread_setspecific(g_opt_key, popt_stmts.release());
	return TRUE;
}

void common_util_end_message_optimize()
{
	auto popt_stmts = static_cast<OPTIMIZE_STMTS *>(pthread_getspecific(g_opt_key));
	if (NULL == popt_stmts) {
		return;
	}
	pthread_setspecific(g_opt_key, NULL);
	delete popt_stmts;
}

static sqlite3_stmt* common_util_get_optimize_stmt(
	int table_type, BOOL b_normal)
{
	if (MESSAGE_PROPERTIES_TABLE != table_type &&
		RECIPIENT_PROPERTIES_TABLE != table_type) {
		return NULL;	
	}
	auto popt_stmts = static_cast<OPTIMIZE_STMTS *>(pthread_getspecific(g_opt_key));
	if (NULL == popt_stmts) {
		return NULL;
	}
	if (MESSAGE_PROPERTIES_TABLE == table_type) {
		return b_normal ? popt_stmts->pstmt_msg1 : popt_stmts->pstmt_msg2;
	} else {
		return b_normal ? popt_stmts->pstmt_rcpt1 : popt_stmts->pstmt_rcpt2;
	}
}

BOOL common_util_get_proptags(int table_type, uint64_t id,
	sqlite3 *psqlite, PROPTAG_ARRAY *pproptags)
{
	BOOL b_subject;
	char sql_string[128];
	uint32_t proptags[0x8000];
	size_t i = 0;

	switch (table_type) {
	case STORE_PROPERTIES_TABLE:
		sprintf(sql_string, "SELECT proptag FROM store_properties");
		proptags[i++] = PROP_TAG_INTERNETARTICLENUMBER;
		break;
	case FOLDER_PROPERTIES_TABLE:
		sprintf(sql_string, "SELECT proptag FROM "
		        "folder_properties WHERE folder_id=%llu", LLU(id));
		proptags[i++] = PROP_TAG_ASSOCIATEDCONTENTCOUNT;
		proptags[i++] = PROP_TAG_CONTENTCOUNT;
		proptags[i++] = PR_MESSAGE_SIZE_EXTENDED;
		proptags[i++] = PROP_TAG_ASSOCMESSAGESIZEEXTENDED;
		proptags[i++] = PROP_TAG_NORMALMESSAGESIZEEXTENDED;
		proptags[i++] = PROP_TAG_FOLDERCHILDCOUNT;
		proptags[i++] = PROP_TAG_FOLDERTYPE;
		proptags[i++] = PROP_TAG_CONTENTUNREADCOUNT;
		proptags[i++] = PROP_TAG_SUBFOLDERS;
		proptags[i++] = PROP_TAG_HASRULES;
		proptags[i++] = PROP_TAG_FOLDERPATHNAME;
		proptags[i++] = PROP_TAG_LOCALCOMMITTIME;
		proptags[i++] = PROP_TAG_FOLDERID;
		proptags[i++] = PROP_TAG_CHANGENUMBER;
		proptags[i++] = PROP_TAG_FOLDERFLAGS;
		break;
	case MESSAGE_PROPERTIES_TABLE:
		sprintf(sql_string, "SELECT proptag FROM "
		        "message_properties WHERE message_id=%llu", LLU(id));
		proptags[i++] = PROP_TAG_MID;
		proptags[i++] = PR_MESSAGE_SIZE;
		proptags[i++] = PROP_TAG_ASSOCIATED;
		proptags[i++] = PROP_TAG_CHANGENUMBER;
		proptags[i++] = PR_READ;
		proptags[i++] = PROP_TAG_HASATTACHMENTS;
		proptags[i++] = PR_MESSAGE_FLAGS;
		proptags[i++] = PR_DISPLAY_TO;
		proptags[i++] = PR_DISPLAY_CC;
		proptags[i++] = PR_DISPLAY_BCC;
		break;
	case RECIPIENT_PROPERTIES_TABLE:
		sprintf(sql_string, "SELECT proptag FROM "
		        "recipients_properties WHERE recipient_id=%llu", LLU(id));
		break;
	case ATTACHMENT_PROPERTIES_TABLE:
		sprintf(sql_string, "SELECT proptag FROM "
		        "attachment_properties WHERE attachment_id=%llu", LLU(id));
		proptags[i++] = PR_RECORD_KEY;
		break;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	b_subject = FALSE;
	while (sqlite3_step(pstmt) == SQLITE_ROW && i < GX_ARRAY_SIZE(proptags)) {
		proptags[i] = sqlite3_column_int64(pstmt, 0);
		if (MESSAGE_PROPERTIES_TABLE == table_type &&
		    proptags[i] == PR_MESSAGE_FLAGS)
			continue;
		if (MESSAGE_PROPERTIES_TABLE == table_type && FALSE == b_subject) {
			if ((proptags[i] == PROP_TAG_NORMALIZEDSUBJECT ||
			    proptags[i] == PROP_TAG_SUBJECTPREFIX) &&
			    i + 1 < GX_ARRAY_SIZE(proptags)) {
				b_subject = TRUE;
				i ++;
				proptags[i] = PROP_TAG_SUBJECT;
			} else if ((proptags[i] == PROP_TAG_NORMALIZEDSUBJECT_STRING8 ||
			    proptags[i] == PROP_TAG_SUBJECTPREFIX_STRING8) &&
			    i + 1 < GX_ARRAY_SIZE(proptags)) {
				b_subject = TRUE;
				i ++;
				proptags[i] = PROP_TAG_SUBJECT_STRING8;
			}
		}
		i ++;
	}
	pstmt.finalize();
	pproptags->count = i;
	pproptags->pproptag = cu_alloc<uint32_t>(i);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, proptags, sizeof(uint32_t)*i);
	return TRUE;
}

static BINARY* common_util_get_mailbox_guid(sqlite3 *psqlite)
{
	GUID tmp_guid;
	char sql_string[128];
	
	sprintf(sql_string, "SELECT config_value "
				"FROM configurations WHERE config_id=%d",
				CONFIG_ID_MAILBOX_GUID);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return NULL;
	if (!guid_from_string(&tmp_guid, S2A(sqlite3_column_text(pstmt, 0)))) {
		return NULL;
	}
	pstmt.finalize();
	auto ptmp_bin = cu_alloc<BINARY>();
	if (NULL == ptmp_bin) {
		return NULL;
	}
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
	
	sprintf(sql_string, "SELECT config_value "
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
	
	sprintf(sql_string, "SELECT replguid FROM "
		"replca_mapping WHERE replid=%d", (int)replid);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		*pb_found = FALSE;
		return TRUE;
	}
	guid_from_string(pguid, S2A(sqlite3_column_text(pstmt, 0)));
	*pb_found = TRUE;
	return TRUE;
}

static uint32_t common_util_calculate_childcount(
	uint32_t folder_id, sqlite3 *psqlite)
{
	uint32_t count;
	char sql_string[80];
	
	count = 0;
	sprintf(sql_string, "SELECT folder_id FROM "
	          "folders WHERE parent_id=%llu", LLU(folder_id));
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
	
	if (TRUE == exmdb_server_check_private()) {
		sprintf(sql_string, "SELECT folder_id FROM "
		          "folders WHERE parent_id=%llu", LLU(folder_id));
	} else {
		sprintf(sql_string, "SELECT folder_id FROM"
			" folders WHERE parent_id=%llu AND is_deleted=0",
			LLU(folder_id));
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW ? TRUE : false;
}

static char* common_util_calculate_folder_path(
	uint32_t folder_id, sqlite3 *psqlite)
{
	int len;
	int len1;
	BOOL b_private;
	uint64_t tmp_fid;
	char sql_string[128], temp_path[4096]{};
	
	len = 0;
	tmp_fid = folder_id;
	b_private = exmdb_server_check_private();
	while (TRUE) {
		sprintf(sql_string, "SELECT propval FROM"
				" folder_properties WHERE proptag=%u AND "
		        "folder_id=%llu", PR_DISPLAY_NAME, LLU(tmp_fid));
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return NULL;
		len1 = sqlite3_column_bytes(pstmt, 0);
		len += len1;
		if (len >= 4096) {
			return NULL;
		}
		memcpy(temp_path + 4095 - len, sqlite3_column_text(pstmt, 0), len1);
		pstmt.finalize();
		len ++;
		temp_path[4095-len] = '\\';
		if ((TRUE == b_private && PRIVATE_FID_ROOT == tmp_fid) ||
			(FALSE == b_private && PUBLIC_FID_ROOT == tmp_fid)) {
			break;
		}
		sprintf(sql_string, "SELECT parent_id FROM "
		          "folders WHERE folder_id=%llu", LLU(tmp_fid));
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
	
	if (0 == g_max_msg) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT "
		"count(message_id) FROM messages");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) >= g_max_msg ? TRUE : false;
}

BOOL cu_check_msgsize_overflow(sqlite3 *psqlite, uint32_t qtag)
{
	uint64_t quota;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[2];
	
	proptags.count = 2;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = qtag;
	proptag_buff[1] = PR_MESSAGE_SIZE_EXTENDED;
	if (FALSE == common_util_get_properties(STORE_PROPERTIES_TABLE,
		0, 0, psqlite, &proptags, &propvals)) {
		return FALSE;
	}
	auto ptotal = static_cast<uint64_t *>(common_util_get_propvals(&propvals, PR_MESSAGE_SIZE_EXTENDED));
	auto pvalue = static_cast<uint32_t *>(common_util_get_propvals(&propvals, qtag));
	if (NULL != ptotal && NULL != pvalue) {
		quota = *(uint32_t*)pvalue;
		quota *= 1024;
		if (*ptotal >= quota) {
			return TRUE;
		}
	}
	return FALSE;
}

static uint32_t common_util_get_store_message_count(
	sqlite3 *psqlite, BOOL b_associated)
{
	char sql_string[64];
	
	if (FALSE == b_associated) {
		sprintf(sql_string, "SELECT count(*)"
				" FROM messages WHERE is_associated=0");
	} else {
		sprintf(sql_string, "SELECT count(*)"
				" FROM messages WHERE is_associated=1");
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

static uint32_t common_util_get_store_article_number(sqlite3 *psqlite)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT config_value "
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
	
	if (TRUE == common_util_get_folder_type(
		psqlite, folder_id, &folder_type) &&
		FOLDER_TYPE_SEARCH == folder_type) {
		snprintf(sql_string, GX_ARRAY_SIZE(sql_string), "SELECT count(*)"
			" FROM messages JOIN search_result ON "
			"search_result.folder_id=%llu AND "
			"search_result.message_id=messages.message_id"
			" AND messages.is_associated=%u",
			LLU(folder_id), !!b_associated);
	} else {
		if (TRUE == exmdb_server_check_private()) {
			snprintf(sql_string, GX_ARRAY_SIZE(sql_string), "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu "
				"AND is_associated=%u", LLU(folder_id), !!b_associated);
		} else {
			snprintf(sql_string, GX_ARRAY_SIZE(sql_string), "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu "
				"AND is_deleted=0 AND is_associated=%u",
				LLU(folder_id), !!b_associated);
		}
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

uint32_t common_util_get_folder_unread_count(
	sqlite3 *psqlite, uint64_t folder_id)
{
	uint32_t count;
	uint32_t folder_type;
	char sql_string[256];
	const char *username;
	
	if (TRUE == exmdb_server_check_private()) {
		if (TRUE == common_util_get_folder_type(
			psqlite, folder_id, &folder_type) &&
			FOLDER_TYPE_SEARCH == folder_type) {
			sprintf(sql_string, "SELECT count(*)"
				" FROM messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id AND "
				"messages.read_state=0 AND messages.is_associated=0",
				LLU(folder_id));
		} else {
			sprintf(sql_string, "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu AND "
				"read_state=0 AND is_associated=0", LLU(folder_id));
		}
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
		       sqlite3_column_int64(pstmt, 0);
	}
	username = exmdb_server_get_public_username();
	if (NULL == username) {
		return 0;
	}
	sprintf(sql_string, "SELECT count(*) FROM messages WHERE"
				" parent_fid=%llu AND is_deleted=0 AND is_associated=0",
				LLU(folder_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return 0;
	count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	sprintf(sql_string, "SELECT count(*) FROM read_states"
				" JOIN messages ON read_states.username=?"
				" AND messages.parent_fid=%llu AND "
				"messages.message_id=read_states.message_id"
				" AND messages.is_associated=0", LLU(folder_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	return sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       count - sqlite3_column_int64(pstmt, 0);
}

static uint64_t common_util_get_folder_message_size(
	sqlite3 *psqlite, uint64_t folder_id, BOOL b_normal,
	BOOL b_associated)
{
	uint32_t folder_type;
	char sql_string[256];
	
	if (TRUE == common_util_get_folder_type(
		psqlite, folder_id, &folder_type) &&
		FOLDER_TYPE_SEARCH == folder_type) {
		if (TRUE == b_normal && TRUE == b_associated) {
			sprintf(sql_string, "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id",
				LLU(folder_id));
		} else if (TRUE == b_normal) {
			sprintf(sql_string, "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id"
				" AND messages.is_associated=0", LLU(folder_id));
		} else if (TRUE == b_associated) {
			sprintf(sql_string, "SELECT "
				"sum(messages.message_size) FROM "
				"messages JOIN search_result ON "
				"search_result.folder_id=%llu AND "
				"search_result.message_id=messages.message_id"
				" AND messages.is_associated=1", LLU(folder_id));
		} else {
			return 0;
		}
	} else {
		if (TRUE == b_normal && TRUE == b_associated) {
			sprintf(sql_string, "SELECT sum(message_size) "
			          "FROM messages WHERE parent_fid=%llu", LLU(folder_id));
		} else if (TRUE == b_normal) {
			sprintf(sql_string, "SELECT sum(message_size) "
						"FROM messages WHERE parent_fid=%llu AND "
						"is_associated=0", LLU(folder_id));
						
		} else if (TRUE == b_associated) {
			sprintf(sql_string, "SELECT sum(message_size) "
						"FROM messages WHERE parent_fid=%llu AND "
						"is_associated=1", LLU(folder_id));
		} else {
			return 0;
		}
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       gx_sql_col_uint64(pstmt, 0);
}

BOOL common_util_get_folder_type(sqlite3 *psqlite, uint64_t folder_id,
    uint32_t *pfolder_type, const char *dir)
{
	char sql_string[128];
	
	if (TRUE == exmdb_server_check_private()) {
		if (PRIVATE_FID_ROOT == folder_id) {
			*pfolder_type = FOLDER_TYPE_ROOT;
			return TRUE;
		}
		sprintf(sql_string, "SELECT is_search "
		          "FROM folders WHERE folder_id=%llu", LLU(folder_id));
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			fprintf(stderr, "W-1299: folder_type of %s:%llxh indeterminate, possible db corruption\n",
			        dir != nullptr ? dir : "", static_cast<unsigned long long>(folder_id));
			return FALSE;
		}
		*pfolder_type = sqlite3_column_int64(pstmt, 0) == 0 ? FOLDER_TYPE_GENERIC : FOLDER_TYPE_SEARCH;
	} else {
		*pfolder_type = folder_id == PUBLIC_FID_ROOT ? FOLDER_TYPE_ROOT : FOLDER_TYPE_GENERIC;
	}
	return TRUE;
}

static BOOL common_util_check_folder_rules(
	sqlite3 *psqlite, uint64_t folder_id)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT count(*) FROM "
	          "rules WHERE folder_id=%llu", LLU(folder_id));
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
	if (TRUE == common_util_get_folder_type(
		psqlite, folder_id, &folder_type)) {
		if (FOLDER_TYPE_SEARCH == folder_type) {
			folder_flags |= FOLDER_FLAGS_SEARCH;
		} else {
			folder_flags |= FOLDER_FLAGS_NORMAL;
		}
	}
	if (TRUE == common_util_check_folder_rules(
		psqlite, folder_id)) {
		folder_flags |= FOLDER_FLAGS_RULES;
	}
	if (TRUE == exmdb_server_check_private()) {
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
	
	sprintf(sql_string, "SELECT message_size FROM "
	          "messages WHERE message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

uint64_t common_util_get_folder_parent_fid(
	sqlite3 *psqlite, uint64_t folder_id)
{
	uint64_t parent_fid;
	char sql_string[128];
	
	sprintf(sql_string, "SELECT parent_id FROM "
	          "folders WHERE folder_id=%llu", LLU(folder_id));
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
	
	sprintf(sql_string, "SELECT change_number FROM "
	          "folders WHERE folder_id=%llu", LLU(folder_id));
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
	
	sprintf(sql_string, "SELECT folder_id "
	          "FROM folders WHERE parent_id=%llu", LLU(parent_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sprintf(sql_string, "SELECT propval "
		"FROM folder_properties WHERE folder_id=?"
	        " AND proptag=%u", PR_DISPLAY_NAME);
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr) {
		return FALSE;
	}
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

static BINARY* common_util_to_folder_entryid(
	sqlite3 *psqlite, uint64_t folder_id)
{
	BOOL b_found;
	int account_id;
	uint16_t replid;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	account_id = exmdb_server_get_account_id();
	if (account_id < 0) {
		return NULL;
	}
	tmp_entryid.flags = 0;
	if (TRUE == exmdb_server_check_private()) {
		auto pbin = common_util_get_mailbox_guid(psqlite);
		if (NULL == pbin) {
			return NULL;
		}
		memcpy(tmp_entryid.provider_uid, pbin->pb, 16);
		tmp_entryid.database_guid =
			rop_util_make_user_guid(account_id);
		tmp_entryid.folder_type = EITLT_PRIVATE_FOLDER;
	} else {
		rop_util_get_provider_uid(PROVIDER_UID_PUBLIC,
							tmp_entryid.provider_uid);
		replid = folder_id >> 48;
		if (0 != replid) {
			if (FALSE == common_util_get_mapping_guid(psqlite,
				replid, &b_found, &tmp_entryid.database_guid)
				|| FALSE == b_found) {
				return NULL;	
			}
		} else {
			tmp_entryid.database_guid =
				rop_util_make_domain_guid(account_id);
		}
		tmp_entryid.folder_type = EITLT_PUBLIC_FOLDER;
	}
	rop_util_value_to_gc(folder_id, tmp_entryid.global_counter);
	tmp_entryid.pad[0] = 0;
	tmp_entryid.pad[1] = 0;
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pv, 256, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != ext_buffer_push_folder_entryid(
		&ext_push, &tmp_entryid)) {
		return NULL;	
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

static BINARY* common_util_to_message_entryid(
	sqlite3 *psqlite, uint64_t message_id)
{
	BINARY *pbin;
	int account_id;
	EXT_PUSH ext_push;
	uint64_t folder_id;
	MESSAGE_ENTRYID tmp_entryid;
	
	if (FALSE == common_util_get_message_parent_folder(
		psqlite, message_id, &folder_id)) {
		return NULL;	
	}
	account_id = exmdb_server_get_account_id();
	if (account_id < 0) {
		return NULL;
	}
	tmp_entryid.flags = 0;
	if (TRUE == exmdb_server_check_private()) {
		pbin = common_util_get_mailbox_guid(psqlite);
		if (NULL == pbin) {
			return NULL;
		}
		memcpy(tmp_entryid.provider_uid, pbin->pb, 16);
		tmp_entryid.folder_database_guid =
			rop_util_make_user_guid(account_id);
		tmp_entryid.message_type = EITLT_PRIVATE_MESSAGE;
	} else {
		rop_util_get_provider_uid(PROVIDER_UID_PUBLIC,
							tmp_entryid.provider_uid);
		tmp_entryid.folder_database_guid =
			rop_util_make_domain_guid(account_id);
		tmp_entryid.message_type = EITLT_PUBLIC_MESSAGE;
	}
	tmp_entryid.message_database_guid = tmp_entryid.folder_database_guid;
	rop_util_value_to_gc(folder_id, tmp_entryid.folder_global_counter);
	rop_util_value_to_gc(message_id, tmp_entryid.message_global_counter);
	tmp_entryid.pad1[0] = 0;
	tmp_entryid.pad1[1] = 0;
	tmp_entryid.pad2[0] = 0;
	tmp_entryid.pad2[1] = 0;
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pv, 256, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != ext_buffer_push_message_entryid(
		&ext_push, &tmp_entryid)) {
		return NULL;	
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

BOOL common_util_check_message_associated(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT is_associated FROM "
	          "messages WHERE message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static BOOL common_util_check_message_named_properties(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT proptag"
				" FROM message_properties WHERE "
				"message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (0x8000 & sqlite3_column_int64(pstmt, 0)) {
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL common_util_check_message_has_attachments(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT count(*) FROM "
	          "attachments WHERE message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static BOOL common_util_check_message_read(
	sqlite3 *psqlite, uint64_t message_id)
{
	char sql_string[128];
	const char *username;
	
	if (FALSE == exmdb_server_check_private()) {
		username = exmdb_server_get_public_username();
		if (NULL == username) {
			return FALSE;
		}
		sprintf(sql_string, "SELECT message_id"
				" FROM read_states WHERE username=? AND "
				"message_id=%llu", LLU(message_id));
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		return sqlite3_step(pstmt) == SQLITE_ROW ? TRUE : false;
	}
	sprintf(sql_string, "SELECT read_state FROM "
	          "messages WHERE message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	return pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW &&
	       sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
}

static uint64_t common_util_get_message_changenum(
	sqlite3 *psqlite, uint64_t message_id)
{
	uint64_t change_num;
	char sql_string[128];
	
	sprintf(sql_string, "SELECT change_number FROM "
	          "messages WHERE message_id=%llu", LLU(message_id));
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
	char sql_string[128];
	
	auto pstmt = common_util_get_optimize_stmt(MESSAGE_PROPERTIES_TABLE, TRUE);
	xstmt own_stmt;
	if (NULL != pstmt) {
		sqlite3_reset(pstmt);
	} else {
		sprintf(sql_string, "SELECT propval "
			"FROM message_properties WHERE message_id=?"
			" AND proptag=?");
		own_stmt = gx_sql_prep(psqlite, sql_string);
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
	if (FALSE == b_native) {
		if (TRUE == common_util_check_message_read(
			psqlite, message_id)) {
			message_flags |= MSGFLAG_READ;
		}
		if (TRUE == common_util_check_message_has_attachments(
			psqlite, message_id)) {
			message_flags |= MSGFLAG_HASATTACH;
		}
		if (TRUE == common_util_check_message_associated(
			psqlite, message_id)) {
			message_flags |= MSGFLAG_ASSOCIATED;
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, PROP_TAG_READRECEIPTREQUESTED);
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			if (0 != sqlite3_column_int64(pstmt, 0)) {
				message_flags |= MSGFLAG_RN_PENDING;
			}
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2,
			PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED);
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			if (0 != sqlite3_column_int64(pstmt, 0)) {
				message_flags |= MSGFLAG_NRN_PENDING;
			}
		}
	}
	own_stmt.finalize();
	*ppmessage_flags = cu_alloc<uint32_t>();
	if (NULL == *ppmessage_flags) {
		return FALSE;
	}
	**ppmessage_flags = message_flags;
	return TRUE;
}

static void* common_util_get_message_parent_display(
	sqlite3 *psqlite, uint64_t message_id)
{
	void *pvalue;
	uint64_t folder_id;
	
	if (FALSE == common_util_get_message_parent_folder(
		psqlite, message_id, &folder_id)) {
		return NULL;	
	}
	if (!common_util_get_property(FOLDER_PROPERTIES_TABLE, folder_id, 0,
	    psqlite, PR_DISPLAY_NAME, &pvalue))
		return NULL;	
	return pvalue;
}

static BOOL common_util_get_message_subject(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppvalue)
{
	char *pvalue;
	char sql_string[128];
	const char *psubject_prefix, *pnormalized_subject;
	
	psubject_prefix = NULL;
	pnormalized_subject = NULL;
	auto pstmt = common_util_get_optimize_stmt(MESSAGE_PROPERTIES_TABLE, TRUE);
	xstmt own_stmt;
	if (NULL != pstmt) {
		sqlite3_reset(pstmt);
	} else {
		sprintf(sql_string, "SELECT propval "
			"FROM message_properties WHERE message_id=?"
			" AND proptag=?");
		own_stmt = gx_sql_prep(psqlite, sql_string);
		if (own_stmt == nullptr)
			return FALSE;
		pstmt = own_stmt;
	}
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_NORMALIZEDSUBJECT);
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		pnormalized_subject = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
		if (NULL == pnormalized_subject) {
			return FALSE;
		}
	} else {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2,
			PROP_TAG_NORMALIZEDSUBJECT_STRING8);
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			pnormalized_subject =
				common_util_convert_copy(TRUE, cpid,
				S2A(sqlite3_column_text(pstmt, 0)));
		}
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_SUBJECTPREFIX);
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		psubject_prefix = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
		if (NULL == psubject_prefix) {
			return FALSE;
		}
	} else {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		sqlite3_bind_int64(pstmt, 2, 
			PROP_TAG_SUBJECTPREFIX_STRING8);
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			psubject_prefix =
				common_util_convert_copy(TRUE, cpid,
				S2A(sqlite3_column_text(pstmt, 0)));
		}
	}
	own_stmt.finalize();
	if (NULL == pnormalized_subject) {
		pnormalized_subject = "";
	}
	if (NULL == psubject_prefix) {
		psubject_prefix = "";
	}
	pvalue = cu_alloc<char>(strlen(pnormalized_subject) + strlen(psubject_prefix) + 1);
	if (NULL == pvalue) {
		return FALSE;
	}
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
		recipient_type = RECIPIENT_TYPE_TO;
		break;
	case PR_DISPLAY_CC:
	case PR_DISPLAY_CC_A:
		recipient_type = RECIPIENT_TYPE_CC;
		break;
	case PR_DISPLAY_BCC:
	case PR_DISPLAY_BCC_A:
		recipient_type = RECIPIENT_TYPE_BCC;
		break;
	}
	sprintf(sql_string, "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	offset = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		rcpt_id = sqlite3_column_int64(pstmt, 0);
		if (FALSE == common_util_get_property(
			RECIPIENT_PROPERTIES_TABLE, rcpt_id, 0,
			psqlite, PROP_TAG_RECIPIENTTYPE, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue || *(uint32_t*)pvalue != recipient_type) {
			continue;
		}
		if (!common_util_get_property(RECIPIENT_PROPERTIES_TABLE,
		    rcpt_id, cpid, psqlite, PR_DISPLAY_NAME, &pvalue))
			return FALSE;	
		if (NULL == pvalue) {
			if (!common_util_get_property(RECIPIENT_PROPERTIES_TABLE,
			    rcpt_id, cpid, psqlite, PR_SMTP_ADDRESS, &pvalue))
				return FALSE;	
		}
		if (NULL == pvalue) {
			continue;
		}
		if (0 == offset) {
			offset = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s",
			         static_cast<const char *>(pvalue));
		} else {
			offset += gx_snprintf(tmp_buff + offset,
			          GX_ARRAY_SIZE(tmp_buff) - offset, "; %s",
			          static_cast<const char *>(pvalue));
		}
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

static void *common_util_get_message_body(sqlite3 *psqlite,
	uint32_t cpid, uint64_t message_id, uint32_t proptag)
{
	uint64_t cid;
	char path[256];
	const char *dir;
	uint32_t proptag1;
	char sql_string[256];
	struct stat node_stat;
	
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return NULL;
	}
	if (proptag != PR_BODY && proptag != PR_BODY_A)
		return NULL;
	sprintf(sql_string, "SELECT proptag, propval "
		"FROM message_properties WHERE (message_id=%llu AND"
		" proptag=%u) OR (message_id=%llu AND proptag=%u)",
		LLU(message_id), PR_BODY,
		LLU(message_id), PR_BODY_A);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return nullptr;
	proptag1 = sqlite3_column_int64(pstmt, 0);
	cid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	wrapfd fd = open(path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
		return nullptr;
	auto pbuff = cu_alloc<char>(node_stat.st_size + 1);
	if (NULL == pbuff) {
		return NULL;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size)
		return NULL;
	pbuff[node_stat.st_size] = 0;
	if (proptag1 == PR_BODY)
		pbuff += sizeof(int);
	if (proptag == proptag1) {
		return pbuff;
	}
	if (PROP_TYPE(proptag) == PT_STRING8)
		return common_util_convert_copy(TRUE, cpid, static_cast<char *>(pbuff));
	else
		return common_util_convert_copy(FALSE, cpid, static_cast<char *>(pbuff));
}

static void *common_util_get_message_header(sqlite3 *psqlite,
	uint32_t cpid, uint64_t message_id, uint32_t proptag)
{
	uint64_t cid;
	char path[256];
	const char *dir;
	uint32_t proptag1;
	char sql_string[256];
	struct stat node_stat;
	
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return NULL;
	}
	if (PROP_TAG_TRANSPORTMESSAGEHEADERS != proptag &&
		PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8 != proptag) {
		return NULL;
	}
	sprintf(sql_string, "SELECT proptag, propval "
		"FROM message_properties WHERE (message_id=%llu AND"
		" proptag=%u) OR (message_id=%llu AND proptag=%u)",
		LLU(message_id), PROP_TAG_TRANSPORTMESSAGEHEADERS,
		LLU(message_id), PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return nullptr;
	proptag1 = sqlite3_column_int64(pstmt, 0);
	cid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	wrapfd fd = open(path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
		return nullptr;
	auto pbuff = cu_alloc<char>(node_stat.st_size + 1);
	if (NULL == pbuff) {
		return NULL;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size) 
		return NULL;
	pbuff[node_stat.st_size] = 0;
	if (PROP_TAG_TRANSPORTMESSAGEHEADERS == proptag1) {
		pbuff += sizeof(int);
	}
	if (proptag == proptag1) {
		return pbuff;
	}
	if (PROP_TYPE(proptag) == PT_STRING8)
		return common_util_convert_copy(TRUE, cpid, static_cast<char *>(pbuff));
	else
		return common_util_convert_copy(FALSE, cpid, static_cast<char *>(pbuff));
}

static void* common_util_get_message_cid_value(
	sqlite3 *psqlite, uint64_t message_id, uint32_t proptag)
{
	void *pbuff;
	uint64_t cid;
	BINARY *pbin;
	char path[256];
	const char *dir;
	char sql_string[256];
	struct stat node_stat;
	
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return NULL;
	}
	if (PROP_TAG_HTML != proptag && PROP_TAG_RTFCOMPRESSED != proptag) {
		return NULL;
	}
	sprintf(sql_string, "SELECT propval FROM "
		"message_properties WHERE message_id=%llu AND "
		"proptag=%u", LLU(message_id), UI(proptag));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return nullptr;
	cid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	wrapfd fd = open(path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
		return nullptr;
	pbuff = common_util_alloc(node_stat.st_size);
	if (NULL == pbuff) {
		return NULL;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size)
		return NULL;
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = node_stat.st_size;
	pbin->pv = pbuff;
	return pbin;
}

static void* common_util_get_attachment_cid_value(sqlite3 *psqlite,
	uint64_t attachment_id, uint32_t proptag)
{
	void *pbuff;
	uint64_t cid;
	BINARY *pbin;
	char path[256];
	const char *dir;
	char sql_string[256];
	struct stat node_stat;
	
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return NULL;
	}
	if (proptag != PR_ATTACH_DATA_BIN && proptag != PR_ATTACH_DATA_OBJ)
		return NULL;
	sprintf(sql_string, "SELECT propval FROM "
		"attachment_properties WHERE attachment_id=%llu"
		" AND proptag=%u", LLU(attachment_id), UI(proptag));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return nullptr;
	cid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	wrapfd fd = open(path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
		return nullptr;
	pbuff = common_util_alloc(node_stat.st_size);
	if (NULL == pbuff) {
		return NULL;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size)
		return NULL;
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = node_stat.st_size;
	pbin->pv = pbuff;
	return pbin;
}

BOOL common_util_get_property(int table_type, uint64_t id,
	uint32_t cpid, sqlite3 *psqlite, uint32_t proptag,
	void **ppvalue)
{
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	
	proptags.count = 1;
	proptags.pproptag = &proptag;
	if (FALSE == common_util_get_properties(table_type,
		id, cpid, psqlite, &proptags, &propvals)) {
		return FALSE;
	}
	*ppvalue = propvals.count == 0 ? nullptr : propvals.ppropval[0].pvalue;
	return TRUE;
}

namespace {
enum GP_RESULT { GP_ADV, GP_UNHANDLED, GP_SKIP, GP_ERR };
}

static GP_RESULT gp_storeprop(uint32_t tag, TAGGED_PROPVAL &pv, sqlite3 *db)
{
	pv.proptag = tag;
	switch (tag) {
	case PR_STORE_RECORD_KEY:
		pv.pvalue = common_util_get_mailbox_guid(db);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	case PR_STORE_STATE:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_store_state(db);
		return GP_ADV;
	case PROP_TAG_CONTENTCOUNT:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_store_message_count(db, false);
		return GP_ADV;
	case PROP_TAG_ASSOCIATEDCONTENTCOUNT:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_store_message_count(db, TRUE);
		return GP_ADV;
	case PROP_TAG_INTERNETARTICLENUMBER:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_store_article_number(db);
		return GP_ADV;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_folderprop(uint32_t tag, TAGGED_PROPVAL &pv,
    sqlite3 *db, uint64_t id)
{
	pv.proptag = tag;
	switch (tag) {
	case PR_ENTRYID:
		pv.pvalue = common_util_to_folder_entryid(db, id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	case PROP_TAG_FOLDERID:
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) =
			(id & 0xFF00000000000000ULL) == 0 ?
			rop_util_make_eid_ex(1, id) :
			rop_util_make_eid_ex(id >> 48, id & 0x00FFFFFFFFFFFFFFULL);
		return GP_ADV;
	case PROP_TAG_PARENTFOLDERID: {
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		auto tmp_id = common_util_get_folder_parent_fid(db, id);
		if (tmp_id == 0)
			return GP_SKIP;
		*static_cast<uint64_t *>(pv.pvalue) = rop_util_make_eid_ex(1, tmp_id);
		return GP_ADV;
	}
	case PR_PARENT_ENTRYID: {
		auto tmp_id = common_util_get_folder_parent_fid(db, id);
		if (tmp_id == 0)
			return GP_SKIP;
		pv.pvalue = common_util_to_folder_entryid(db, tmp_id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	}
	case PROP_TAG_CHANGENUMBER:
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) = common_util_get_folder_changenum(db, id);
		return GP_ADV;
	case PROP_TAG_FOLDERFLAGS:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_folder_flags(db, id);
		return GP_ADV;
	case PROP_TAG_SUBFOLDERS:
		pv.pvalue = cu_alloc<uint8_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint8_t *>(pv.pvalue) = !!common_util_check_subfolders(db, id);
		return GP_ADV;
	case PROP_TAG_CONTENTCOUNT:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_folder_count(db, id, false);
		return GP_ADV;
	case PROP_TAG_ASSOCIATEDCONTENTCOUNT:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_folder_count(db, id, TRUE);
		return GP_ADV;
	case PROP_TAG_FOLDERCHILDCOUNT:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_calculate_childcount(id, db);
		return GP_ADV;
	case PROP_TAG_CONTENTUNREADCOUNT:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_folder_unread_count(db, id);
		return GP_ADV;
	case PROP_TAG_FOLDERTYPE:
		pv.pvalue = cu_alloc<uint32_t>();
		return pv.pvalue != nullptr && common_util_get_folder_type(db,
		       id, static_cast<uint32_t *>(pv.pvalue)) ? GP_ADV : GP_ERR;
	case PROP_TAG_HASRULES:
		pv.pvalue = cu_alloc<uint8_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint8_t *>(pv.pvalue) = !!common_util_check_folder_rules(db, id);
		return GP_ADV;
	case PROP_TAG_FOLDERPATHNAME:
		pv.pvalue = common_util_calculate_folder_path(id, db);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	case PR_MESSAGE_SIZE_EXTENDED:
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) = common_util_get_folder_message_size(db, id, TRUE, TRUE);
		return GP_ADV;
	case PROP_TAG_ASSOCMESSAGESIZEEXTENDED:
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) = common_util_get_folder_message_size(db, id, false, TRUE);
		return GP_ADV;
	case PROP_TAG_NORMALMESSAGESIZEEXTENDED:
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) = common_util_get_folder_message_size(db, id, TRUE, false);
		return GP_ADV;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_msgprop(uint32_t tag, TAGGED_PROPVAL &pv, sqlite3 *db,
    uint64_t id, uint32_t cpid)
{
	pv.proptag = tag;
	switch (tag) {
	case PR_ENTRYID:
		pv.pvalue = common_util_to_message_entryid(db, id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	case PR_PARENT_ENTRYID: {
		uint64_t tmp_id;
		if (!common_util_get_message_parent_folder(db, id, &tmp_id) || tmp_id == 0)
			return GP_ERR;
		pv.pvalue = common_util_to_folder_entryid(db, tmp_id);
		return pv.pvalue != nullptr ? GP_ADV : GP_ERR;
	}
	case PROP_TAG_FOLDERID:
	case PROP_TAG_PARENTFOLDERID: {
		uint64_t tmp_id;
		if (!common_util_get_message_parent_folder(db, id, &tmp_id) || tmp_id == 0)
			return GP_ERR;
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) = rop_util_make_eid_ex(1, tmp_id);
		return GP_ADV;
	}
	case PROP_TAG_INSTANCESVREID: {
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
	case PR_MESSAGE_SIZE:
		pv.pvalue = cu_alloc<uint32_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint32_t *>(pv.pvalue) = common_util_get_message_size(db, id);
		return GP_ADV;
	case PROP_TAG_ASSOCIATED:
		pv.pvalue = cu_alloc<uint8_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint8_t *>(pv.pvalue) = !!common_util_check_message_associated(db, id);
		return GP_ADV;
	case PROP_TAG_CHANGENUMBER:
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) = common_util_get_message_changenum(db, id);
		return GP_ADV;
	case PR_READ:
		pv.pvalue = cu_alloc<uint8_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint8_t *>(pv.pvalue) = !!common_util_check_message_read(db, id);
		return GP_ADV;
	case PROP_TAG_HASNAMEDPROPERTIES:
		pv.pvalue = cu_alloc<uint8_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint8_t *>(pv.pvalue) = !!common_util_check_message_named_properties(db, id);
		return GP_ADV;
	case PROP_TAG_HASATTACHMENTS:
		pv.pvalue = cu_alloc<uint8_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint8_t *>(pv.pvalue) = !!common_util_check_message_has_attachments(db, id);
		return GP_ADV;
	case PROP_TAG_MID:
		pv.pvalue = cu_alloc<uint64_t>();
		if (pv.pvalue == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(pv.pvalue) = rop_util_make_eid_ex(1, id);
		return GP_ADV;
	case PR_MESSAGE_FLAGS:
		if (!common_util_get_message_flags(db, id, false,
		    reinterpret_cast<uint32_t **>(&pv.pvalue)))
			return GP_ERR;
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PROP_TAG_SUBJECT:
	case PROP_TAG_SUBJECT_STRING8:
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
		pv.pvalue = common_util_get_message_body(db, cpid, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PROP_TAG_HTML:
	case PROP_TAG_RTFCOMPRESSED:
		pv.pvalue = common_util_get_message_cid_value(db, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PROP_TAG_TRANSPORTMESSAGEHEADERS:
	case PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
		pv.pvalue = common_util_get_message_header(db, cpid, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	case PROP_TAG_MIDSTRING: /* self-defined proptag */
		return common_util_get_mid_string(db, id, reinterpret_cast<char **>(&pv.pvalue)) &&
		       pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_atxprop(uint32_t tag, TAGGED_PROPVAL &pv,
    sqlite3 *db, uint64_t id)
{
	pv.proptag = tag;
	switch (tag) {
	case PR_RECORD_KEY: {
		auto ptmp_bin = cu_alloc<BINARY>();
		if (ptmp_bin == nullptr)
			return GP_ERR;
		ptmp_bin->cb = sizeof(uint64_t);
		ptmp_bin->pv = common_util_alloc(ptmp_bin->cb);
		if (ptmp_bin->pv == nullptr)
			return GP_ERR;
		*static_cast<uint64_t *>(ptmp_bin->pv) = id;
		pv.pvalue = ptmp_bin;
		return GP_ADV;
	}
	case PR_ATTACH_DATA_BIN:
	case PR_ATTACH_DATA_OBJ:
		pv.pvalue = common_util_get_attachment_cid_value(db, id, tag);
		return pv.pvalue != nullptr ? GP_ADV : GP_SKIP;
	}
	return GP_UNHANDLED;
}

static GP_RESULT gp_spectableprop(unsigned int table_type, uint32_t tag,
    TAGGED_PROPVAL &pv, sqlite3 *db, uint64_t id, uint32_t cpid)
{
	switch (table_type) {
	case STORE_PROPERTIES_TABLE:
		return gp_storeprop(tag, pv, db);
	case FOLDER_PROPERTIES_TABLE:
		return gp_folderprop(tag, pv, db, id);
	case MESSAGE_PROPERTIES_TABLE:
		return gp_msgprop(tag, pv, db, id, cpid);
	case RECIPIENT_PROPERTIES_TABLE:
		return GP_UNHANDLED;
	case ATTACHMENT_PROPERTIES_TABLE:
		return gp_atxprop(tag, pv, db, id);
	default:
		return GP_UNHANDLED;
	}
}

BOOL common_util_get_properties(int table_type,
	uint64_t id, uint32_t cpid, sqlite3 *psqlite,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	void *pvalue;
	char *pstring;
	uint32_t proptag;
	uint16_t proptype;
	EXT_PULL ext_pull;
	sqlite3_stmt *pstmt = nullptr;
	char sql_string[256];
	TYPED_PROPVAL *ptyped;
	
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	for (size_t i = 0; i < pproptags->count; ++i) {
		if (PROP_TYPE(pproptags->pproptag[i]) == PT_OBJECT &&
		    (table_type != ATTACHMENT_PROPERTIES_TABLE ||
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
		proptype = PROP_TYPE(pproptags->pproptag[i]);
		if (proptype == PT_UNSPECIFIED || proptype == PT_STRING8 ||
		    proptype == PT_UNICODE) {
			switch (table_type) {
			case STORE_PROPERTIES_TABLE:
				sprintf(sql_string, "SELECT proptag, propval"
							" FROM store_properties WHERE proptag=?");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE));
				break;
			case FOLDER_PROPERTIES_TABLE:
				sprintf(sql_string, "SELECT proptag,"
						" propval FROM folder_properties WHERE"
						" folder_id=? AND proptag=?");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE));
				break;
			case MESSAGE_PROPERTIES_TABLE:
				pstmt = common_util_get_optimize_stmt(table_type, FALSE);
				if (NULL != pstmt) {
					sqlite3_reset(pstmt);
				} else {
					sprintf(sql_string, "SELECT proptag, "
							"propval FROM message_properties WHERE "
							"message_id=? AND (proptag=? OR proptag=?)");
					own_stmt = gx_sql_prep(psqlite, sql_string);
					if (own_stmt == nullptr)
						return FALSE;
					pstmt = own_stmt;
				}
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE));
				sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8));
				break;
			case RECIPIENT_PROPERTIES_TABLE:
				pstmt = common_util_get_optimize_stmt(table_type, FALSE);
				if (NULL != pstmt) {
					sqlite3_reset(pstmt);
				} else {
					sprintf(sql_string, "SELECT proptag,"
						" propval FROM recipients_properties WHERE"
						" recipient_id=? AND (proptag=? OR proptag=?)");
					own_stmt = gx_sql_prep(psqlite, sql_string);
					if (own_stmt == nullptr)
						return FALSE;
					pstmt = own_stmt;
				}
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE));
				sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8));
				break;
			case ATTACHMENT_PROPERTIES_TABLE:
				sprintf(sql_string, "SELECT proptag, propval"
					" FROM attachment_properties WHERE attachment_id=?"
					" AND (proptag=? OR proptag=?)");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE));
				sqlite3_bind_int64(pstmt, 3, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8));
				break;
			}
		} else if (proptype == PT_MV_STRING8) {
			switch (table_type) {
			case STORE_PROPERTIES_TABLE:
				sprintf(sql_string, "SELECT propval"
					" FROM store_properties WHERE proptag=?");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE));
				break;
			case FOLDER_PROPERTIES_TABLE:
				sprintf(sql_string, "SELECT propval "
					"FROM folder_properties WHERE folder_id=? "
					"AND proptag=?)");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE));
				break;
			case MESSAGE_PROPERTIES_TABLE:
				pstmt = common_util_get_optimize_stmt(table_type, TRUE);
				if (NULL != pstmt) {
					sqlite3_reset(pstmt);
				} else {
					sprintf(sql_string, "SELECT propval"
								" FROM message_properties WHERE "
								"message_id=? AND proptag=?");
					own_stmt = gx_sql_prep(psqlite, sql_string);
					if (own_stmt == nullptr)
						return FALSE;
					pstmt = own_stmt;
				}
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE));
				break;
			case RECIPIENT_PROPERTIES_TABLE:
				pstmt = common_util_get_optimize_stmt(table_type, TRUE);
				if (NULL != pstmt) {
					sqlite3_reset(pstmt);
				} else {
					sprintf(sql_string, "SELECT propval "
								"FROM recipients_properties WHERE "
								"recipient_id=? AND proptag=?");
					own_stmt = gx_sql_prep(psqlite, sql_string);
					if (own_stmt == nullptr)
						return FALSE;
					pstmt = own_stmt;
				}
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE));
				break;
			case ATTACHMENT_PROPERTIES_TABLE:
				sprintf(sql_string, "SELECT propval "
							"FROM attachment_properties WHERE "
							"attachment_id=? AND proptag=?");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE));
				break;
			}
		} else {
			switch (table_type) {
			case STORE_PROPERTIES_TABLE:
				proptag = pproptags->pproptag[i];
				sprintf(sql_string, "SELECT propval "
					"FROM store_properties WHERE proptag=?");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, proptag);
				break;
			case FOLDER_PROPERTIES_TABLE:
				switch (pproptags->pproptag[i]) {
				case PROP_TAG_LOCALCOMMITTIME:
					proptag = PR_LAST_MODIFICATION_TIME;
					break;
				default:
					proptag = pproptags->pproptag[i];
					break;
				}
				sprintf(sql_string, "SELECT propval FROM "
					"folder_properties WHERE folder_id=? AND proptag=?");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, proptag);
				break;
			case MESSAGE_PROPERTIES_TABLE:
				pstmt = common_util_get_optimize_stmt(table_type, TRUE);
				if (NULL != pstmt) {
					sqlite3_reset(pstmt);
				} else {
					sprintf(sql_string, "SELECT propval"
								" FROM message_properties WHERE "
								"message_id=? AND proptag=?");
					own_stmt = gx_sql_prep(psqlite, sql_string);
					if (own_stmt == nullptr)
						return FALSE;
					pstmt = own_stmt;
				}
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, pproptags->pproptag[i]);
				break;
			case RECIPIENT_PROPERTIES_TABLE:
				pstmt = common_util_get_optimize_stmt(table_type, TRUE);
				if (NULL != pstmt) {
					sqlite3_reset(pstmt);
				} else {
					sprintf(sql_string, "SELECT propval "
								"FROM recipients_properties WHERE "
								"recipient_id=? AND proptag=?");
					own_stmt = gx_sql_prep(psqlite, sql_string);
					if (own_stmt == nullptr)
						return FALSE;
					pstmt = own_stmt;
				}
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, pproptags->pproptag[i]);
				break;
			case ATTACHMENT_PROPERTIES_TABLE:
				sprintf(sql_string, "SELECT propval FROM "
						"attachment_properties WHERE attachment_id=?"
						" AND proptag=?");
				own_stmt = gx_sql_prep(psqlite, sql_string);
				if (own_stmt == nullptr)
					return FALSE;
				pstmt = own_stmt;
				sqlite3_bind_int64(pstmt, 1, id);
				sqlite3_bind_int64(pstmt, 2, pproptags->pproptag[i]);
				break;
			}
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			continue;
		}
		if (proptype == PT_UNSPECIFIED) {
			ptyped = cu_alloc<TYPED_PROPVAL>();
			if (NULL == ptyped) {
				return FALSE;
			}
			ptyped->type = PROP_TYPE(sqlite3_column_int64(pstmt, 0));
			ptyped->pvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 1)));
			if (NULL == ptyped->pvalue) {
				return FALSE;
			}
			pv.proptag = pproptags->pproptag[i];
			pv.pvalue = ptyped;
			ppropvals->count ++;
			continue;
		} else if (proptype == PT_STRING8) {
			if (proptype == PROP_TYPE(sqlite3_column_int64(pstmt, 0)))
				pvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 1)));
			else
				pvalue = common_util_convert_copy(FALSE, cpid,
				         S2A(sqlite3_column_text(pstmt, 1)));
		} else if (proptype == PT_UNICODE) {
			if (proptype == PROP_TYPE(sqlite3_column_int64(pstmt, 0)))
				pvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 1)));
			else
				pvalue = common_util_convert_copy(TRUE, cpid,
				         S2A(sqlite3_column_text(pstmt, 1)));
		} else {
			switch (proptype) {
			case PT_FLOAT:
				pvalue = cu_alloc<float>();
				if (NULL != pvalue) {
					*(float*)pvalue = sqlite3_column_double(pstmt, 0);
				}
				break;
			case PT_DOUBLE:
			case PT_APPTIME:
				pvalue = cu_alloc<double>();
				if (NULL != pvalue) {
					*(double*)pvalue = sqlite3_column_double(pstmt, 0);
				}
				break;
			case PT_CURRENCY:
			case PT_I8:
			case PT_SYSTIME:
				pvalue = cu_alloc<uint64_t>();
				if (NULL != pvalue) {
					*(uint64_t*)pvalue = sqlite3_column_int64(pstmt, 0);
				}
				break;
			case PT_SHORT:
				pvalue = cu_alloc<uint16_t>();
				if (NULL != pvalue) {
					*(uint16_t*)pvalue = sqlite3_column_int64(pstmt, 0);
				}
				break;
			case PT_LONG:
				pvalue = cu_alloc<uint32_t>();
				if (NULL != pvalue) {
					*(uint32_t*)pvalue = sqlite3_column_int64(pstmt, 0);
				}
				break;
			case PT_BOOLEAN:
				pvalue = cu_alloc<uint8_t>();
				if (NULL != pvalue) {
					*(uint8_t*)pvalue = sqlite3_column_int64(pstmt, 0);
				}
				break;
			case PT_CLSID:
				pvalue = cu_alloc<GUID>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_guid(&ext_pull,
					    static_cast<GUID *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_SVREID:
				pvalue = cu_alloc<SVREID>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_svreid(&ext_pull,
					    static_cast<SVREID *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_SRESTRICT:
				pvalue = cu_alloc<RESTRICTION>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_restriction(&ext_pull,
					    static_cast<RESTRICTION *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_ACTIONS:
				pvalue = cu_alloc<RULE_ACTIONS>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_rule_actions(&ext_pull,
					    static_cast<RULE_ACTIONS *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_OBJECT:
			case PT_BINARY: {
				pvalue = cu_alloc<BINARY>();
				auto bv = static_cast<BINARY *>(pvalue);
				if (NULL != pvalue) {
					bv->cb = sqlite3_column_bytes(pstmt, 0);
					bv->pv = common_util_alloc(bv->cb);
					if (bv->pv == nullptr) {
						return FALSE;
					}
					auto blob = sqlite3_column_blob(pstmt, 0);
					if (bv->cb != 0 || blob != nullptr)
						memcpy(bv->pv, blob, bv->cb);
				}
				break;
			}
			case PT_MV_SHORT:
				pvalue = cu_alloc<SHORT_ARRAY>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_short_array(&ext_pull,
					    static_cast<SHORT_ARRAY *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_MV_LONG:
				pvalue = cu_alloc<LONG_ARRAY>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_long_array(&ext_pull,
					    static_cast<LONG_ARRAY *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_MV_I8:
				pvalue = cu_alloc<LONGLONG_ARRAY>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_longlong_array(&ext_pull,
					    static_cast<LONGLONG_ARRAY *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_MV_STRING8:
			case PT_MV_UNICODE: {
				auto sa = cu_alloc<STRING_ARRAY>();
				pvalue = sa;
				if (sa != nullptr) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_wstring_array(&ext_pull, sa) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
					if (proptype == PT_MV_STRING8) {
						for (size_t j = 0; j < sa->count; ++j) {
							pstring = common_util_convert_copy(false, cpid, sa->ppstr[j]);
							if (NULL == pstring) {
								return FALSE;
							}
							sa->ppstr[j] = pstring;
						}
					}
				}
				break;
			}
			case PT_MV_CLSID:
				pvalue = cu_alloc<GUID_ARRAY>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_guid_array(&ext_pull,
					    static_cast<GUID_ARRAY *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			case PT_MV_BINARY:
				pvalue = cu_alloc<BINARY_ARRAY>();
				if (NULL != pvalue) {
					ext_buffer_pull_init(&ext_pull,
						sqlite3_column_blob(pstmt, 0),
						sqlite3_column_bytes(pstmt, 0),
						common_util_alloc, 0);
					if (ext_buffer_pull_binary_array(&ext_pull,
					    static_cast<BINARY_ARRAY *>(pvalue)) != EXT_ERR_SUCCESS) {
						return FALSE;
					}
				}
				break;
			default:
				pvalue = NULL;
				break;
			}
		}
		if (NULL == pvalue) {
			return FALSE;
		}
		pv.proptag = pproptags->pproptag[i];
		pv.pvalue = pvalue;
		ppropvals->count ++;
	}
	return TRUE;
}

static void common_util_set_folder_changenum(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t change_num)
{
	char sql_string[128];
	
	sprintf(sql_string, "UPDATE folders SET change_number=%llu"
	        " WHERE folder_id=%llu", LLU(change_num), LLU(folder_id));
	sqlite3_exec(psqlite, sql_string, NULL, NULL, NULL);
}

static void common_util_set_message_changenum(sqlite3 *psqlite,
	uint64_t message_id, uint64_t change_num)
{
	char sql_string[128];
	
	sprintf(sql_string, "UPDATE messages SET change_number=%llu"
	        " WHERE message_id=%llu", LLU(change_num), LLU(message_id));
	sqlite3_exec(psqlite, sql_string, NULL, NULL, NULL);
}

void common_util_set_message_read(sqlite3 *psqlite,
	uint64_t message_id, uint8_t is_read)
{
	char sql_string[128];
	const char *username;
	
	if (0 != is_read) {
		sprintf(sql_string, "UPDATE message_properties "
			"SET propval=propval|%u WHERE message_id=%llu"
			" AND proptag=%u", MSGFLAG_EVERREAD,
		        LLU(message_id), PR_MESSAGE_FLAGS);
	} else {
		sprintf(sql_string, "UPDATE message_properties "
			"SET propval=propval&(~%u) WHERE message_id=%llu"
			" AND proptag=%u", MSGFLAG_EVERREAD,
		        LLU(message_id), PR_MESSAGE_FLAGS);
	}
	sqlite3_exec(psqlite, sql_string, NULL, NULL, NULL);
	if (TRUE == exmdb_server_check_private()) {
		if (0 == is_read) {
			sprintf(sql_string, "UPDATE messages SET "
				"read_state=0 WHERE message_id=%llu", LLU(message_id));
		} else {
			sprintf(sql_string, "UPDATE messages SET "
				"read_state=1 WHERE message_id=%llu", LLU(message_id));
		}
		sqlite3_exec(psqlite, sql_string, NULL, NULL, NULL);
		return;
	}
	username = exmdb_server_get_public_username();
	if (NULL == username) {
		return;
	}
	if (0 != is_read) {
		sprintf(sql_string, "REPLACE INTO "
			"read_states VALUES (%llu, ?)", LLU(message_id));
	} else {
		sprintf(sql_string, "DELETE FROM "
			"read_states WHERE message_id=%llu AND "
			"username=?", LLU(message_id));
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return;
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	auto ret = sqlite3_step(pstmt);
	if (ret != SQLITE_DONE)
		fprintf(stderr, "W-1274: %s\n", sqlite3_errstr(ret));
}

static BOOL common_util_update_message_cid(sqlite3 *psqlite,
	uint64_t message_id, uint32_t proptag, uint64_t cid)
{
	char sql_string[256];
	
	sprintf(sql_string, "REPLACE INTO message_properties"
	          " VALUES (%llu, %u, ?)", LLU(message_id), UI(proptag));
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
	
	if (PROP_TAG_SUBJECT == ppropval->proptag) {
		sqlite3_bind_int64(pstmt, 1, PROP_TAG_NORMALIZEDSUBJECT);
		sqlite3_bind_text(pstmt, 2, static_cast<char *>(ppropval->pvalue), -1, SQLITE_STATIC);
	} else {
		if (0 != cpid) {
			pstring = common_util_convert_copy(TRUE, cpid, static_cast<char *>(ppropval->pvalue));
			if (NULL == pstring) {
				return FALSE;
			}
			sqlite3_bind_int64(pstmt, 1, PROP_TAG_NORMALIZEDSUBJECT);
			sqlite3_bind_text(pstmt, 2, pstring, -1, SQLITE_STATIC);
		} else {
			sqlite3_bind_int64(pstmt, 1, PROP_TAG_NORMALIZEDSUBJECT_STRING8);
			sqlite3_bind_text(pstmt, 2, static_cast<char *>(ppropval->pvalue), -1, SQLITE_STATIC);
		}
	}
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	return TRUE;
}

static BOOL common_util_set_message_body(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	const TAGGED_PROPVAL *ppropval)
{
	int fd;
	int len;
	uint64_t cid;
	void *pvalue;
	char path[256];
	const char *dir;
	uint32_t proptag;
	
	if (ppropval->proptag == PR_BODY_A) {
		if (0 == cpid) {
			proptag = PR_BODY_A;
			pvalue = ppropval->pvalue;
		} else {
			proptag = PR_BODY;
			pvalue = common_util_convert_copy(TRUE, cpid, static_cast<char *>(ppropval->pvalue));
			if (NULL == pvalue) {
				return FALSE;
			}
		}
	} else if (ppropval->proptag == PR_BODY_W) {
		proptag = PR_BODY_W;
		pvalue = ppropval->pvalue;
	} else {
		return FALSE;
	}
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return FALSE;
	}
	if (FALSE == common_util_allocate_cid(psqlite, &cid)) {
		return FALSE;
	}
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0666);
	if (-1 == fd) {
		return FALSE;
	}
	if (proptag == PR_BODY) {
		if (!utf8_len(static_cast<char *>(pvalue), &len) ||
			sizeof(int) != write(fd, &len, sizeof(int))) {
			close(fd);
			if (remove(path) < 0 && errno != ENOENT)
				fprintf(stderr, "W-1382: remove %s: %s\n", path, strerror(errno));
			return FALSE;
		}
	}
	len = strlen(static_cast<char *>(pvalue)) + 1;
	if (len != write(fd, pvalue, len)) {
		close(fd);
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1383: remove %s: %s\n", path, strerror(errno));
		return FALSE;
	}
	close(fd);
	if (FALSE == common_util_update_message_cid(
		psqlite, message_id, proptag, cid)) {
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1384: remove %s: %s\n", path, strerror(errno));
	}
	return TRUE;
}

static BOOL common_util_set_message_header(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	const TAGGED_PROPVAL *ppropval)
{
	int fd;
	int len;
	uint64_t cid;
	void *pvalue;
	char path[256];
	const char *dir;
	uint32_t proptag;
	
	if (PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8 == ppropval->proptag) {
		if (0 == cpid) {
			proptag = PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8;
			pvalue = ppropval->pvalue;
		} else {
			proptag = PROP_TAG_TRANSPORTMESSAGEHEADERS;
			pvalue = common_util_convert_copy(TRUE, cpid, static_cast<char *>(ppropval->pvalue));
			if (NULL == pvalue) {
				return FALSE;
			}
		}
	} else if (PROP_TAG_TRANSPORTMESSAGEHEADERS == ppropval->proptag) {
		proptag = PROP_TAG_TRANSPORTMESSAGEHEADERS;
		pvalue = ppropval->pvalue;
	} else {
		return FALSE;
	}
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return FALSE;
	}
	if (FALSE == common_util_allocate_cid(psqlite, &cid)) {
		return FALSE;
	}
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0666);
	if (-1 == fd) {
		return FALSE;
	}
	if (PROP_TAG_TRANSPORTMESSAGEHEADERS == proptag) {
		if (!utf8_len(static_cast<char *>(pvalue), &len) ||
			sizeof(int) != write(fd, &len, sizeof(int))) {
			close(fd);
			if (remove(path) < 0 && errno != ENOENT)
				fprintf(stderr, "W-1366: remove %s: %s\n", path, strerror(errno));
			return FALSE;
		}
	}
	len = strlen(static_cast<char *>(pvalue)) + 1;
	if (len != write(fd, pvalue, len)) {
		close(fd);
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1367: remove %s: %s\n", path, strerror(errno));
		return FALSE;
	}
	close(fd);
	if (FALSE == common_util_update_message_cid(
		psqlite, message_id, proptag, cid)) {
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1368: remove %s: %s\n", path, strerror(errno));
	}
	return TRUE;
}

static BOOL common_util_set_message_cid_value(sqlite3 *psqlite,
	uint64_t message_id, const TAGGED_PROPVAL *ppropval)
{
	int fd;
	uint64_t cid;
	char path[256];
	const char *dir;
	
	if (PROP_TAG_HTML != ppropval->proptag &&
		PROP_TAG_RTFCOMPRESSED != ppropval->proptag) {
		return FALSE;
	}
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return FALSE;
	}
	if (FALSE == common_util_allocate_cid(psqlite, &cid)) {
		return FALSE;
	}
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0666);
	if (-1 == fd) {
		return FALSE;
	}
	auto bv = static_cast<BINARY *>(ppropval->pvalue);
	if (write(fd, bv->pv, bv->cb) != bv->cb) {
		close(fd);
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1389: remove %s: %s\n", path, strerror(errno));
		return FALSE;
	}
	close(fd);
	if (FALSE == common_util_update_message_cid(
		psqlite, message_id, ppropval->proptag, cid)) {
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1390: remove %s: %s\n", path, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

static BOOL common_util_update_attachment_cid(sqlite3 *psqlite,
	uint64_t attachment_id, uint32_t proptag, uint64_t cid)
{
	char sql_string[256];
	
	sprintf(sql_string, "REPLACE INTO attachment_properties"
	          " VALUES (%llu, %u, ?)", LLU(attachment_id), UI(proptag));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, cid);
	return sqlite3_step(pstmt) == SQLITE_DONE ? TRUE : false;
}

static BOOL common_util_set_attachment_cid_value(sqlite3 *psqlite,
	uint64_t attachment_id, const TAGGED_PROPVAL *ppropval)
{
	int fd;
	uint64_t cid;
	char path[256];
	const char *dir;
	
	if (ppropval->proptag != PR_ATTACH_DATA_BIN &&
	    ppropval->proptag != PR_ATTACH_DATA_OBJ)
		return FALSE;
	dir = exmdb_server_get_dir();
	if (NULL == dir) {
		return FALSE;
	}
	if (FALSE == common_util_allocate_cid(psqlite, &cid)) {
		return FALSE;
	}
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0666);
	if (-1 == fd) {
		return FALSE;
	}
	auto bv = static_cast<BINARY *>(ppropval->pvalue);
	if (write(fd, bv->pv, bv->cb) != bv->cb) {
		close(fd);
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1363: remove %s: %s\n", path, strerror(errno));
		return FALSE;
	}
	close(fd);
	if (FALSE == common_util_update_attachment_cid(
		psqlite, attachment_id, ppropval->proptag, cid)) {
		if (remove(path) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1364: remove %s: %s\n", path, strerror(errno));
		return FALSE;	
	}
	return TRUE;
}

BOOL common_util_set_property(int table_type,
	uint64_t id, uint32_t cpid, sqlite3 *psqlite,
	const TAGGED_PROPVAL *ppropval, BOOL *pb_result)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	
	if (FALSE == common_util_set_properties(table_type,
		id, cpid, psqlite, &tmp_propvals, &tmp_problems)) {
		return FALSE;
	}
	*pb_result = tmp_problems.count == 1 ? false : TRUE;
	return TRUE;
}

BOOL common_util_set_properties(int table_type,
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
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	switch (table_type) {
	case STORE_PROPERTIES_TABLE:
		sprintf(sql_string, "REPLACE INTO "
					"store_properties VALUES (?, ?)");
		break;
	case FOLDER_PROPERTIES_TABLE:
		sprintf(sql_string, "REPLACE INTO "
		          "folder_properties VALUES (%llu, ?, ?)", LLU(id));
		break;
	case MESSAGE_PROPERTIES_TABLE:
		sprintf(sql_string, "REPLACE INTO "
		          "message_properties VALUES (%llu, ?, ?)", LLU(id));
		break;
	case RECIPIENT_PROPERTIES_TABLE:
		sprintf(sql_string, "REPLACE INTO "
		          "recipients_properties VALUES (%llu, ?, ?)", LLU(id));
		break;
	case ATTACHMENT_PROPERTIES_TABLE:
		sprintf(sql_string, "REPLACE INTO "
		          "attachment_properties VALUES (%llu, ?, ?)", LLU(id));
		break;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (size_t i = 0; i < ppropvals->count; ++i) {
		if (PROP_TYPE(ppropvals->ppropval[i].proptag) == PT_OBJECT &&
		    (table_type != ATTACHMENT_PROPERTIES_TABLE ||
		    ppropvals->ppropval[i].proptag != PR_ATTACH_DATA_OBJ)) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count].err = ecError;
			pproblems->count ++;
			continue;
		}
		switch (table_type) {
		case STORE_PROPERTIES_TABLE:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_STORE_STATE:
			case PR_MESSAGE_SIZE:
			case PROP_TAG_CONTENTCOUNT:
			case PR_STORE_RECORD_KEY:
			case PROP_TAG_ASSOCMESSAGESIZE:
			case PR_NORMAL_MESSAGE_SIZE:
			case PR_MESSAGE_SIZE_EXTENDED:
			case PROP_TAG_INTERNETARTICLENUMBER:
			case PROP_TAG_ASSOCIATEDCONTENTCOUNT:
			case PROP_TAG_ASSOCMESSAGESIZEEXTENDED:
			case PROP_TAG_NORMALMESSAGESIZEEXTENDED:
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count].err = ecAccessDenied;
				pproblems->count ++;
				continue;
			}
			break;
		case FOLDER_PROPERTIES_TABLE:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_ENTRYID:
			case PROP_TAG_FOLDERID:
			case PROP_TAG_PARENTFOLDERID:
			case PROP_TAG_FOLDERFLAGS:
			case PROP_TAG_SUBFOLDERS:
			case PROP_TAG_CONTENTCOUNT:
			case PROP_TAG_ASSOCIATEDCONTENTCOUNT:
			case PROP_TAG_FOLDERCHILDCOUNT:
			case PROP_TAG_CONTENTUNREADCOUNT:
			case PROP_TAG_FOLDERTYPE:
			case PROP_TAG_HASRULES:
			case PROP_TAG_FOLDERPATHNAME:
			case PR_PARENT_SOURCE_KEY:
			case PR_MESSAGE_SIZE_EXTENDED:
			case PROP_TAG_ASSOCMESSAGESIZEEXTENDED:
			case PROP_TAG_NORMALMESSAGESIZEEXTENDED:
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count].err = ecAccessDenied;
				pproblems->count ++;
				continue;
			case PROP_TAG_CHANGENUMBER:
				common_util_set_folder_changenum(psqlite, id,
					rop_util_get_gc_value(*(uint64_t*)
					ppropvals->ppropval[i].pvalue));
				continue;
			case PR_DISPLAY_NAME:
			case PR_DISPLAY_NAME_A:
				if (ppropvals->ppropval[i].proptag == PR_DISPLAY_NAME_A) {
					pstring = common_util_convert_copy(TRUE,
					          cpid, static_cast<char *>(ppropvals->ppropval[i].pvalue));
					if (NULL == pstring) {
						break;
					}
				} else {
					pstring = static_cast<char *>(ppropvals->ppropval[i].pvalue);
				}
				tmp_id = common_util_get_folder_parent_fid(psqlite, id);
				if (0 == tmp_id && id == tmp_id) {
					break;
				}
				if (TRUE == common_util_get_folder_by_name(
					psqlite, tmp_id, pstring, &tmp_id)) {
					if (0 == tmp_id || tmp_id == id) {
						break;
					}
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count].err = ecDuplicateName;
					pproblems->count ++;
					continue;
				}
				break;
			}
			break;
		case MESSAGE_PROPERTIES_TABLE:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_ENTRYID:
			case PROP_TAG_FOLDERID:
			case PROP_TAG_PARENTFOLDERID:
			case PROP_TAG_INSTANCESVREID:
			case PR_PARENT_SOURCE_KEY:
			case PROP_TAG_HASNAMEDPROPERTIES:
			case PROP_TAG_MID:
			case PR_MESSAGE_SIZE:
			case PROP_TAG_ASSOCIATED:
			case PROP_TAG_HASATTACHMENTS:
			case PR_DISPLAY_TO:
			case PR_DISPLAY_CC:
			case PR_DISPLAY_BCC:
			case PR_DISPLAY_TO_A:
			case PR_DISPLAY_CC_A:
			case PR_DISPLAY_BCC_A:
			case PROP_TAG_MIDSTRING: /* self-defined proptag */
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count].err = ecAccessDenied;
				pproblems->count ++;
				continue;
			case PROP_TAG_CHANGENUMBER:
				common_util_set_message_changenum(psqlite, id,
					rop_util_get_gc_value(*(uint64_t*)
					ppropvals->ppropval[i].pvalue));
				continue;
			case PR_READ:
				common_util_set_message_read(psqlite, id,
					*(uint8_t*)ppropvals->ppropval[i].pvalue);
				continue;
			case PR_MESSAGE_FLAGS:
				/* XXX: Why no SQL update? */
				*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) &=
					~(MSGFLAG_READ | MSGFLAG_HASATTACH |
					MSGFLAG_FROMME | MSGFLAG_ASSOCIATED |
					MSGFLAG_RN_PENDING | MSGFLAG_NRN_PENDING);
				break;
			case PROP_TAG_SUBJECT:
			case PROP_TAG_SUBJECT_STRING8:
				if (FALSE == common_util_remove_property(
					MESSAGE_PROPERTIES_TABLE, id,
					psqlite, PROP_TAG_SUBJECTPREFIX)) {
					return FALSE;	
				}
				if (FALSE == common_util_set_message_subject(
					cpid, id, pstmt, ppropvals->ppropval + i)) {
					return FALSE;	
				}
				continue;
			case ID_TAG_BODY:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (!common_util_update_message_cid(psqlite,
				    id, PR_BODY, *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case ID_TAG_BODY_STRING8:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (!common_util_update_message_cid(psqlite,
				    id, PR_BODY_A, *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case PR_BODY:
			case PR_BODY_A:
				if (FALSE == common_util_set_message_body(
					psqlite, cpid, id, ppropvals->ppropval + i)) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count].err = ecError;
					pproblems->count ++;
				}
				continue;
			case ID_TAG_HTML:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (FALSE == common_util_update_message_cid(
					psqlite, id, PROP_TAG_HTML, *(uint64_t*)
					ppropvals->ppropval[i].pvalue)) {
					return FALSE;	
				}
				continue;
			case ID_TAG_RTFCOMPRESSED:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (FALSE == common_util_update_message_cid(
					psqlite, id, PROP_TAG_RTFCOMPRESSED,
					*(uint64_t*)ppropvals->ppropval[i].pvalue)) {
					return FALSE;	
				}
				continue;
			case PROP_TAG_HTML:
			case PROP_TAG_RTFCOMPRESSED:
				if (FALSE == common_util_set_message_cid_value(
					psqlite, id, ppropvals->ppropval + i)) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count].err = ecError;
					pproblems->count ++;
				}
				continue;
			case ID_TAG_TRANSPORTMESSAGEHEADERS:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (FALSE == common_util_update_message_cid(
					psqlite, id, PROP_TAG_TRANSPORTMESSAGEHEADERS,
					*(uint64_t*)ppropvals->ppropval[i].pvalue)) {
					return FALSE;	
				}
				continue;
			case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (FALSE == common_util_update_message_cid(psqlite,
					id, PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8,
					*(uint64_t*)ppropvals->ppropval[i].pvalue)) {
					return FALSE;	
				}
				continue;
			case PROP_TAG_TRANSPORTMESSAGEHEADERS:
			case PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
				if (FALSE == common_util_set_message_header(
					psqlite, cpid, id, ppropvals->ppropval + i)) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count].err = ecError;
					pproblems->count ++;
				}
				continue;
			}
			break;
		case RECIPIENT_PROPERTIES_TABLE:
			switch (ppropvals->ppropval[i].proptag) {
			case PROP_TAG_ROWID:
				continue;
			}
			break;
		case ATTACHMENT_PROPERTIES_TABLE:
			switch (ppropvals->ppropval[i].proptag) {
			case PR_RECORD_KEY:
			case PROP_TAG_ATTACHNUMBER:
				continue;
			case ID_TAG_ATTACHDATABINARY:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (!common_util_update_attachment_cid(psqlite,
				    id, PR_ATTACH_DATA_BIN,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case ID_TAG_ATTACHDATAOBJECT:
				if (NULL == common_util_get_tls_var()) {
					break;
				}
				if (!common_util_update_attachment_cid(psqlite,
				    id, PR_ATTACH_DATA_OBJ,
				    *static_cast<uint64_t *>(ppropvals->ppropval[i].pvalue)))
					return FALSE;	
				continue;
			case PR_ATTACH_DATA_BIN:
			case PR_ATTACH_DATA_OBJ:
				if (FALSE == common_util_set_attachment_cid_value(
					psqlite, id, ppropvals->ppropval + i)) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count].err = ecError;
					pproblems->count ++;
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
				if (NULL == pstring) {
					return FALSE;
				}
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
				*(float*)ppropvals->ppropval[i].pvalue);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_DOUBLE:
		case PT_APPTIME:
			sqlite3_bind_double(pstmt, 2,
				*(double*)ppropvals->ppropval[i].pvalue);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_CURRENCY:
		case PT_I8:
		case PT_SYSTIME:
			sqlite3_bind_int64(pstmt, 2,
				*(uint64_t*)ppropvals->ppropval[i].pvalue);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_SHORT:
			sqlite3_bind_int64(pstmt, 2,
				*(uint16_t*)ppropvals->ppropval[i].pvalue);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_LONG:
			sqlite3_bind_int64(pstmt, 2,
				*(uint32_t*)ppropvals->ppropval[i].pvalue);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_BOOLEAN:
			sqlite3_bind_int64(pstmt, 2,
				*(uint8_t*)ppropvals->ppropval[i].pvalue);
			s_result = sqlite3_step(pstmt);
			break;
		case PT_CLSID: {
			EXT_PUSH ext_push;
			if (!ext_buffer_push_init(&ext_push, temp_buff, 16, 0) ||
			    ext_buffer_push_guid(&ext_push,
			    static_cast<GUID *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_SVREID: {
			EXT_PUSH ext_push;
			if (!ext_buffer_push_init(&ext_push, temp_buff, 256, 0) ||
			    ext_buffer_push_svreid(&ext_push,
			    static_cast<SVREID *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_SRESTRICT: {
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_restriction(&ext_push,
			    static_cast<RESTRICTION *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_ACTIONS: {
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_rule_actions(&ext_push,
			    static_cast<RULE_ACTIONS *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
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
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_short_array(&ext_push,
			    static_cast<SHORT_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_LONG: {
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_long_array(&ext_push,
			    static_cast<LONG_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_I8: {
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_longlong_array(&ext_push,
			    static_cast<LONGLONG_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_STRING8: {
			if (0 != cpid) {
				tmp_strings.count = ((STRING_ARRAY*)
					ppropvals->ppropval[i].pvalue)->count;
				tmp_strings.ppstr = cu_alloc<char *>(tmp_strings.count);
				if (NULL == tmp_strings.ppstr) {
					return FALSE;
				}
				for (size_t j = 0; j < tmp_strings.count; ++j) {
					tmp_strings.ppstr[j] = common_util_convert_copy(
						TRUE, cpid, ((STRING_ARRAY*)
						ppropvals->ppropval[i].pvalue)->ppstr[j]);
					if (NULL == tmp_strings.ppstr[j]) {
						return FALSE;
					}
				}
				pstrings = &tmp_strings;
			} else {
				pstrings = static_cast<STRING_ARRAY *>(ppropvals->ppropval[i].pvalue);
			}
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (EXT_ERR_SUCCESS != ext_buffer_push_string_array(
				&ext_push, pstrings)) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_UNICODE: {
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_wstring_array(&ext_push,
			    static_cast<STRING_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_CLSID: {
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_guid_array(&ext_push,
			    static_cast<GUID_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		case PT_MV_BINARY: {
			EXT_PUSH ext_push;
			if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
				return FALSE;
			}
			if (ext_buffer_push_binary_array(&ext_push,
			    static_cast<BINARY_ARRAY *>(ppropvals->ppropval[i].pvalue)) != EXT_ERR_SUCCESS) {
				return FALSE;
			}
			sqlite3_bind_blob(pstmt, 2, ext_push.data,
					ext_push.offset, SQLITE_STATIC);
			s_result = sqlite3_step(pstmt);
			break;
		}
		default:
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count].err = ecNotSupported;
			pproblems->count ++;
			sqlite3_reset(pstmt);
			continue;
		}
		sqlite3_reset(pstmt);
		if (SQLITE_DONE != s_result) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count].err = ecError;
			pproblems->count ++;
		}
	}
	return TRUE;
}

BOOL common_util_remove_property(int table_type,
	uint64_t id, sqlite3 *psqlite, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	
	return common_util_remove_properties(
		table_type, id, psqlite, &tmp_proptags);
}

BOOL common_util_remove_properties(int table_type, uint64_t id,
	sqlite3 *psqlite, const PROPTAG_ARRAY *pproptags)
{
	int i;
	uint32_t proptag;
	char sql_string[128];
	
	switch (table_type) {
	case STORE_PROPERTIES_TABLE:
		sprintf(sql_string, "DELETE FROM "
				"store_properties WHERE proptag=?");
		break;
	case FOLDER_PROPERTIES_TABLE:
		sprintf(sql_string, "DELETE FROM "
			"folder_properties WHERE folder_id=%llu"
			" AND proptag=?", LLU(id));
		break;
	case MESSAGE_PROPERTIES_TABLE:
		sprintf(sql_string, "DELETE FROM "
			"message_properties WHERE message_id=%llu"
			" AND proptag=?", LLU(id));
		break;
	case ATTACHMENT_PROPERTIES_TABLE:
		sprintf(sql_string, "DELETE FROM "
			"attachment_properties WHERE attachment_id=%llu"
			" AND proptag=?", LLU(id));
		break;
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	for (i=0; i<pproptags->count; i++) {
		switch (table_type) {
		case STORE_PROPERTIES_TABLE:
			switch (pproptags->pproptag[i]) {
			case PR_MESSAGE_SIZE_EXTENDED:
			case PROP_TAG_ASSOCIATEDCONTENTCOUNT:
			case PROP_TAG_ASSOCMESSAGESIZEEXTENDED:
			case PROP_TAG_NORMALMESSAGESIZEEXTENDED:
				continue;
			}
			break;
		case FOLDER_PROPERTIES_TABLE:
			switch (pproptags->pproptag[i]) {
			case PR_DISPLAY_NAME:
			case PR_PREDECESSOR_CHANGE_LIST:
				continue;
			}
			break;
		case MESSAGE_PROPERTIES_TABLE:
			switch (pproptags->pproptag[i]) {
			case PROP_TAG_MESSAGESTATUS:
			case PR_PREDECESSOR_CHANGE_LIST:
				continue;
			}
			break;
		}
		proptag = pproptags->pproptag[i];
		switch (PROP_TYPE(proptag)) {
		case PT_STRING8:
		case PT_UNICODE:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_UNICODE));
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				return FALSE;
			}
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_STRING8));
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				return FALSE;
			}
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_MV_UNICODE));
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				return FALSE;
			}
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, CHANGE_PROP_TYPE(proptag, PT_MV_STRING8));
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				return FALSE;
			}
			break;
		default:
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, proptag);
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				return FALSE;
			}
			break;
		}
	}
	return TRUE;
}

BOOL common_util_get_rule_property(uint64_t rule_id,
	sqlite3 *psqlite, uint32_t proptag, void **ppvalue)
{
	EXT_PULL ext_pull;
	char sql_string[128];
	
	switch (proptag) {
	case PROP_TAG_RULEID:
		*ppvalue = cu_alloc<uint64_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint64_t*)(*ppvalue) = rop_util_make_eid_ex(1, rule_id);
		return TRUE;
	case PROP_TAG_RULESEQUENCE:
		sprintf(sql_string, "SELECT sequence"
		          " FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULESTATE:
		sprintf(sql_string, "SELECT state "
		          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULENAME:
		sprintf(sql_string, "SELECT name "
		          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULEPROVIDER:
		sprintf(sql_string, "SELECT provider"
		          " FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULELEVEL:
		sprintf(sql_string, "SELECT level "
		          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULEUSERFLAGS:
		sprintf(sql_string, "SELECT user_flags "
		          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULEPROVIDERDATA:
		sprintf(sql_string, "SELECT provider_data"
		          " FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULECONDITION:
		sprintf(sql_string, "SELECT condition "
		          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	case PROP_TAG_RULEACTIONS:
		sprintf(sql_string, "SELECT actions "
		          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
		break;
	default:
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
	case PROP_TAG_RULESEQUENCE:
	case PROP_TAG_RULESTATE:
	case PROP_TAG_RULELEVEL:
	case PROP_TAG_RULEUSERFLAGS:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = sqlite3_column_int64(pstmt, 0);
		break;
	case PROP_TAG_RULENAME:
	case PROP_TAG_RULEPROVIDER:
		*ppvalue = common_util_dup(S2A(sqlite3_column_text(pstmt, 0)));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		break;
	case PROP_TAG_RULEPROVIDERDATA: {
		*ppvalue = cu_alloc<BINARY>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		auto bv = static_cast<BINARY *>(*ppvalue);
		bv->cb = sqlite3_column_bytes(pstmt, 0);
		bv->pv = common_util_alloc(bv->cb);
		if (bv->pv == nullptr) {
			return FALSE;
		}
		memcpy(bv->pv, sqlite3_column_blob(pstmt, 0), bv->cb);
		break;
	}
	case PROP_TAG_RULECONDITION:
		*ppvalue = cu_alloc<RESTRICTION>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		ext_buffer_pull_init(&ext_pull,
			sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_buffer_pull_restriction(&ext_pull,
		    static_cast<RESTRICTION *>(*ppvalue)) != EXT_ERR_SUCCESS) {
			*ppvalue = NULL;
			return TRUE;
		}
		break;
	case PROP_TAG_RULEACTIONS:
		*ppvalue = cu_alloc<RULE_ACTIONS>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		ext_buffer_pull_init(&ext_pull,
			sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (ext_buffer_pull_rule_actions(&ext_pull,
		    static_cast<RULE_ACTIONS *>(*ppvalue)) != EXT_ERR_SUCCESS) {
			*ppvalue = NULL;
			return TRUE;
		}
		break;
	}
	return TRUE;
}

BOOL common_util_get_permission_property(uint64_t member_id,
	sqlite3 *psqlite, uint32_t proptag, void **ppvalue)
{
	char sql_string[128];
	const char *pusername;
	char display_name[256];
	static const BINARY fake_bin{};
	
	switch (proptag) {
	case PR_ENTRYID:
		if (0 == member_id || -1 == (int64_t)member_id) {
			*ppvalue = deconst(&fake_bin);
			return TRUE;
		}
		sprintf(sql_string, "SELECT username FROM"
		          " permissions WHERE member_id=%llu", LLU(member_id));
		break;
	case PROP_TAG_MEMBERNAME:
		if (0 == member_id) {
			*ppvalue = deconst("default");
			return TRUE;
		} else if (member_id == 0xFFFFFFFFFFFFFFFF) {
			*ppvalue = deconst("anonymous");
			return TRUE;
		}
		sprintf(sql_string, "SELECT username FROM"
		          " permissions WHERE member_id=%llu", LLU(member_id));
		break;
	case PROP_TAG_MEMBERID:
		if (0 == member_id || -1 == (int64_t)member_id) {
			*ppvalue = cu_alloc<uint64_t>();
			if (NULL == *ppvalue) {
				return FALSE;
			}
			*(uint64_t*)(*ppvalue) = member_id;
			return TRUE;
		}
		sprintf(sql_string, "SELECT username FROM"
		          " permissions WHERE member_id=%llu", LLU(member_id));
		break;
	case PROP_TAG_MEMBERRIGHTS:
		if (0 == member_id) {
			sprintf(sql_string, "SELECT config_value "
					"FROM configurations WHERE config_id=%d",
					CONFIG_ID_DEFAULT_PERMISSION);
		} else if (member_id == 0xFFFFFFFFFFFFFFFF) {
			sprintf(sql_string, "SELECT config_value "
					"FROM configurations WHERE config_id=%d",
					CONFIG_ID_ANONYMOUS_PERMISSION);
		} else {
			sprintf(sql_string, "SELECT permission FROM "
			          "permissions WHERE member_id=%llu", LLU(member_id));
		}
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
	if (PROP_TAG_MEMBERID == proptag) {
		*ppvalue = cu_alloc<uint64_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
			*ppvalue = NULL;
			return TRUE;
		}
		pusername = S2A(sqlite3_column_text(pstmt, 0));
		if ('\0' == pusername[0]) {
			*(int64_t*)(*ppvalue) = -1;
		} else if (0 == strcasecmp(pusername, "default")) {
			*(uint64_t*)(*ppvalue) = 0;
		} else {
			*(uint64_t*)(*ppvalue) = member_id;
		}
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
	case PROP_TAG_MEMBERNAME:
		pusername = S2A(sqlite3_column_text(pstmt, 0));
		if ('\0' == pusername[0]) {
			*ppvalue = deconst("default");
			return TRUE;
		} else if (0 == strcasecmp(pusername, "default")) {
			*ppvalue = deconst("anonymous");
			return TRUE;
		}
		*ppvalue = common_util_dup(!common_util_get_user_displayname(pusername, display_name) ||
		           display_name[0] == '\0' ? pusername : display_name);
		if (NULL == *ppvalue) {
			*ppvalue = NULL;
			return FALSE;
		}
		break;
	case PROP_TAG_MEMBERRIGHTS:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = sqlite3_column_int64(pstmt, 0);
		break;
	}
	return TRUE;
}

BOOL common_util_addressbook_entryid_to_username(const BINARY *pentryid_bin,
     char *username, size_t ulen)
{
	EXT_PULL ext_pull;
	ADDRESSBOOK_ENTRYID tmp_entryid;

	ext_buffer_pull_init(&ext_pull, pentryid_bin->pb,
		pentryid_bin->cb, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
		&ext_pull, &tmp_entryid)) {
		return FALSE;
	}
	return common_util_essdn_to_username(tmp_entryid.px500dn, username, ulen);
}

BOOL common_util_addressbook_entryid_to_essdn(const BINARY *pentryid_bin,
    char *pessdn, size_t dnmax)
{
	EXT_PULL ext_pull;
	ADDRESSBOOK_ENTRYID tmp_entryid;

	ext_buffer_pull_init(&ext_pull, pentryid_bin->pb,
		pentryid_bin->cb, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
		&ext_pull, &tmp_entryid)) {
		return FALSE;
	}
	gx_strlcpy(pessdn, tmp_entryid.px500dn, dnmax);
	return TRUE;
}

BOOL common_util_entryid_to_username(const BINARY *pbin,
    char *username, size_t ulen)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	uint8_t tmp_uid[16];
	uint8_t provider_uid[16];
	ONEOFF_ENTRYID oneoff_entry;
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	if (pbin->cb < 20) {
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb, 20, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		&ext_pull, &flags) || 0 != flags) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_bytes(
		&ext_pull, provider_uid, 16)) {
		return FALSE;
	}
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK, tmp_uid);
	if (0 == memcmp(tmp_uid, provider_uid, 16)) {
		ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
			&ext_pull, &ab_entryid)) {
			return FALSE;
		}
		if (ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER != ab_entryid.type) {
			return FALSE;
		}
		return common_util_essdn_to_username(ab_entryid.px500dn, username, ulen);
	}
	rop_util_get_provider_uid(PROVIDER_UID_ONE_OFF, tmp_uid);
	if (0 == memcmp(tmp_uid, provider_uid, 16)) {
		ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_oneoff_entryid(
			&ext_pull, &oneoff_entry)) {
			return FALSE;
		}
		if (0 != strcasecmp(oneoff_entry.paddress_type, "SMTP")) {
			return FALSE;
		}
		gx_strlcpy(username, oneoff_entry.pmail_address, ulen);
		return TRUE;
	}
	return FALSE;
}

BOOL common_util_parse_addressbook_entryid(const BINARY *pbin,
    char *address_type, size_t atsize, char *email_address, size_t emsize)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	uint8_t tmp_uid[16];
	uint8_t provider_uid[16];
	ONEOFF_ENTRYID oneoff_entry;
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	if (pbin->cb < 20) {
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb, 20, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		&ext_pull, &flags) || 0 != flags) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_bytes(
		&ext_pull, provider_uid, 16)) {
		return FALSE;
	}
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK, tmp_uid);
	if (0 == memcmp(tmp_uid, provider_uid, 16)) {
		ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
			&ext_pull, &ab_entryid)) {
			return FALSE;
		}
		if (ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER != ab_entryid.type) {
			return FALSE;
		}
		gx_strlcpy(address_type, "EX", atsize);
		gx_strlcpy(email_address, ab_entryid.px500dn, emsize);
		return TRUE;
	}
	rop_util_get_provider_uid(PROVIDER_UID_ONE_OFF, tmp_uid);
	if (0 == memcmp(tmp_uid, provider_uid, 16)) {
		ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_oneoff_entryid(
			&ext_pull, &oneoff_entry)) {
			return FALSE;
		}
		if (0 != strcasecmp(oneoff_entry.paddress_type, "SMTP")) {
			return FALSE;
		}
		gx_strlcpy(address_type, "SMTP", atsize);
		gx_strlcpy(email_address, oneoff_entry.pmail_address, emsize);
		return TRUE;
	}
	return FALSE;
}

BINARY* common_util_to_private_folder_entryid(
	sqlite3 *psqlite, const char *username,
	uint64_t folder_id)
{
	int user_id;
	BINARY *pbin;
	EXT_PUSH ext_push;
	FOLDER_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	pbin = common_util_get_mailbox_guid(psqlite);
	if (NULL == pbin) {
		return nullptr;
	}
	memcpy(tmp_entryid.provider_uid, pbin->pb, 16);
	if (FALSE == common_util_get_id_from_username(
		username, &user_id)) {
		return nullptr;
	}
	tmp_entryid.database_guid = rop_util_make_user_guid(user_id);
	tmp_entryid.folder_type = EITLT_PRIVATE_FOLDER;
	rop_util_get_gc_array(folder_id, tmp_entryid.global_counter);
	tmp_entryid.pad[0] = 0;
	tmp_entryid.pad[1] = 0;
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pv, 256, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != ext_buffer_push_folder_entryid(
		&ext_push, &tmp_entryid)) {
		return NULL;
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

BINARY* common_util_to_private_message_entryid(
	sqlite3 *psqlite, const char *username,
	uint64_t folder_id, uint64_t message_id)
{
	int user_id;
	BINARY *pbin;
	EXT_PUSH ext_push;
	MESSAGE_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	pbin = common_util_get_mailbox_guid(psqlite);
	if (NULL == pbin) {
		return nullptr;
	}
	memcpy(tmp_entryid.provider_uid, pbin->pb, 16);
	if (FALSE == common_util_get_id_from_username(
		username, &user_id)) {
		return nullptr;
	}
	tmp_entryid.folder_database_guid = rop_util_make_user_guid(user_id);
	tmp_entryid.message_type = EITLT_PRIVATE_MESSAGE;
	tmp_entryid.message_database_guid = tmp_entryid.folder_database_guid;
	rop_util_get_gc_array(folder_id, tmp_entryid.folder_global_counter);
	rop_util_get_gc_array(message_id, tmp_entryid.message_global_counter);
	tmp_entryid.pad1[0] = 0;
	tmp_entryid.pad1[1] = 0;
	tmp_entryid.pad2[0] = 0;
	tmp_entryid.pad2[1] = 0;
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pv, 256, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != ext_buffer_push_message_entryid(
		&ext_push, &tmp_entryid)) {
		return NULL;
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

BOOL common_util_check_folder_permission(
	sqlite3 *psqlite, uint64_t folder_id,
	const char *username, uint32_t *ppermission)
{
	char sql_string[1024];
	
	*ppermission = 0;
	snprintf(sql_string, 1024, "SELECT permission"
				" FROM permissions WHERE folder_id=%llu AND"
				" username=?", LLU(folder_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, username == nullptr ? "" : username, -1, SQLITE_STATIC);
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		*ppermission = sqlite3_column_int64(pstmt, 0);
		return TRUE;
	} else {
		if (NULL != username && '\0' != username[0]) {
			sprintf(sql_string, "SELECT username, permission"
			          " FROM permissions WHERE folder_id=%llu", LLU(folder_id));
			auto pstmt1 = gx_sql_prep(psqlite, sql_string);
			if (pstmt1 == nullptr) {
				return FALSE;
			}
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
		if (NULL == username || '\0' == username[0]) {
			sprintf(sql_string, "SELECT config_value "
						"FROM configurations WHERE config_id=%d",
						CONFIG_ID_ANONYMOUS_PERMISSION);
		} else {
			sprintf(sql_string, "SELECT config_value "
						"FROM configurations WHERE config_id=%d",
						CONFIG_ID_DEFAULT_PERMISSION);
		}
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			*ppermission = sqlite3_column_int64(pstmt, 0);
		}
		return TRUE;
	}
}

BINARY* common_util_username_to_addressbook_entryid(
	const char *username)
{
	BINARY *pbin;
	char x500dn[1024];
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID tmp_entryid;
	
	if (!common_util_username_to_essdn(username, x500dn, GX_ARRAY_SIZE(x500dn)))
		return NULL;
	tmp_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
							tmp_entryid.provider_uid);
	tmp_entryid.version = 1;
	tmp_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER;
	tmp_entryid.px500dn = x500dn;
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(1280);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pv, 1280, EXT_FLAG_UTF16))
		return NULL;
	if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
		&ext_push, &tmp_entryid)) {
		return NULL;
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

BOOL common_util_check_descendant(sqlite3 *psqlite,
	uint64_t inner_fid, uint64_t outer_fid, BOOL *pb_included)
{
	BOOL b_private;
	uint64_t folder_id;
	char sql_string[128];
	
	if (inner_fid == outer_fid) {
		*pb_included = TRUE;
		return TRUE;
	}
	folder_id = inner_fid;
	b_private = exmdb_server_check_private();
	sprintf(sql_string, "SELECT parent_id"
				" FROM folders WHERE folder_id=?");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (!((TRUE == b_private && PRIVATE_FID_ROOT == folder_id) ||
		(FALSE == b_private && PUBLIC_FID_ROOT == folder_id))) {
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
	
	sprintf(sql_string, "SELECT parent_fid FROM"
	          " messages WHERE message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;	
	*pfolder_id = sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	              sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

static BINARY* common_util_get_message_parent_svrid(
	sqlite3 *psqlite, uint64_t message_id)
{
	BINARY *pbin;
	EXT_PUSH ext_push;
	uint64_t folder_id;
	
	if (FALSE == common_util_get_message_parent_folder(
		psqlite, message_id, &folder_id)) {
		return NULL;	
	}
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = sizeof(uint8_t) + sizeof(uint32_t) + 
				sizeof(uint64_t) + sizeof(uint64_t);
	pbin->pv = common_util_alloc(pbin->cb);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pv, pbin->cb, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(&ext_push, 1)) {
		return NULL;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint64(&ext_push, folder_id)) {
		return NULL;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint64(&ext_push, 0)) {
		return NULL;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(&ext_push, 0)) {
		return NULL;
	}
	if (ext_push.offset != pbin->cb) {
		return NULL;
	}
	return pbin;
}

BOOL common_util_load_search_scopes(sqlite3 *psqlite,
	uint64_t folder_id, LONGLONG_ARRAY *pfolder_ids)
{
	int i;
	char sql_string[128];
	
	sprintf(sql_string, "SELECT count(*) FROM "
	          "search_scopes WHERE folder_id=%llu", LLU(folder_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	pfolder_ids->count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	pfolder_ids->pll = cu_alloc<uint64_t>();
	if (NULL == pfolder_ids->pll) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT included_fid FROM"
	          " search_scopes WHERE folder_id=%llu", LLU(folder_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	i = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		pfolder_ids->pll[i] = sqlite3_column_int64(pstmt, 0);
		i ++;
	}
	return TRUE;
}

static BOOL common_util_evaluate_subitem_restriction(
	sqlite3 *psqlite, uint32_t cpid, int table_type,
	uint64_t id, const RESTRICTION *pres)
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
		if (!common_util_get_property(table_type, id, cpid, psqlite,
		    rcon->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strcmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
				return FALSE;
			} else {
				if (strstr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		case FL_PREFIX:
			len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strncasecmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strncmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!common_util_get_property(table_type, id, cpid, psqlite,
		    rprop->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		if (rprop->proptag == PROP_TAG_ANR) {
			if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
				return FALSE;
			if (strcasestr(static_cast<char *>(pvalue),
			    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
				return TRUE;
			return FALSE;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
			return FALSE;
		if (!common_util_get_property(table_type, id, cpid, psqlite,
		    rprop->proptag1, &pvalue) || pvalue == nullptr)
			return FALSE;
		if (!common_util_get_property(table_type, id, cpid, psqlite,
		    rprop->proptag1, &pvalue1) || pvalue1 == nullptr)
			return FALSE;
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		if (!common_util_get_property(table_type, id, cpid, psqlite,
		    rbm->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			if ((*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0)
				return TRUE;
			break;
		case BMR_NEZ:
			if (*static_cast<uint32_t *>(pvalue) & rbm->mask)
				return TRUE;
			break;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!common_util_get_property(table_type, id, cpid, psqlite,
		    rsize->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		val_size = propval_size(rsize->proptag, pvalue);
		return propval_compare_relop(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
	}
	case RES_EXIST: {
		auto rex = pres->exist;
		if (!common_util_get_property(table_type, id, cpid, psqlite,
		    rex->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		return TRUE;
	}
	case RES_COMMENT: {
		auto rcom = pres->comment;
		if (rcom->pres == nullptr)
			return TRUE;
		return common_util_evaluate_subitem_restriction(psqlite, cpid,
		       table_type, id, rcom->pres);
	}
	default:
		return false;
	}
	return FALSE;
}

static BOOL common_util_evaluate_msgsubs_restriction(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, const RESTRICTION *pres)
{
	uint64_t id;
	uint32_t count;
	int table_type;
	char sql_string[128];
	
	if (proptag == PR_MESSAGE_RECIPIENTS) {
		table_type = RECIPIENT_PROPERTIES_TABLE;
		sprintf(sql_string, "SELECT recipient_id FROM "
				"recipients WHERE message_id=%llu", LLU(message_id));
	} else {
		table_type = ATTACHMENT_PROPERTIES_TABLE;
		sprintf(sql_string, "SELECT attachment_id FROM"
				" attachments WHERE message_id=%llu", LLU(message_id));
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		id = sqlite3_column_int64(pstmt, 0);
		if (pres->rt == RES_COUNT) {
			if (TRUE == common_util_evaluate_subitem_restriction(
				psqlite, cpid, table_type, id,
				&((RESTRICTION_COUNT*)pres->pres)->sub_res)) {
				count ++;
			}
		} else {
			if (TRUE == common_util_evaluate_subitem_restriction(
				psqlite, cpid, table_type, id, pres)) {
				return TRUE;
			}
		}
	}
	return pres->rt == RES_COUNT && count == pres->count->count ? TRUE : false;
}

static BOOL common_util_evaluate_subobject_restriction(
	sqlite3 *psqlite, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, const RESTRICTION *pres)
{
	switch (pres->rt) {
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (common_util_evaluate_subobject_restriction(psqlite,
			    cpid, message_id, proptag, &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!common_util_evaluate_subobject_restriction(psqlite,
			    cpid, message_id, proptag, &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		if (common_util_evaluate_subobject_restriction(psqlite, cpid,
		    message_id, proptag, &pres->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT:
	case RES_PROPERTY:
	case RES_PROPCOMPARE:
	case RES_BITMASK:
	case RES_SIZE:
	case RES_EXIST:
	case RES_COMMENT:
	case RES_COUNT:
		return common_util_evaluate_msgsubs_restriction(
				psqlite, cpid, message_id, proptag, pres);
	default:
		return false;
	}	
	return FALSE;
}

BOOL common_util_evaluate_folder_restriction(sqlite3 *psqlite,
	uint64_t folder_id, const RESTRICTION *pres)
{
	void *pvalue;
	void *pvalue1;
	uint32_t val_size;
	
	switch (pres->rt) {
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (common_util_evaluate_folder_restriction(psqlite,
			    folder_id, &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!common_util_evaluate_folder_restriction(psqlite,
			    folder_id, &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		if (common_util_evaluate_folder_restriction(psqlite,
		    folder_id, &pres->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		if (!common_util_get_property(FOLDER_PROPERTIES_TABLE,
		    folder_id, 0, psqlite, rcon->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strcmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
				return FALSE;
			} else {
				if (strstr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		case FL_PREFIX: {
			auto len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strncasecmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strncmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		}
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!common_util_get_property(FOLDER_PROPERTIES_TABLE,
		    folder_id, 0, psqlite, rprop->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		if (rprop->proptag == PROP_TAG_ANR) {
			if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
				return FALSE;
			if (strcasestr(static_cast<char *>(pvalue),
			    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
				return TRUE;
			return FALSE;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
			return FALSE;
		if (!common_util_get_property(FOLDER_PROPERTIES_TABLE,
		    folder_id, 0, psqlite, rprop->proptag1, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		if (!common_util_get_property(FOLDER_PROPERTIES_TABLE,
		    folder_id, 0, psqlite, rprop->proptag2, &pvalue1) ||
		    pvalue1 == nullptr)
			return FALSE;
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		if (!common_util_get_property(FOLDER_PROPERTIES_TABLE,
		    folder_id, 0, psqlite, rbm->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			if ((*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0)
				return TRUE;
			break;
		case BMR_NEZ:
			if (*static_cast<uint32_t *>(pvalue) & rbm->mask)
				return TRUE;
			break;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!common_util_get_property(FOLDER_PROPERTIES_TABLE,
		    folder_id, 0, psqlite, rsize->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		val_size = propval_size(rsize->proptag, pvalue);
		return propval_compare_relop(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
	}
	case RES_EXIST:
		if (!common_util_get_property(FOLDER_PROPERTIES_TABLE,
		    folder_id, 0, psqlite, pres->exist->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		return TRUE;
	case RES_COMMENT:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return common_util_evaluate_folder_restriction(psqlite,
		       folder_id, pres->comment->pres);
	default:
		return FALSE;
	}	
	return FALSE;
}

BOOL common_util_evaluate_message_restriction(sqlite3 *psqlite,
	uint32_t cpid, uint64_t message_id, const RESTRICTION *pres)
{
	void *pvalue;
	void *pvalue1;
	uint32_t val_size;
	
	switch (pres->rt) {
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (common_util_evaluate_message_restriction(psqlite,
			    cpid, message_id, &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!common_util_evaluate_message_restriction(psqlite,
			    cpid, message_id, &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		if (common_util_evaluate_message_restriction(psqlite,
		    cpid, message_id, &pres->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (PROP_TYPE(rcon->proptag) != PT_STRING8 &&
		    PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		if (!common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		    message_id, cpid, psqlite, rcon->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strcmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
				return FALSE;
			} else {
				if (strstr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		case FL_PREFIX: {
			auto len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strncasecmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strncmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		}
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		switch (rprop->proptag) {
		case PR_PARENT_SVREID:
		case PR_PARENT_ENTRYID:
			/* parent entryid under this situation is a SVREID binary */
			pvalue = common_util_get_message_parent_svrid(
									psqlite, message_id);
			if (NULL == pvalue) {
				return FALSE;
			}
			break;
		default:
			if (!common_util_get_property(MESSAGE_PROPERTIES_TABLE,
			    message_id, cpid, psqlite, rprop->proptag, &pvalue) ||
			    pvalue == nullptr)
				return FALSE;
			if (rprop->proptag == PROP_TAG_ANR) {
				if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
					return FALSE;
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
					return TRUE;
				return FALSE;
			}
			break;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
			return FALSE;
		if (!common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		    message_id, cpid, psqlite, rprop->proptag1, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		if (!common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		    message_id, cpid, psqlite, rprop->proptag1, &pvalue1) ||
		    pvalue1 == nullptr)
			return FALSE;
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		if (!common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		    message_id, cpid, psqlite, rbm->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			if ((*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0)
				return TRUE;
			break;
		case BMR_NEZ:
			if (*static_cast<uint32_t *>(pvalue) & rbm->mask)
				return TRUE;
			break;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		    message_id, cpid, psqlite, rsize->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		val_size = propval_size(rsize->proptag, pvalue);
		return propval_compare_relop(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
	}
	case RES_EXIST:
		if (!common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		    message_id, cpid, psqlite, pres->exist->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		return TRUE;
	case RES_SUBRESTRICTION: {
		auto rsub = pres->sub;
		switch (rsub->subobject) {
		case PR_MESSAGE_RECIPIENTS:
			return common_util_evaluate_subobject_restriction(psqlite,
			       cpid, message_id, PR_MESSAGE_RECIPIENTS,
			       &rsub->res);
		case PR_MESSAGE_ATTACHMENTS:
			return common_util_evaluate_subobject_restriction(psqlite,
			       cpid, message_id, PR_MESSAGE_ATTACHMENTS,
			       &rsub->res);
		default:
			return FALSE;
		}
		return FALSE;
	}
	case RES_COMMENT:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return common_util_evaluate_message_restriction(psqlite, cpid,
		       message_id, pres->comment->pres);
	case RES_COUNT: {
		auto rcnt = pres->count;
		if (rcnt->count == 0)
			return FALSE;
		if (common_util_evaluate_message_restriction(psqlite,
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
	
	sprintf(sql_string, "SELECT message_id FROM"
				" search_result WHERE folder_id=%llu AND "
				"message_id=%llu", LLU(folder_id), LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_exist = sqlite3_step(pstmt) == SQLITE_ROW;
	return TRUE;
}

BOOL common_util_get_mid_string(sqlite3 *psqlite,
	uint64_t message_id, char **ppmid_string)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT mid_string FROM"
	          " messages WHERE message_id=%llu", LLU(message_id));
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
	
	sprintf(sql_string, "UPDATE messages set "
	          "mid_string=? WHERE message_id=%llu", LLU(message_id));
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
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	if (FALSE == common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		message_id, 0, psqlite, PROP_TAG_CREATORENTRYID, (void**)&pbin)) {
		return FALSE;
	}
	if (NULL == pbin) {
		*pb_owner = FALSE;
		return TRUE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb,
		pbin->cb, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
		&ext_pull, &ab_entryid)) {
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
	auto b_private = exmdb_server_check_private();
	
	if (FALSE == b_embedded) {
		if (0 == *pdst_mid) {
			if (FALSE == common_util_allocate_eid_from_folder(
				psqlite, parent_id, pdst_mid)) {
				return FALSE;
			}
		}
	} else {
		if (FALSE == common_util_allocate_eid(psqlite, pdst_mid)) {
			return FALSE;
		}
	}
	if (FALSE == common_util_allocate_cn(psqlite, &change_num)) {
		return FALSE;
	}
	if (NULL != pchange_num) {
		*pchange_num = change_num;
	}
	if (TRUE == b_private) {
		sprintf(sql_string, "SELECT is_associated, message_size,"
			" read_state, mid_string FROM messages WHERE message_id=%llu",
		          LLU(message_id));
	} else {
		sprintf(sql_string, "SELECT is_associated, "
			"message_size FROM messages WHERE message_id=%llu",
		          LLU(message_id));
	}
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		*pb_result = FALSE;
		return TRUE;
	}
	is_associated = sqlite3_column_int64(pstmt, 0);
	message_size = sqlite3_column_int64(pstmt, 1);
	if (TRUE == b_private) {
		read_state = sqlite3_column_int64(pstmt, 2);
		if (SQLITE_NULL == sqlite3_column_type(pstmt, 3)) {
			mid_string[0] = '\0';
		} else {
			gx_strlcpy(mid_string1, S2A(sqlite3_column_text(pstmt, 3)), sizeof(mid_string1));
			snprintf(mid_string, 128, "%lld.%d.%s", LLD(time(nullptr)),
					common_util_sequence_ID(), get_host_ID());
			sprintf(tmp_path, "%s/eml/%s",
				exmdb_server_get_dir(), mid_string);
			sprintf(tmp_path1, "%s/eml/%s",
				exmdb_server_get_dir(), mid_string1);
			link(tmp_path1, tmp_path);
			sprintf(tmp_path, "%s/ext/%s",
				exmdb_server_get_dir(), mid_string);
			sprintf(tmp_path1, "%s/ext/%s",
				exmdb_server_get_dir(), mid_string1);
			link(tmp_path1, tmp_path);
		}
	}
	if (NULL != pmessage_size) {
		*pmessage_size = message_size;
	}
	pstmt.finalize();
	if (FALSE == b_embedded) {
		if (TRUE == b_private) {
			sprintf(sql_string, "INSERT INTO messages (message_id, "
					"parent_fid, parent_attid, is_associated, change_number, "
					"read_state, message_size, mid_string) VALUES (%llu, %llu,"
					" NULL, %d, %llu, %d, %u, ?)", LLU(*pdst_mid), LLU(parent_id),
					is_associated, LLU(change_num), read_state, message_size);
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr)
				return FALSE;
			if ('\0' == mid_string[0]) {
				sqlite3_bind_null(pstmt, 1);
			} else {
				sqlite3_bind_text(pstmt, 1, mid_string, -1, SQLITE_STATIC);
			}
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				return FALSE;
			}
			pstmt.finalize();
		} else {
			sprintf(sql_string, "INSERT INTO messages (message_id, parent_fid,"
				" parent_attid, is_associated, change_number, message_size) "
				"VALUES (%llu, %llu, NULL, %d, %llu, %u)", LLU(*pdst_mid),
				LLU(parent_id), is_associated, LLU(change_num), message_size);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
		}
	} else {
		sprintf(sql_string, "INSERT INTO messages (message_id, parent_fid,"
			" parent_attid, is_associated, change_number, message_size) "
			"VALUES (%llu, NULL, %llu, %d, %llu, %u)", LLU(*pdst_mid),
			LLU(parent_id), 0, LLU(change_num), message_size);
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
	}
	sprintf(sql_string, "INSERT INTO message_properties (message_id,"
			" proptag, propval) SELECT %llu, proptag, propval FROM "
			"message_properties WHERE message_id=%llu",
			LLU(*pdst_mid), LLU(message_id));
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU(message_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sprintf(sql_string, "INSERT INTO recipients"
	          " (message_id) VALUES (%llu)", LLU(*pdst_mid));
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr) {
		return FALSE;
	}
	sprintf(sql_string, "INSERT INTO recipients_properties "
				"(recipient_id, proptag, propval) SELECT ?, proptag, "
				"propval FROM recipients_properties WHERE recipient_id=?");
	auto pstmt2 = gx_sql_prep(psqlite, sql_string);
	if (pstmt2 == nullptr) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		tmp_id = sqlite3_column_int64(pstmt, 0);
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			return FALSE;
		}
		last_id = sqlite3_last_insert_rowid(psqlite);
		sqlite3_bind_int64(pstmt2, 1, last_id);
		sqlite3_bind_int64(pstmt2, 2, tmp_id);
		if (SQLITE_DONE != sqlite3_step(pstmt2)) {
			return FALSE;
		}
		sqlite3_reset(pstmt2);
	}
	pstmt.finalize();
	pstmt1.finalize();
	pstmt2.finalize();
	sprintf(sql_string, "SELECT attachment_id FROM"
	          " attachments WHERE message_id=%llu", LLU(message_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sprintf(sql_string, "INSERT INTO attachments"
	          " (message_id) VALUES (%llu)", LLU(*pdst_mid));
	pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr) {
		return FALSE;
	}
	sprintf(sql_string, "INSERT INTO attachment_properties "
				"(attachment_id, proptag, propval) SELECT ?, proptag, "
				"propval FROM attachment_properties WHERE attachment_id=?");
	pstmt2 = gx_sql_prep(psqlite, sql_string);
	if (pstmt2 == nullptr) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT message_id"
			" FROM messages WHERE parent_attid=?");
	auto pstmt3 = gx_sql_prep(psqlite, sql_string);
	if (pstmt3 == nullptr) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		tmp_id = sqlite3_column_int64(pstmt, 0);
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			return FALSE;
		}
		last_id = sqlite3_last_insert_rowid(psqlite);
		sqlite3_bind_int64(pstmt2, 1, last_id);
		sqlite3_bind_int64(pstmt2, 2, tmp_id);
		if (SQLITE_DONE != sqlite3_step(pstmt2)) {
			return FALSE;
		}
		sqlite3_reset(pstmt2);
		sqlite3_bind_int64(pstmt3, 1, tmp_id);
		if (SQLITE_ROW == sqlite3_step(pstmt3)) {
			if (FALSE == common_util_copy_message_internal(
				psqlite, TRUE, sqlite3_column_int64(pstmt3, 0),
				last_id, &tmp_mid, &b_result, NULL, NULL)) {
				return FALSE;
			}
			if (FALSE == b_result) {
				*pb_result = FALSE;
				return TRUE;
			}
		}
		sqlite3_reset(pstmt3);
	}
	*pb_result = TRUE;
	return TRUE;
}

BOOL common_util_copy_message(sqlite3 *psqlite, int account_id,
	uint64_t message_id, uint64_t folder_id, uint64_t *pdst_mid,
	BOOL *pb_result, uint32_t *pmessage_size)
{
	XID tmp_xid;
	void *pvalue;
	uint32_t next;
	BOOL b_result;
	uint64_t nt_time;
	uint64_t change_num;
	TPROPVAL_ARRAY propvals;
	PROBLEM_ARRAY tmp_problems;
	TAGGED_PROPVAL tmp_propval;
	static const uint32_t fake_uid = 1;
	TAGGED_PROPVAL propval_buff[4];
	
	if (FALSE == common_util_copy_message_internal(psqlite, 
		FALSE, message_id, folder_id, pdst_mid, pb_result,
		&change_num, pmessage_size)) {
		return FALSE;
	}
	if (TRUE == *pb_result) {
		if (FALSE == common_util_get_property(FOLDER_PROPERTIES_TABLE,
			folder_id, 0, psqlite, PROP_TAG_ARTICLENUMBERNEXT, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue) {
			pvalue = deconst(&fake_uid);
		}
		next = *(uint32_t*)pvalue + 1;
		tmp_propval.proptag = PROP_TAG_ARTICLENUMBERNEXT;
		tmp_propval.pvalue = &next;
		if (FALSE == common_util_set_property(FOLDER_PROPERTIES_TABLE,
			folder_id, 0, psqlite, &tmp_propval, &b_result)) {
			return FALSE;	
		}
		tmp_xid.guid = exmdb_server_check_private() ?
		               rop_util_make_user_guid(account_id) :
		               rop_util_make_domain_guid(account_id);
		rop_util_value_to_gc(change_num, tmp_xid.local_id);
		propval_buff[0].proptag = PR_CHANGE_KEY;
		propval_buff[0].pvalue = common_util_xid_to_binary(22, &tmp_xid);
		if (NULL == propval_buff[0].pvalue) {
			return FALSE;
		}
		propval_buff[1].proptag = PR_PREDECESSOR_CHANGE_LIST;
		propval_buff[1].pvalue = common_util_pcl_append(nullptr, static_cast<BINARY *>(propval_buff[0].pvalue));
		if (NULL == propval_buff[1].pvalue) {
			return FALSE;
		}
		propval_buff[2].proptag = PROP_TAG_INTERNETARTICLENUMBER;
		propval_buff[2].pvalue = pvalue;
		nt_time = rop_util_current_nttime();
		propval_buff[3].proptag = PR_LAST_MODIFICATION_TIME;
		propval_buff[3].pvalue = &nt_time;
		propvals.count = 4;
		propvals.ppropval = propval_buff;
		if (FALSE == common_util_set_properties(
			MESSAGE_PROPERTIES_TABLE, *pdst_mid, 0,
			psqlite, &propvals, &tmp_problems)) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL common_util_get_named_propids(sqlite3 *psqlite,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	int i;
	char sql_string[128];
	char guid_string[64];
	char name_string[2560];
	
	ppropids->ppropid = cu_alloc<uint16_t>(ppropnames->count);
	if (NULL == ppropids->ppropid) {
		return FALSE;
	}
	ppropids->count = ppropnames->count;
	if (TRUE == b_create) {
		sprintf(sql_string, "SELECT"
			" count(*) FROM named_properties");
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		/* if there're too many property names in table, stop creating */
		if (sqlite3_column_int64(pstmt, 0) + ppropnames->count >
			MAXIMUM_PROPNAME_NUMBER) {
			b_create = FALSE;
		}
	}
	sprintf(sql_string, "SELECT propid FROM "
				"named_properties WHERE name_string=?");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	decltype(pstmt) pstmt1;
	if (pstmt == nullptr)
		return FALSE;
	if (TRUE == b_create) {
		sprintf(sql_string, "INSERT INTO "
			"named_properties (name_string) VALUES (?)");
		pstmt1 = gx_sql_prep(psqlite, sql_string);
		if (pstmt1 == nullptr) {
			return FALSE;
		}
	}
	for (i=0; i<ppropnames->count; i++) {
		guid_to_string(&ppropnames->ppropname[i].guid, guid_string, 64);
		switch (ppropnames->ppropname[i].kind) {
		case MNID_ID:
			snprintf(name_string, 1024, "GUID=%s,LID=%u",
				guid_string, *ppropnames->ppropname[i].plid);
			break;
		case MNID_STRING:
			if (strlen(ppropnames->ppropname[i].pname) >= 1024) {
				ppropids->ppropid[i] = 0;
				continue;
			}
			snprintf(name_string, 1024, "GUID=%s,NAME=%s",
				guid_string, ppropnames->ppropname[i].pname);
			break;
		default:
			ppropids->ppropid[i] = 0;
			continue;
		}
		sqlite3_bind_text(pstmt, 1, name_string, -1, SQLITE_STATIC);
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			ppropids->ppropid[i] = sqlite3_column_int64(pstmt, 0);
			sqlite3_reset(pstmt);
			continue;
		}
		sqlite3_reset(pstmt);
		if (TRUE == b_create) {
			sqlite3_bind_text(pstmt1, 1, name_string, -1, SQLITE_STATIC);
			if (SQLITE_DONE != sqlite3_step(pstmt1)) {
				return FALSE;
			}
			ppropids->ppropid[i] = sqlite3_last_insert_rowid(psqlite);
			sqlite3_reset(pstmt1);
		} else {
			ppropids->ppropid[i] = 0;
		}
	}
	return TRUE;
}

BOOL common_util_get_named_propnames(sqlite3 *psqlite,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	int i;
	char *ptoken;
	char sql_string[128];
	char temp_name[1024];
	
	ppropnames->ppropname = cu_alloc<PROPERTY_NAME>(ppropids->count);
	if (NULL == ppropnames->ppropname) {
		return FALSE;
	}
	ppropnames->count = ppropids->count;
	sprintf(sql_string, "SELECT name_string "
				"FROM named_properties WHERE propid=?");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
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
		if (0 != strncasecmp(temp_name, "GUID=", 5)) {
			goto NOT_FOUND_PROPNAME;
		}
		ptoken = strchr(temp_name + 5, ',');
		if (NULL == ptoken) {
			goto NOT_FOUND_PROPNAME;
		}
		*ptoken = '\0';
		ptoken ++;
		if (FALSE == guid_from_string(
			&ppropnames->ppropname[i].guid, temp_name + 5)) {
			goto NOT_FOUND_PROPNAME;
		}
		if (0 == strncasecmp(ptoken, "LID=", 4)) {
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].plid = cu_alloc<uint32_t>();
			if (NULL == ppropnames->ppropname[i].plid) {
				return FALSE;
			}
			*ppropnames->ppropname[i].plid = atoi(ptoken + 4);
			if (0 == *ppropnames->ppropname[i].plid) {
				goto NOT_FOUND_PROPNAME;
			}
			ppropnames->ppropname[i].pname = NULL;
			continue;
		} else if (0 == strncasecmp(ptoken, "NAME=", 5)) {
			ppropnames->ppropname[i].kind = MNID_STRING;
			HX_strrtrim(ptoken + 5);
			HX_strltrim(ptoken + 5);
			if ('\0' == ptoken[5]) {
				goto NOT_FOUND_PROPNAME;
			}
			ppropnames->ppropname[i].pname =
					common_util_dup(ptoken + 5);
			if (NULL == ppropnames->ppropname[i].pname) {
				return FALSE;
			}
			ppropnames->ppropname[i].plid = NULL;
			continue;
		}
 NOT_FOUND_PROPNAME:
		ppropnames->ppropname[i].kind = KIND_NONE;
		ppropnames->ppropname[i].plid = NULL;
		ppropnames->ppropname[i].pname = NULL;
	}
	return TRUE;
}

BOOL common_util_check_folder_id(sqlite3 *psqlite,
	uint64_t folder_id, BOOL *pb_exist)
{
	char sql_string[256];
	
	sprintf(sql_string, "SELECT folder_id "
	          "FROM folders WHERE folder_id=%llu", LLU(folder_id));
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
	
	sprintf(sql_string, "UPDATE folder_properties"
		" SET propval=propval+%u WHERE proptag=%u"
		" AND folder_id=%llu", del_count,
	        PR_DELETED_COUNT_TOTAL, LLU(folder_id));
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	return TRUE;
}

BOOL common_util_increase_store_size(sqlite3 *psqlite,
	uint64_t normal_size, uint64_t fai_size)
{
	char sql_string[256];
	
	sprintf(sql_string, "UPDATE store_properties"
				" SET propval=propval+? WHERE proptag=?");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, normal_size + fai_size);
	sqlite3_bind_int64(pstmt, 2, PR_MESSAGE_SIZE_EXTENDED);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	if (0 != normal_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, normal_size);
		sqlite3_bind_int64(pstmt, 2, PROP_TAG_NORMALMESSAGESIZEEXTENDED);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
	}
	if (0 != fai_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, fai_size);
		sqlite3_bind_int64(pstmt, 2, PROP_TAG_ASSOCMESSAGESIZEEXTENDED);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL common_util_decrease_store_size(sqlite3 *psqlite,
	uint64_t normal_size, uint64_t fai_size)
{
	char sql_string[256];
	
	sprintf(sql_string, "UPDATE store_properties"
				" SET propval=propval-? WHERE proptag=?");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, normal_size + fai_size);
	sqlite3_bind_int64(pstmt, 2, PR_MESSAGE_SIZE_EXTENDED);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	if (0 != normal_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, normal_size);
		sqlite3_bind_int64(pstmt, 2, PROP_TAG_NORMALMESSAGESIZEEXTENDED);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
	}
	if (0 != fai_size) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, fai_size);
		sqlite3_bind_int64(pstmt, 2, PROP_TAG_ASSOCMESSAGESIZEEXTENDED);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
	}
	return TRUE;
}

unsigned int common_util_get_param(int param)
{
	switch (param) {
	case COMMON_UTIL_MAX_RULE_NUMBER:
		return g_max_rule_num;
	case COMMON_UTIL_MAX_EXT_RULE_NUMBER:
		return g_max_ext_rule_num;
	}
	return 0;
}

BOOL common_util_recipients_to_list(
	TARRAY_SET *prcpts, DOUBLE_LIST *plist)
{
	void *pvalue;
	DOUBLE_LIST_NODE *pnode;
	
	for (size_t i = 0; i < prcpts->count; ++i) {
		pnode = cu_alloc<DOUBLE_LIST_NODE>();
		if (NULL == pnode) {
			return FALSE;
		}
		pnode->pdata = common_util_get_propvals(prcpts->pparray[i], PR_SMTP_ADDRESS);
		if (NULL != pnode->pdata) {
			double_list_append_as_tail(plist, pnode);
			continue;
		}
		pvalue = common_util_get_propvals(
			prcpts->pparray[i], PROP_TAG_ADDRESSTYPE);
		if (NULL == pvalue) {
 CONVERT_ENTRYID:
			pvalue = common_util_get_propvals(prcpts->pparray[i], PR_ENTRYID);
			if (NULL == pvalue) {
				return FALSE;
			}
			pnode->pdata = common_util_alloc(UADDR_SIZE);
			if (NULL == pnode->pdata) {
				return FALSE;
			}
			if (!common_util_entryid_to_username(static_cast<BINARY *>(pvalue),
			    static_cast<char *>(pnode->pdata), UADDR_SIZE))
				return FALSE;
		} else {
			if (strcasecmp(static_cast<char *>(pvalue), "SMTP") == 0) {
				pnode->pdata = common_util_get_propvals(prcpts->pparray[i], PR_EMAIL_ADDRESS);
				if (NULL == pnode->pdata) {
					goto CONVERT_ENTRYID;
				}
			} else {
				goto CONVERT_ENTRYID;
			}
		}
		double_list_append_as_tail(plist, pnode);
	}
	return TRUE;
}

BINARY* common_util_xid_to_binary(uint8_t size, const XID *pxid)
{
	EXT_PUSH ext_push;
	
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(24);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pv, 24, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != ext_buffer_push_xid(
		&ext_push, size, pxid)) {
		return NULL;
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid)
{
	EXT_PULL ext_pull;
	
	if (pbin->cb < 17 || pbin->cb > 24) {
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb,
		pbin->cb, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_xid(
		&ext_pull, pbin->cb, pxid)) {
		return FALSE;
	}
	return TRUE;
}

BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key)
{
	PCL *ppcl;
	SIZED_XID xid;
	BINARY *ptmp_bin;
	
	auto pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	ppcl = pcl_init();
	if (NULL == ppcl) {
		return NULL;
	}
	if (NULL != pbin_pcl) {
		if (FALSE == pcl_deserialize(ppcl, pbin_pcl)) {
			pcl_free(ppcl);
			return NULL;
		}
	}
	xid.size = pchange_key->cb;
	if (FALSE == common_util_binary_to_xid(pchange_key, &xid.xid)) {
		pcl_free(ppcl);
		return NULL;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		return NULL;
	}
	ptmp_bin = pcl_serialize(ppcl);
	pcl_free(ppcl);
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

BOOL common_util_copy_file(const char *src_file, const char *dst_file)
{
	struct stat node_stat;
	wrapfd fd = open(src_file, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
		return false;
	auto pbuff = me_alloc<char>(node_stat.st_size);
	if (NULL == pbuff) {
		return FALSE;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size) {
		free(pbuff);
		return FALSE;
	}
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (fd.get() < 0) {
		free(pbuff);
		return FALSE;
	}
	write(fd.get(), pbuff, node_stat.st_size);
	free(pbuff);
	return TRUE;
}


BOOL common_util_bind_sqlite_statement(sqlite3_stmt *pstmt,
	int bind_index, uint16_t proptype, void *pvalue)
{
	EXT_PUSH ext_push;
	char temp_buff[256];
	
	if (NULL == pvalue) {
		return FALSE;
	}
	switch (proptype) {
	case PT_STRING8:
	case PT_UNICODE:
		sqlite3_bind_text(pstmt, bind_index, static_cast<char *>(pvalue), -1, SQLITE_STATIC);
		break;
	case PT_FLOAT:
		sqlite3_bind_double(pstmt, bind_index, *(float*)pvalue);
		break;
	case PT_DOUBLE:
	case PT_APPTIME:
		sqlite3_bind_double(pstmt, bind_index, *(double*)pvalue);
		break;
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		sqlite3_bind_int64(pstmt, bind_index, *(uint64_t*)pvalue);
		break;
	case PT_SHORT:
		sqlite3_bind_int64(pstmt, bind_index, *(uint16_t*)pvalue);
		break;
	case PT_LONG:
		sqlite3_bind_int64(pstmt, bind_index, *(uint32_t*)pvalue);
		break;
	case PT_BOOLEAN:
		sqlite3_bind_int64(pstmt, bind_index, *(uint8_t*)pvalue);
		break;
	case PT_CLSID:
		if (!ext_buffer_push_init(&ext_push, temp_buff, 16, 0) ||
		    ext_buffer_push_guid(&ext_push, static_cast<GUID *>(pvalue)) != EXT_ERR_SUCCESS)
			return FALSE;
		sqlite3_bind_blob(pstmt, bind_index, ext_push.data,
							ext_push.offset, SQLITE_STATIC);
		break;
	case PT_SVREID:
		if (!ext_buffer_push_init(&ext_push, temp_buff, 256, 0) ||
		    ext_buffer_push_svreid(&ext_push,
		    static_cast<SVREID *>(pvalue)) != EXT_ERR_SUCCESS)
			return FALSE;
		sqlite3_bind_blob(pstmt, bind_index, ext_push.data,
							ext_push.offset, SQLITE_STATIC);
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
	
	if (SQLITE_NULL == sqlite3_column_type(pstmt, column_index)) {
		return NULL;
	}
	switch (proptype) {
	case PT_STRING8:
	case PT_UNICODE:
		pvalue = (void*)sqlite3_column_text(pstmt, column_index);
		if (NULL == pvalue) {
			return NULL;
		}
		return common_util_dup(static_cast<char *>(pvalue));
	case PT_FLOAT:
		pvalue = cu_alloc<float>();
		if (NULL == pvalue) {
			return NULL;
		}
		*(float*)pvalue = sqlite3_column_double(
							pstmt, column_index);
		return pvalue;
	case PT_DOUBLE:
	case PT_APPTIME:
		pvalue = cu_alloc<double>();
		if (NULL == pvalue) {
			return NULL;
		}
		*(double*)pvalue = sqlite3_column_double(
							pstmt, column_index);
		return pvalue;
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		pvalue = cu_alloc<uint64_t>();
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint64_t*)pvalue = sqlite3_column_int64(
							pstmt, column_index);
		return pvalue;
	case PT_SHORT:
		pvalue = cu_alloc<uint16_t>();
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint16_t*)pvalue = sqlite3_column_int64(
							pstmt, column_index);
		return pvalue;
	case PT_LONG:
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint32_t*)pvalue = sqlite3_column_int64(
							pstmt, column_index);
		return pvalue;
	case PT_BOOLEAN:
		pvalue = cu_alloc<uint8_t>();
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint8_t*)pvalue = sqlite3_column_int64(
							pstmt, column_index);
		return pvalue;
	case PT_CLSID:
		pvalue = (void*)sqlite3_column_blob(pstmt, column_index);
		if (NULL == pvalue) {
			return NULL;
		}
		ext_buffer_pull_init(&ext_pull, pvalue,
			sqlite3_column_bytes(pstmt, column_index),
			common_util_alloc, 0);
		pvalue = cu_alloc<GUID>();
		if (NULL == pvalue) {
			return NULL;
		}
		if (ext_buffer_pull_guid(&ext_pull,
		    static_cast<GUID *>(pvalue)) != EXT_ERR_SUCCESS)
			return NULL;
		return pvalue;
	case PT_SVREID:
		pvalue = (void*)sqlite3_column_blob(pstmt, column_index);
		if (NULL == pvalue) {
			return NULL;
		}
		ext_buffer_pull_init(&ext_pull, pvalue,
			sqlite3_column_bytes(pstmt, column_index),
			common_util_alloc, 0);
		pvalue = cu_alloc<SVREID>();
		if (NULL == pvalue) {
			return NULL;
		}
		if (ext_buffer_pull_svreid(&ext_pull,
		    static_cast<SVREID *>(pvalue)) != EXT_ERR_SUCCESS)
			return NULL;
		return pvalue;
	case PT_OBJECT:
	case PT_BINARY: {
		if (sqlite3_column_bytes(pstmt, column_index) > 512) {
			return NULL;
		}
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return NULL;
		}
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
	
	while (TRUE) {
		(*pidx) ++;
		row_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_bind_int64(pstmt1, 1, *pidx);
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			return FALSE;
		}
		sqlite3_reset(pstmt1);
		if (step > 0 && 0 != sqlite3_column_int64(pstmt, 1)) {
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, -row_id);
			if (SQLITE_ROW == sqlite3_step(pstmt)) {
				if (FALSE == common_util_indexing_sub_contents(
					step - 1, pstmt, pstmt1, pidx)) {
					return FALSE;	
				}
			}
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, row_id);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			return TRUE;
		}
	}
}

static uint32_t common_util_get_cid_string_length(uint32_t cid)
{
	int length;
	char path[256];
	const char *dir;
	struct stat node_stat;
	
	dir = exmdb_server_get_dir();
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	wrapfd fd = open(path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
	    read(fd.get(), &length, sizeof(int)) != sizeof(int))
		return 0;
	return 2*length;
}

static uint32_t common_util_get_cid_length(uint64_t cid)
{
	char path[256];
	const char *dir;
	struct stat node_stat;
	
	dir = exmdb_server_get_dir();
	snprintf(path, sizeof(path), "%s/cid/%llu", dir, LLU(cid));
	if (0 != stat(path, &node_stat)) {
		return 0;
	}
	return node_stat.st_size;
}

uint32_t common_util_calculate_message_size(
	const MESSAGE_CONTENT *pmsgctnt)
{
	uint32_t tmp_len;
	uint32_t message_size;
	TAGGED_PROPVAL *ppropval;
	ATTACHMENT_CONTENT *pattachment;
	
	/* PROP_TAG_ASSOCIATED, PROP_TAG_MID, PROP_TAG_CHANGENUMBER */
	message_size = sizeof(uint8_t) + 2*sizeof(uint64_t);
	for (size_t i = 0; i < pmsgctnt->proplist.count; ++i) {
		ppropval = pmsgctnt->proplist.ppropval + i;
		switch (ppropval->proptag) {
		case PROP_TAG_ASSOCIATED:
		case PROP_TAG_MID:
		case PROP_TAG_CHANGENUMBER:
			continue;
		case ID_TAG_BODY:
			message_size += common_util_get_cid_string_length(
								*(uint64_t*)ppropval->pvalue);
			break;
		case ID_TAG_BODY_STRING8:
			tmp_len = common_util_get_cid_length(
					*(uint64_t*)ppropval->pvalue);
			if (tmp_len > 0) {
				message_size += tmp_len - 1;
			}
			break;
		case ID_TAG_HTML:
		case ID_TAG_RTFCOMPRESSED:
			message_size += common_util_get_cid_length(
						*(uint64_t*)ppropval->pvalue);
			break;
		case ID_TAG_TRANSPORTMESSAGEHEADERS:
			message_size += common_util_get_cid_string_length(
								*(uint64_t*)ppropval->pvalue);
			break;
		case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
			tmp_len = common_util_get_cid_length(
					*(uint64_t*)ppropval->pvalue);
			if (tmp_len > 0) {
				message_size += tmp_len - 1;
			}
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
				if (PROP_TAG_ROWID == ppropval->proptag) {
					continue;
				}
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
				case PROP_TAG_ATTACHNUMBER:
					continue;
				case ID_TAG_ATTACHDATABINARY:
				case ID_TAG_ATTACHDATAOBJECT:
					message_size += common_util_get_cid_length(
								*(uint64_t*)ppropval->pvalue);
					break;
				default:
					message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
				}
			}
			if (NULL != pattachment->pembedded) {
				message_size += common_util_calculate_message_size(
											pattachment->pembedded);
			}
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
		case PROP_TAG_ATTACHNUMBER:
			continue;
		case ID_TAG_ATTACHDATABINARY:
		case ID_TAG_ATTACHDATAOBJECT:
			attachment_size += common_util_get_cid_length(
						*(uint64_t*)ppropval->pvalue);
			break;
		default:
			attachment_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
		}
	}
	if (NULL != pattachment->pembedded) {
		attachment_size += common_util_calculate_message_size(
										pattachment->pembedded);
	}
	return attachment_size;
}
