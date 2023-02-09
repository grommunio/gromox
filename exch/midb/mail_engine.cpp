// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iconv.h>
#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/database.h>
#include <gromox/dbop.h>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/midb.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/mjson.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "cmd_parser.h"
#include "common_util.h"
#include "exmdb_client.h"
#include "mail_engine.hpp"
#include "system_services.hpp"
#define FILENUM_PER_MIME				8
#define MAX_DIGLEN						256*1024
#define RELOAD_INTERVAL					3600
#define MAX_DB_WAITING_THREADS			5

using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

enum {
	CONFIG_ID_USERNAME = 1, /* obsolete */
};

enum class midb_cond {
	x_none, all, answered, bcc, before, body, cc, deleted, draft, flagged, from,
	header, id, keyword, larger, is_new, old, on, recent, seen,
	sent_before, sent_on, sent_since, since, smaller, subject, text, to,
	uid, unanswered, undeleted, undraft, unflagged, unkeyword, unseen,
};

enum class midb_conj {
	c_and, c_or, c_not,
};

namespace {

struct ct_node;
using CONDITION_TREE = std::vector<ct_node>;
struct ct_node {
	ct_node() = default;
	ct_node(ct_node &&);
	~ct_node();
	void operator=(ct_node &&) = delete;

	CONDITION_TREE *pbranch = nullptr;
	enum midb_conj conjunction = midb_conj::c_and;
	enum midb_cond condition = midb_cond::x_none;

	union {
		char *ct_headers[2];
		char *ct_keyword;
		time_t ct_time;
		size_t ct_size;
		std::vector<seq_node> *ct_seq;
	};
};
using CONDITION_TREE_NODE = ct_node;

struct KEYWORD_ENUM {
	MJSON *pjson;
	BOOL b_result;
	const char *charset;
	const char *keyword;
};

struct IDB_ITEM {
	IDB_ITEM() = default;
	~IDB_ITEM();
	NOMOVE(IDB_ITEM);

	sqlite3 *psqlite = nullptr;
	/* client reference count, item can be flushed into file system only count is 0 */
	std::string username;
	time_t last_time = 0, load_time = 0;
	uint32_t sub_id = 0;
	std::atomic<int> reference{0};
	std::timed_mutex lock;
};

struct idb_item_del {
	void operator()(IDB_ITEM *);
};

}

using IDB_REF = std::unique_ptr<IDB_ITEM, idb_item_del>;

enum {
	FIELD_NONE = 0,
	FIELD_UID,
	FIELD_RECEIVED,
	FIELD_SUBJECT,
	FIELD_FROM,
	FIELD_RCPT,
	FIELD_SIZE,
	FIELD_READ,
	FIELD_FLAG
};


unsigned int g_midb_schema_upgrades;
unsigned int g_midb_cache_interval, g_midb_reload_interval;

static constexpr auto DB_LOCK_TIMEOUT = std::chrono::seconds(60);
static BOOL g_wal;
static BOOL g_async;
static int g_mime_num;
static size_t g_table_size;
static std::atomic<unsigned int> g_sequence_id;
static gromox::atomic_bool g_notify_stop; /* stop signal for scanning thread */
static uint64_t g_mmap_size;
static pthread_t g_scan_tid;
static char g_org_name[256];
static std::shared_ptr<MIME_POOL> g_mime_pool;
static alloc_limiter<MJSON_MIME> g_alloc_mjson{"g_alloc_mjson.d"};
static char g_default_charset[32];
static std::mutex g_hash_lock;
static std::unordered_map<std::string, IDB_ITEM> g_hash_table;

static std::unique_ptr<std::vector<seq_node>> ct_parse_seq(char *);
static BOOL ct_hint_seq(const std::vector<seq_node> &plist, unsigned int num, unsigned int max_uid);

template<typename T> static inline bool
array_find_str(const T &kwlist, const char *s)
{
	for (const auto kw : kwlist)
		if (strcmp(s, kw) == 0)
			return true;
	return false;
}

template<typename T> static inline bool
array_find_istr(const T &kwlist, const char *s)
{
	for (const auto kw : kwlist)
		if (strcasecmp(s, kw) == 0)
			return true;
	return false;
}

static std::unique_ptr<char[]> mail_engine_ct_to_utf8(const char *charset,
    const char *string) try
{
	int length;
	iconv_t conv_id;
	size_t in_len, out_len;

	if (strcasecmp(charset, "UTF-8") == 0||
	    strcasecmp(charset, "US-ASCII") == 0)
		return std::unique_ptr<char[]>(strdup(string));
	cset_cstr_compatible(charset);
	length = strlen(string) + 1;
	auto ret_string = std::make_unique<char[]>(2 * length);
	conv_id = iconv_open("UTF-8", charset);
	if (conv_id == (iconv_t)-1)
		return NULL;
	auto pin = deconst(string);
	auto pout = ret_string.get();
	in_len = length;
	out_len = 2*length;
	if (iconv(conv_id, &pin, &in_len, &pout, &out_len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return NULL;
	}
	iconv_close(conv_id);
	return ret_string;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1963: ENOMEM");
	return nullptr;
}

static uint64_t mail_engine_get_digest(sqlite3 *psqlite,
	const char *mid_string, char *digest_buff)
{
	size_t size;
	int tmp_len;
	char *ptoken;
	uint64_t folder_id;
	char temp_path[256];
	struct stat node_stat;
	
	snprintf(temp_path, 256, "%s/ext/%s",
		common_util_get_maildir(), mid_string);
	wrapfd fd = open(temp_path, O_RDONLY);
	if (fd.get() < 0) {
		snprintf(temp_path, 256, "%s/eml/%s",
			common_util_get_maildir(), mid_string);
		fd = open(temp_path, O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) < 0) {
			mlog(LV_ERR, "E-1252: %s: %s", temp_path, strerror(errno));
			return 0;
		}
		if (!S_ISREG(node_stat.st_mode))
			return 0;
		std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(node_stat.st_size));
		if (pbuff == nullptr)
			return 0;
		if (HXio_fullread(fd.get(), pbuff.get(), node_stat.st_size) != node_stat.st_size)
			return 0;
		fd.close_rd();
		MAIL imail(g_mime_pool);
		if (!imail.load_from_str_move(pbuff.get(), node_stat.st_size))
			return 0;
		tmp_len = sprintf(digest_buff, "{\"file\":\"\",");
		if (imail.get_digest(&size, digest_buff + tmp_len,
		    MAX_DIGLEN - tmp_len - 1) <= 0)
			return 0;
		imail.clear();
		pbuff.reset();
		tmp_len = strlen(digest_buff);
		strcpy(&digest_buff[tmp_len], "}");
		tmp_len ++;
		snprintf(temp_path, 256, "%s/ext/%s",
			common_util_get_maildir(), mid_string);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (fd.get() >= 0) {
			if (HXio_fullwrite(fd.get(), digest_buff, tmp_len) != tmp_len ||
			    fd.close_wr() < 0)
				mlog(LV_ERR, "E-2082: write %s: %s", temp_path, strerror(errno));
		}
	} else {
		if (fstat(fd.get(), &node_stat) != 0 || !S_ISREG(node_stat.st_mode) ||
		    node_stat.st_size >= MAX_DIGLEN)
			return 0;
		fd = open(temp_path, O_RDONLY);
		if (fd.get() < 0 || HXio_fullread(fd.get(), digest_buff,
		    node_stat.st_size) != node_stat.st_size)
			return 0;
		digest_buff[node_stat.st_size] = '\0';
		fd.close_rd();
	}
	auto pstmt = gx_sql_prep(psqlite, "SELECT uid, recent, read,"
	             " unsent, flagged, replied, forwarded, deleted, ext,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return 0;
	sqlite3_bind_text(pstmt, 1, mid_string, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return 0;
	folder_id = sqlite3_column_int64(pstmt, 9);
	set_digest(digest_buff, MAX_DIGLEN, "file", mid_string);
	set_digest(digest_buff, MAX_DIGLEN, "uid", pstmt.col_int64(0));
	set_digest(digest_buff, MAX_DIGLEN, "recent", pstmt.col_int64(1));
	set_digest(digest_buff, MAX_DIGLEN, "read", pstmt.col_int64(2));
	set_digest(digest_buff, MAX_DIGLEN, "unsent", pstmt.col_int64(3));
	set_digest(digest_buff, MAX_DIGLEN, "flag", pstmt.col_int64(4));
	set_digest(digest_buff, MAX_DIGLEN, "replied", pstmt.col_int64(5));
	set_digest(digest_buff, MAX_DIGLEN, "forwarded", pstmt.col_int64(6));
	set_digest(digest_buff, MAX_DIGLEN, "deleted", pstmt.col_int64(7));
	if (sqlite3_column_type(pstmt, 8) == SQLITE_NULL)
		return folder_id;
	auto pext = pstmt.col_text(8);
	ptoken = strrchr(digest_buff, '}');
	if (ptoken == nullptr)
		return 0;
	*ptoken = ',';
	if (ptoken + 1 - digest_buff + strlen(pext + 1) >= MAX_DIGLEN)
		return 0;
	strcpy(ptoken + 1, pext + 1);
	return folder_id;
}

static std::unique_ptr<char[]> mail_engine_ct_decode_mime(const char *charset,
    const char *mime_string) try
{
	int i, buff_len;
	int offset;
	int last_pos, begin_pos, end_pos;
	ENCODE_STRING encode_string;
	char temp_buff[1024];

	buff_len = strlen(mime_string);
	auto ret_string = std::make_unique<char[]>(2 * (buff_len + 1));
	auto in_buff = deconst(mime_string);
	auto out_buff = ret_string.get();
	offset = 0;
	begin_pos = -1;
	end_pos = -1;
	last_pos = 0;
	for (i=0; i<buff_len-1&&offset<2*buff_len+1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				memcpy(temp_buff, in_buff + last_pos, begin_pos - last_pos);
				temp_buff[begin_pos - last_pos] = '\0';
				HX_strltrim(temp_buff);
				auto tmp_string = mail_engine_ct_to_utf8(charset, temp_buff);
				if (tmp_string == nullptr)
					return NULL;
				auto tmp_len = strlen(tmp_string.get());
				memcpy(out_buff + offset, tmp_string.get(), tmp_len);
				offset += tmp_len;
				last_pos = i;
			}
		}
		if (end_pos == -1 && begin_pos != -1 && in_buff[i] == '?' &&
		    in_buff[i+1] == '=' && ((in_buff[i-1] != 'q' &&
		    in_buff[i-1] != 'Q') || in_buff[i-2] != '?'))
			end_pos = i + 1;
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			auto tmp_len = strlen(encode_string.title);
			std::unique_ptr<char[]> tmp_string;
			if (0 == strcmp(encode_string.encoding, "base64")) {
				size_t decode_len = 0;
				decode64(encode_string.title, tmp_len,
				         temp_buff, arsizeof(temp_buff), &decode_len);
				temp_buff[decode_len] = '\0';
				tmp_string = mail_engine_ct_to_utf8(encode_string.charset, temp_buff);
			} else if (0 == strcmp(encode_string.encoding, "quoted-printable")){
				auto decode_len = qp_decode_ex(temp_buff, arsizeof(temp_buff),
				                  encode_string.title, tmp_len);
				if (decode_len < 0)
					return NULL;
				temp_buff[decode_len] = '\0';
				tmp_string = mail_engine_ct_to_utf8(encode_string.charset, temp_buff);
			} else {
				tmp_string = mail_engine_ct_to_utf8(charset, encode_string.title);
			}
			if (tmp_string == nullptr)
				return NULL;
			tmp_len = strlen(tmp_string.get());
			memcpy(out_buff + offset, tmp_string.get(), tmp_len);
			offset += tmp_len;
			
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos) {
		auto tmp_string = mail_engine_ct_to_utf8(charset, in_buff + last_pos);
		if (tmp_string == nullptr)
			return NULL;
		auto tmp_len = strlen(tmp_string.get());
		memcpy(out_buff + offset, tmp_string.get(), tmp_len);
		offset += tmp_len;
	} 
	out_buff[offset] = '\0';
	return ret_string;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1968: ENOMEM");
	return nullptr;
}

static void mail_engine_ct_enum_mime(MJSON_MIME *pmime, void *param) try
{
	auto penum = static_cast<KEYWORD_ENUM *>(param);
	size_t length;
	size_t temp_len;
	const char *charset;
	const char *filename;
	
	if (penum->b_result || pmime->get_mtype() != mime_type::single)
		return;

	if (strncmp(pmime->get_ctype(), "text/", 5) != 0) {
		filename = pmime->get_filename();
		if ('\0' != filename[0]) {
			auto rs = mail_engine_ct_decode_mime(penum->charset, filename);
			if (rs != nullptr &&
			    search_string(rs.get(), penum->keyword,
			    strlen(rs.get())) != nullptr)
				penum->b_result = TRUE;
		}
	}
	length = pmime->get_length(MJSON_MIME_CONTENT);
	auto pbuff = std::make_unique<char[]>(2 * length + 1);
	auto fd = penum->pjson->seek_fd(pmime->get_id(), MJSON_MIME_CONTENT);
	if (fd == -1)
		return;
	auto read_len = HXio_fullread(fd, pbuff.get(), length);
	if (read_len < 0 || static_cast<size_t>(read_len) != length)
		return;
	if (strcasecmp(pmime->get_encoding(), "base64") == 0) {
		if (decode64_ex(pbuff.get(), length, &pbuff[length],
		    length, &temp_len) != 0)
			return;
		pbuff[length + temp_len] = '\0';
	} else if (strcasecmp(pmime->get_encoding(), "quoted-printable") == 0) {
		auto xl = qp_decode_ex(&pbuff[length], length, pbuff.get(), length);
		if (xl < 0)
			return;
		temp_len = xl;
		pbuff[length + temp_len] = '\0';
	} else {
		memcpy(&pbuff[length], pbuff.get(), length);
		pbuff[2*length] = '\0';
	}

	charset = pmime->get_charset();
	auto rs = mail_engine_ct_to_utf8(*charset != '\0' ?
	          charset : penum->charset, &pbuff[length]);
	if (rs != nullptr && search_string(rs.get(), penum->keyword,
	    strlen(rs.get())) != nullptr)
		penum->b_result = TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1970: ENOMEM");
}

static BOOL mail_engine_ct_search_head(const char *charset,
	const char *file_path, const char *tag, const char *value)
{
	FILE * fp;
	BOOL stat_head;
	size_t head_offset = 0, offset = 0, len;
	MIME_FIELD mime_field;
	char head_buff[64*1024];
	
	stat_head = FALSE;
	fp = fopen(file_path, "r");
	if (fp == nullptr)
		return FALSE;
	while (NULL != fgets(head_buff + head_offset,
		64*1024 - head_offset, fp)) {
		len = strlen(head_buff + head_offset);
		head_offset += len;
		
		if (head_offset >= 64*1024 - 1)
			break;
		if (2 == len && 0 == strcmp("\r\n", head_buff + head_offset - 2)) {
			stat_head = TRUE;
			break;
		}
	}
	fclose(fp);
	if (!stat_head)
		return FALSE;

	while ((len = parse_mime_field(head_buff + offset,
	       head_offset - offset, &mime_field)) != 0) {
		offset += len;
		if (strcasecmp(tag, mime_field.name.c_str()) != 0)
			continue;
		auto rs = mail_engine_ct_decode_mime(charset, mime_field.value.c_str());
		if (rs != nullptr &&
		    search_string(rs.get(), value, strlen(rs.get())))
			return TRUE;
	}
	return FALSE;
}

static BOOL mail_engine_ct_match_mail(sqlite3 *psqlite, const char *charset,
    sqlite3_stmt *pstmt_message, const char *mid_string, int id, int total_mail,
    uint32_t uidnext, const CONDITION_TREE *ptree)
{
	int sp = 0;
	BOOL b_loaded;
	BOOL b_result;
	BOOL b_result1;
	midb_conj conjunction;
	time_t tmp_time;
	size_t temp_len;
	int results[1024];
	char temp_buff[1024];
	char temp_buff1[1024];
	midb_conj conjunctions[1024];
	KEYWORD_ENUM keyword_enum;
	const CONDITION_TREE *trees[1024];
	CONDITION_TREE::const_iterator pnode, nodes[1024];
	char digest_buff[MAX_DIGLEN];
	
#define PUSH_MATCH(TREE, NODE, CONJUNCTION, RESULT) \
		{trees[sp]=TREE;nodes[sp]=NODE;conjunctions[sp]=CONJUNCTION;results[sp]=RESULT;sp++;}
	
#define POP_MATCH(TREE, NODE, CONJUNCTION, RESULT) \
		{sp--;TREE=trees[sp];NODE=nodes[sp];CONJUNCTION=conjunctions[sp];RESULT=results[sp];}

/* begin of recursion procedure */
	while (true) {
 PROC_BEGIN:
	b_result = TRUE;
	b_loaded = FALSE;
	for (pnode = ptree->begin(); pnode != ptree->end(); ++pnode) {
		{
		auto ptree_node = &*pnode;
		conjunction = ptree_node->conjunction;
		if ((b_result && conjunction == midb_conj::c_or) ||
		    (!b_result && conjunction == midb_conj::c_and))
			continue;
		b_result1 = FALSE;
		if (NULL != ptree_node->pbranch) {
			PUSH_MATCH(ptree, pnode, conjunction, b_result)
			ptree = ptree_node->pbranch;
			goto PROC_BEGIN;
		} else {
			switch (ptree_node->condition) {
			case midb_cond::all:
			case midb_cond::keyword:
			case midb_cond::unkeyword:
				b_result1 = TRUE;
				break;
			case midb_cond::answered:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 7) != 0)
					b_result1 = TRUE;
				break;
			case midb_cond::bcc:
				/* we do not support BCC field in mail digest,
					BCC should not recorded in mail head */
				break;
			case midb_cond::before:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 10));
				if (tmp_time < ptree_node->ct_time)
					b_result1 = TRUE;
				break;
			case midb_cond::body: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string, digest_buff) == 0)
						break;
					b_loaded = TRUE;
				}
				MJSON temp_mjson(&g_alloc_mjson);
				snprintf(temp_buff, 256, "%s/eml",
						common_util_get_maildir());
				if (!temp_mjson.load_from_str_move(digest_buff, strlen(digest_buff), temp_buff))
					break;
				keyword_enum.pjson = &temp_mjson;
				keyword_enum.b_result = FALSE;
				keyword_enum.charset = charset;
				keyword_enum.keyword = ptree_node->ct_keyword;
				temp_mjson.enum_mime(mail_engine_ct_enum_mime, &keyword_enum);
				if (keyword_enum.b_result)
					b_result1 = TRUE;
				break;
			}
			case midb_cond::cc: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string, digest_buff) == 0)
						break;
					b_loaded = TRUE;
				}
				if (!get_digest(digest_buff, "cc", temp_buff, arsizeof(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = TRUE;
				break;
			}
			case midb_cond::deleted:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 9) != 0)
					b_result1 = TRUE;
				break;
			case midb_cond::draft:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 5) != 0)
					b_result1 = TRUE;
				break;
			case midb_cond::flagged:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 6) != 0)
					b_result1 = TRUE;
				break;
			case midb_cond::from: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string, digest_buff) == 0)
						break;
					b_loaded = TRUE;
				}
				if (!get_digest(digest_buff, "from", temp_buff, arsizeof(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = TRUE;
				break;
			}
			case midb_cond::header:
				snprintf(temp_buff1, 256, "%s/eml/%s",
					common_util_get_maildir(), mid_string);
				b_result1 = mail_engine_ct_search_head(charset,
					temp_buff1, ptree_node->ct_headers[0],
					ptree_node->ct_headers[1]);
				break;
			case midb_cond::id:
				b_result1 = ct_hint_seq(*ptree_node->ct_seq, id, total_mail);
				break;
			case midb_cond::larger:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (gx_sql_col_uint64(pstmt_message, 13) >
				    ptree_node->ct_size)
					b_result1 = TRUE;
				break;
			case midb_cond::is_new:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 3) != 0 &&
				    sqlite3_column_int64(pstmt_message, 4) == 0)
					b_result1 = TRUE;
				break;
			case midb_cond::old:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 3) == 0)
					b_result1 = TRUE;
				break;
			case midb_cond::on:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 10));
				if (tmp_time >= ptree_node->ct_time &&
				    tmp_time < ptree_node->ct_time + 86400)
					b_result1 = TRUE;
				break;
			case midb_cond::recent:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 3) != 0)
					b_result1 = TRUE;
				break;
			case midb_cond::seen:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 4) != 0)
					b_result1 = TRUE;
				break;
			case midb_cond::sent_before:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 1));
				if (tmp_time < ptree_node->ct_time)
					b_result1 = TRUE;
				break;
			case midb_cond::sent_on:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 1));
				if (tmp_time >= ptree_node->ct_time &&
				    tmp_time < ptree_node->ct_time + 86400)
					b_result1 = TRUE;
				break;
			case midb_cond::sent_since:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 1));
				if (tmp_time >= ptree_node->ct_time)
					b_result1 = TRUE;
				break;
			case midb_cond::since:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 10));
				if (tmp_time >= ptree_node->ct_time)
					b_result1 = TRUE;
				break;
			case midb_cond::smaller:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (gx_sql_col_uint64(pstmt_message, 13) < ptree_node->ct_size)
					b_result1 = TRUE;
				break;
			case midb_cond::subject: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite,
					    mid_string, digest_buff) == 0)
						break;
					b_loaded = TRUE;
				}
				if (!get_digest(digest_buff, "subject", temp_buff, arsizeof(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = TRUE;
				break;
			}
			case midb_cond::text: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite,
					    mid_string, digest_buff) == 0)
						break;
					b_loaded = TRUE;
				}
				if (get_digest(digest_buff, "cc", temp_buff, arsizeof(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = TRUE;
				}
				if (b_result1)
					break;
				if (get_digest(digest_buff, "from", temp_buff, arsizeof(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = TRUE;
				}
				if (b_result1)
					break;
				if (get_digest(digest_buff, "subject", temp_buff, arsizeof(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = TRUE;
				}
				if (b_result1)
					break;
				if (get_digest(digest_buff, "to", temp_buff, arsizeof(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = TRUE;
				}
				if (b_result1)
					break;
				MJSON temp_mjson(&g_alloc_mjson);
				snprintf(temp_buff, 256, "%s/eml",
						common_util_get_maildir());
				if (!temp_mjson.load_from_str_move(digest_buff, strlen(digest_buff), temp_buff))
					break;
				keyword_enum.pjson = &temp_mjson;
				keyword_enum.b_result = FALSE;
				keyword_enum.charset = charset;
				keyword_enum.keyword = ptree_node->ct_keyword;
				temp_mjson.enum_mime(mail_engine_ct_enum_mime, &keyword_enum);
				if (keyword_enum.b_result)
					b_result1 = TRUE;
				break;
			}
			case midb_cond::to: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite,
					    mid_string, digest_buff) == 0)
						break;
					b_loaded = TRUE;
				}
				if (!get_digest(digest_buff, "to", temp_buff, arsizeof(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, arsizeof(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = TRUE;
				break;
			}
			case midb_cond::unanswered:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 7) == 0)
					b_result1 = TRUE;
				break;
			case midb_cond::uid:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				b_result1 = ct_hint_seq(*ptree_node->ct_seq,
					sqlite3_column_int64(pstmt_message, 2),
					uidnext);
				break;
			case midb_cond::undeleted:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 9) == 0)
					b_result1 = TRUE;
				break;
			case midb_cond::undraft:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 5) == 0)
					b_result1 = TRUE;
				break;
			case midb_cond::unflagged:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 6) == 0)
					b_result1 = TRUE;
				break;
			case midb_cond::unseen:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (sqlite3_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, 4) == 0)
					b_result1 = TRUE;
				break;
			default:
				mlog(LV_DEBUG, "mail_engine: condition stat %u unknown!",
					static_cast<unsigned int>(ptree_node->condition));
				break;
			}
		}
		}
		
 RECURSION_POINT:
		switch (conjunction) {
		case midb_conj::c_and:
			b_result = (b_result&&b_result1)?TRUE:FALSE;
			break;
		case midb_conj::c_or:
			b_result = (b_result||b_result1)?TRUE:FALSE;
			break;
		case midb_conj::c_not:
			b_result = (b_result&&(!b_result1))?TRUE:FALSE;
			break;
		}
	}
	if (sp > 0) {
		b_result1 = b_result;
		POP_MATCH(ptree, pnode, conjunction, b_result)
		goto RECURSION_POINT;
	} else {
		return b_result;
	}
}
/* end of recursion procedure */

}

static int mail_engine_ct_compile_criteria(int argc,
	char **argv, int offset, char **argv_out)
{
	static constexpr const char *kwlist1[] =
		{"ALL", "ANSWERED", "DELETED", "DRAFT", "FLAGGED", "NEW",
		"OLD", "RECENT", "SEEN", "UNANSWERED", "UNDELETED", "UNDRAFT",
		"UNFLAGGED", "UNSEEN"};
	static constexpr const char *kwlist2[] =
		{"BCC", "BEFORE", "BODY", "CC", "FROM", "KEYWORD", "LARGER",
		"ON", "SENTBEFORE", "SENTON", "SENTSINCE", "SINCE", "SMALLER",
		"SUBJECT", "TEXT", "TO", "UID", "UNKEYWORD"};
	int i;
	int tmp_argc;
	int tmp_argc1;
	
	i = offset;
	if (argc < i + 1)
		return -1;
	argv_out[0] = argv[i];
	if (0 == strcasecmp(argv[i], "OR")) {
		i ++;
		if (argc < i + 1)
			return -1;
		tmp_argc = mail_engine_ct_compile_criteria(
						argc, argv, i, argv_out + 1);
		if (tmp_argc == -1)
			return -1;
		i += tmp_argc;
		if (argc < i + 1)
			return -1;
		tmp_argc1 = mail_engine_ct_compile_criteria(
			argc, argv, i, argv_out + 1 + tmp_argc);
		if (tmp_argc1 == -1)
			return -1;
		return tmp_argc + tmp_argc1 + 1;
	} else if (array_find_istr(kwlist1, argv[i])) {
		return 1;
	} else if (array_find_istr(kwlist2, argv[i])) {
		i ++;
		if (argc < i + 1)
			return -1;
		argv_out[1] = argv[i];
		return 2;
	} else if (0 == strcasecmp(argv[i], "HEADER")) {
		i ++;
		if (argc < i + 1)
			return -1;
		argv_out[1] = argv[i];
		i++;
		if (argc < i + 1)
			return -1;
		argv_out[2] = argv[i];
		return 3;
	} else if (0 == strcasecmp(argv[i], "NOT")) {
		i ++;
		if (argc < i + 1)
			return -1;
		tmp_argc = mail_engine_ct_compile_criteria(
						argc, argv, i, argv_out + 1);
		if (-1 == tmp_argc)
			return -1;
		return tmp_argc + 1;
	} else {
		/* <sequence set> or () as default */
		return 1;
	}
}

static inline bool cond_is_id(enum midb_cond x)
{
	return x == midb_cond::id || x == midb_cond::uid;
}

static inline bool cond_w_stmt(enum midb_cond x)
{
	return x == midb_cond::bcc || x == midb_cond::body ||
	       x == midb_cond::cc || x == midb_cond::from ||
	       x == midb_cond::keyword || x == midb_cond::subject ||
	       x == midb_cond::text || x == midb_cond::to ||
	       x == midb_cond::unkeyword;
}

ct_node::ct_node(ct_node &&o) :
	pbranch(o.pbranch), conjunction(o.conjunction), condition(o.condition)
{
	o.pbranch = nullptr;
	if (cond_is_id(condition)) {
		ct_seq = o.ct_seq;
		o.ct_seq = nullptr;
	} else if (cond_w_stmt(condition)) {
		ct_keyword = o.ct_keyword;
		o.ct_keyword = nullptr;
	} else if (condition == midb_cond::header) {
		ct_headers[0] = o.ct_headers[0];
		ct_headers[1] = o.ct_headers[1];
		o.ct_headers[0] = o.ct_headers[1] = nullptr;
	}
	o.condition = midb_cond::x_none;
}

ct_node::~ct_node()
{
	if (pbranch != nullptr) {
	} else if (cond_is_id(condition)) {
		delete ct_seq;
	} else if (cond_w_stmt(condition)) {
		free(ct_keyword);
	} else if (condition == midb_cond::header) {
		free(ct_headers[0]);
		free(ct_headers[1]);
	}
}

static enum midb_cond cond_str_to_cond(const char *s)
{
#define E(kw) if (strcasecmp(s, #kw) == 0) return midb_cond::kw
#define E2(a, kw) if (strcasecmp(s, #a) == 0) return midb_cond::kw
	E(all);
	E(answered);
	E(bcc);
	E(before);
	E(body);
	E(cc);
	E(deleted);
	E(draft);
	E(flagged);
	E(from);
	E(header);
	E(id);
	E(keyword);
	E(larger);
	E2(new, is_new);
	E(old);
	E(on);
	E(recent);
	E(seen);
	E2(sentbefore, sent_before);
	E2(senton, sent_on);
	E2(sentsince, sent_since);
	E(since);
	E(smaller);
	E(subject);
	E(text);
	E(to);
	E(uid);
	E(unanswered);
	E(undeleted);
	E(undraft);
	E(unflagged);
	E(unkeyword);
	E(unseen);
#undef E2
#undef E
	return midb_cond::x_none;
}

static std::unique_ptr<CONDITION_TREE> mail_engine_ct_build_internal(
    const char *charset, int argc, char **argv) try
{
	static constexpr const char *kwlist1[] =
		{"BCC", "BODY", "CC", "FROM", "KEYWORD", "SUBJECT", "TEXT",
		"TO", "UNKEYWORD"};
	static constexpr const char *kwlist2[] =
		{"BEFORE", "ON", "SENTBEFORE", "SENTON", "SENTSINCE", "SINCE"};
	static constexpr const char *kwlist3[] =
		{"ALL", "ANSWERED", "DELETED", "DRAFT", "FLAGGED", "NEW",
		"OLD", "RECENT", "SEEN", "UNANSWERED", "UNDELETED", "UNDRAFT",
		"UNFLAGGED", "UNSEEN"};
	int i, len;
	int tmp_argc;
	int tmp_argc1;
	struct tm tmp_tm;
	char* tmp_argv[256];
	auto plist = std::make_unique<CONDITION_TREE>();

	for (i=0; i<argc; i++) {
		ct_node ctn, *ptree_node = &ctn;
		ptree_node->pbranch = NULL;
		if (0 == strcasecmp(argv[i], "NOT")) {
			ptree_node->conjunction = midb_conj::c_not;
			i ++;
			if (i >= argc) {
				return {};
			}
		} else {
			ptree_node->conjunction = midb_conj::c_and;
		}
		if (array_find_istr(kwlist1, argv[i])) {
			ptree_node->condition = cond_str_to_cond(argv[i]);
			i ++;
			if (i + 1 > argc) {
				return {};
			}
			ptree_node->ct_keyword = mail_engine_ct_to_utf8(charset, argv[i]).release();
			if (ptree_node->ct_keyword == nullptr) {
				return {};
			}
		} else if (array_find_istr(kwlist2, argv[i])) {
			if (i + 1 > argc) {
				return {};
			}
			ptree_node->condition = cond_str_to_cond(argv[i]);
			i ++;
			if (i + 1 > argc) {
				return {};
			}
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL == strptime(argv[i], "%d-%b-%Y", &tmp_tm)) {
				return {};
			}
			ptree_node->ct_time = mktime(&tmp_tm);
		} else if ('(' == argv[i][0]) {
			len = strlen(argv[i]);
			argv[i][len - 1] = '\0';
			tmp_argc = parse_imap_args(argv[i] + 1,
				len - 2, tmp_argv, sizeof(tmp_argv));
			if (-1 == tmp_argc) {
				return {};
			}
			auto plist1 = mail_engine_ct_build_internal(
						charset, tmp_argc, tmp_argv);
			if (NULL == plist1) {
				return {};
			}
			ptree_node->pbranch = plist1.release();
		} else if (0 == strcasecmp(argv[i], "OR")) {
			i ++;
			if (i + 1 > argc) {
				return {};
			}
			tmp_argc = mail_engine_ct_compile_criteria(
								argc, argv, i, tmp_argv);
			if (-1 == tmp_argc) {
				return {};
			}
			i += tmp_argc;
			if (i + 1 > argc) {
				return {};
			}
			tmp_argc1 = mail_engine_ct_compile_criteria(
					argc, argv, i, tmp_argv + tmp_argc);
			if (-1 == tmp_argc1) {
				return {};
			}
			auto plist1 = mail_engine_ct_build_internal(charset,
							tmp_argc + tmp_argc1, tmp_argv);
			if (NULL == plist1) {
				return {};
			}
			if (plist1->size() != 2)
				return {};
			auto &ln = plist1->back();
			ln.conjunction = midb_conj::c_or;
			ln.pbranch = plist1.release();
			i += tmp_argc1 - 1;
		} else if (array_find_istr(kwlist3, argv[i])) {
			ptree_node->condition = cond_str_to_cond(argv[i]);
		} else if (0 == strcasecmp(argv[i], "HEADER")) {
			ptree_node->condition = midb_cond::header;
			i ++;
			if (i + 1 > argc) {
				return {};
			}
			ptree_node->ct_headers[0] = strdup(argv[i]);
			i ++;
			if (i + 1 > argc) {
				return {};
			}
			ptree_node->ct_headers[1] = strdup(argv[i]);
		} else if (0 == strcasecmp(argv[i], "LARGER") ||
			0 == strcasecmp(argv[i], "SMALLER")) {
			ptree_node->condition = strcasecmp(argv[i], "LARGER") == 0 ?
			                        midb_cond::larger : midb_cond::smaller;
			i ++;
			if (i + 1 > argc) {
				return {};
			}
			ptree_node->ct_size = strtol(argv[i], nullptr, 0);
		} else if (0 == strcasecmp(argv[i], "UID")) {
			ptree_node->condition = midb_cond::uid;
			i ++;
			if (i + 1 > argc) {
				return {};
			}
			auto plist1 = ct_parse_seq(argv[i]);
			if (NULL == plist1) {
				return {};
			}
			ptree_node->ct_seq = plist1.release();
		} else {
			auto plist1 = ct_parse_seq(argv[i]);
			if (NULL == plist1) {
				return {};
			}
			ptree_node->condition = midb_cond::id;
			ptree_node->ct_seq = plist1.release();
		}
		plist->push_back(std::move(ctn));
	}
	return plist;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1971: ENOMEM");
	return {};
}

static std::unique_ptr<CONDITION_TREE> mail_engine_ct_build(int argc, char **argv)
{
	if (strcasecmp(argv[0], "CHARSET") != 0)
		return mail_engine_ct_build_internal("UTF-8", argc, argv);
	if (argc < 3)
		return {};
	return mail_engine_ct_build_internal(argv[1], argc - 2, argv + 2);
}

static std::unique_ptr<std::vector<seq_node>> ct_parse_seq(char *string) try
{
	char *last_colon;
	char *last_break;
	
	auto len = strlen(string);
	if (string[len-1] == ',')
		len --;
	else
		string[len] = ',';
	auto plist = std::make_unique<std::vector<seq_node>>();
	last_break = string;
	last_colon = NULL;
	for (size_t i = 0; i <= len; ++i) {
		if (!HX_isdigit(string[i]) && string[i] != '*'
			&& ',' != string[i] && ':' != string[i]) {
			return NULL;
		}
		if (':' == string[i]) {
			if (NULL != last_colon) {
				return NULL;
			} else {
				last_colon = string + i;
				*last_colon = '\0';
			}
			continue;
		} else if (string[i] != ',') {
			continue;
		}
		if (string + i - last_break == 0)
			return NULL;
		string[i] = '\0';
		seq_node seq;
		if (last_colon == nullptr) {
			if (*last_break != '*') {
				seq.min = strtol(last_break, nullptr, 0);
				if (!seq.has_min())
					return NULL;
			}
			seq.max = seq.min;
		} else if (strcmp(last_break, "*") == 0) {
			if (strcmp(last_colon + 1, "*") != 0) {
				seq.min = strtol(last_colon + 1, nullptr, 0);
				if (!seq.has_min())
					return NULL;
			}
			last_colon = nullptr;
		} else {
			seq.min = strtol(last_break, nullptr, 0);
			if (!seq.has_min())
				return NULL;
			if (strcmp(last_colon + 1, "*") != 0) {
				seq.max = strtol(last_colon + 1, nullptr, 0);
				if (!seq.has_max())
					return NULL;
			}
			last_colon = nullptr;
		}
		last_break = string + i + 1;
		plist->push_back(std::move(seq));
	}
	return plist;
} catch (const std::bad_alloc &) {
	return nullptr;
}

static BOOL ct_hint_seq(const std::vector<seq_node> &list,
    unsigned int num, unsigned int max_uid)
{
	for (const auto &seq : list) {
		auto pseq = &seq;
		if (pseq->max == seq_node::unset) {
			if (pseq->min == seq_node::unset) {
				if (num == max_uid)
					return TRUE;
			} else {
				if (num >= pseq->min)
					return TRUE;
			}
		} else {
			if (pseq->max >= num && pseq->min <= num)
				return TRUE;
		}
	}
	return FALSE;
}

static std::optional<std::vector<int>> mail_engine_ct_match(const char *charset,
    sqlite3 *psqlite, uint64_t folder_id, const CONDITION_TREE *ptree,
    BOOL b_uid) try
{
	int i;
	uint32_t uid;
	int total_mail;
	uint32_t uidnext;
	char sql_string[1024];

	snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) "
	          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return {};
	total_mail = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT uidnext FROM"
	          " folders WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return {};
	uidnext = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	auto pstmt_message = gx_sql_prep(psqlite, "SELECT message_id, mod_time, "
	                     "uid, recent, read, unsent, flagged, replied, forwarded,"
	                     "deleted, received, ext, folder_id, size FROM messages "
	                     "WHERE mid_string=?");
	if (pstmt_message == nullptr)
		return {};
	snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string, uid FROM "
	          "messages WHERE folder_id=%llu ORDER BY uid", LLU{folder_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return {};
	i = 0;
	std::optional<std::vector<int>> presult;
	presult.emplace();
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		auto mid_string = pstmt.col_text(0);
		uid = sqlite3_column_int64(pstmt, 1);
		if (mail_engine_ct_match_mail(psqlite, charset, pstmt_message,
		    mid_string, i + 1, total_mail, uidnext, ptree))
			presult->push_back(b_uid ? uid : i + 1);
		i ++;
	}
	return presult;
} catch (const std::bad_alloc &) {
	return {};
}

static uint64_t mail_engine_get_folder_id(IDB_ITEM *pidb, const char *name)
{
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT "
	             "folder_id FROM folders WHERE name=?");
	if (pstmt == nullptr)
		return 0;
	sqlite3_bind_text(pstmt, 1, name, -1, SQLITE_STATIC);
	return sqlite3_step(pstmt) != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

static const char *field_to_col(unsigned int sf)
{
	switch (sf) {
	case FIELD_RECEIVED: return "received";
	case FIELD_SUBJECT: return "subject";
	case FIELD_FROM: return "sender";
	case FIELD_RCPT: return "rcpt";
	case FIELD_SIZE: return "size";
	case FIELD_READ: return "read";
	case FIELD_FLAG: return "flagged";
	default: return nullptr;
	}
}

static BOOL mail_engine_sort_folder(IDB_ITEM *pidb,
	const char *folder_name, int sort_field)
{
	uint32_t idx;
	uint64_t folder_id;
	char sql_string[1024];
	
	auto field_name = field_to_col(sort_field);
	if (field_name == nullptr) {
		field_name = "uid";
		sort_field = FIELD_UID;
	}
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " sort_field FROM folders WHERE name=?");
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, folder_name, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	folder_id = sqlite3_column_int64(pstmt, 0);
	if (sqlite3_column_int64(pstmt, 1) == sort_field)
		return TRUE;
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT message_id FROM messages"
	          " WHERE folder_id=%llu ORDER BY %s", LLU{folder_id}, field_name);
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	auto pstmt1 = gx_sql_prep(pidb->psqlite, "UPDATE messages"
	              " SET idx=? WHERE message_id=?");
	if (pstmt1 == nullptr)
		return FALSE;
	idx = 1;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, idx);
		sqlite3_bind_int64(pstmt1, 2,
			sqlite3_column_int64(pstmt, 0));
		if (sqlite3_step(pstmt1) != SQLITE_DONE)
			return FALSE;
		idx ++;
	}
	pstmt.finalize();
	pstmt1.finalize();
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET sort_field=%d "
	        "WHERE folder_id=%llu", sort_field, LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	return TRUE;
}

static void mail_engine_extract_digest_fields(const char *digest, char *subject,
    size_t subjsize, char *from, size_t fromsize, char *rcpt, size_t rcptsize,
    size_t *psize)
{
	size_t out_len;
	char temp_buff[64*1024];
	char temp_buff1[64*1024];
	EMAIL_ADDR temp_address;
	
	subject[0] = '\0';
	if (get_digest(digest, "subject", temp_buff, arsizeof(temp_buff)) &&
	    decode64(temp_buff, strlen(temp_buff), subject, subjsize, &out_len) != 0)
		/* Decode failed */
		subject[0] = '\0';
	from[0] = '\0';
	if (get_digest(digest, "from", temp_buff, arsizeof(temp_buff)) &&
	    decode64(temp_buff, strlen(temp_buff), temp_buff1,
	    arsizeof(temp_buff1), &out_len) == 0) {
		memset(&temp_address, 0, sizeof(temp_address));
		parse_email_addr(&temp_address, temp_buff1);
		snprintf(from, fromsize, "%s@%s",
		         temp_address.local_part, temp_address.domain);
	}
	rcpt[0] = '\0';
	if (get_digest(digest, "to", temp_buff, arsizeof(temp_buff)) &&
	    decode64(temp_buff, strlen(temp_buff), temp_buff1,
	    arsizeof(temp_buff1), &out_len) == 0) {
		for (size_t i = 0; i < out_len; ++i) {
			if (',' == temp_buff1[i] ||
			    ';' == temp_buff1[i]) {
				temp_buff1[i] = '\0';
				break;
			}
		}
		HX_strrtrim(temp_buff1);
		memset(&temp_address, 0, sizeof(temp_address));
		parse_email_addr(&temp_address, temp_buff1);
		snprintf(rcpt, rcptsize, "%s@%s",
		         temp_address.local_part, temp_address.domain);
	}
	*psize = 0;
	if (get_digest(digest, "size", temp_buff, arsizeof(temp_buff)))
		*psize = strtoull(temp_buff, nullptr, 0);
}

static void mail_engine_insert_message(sqlite3_stmt *pstmt,
	uint32_t *puidnext, uint64_t message_id, const char *mid_string,
	uint32_t message_flags, uint64_t received_time, uint64_t mod_time)
{
	size_t size;
	int tmp_len;
	char from[UADDR_SIZE], rcpt[UADDR_SIZE];
	const char *dir;
	char subject[1024];
	char temp_path[256];
	char temp_path1[256];
	char mid_string1[128];
	struct stat node_stat;
	MESSAGE_CONTENT *pmsgctnt;
	char temp_buff[MAX_DIGLEN];
	
	temp_path[0] = '\0';
	temp_path1[0] = '\0';
	dir = common_util_get_maildir();
	if (NULL != mid_string) {
		sprintf(temp_path, "%s/ext/%s", dir, mid_string);
		wrapfd fd = open(temp_path, O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
		    node_stat.st_size >= MAX_DIGLEN ||
		    HXio_fullread(fd.get(), temp_buff,
		    node_stat.st_size) != node_stat.st_size)
			return;
		temp_buff[node_stat.st_size] = '\0';
	} else {
		if (!common_util_switch_allocator())
			return;
		if (!exmdb_client::read_message(dir, NULL, 0,
			rop_util_make_eid_ex(1, message_id), &pmsgctnt)) {
			common_util_switch_allocator();
			return;
		}
		if (NULL == pmsgctnt) {
			common_util_switch_allocator();
			return;
		}
		MAIL imail;
		if (!oxcmail_export(pmsgctnt, false, oxcmail_body::plain_and_html,
		    g_mime_pool, &imail, common_util_alloc,
		    common_util_get_propids, common_util_get_propname)) {
			common_util_switch_allocator();
			return;
		}
		common_util_switch_allocator();
		tmp_len = sprintf(temp_buff, "{\"file\":\"\",");
		if (imail.get_digest(&size, temp_buff + tmp_len,
		    MAX_DIGLEN - tmp_len - 1) <= 0)
			return;
		tmp_len = strlen(temp_buff);
		strcpy(&temp_buff[tmp_len], "}");
		tmp_len ++;
		snprintf(mid_string1, arsizeof(mid_string1), "%lld.%u.midb",
		         static_cast<long long>(time(nullptr)), ++g_sequence_id);
		mid_string = mid_string1;
		sprintf(temp_path, "%s/ext/%s", dir, mid_string1);
		wrapfd fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (fd.get() < 0)
			return;
		if (HXio_fullwrite(fd.get(), temp_buff, tmp_len) != tmp_len ||
		    fd.close_wr() < 0)
			return;
		sprintf(temp_path1, "%s/eml/%s", dir, mid_string1);
		fd = open(temp_path1, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (fd.get() < 0)
			return;
		if (!imail.to_file(fd.get()))
			return;
	}
	(*puidnext) ++;
	auto b_unsent = !!(message_flags & MSGFLAG_UNSENT);
	auto b_read   = !!(message_flags & MSGFLAG_READ);
	mail_engine_extract_digest_fields(temp_buff, subject, arsizeof(subject),
		from, arsizeof(from), rcpt, arsizeof(rcpt), &size);
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_text(pstmt, 2, mid_string, -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 3, mod_time);
	sqlite3_bind_int64(pstmt, 4, *puidnext);
	sqlite3_bind_int64(pstmt, 5, b_unsent);
	sqlite3_bind_int64(pstmt, 6, b_read);
	sqlite3_bind_text(pstmt, 7, subject, -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 8, from, -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 9, rcpt, -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 10, size);
	sqlite3_bind_int64(pstmt, 11, received_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		mlog(LV_ERR, "E-2075: sqlite_step not finished");
}

static void mail_engine_sync_message(IDB_ITEM *pidb,
	sqlite3_stmt *pstmt, sqlite3_stmt *pstmt1, uint32_t *puidnext,
	uint64_t message_id, uint64_t received_time, const char *mid_string,
	const char *mid_string1, uint64_t mod_time, uint64_t mod_time1,
	uint32_t message_flags, uint8_t b_unsent, uint8_t b_read)
{
	char sql_string[256];
	
	if (NULL != mid_string || mod_time <= mod_time1) {
		auto b_unsent1 = !!(message_flags & MSGFLAG_UNSENT);
		auto b_read1   = !!(message_flags & MSGFLAG_READ);
		if (b_unsent != b_unsent1 || b_read != b_read1) {
			sqlite3_reset(pstmt1);
			sqlite3_bind_int64(pstmt1, 1, b_unsent1);
			sqlite3_bind_int64(pstmt1, 2, b_read1);
			sqlite3_bind_int64(pstmt1, 3, message_id);
			if (sqlite3_step(pstmt1) != SQLITE_DONE)
				return;
		}
		return;
	}
	snprintf(sql_string, arsizeof(sql_string), "DELETE FROM messages"
	        " WHERE message_id=%llu", LLU{message_id});
	if (gx_sql_exec(pidb->psqlite, sql_string) != SQLITE_OK)
		return;	
	mail_engine_insert_message(pstmt, puidnext, message_id,
			NULL, message_flags, received_time, mod_time);
}

static BOOL mail_engine_sync_contents(IDB_ITEM *pidb, uint64_t folder_id) try
{
	const char *dir;
	TARRAY_SET rows;
	sqlite3 *psqlite;
	uint32_t uidnext;
	uint32_t uidnext1;
	char sql_string[1024];
	
	dir = common_util_get_maildir();
	mlog(LV_NOTICE, "Running sync_contents for %s, folder %llu",
	        dir, LLU{folder_id});
	if (!exmdb_client::query_folder_messages(dir,
	    rop_util_make_eid_ex(1, folder_id), &rows))
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT uidnext FROM"
	          " folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return TRUE;
	uidnext = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	uidnext1 = uidnext;
	if (sqlite3_open_v2(":memory:", &psqlite, SQLITE_OPEN_READWRITE |
	    SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK)
		return FALSE;
	{
	auto cl_0 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	auto sql_transact = gx_sql_begin_trans(psqlite);
	snprintf(sql_string, arsizeof(sql_string), "CREATE TABLE messages "
			"(message_id INTEGER PRIMARY KEY,"
			"mid_string TEXT,"
			"mod_time INTEGER,"
			"message_flags INTEGER,"
			"received INTEGER)");
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	pstmt = gx_sql_prep(psqlite, "INSERT INTO messages (message_id,"
	        " mid_string, mod_time, message_flags, received) VALUES "
	        "(?, ?, ?, ?, ?)");
	if (pstmt == nullptr)
		return FALSE;
	for (size_t i = 0; i < rows.count; ++i) {
		auto num = rows.pparray[i]->get<const uint64_t>(PidTagMid);
		if (num == nullptr)
			continue;
		auto message_id = rop_util_get_gc_value(*num);
		auto flags = rows.pparray[i]->get<const uint32_t>(PR_MESSAGE_FLAGS);
		if (flags == nullptr)
			continue;
		auto mod_time = rows.pparray[i]->get<uint64_t>(PR_LAST_MODIFICATION_TIME);
		auto recv_time = rows.pparray[i]->get<uint64_t>(PR_MESSAGE_DELIVERY_TIME);
		auto midstr = rows.pparray[i]->get<const char>(PidTagMidString);
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		if (midstr == nullptr)
			sqlite3_bind_null(pstmt, 2);
		else
			sqlite3_bind_text(pstmt, 2, midstr, -1, SQLITE_STATIC);
		sqlite3_bind_int64(pstmt, 3, mod_time != nullptr ? *mod_time : 0);
		sqlite3_bind_int64(pstmt, 4, *flags);
		sqlite3_bind_int64(pstmt, 5, recv_time != nullptr ? *recv_time : 0);
		if (sqlite3_step(pstmt) != SQLITE_DONE)
			return FALSE;
	}
	pstmt.finalize();
	sql_transact.commit();

	pstmt = gx_sql_prep(psqlite, "SELECT COUNT(*) FROM messages");
	size_t totalmsgs = 0, procmsgs = 0;
	if (pstmt != nullptr && sqlite3_step(pstmt) == SQLITE_ROW)
		totalmsgs = sqlite3_column_int64(pstmt, 0);

	snprintf(sql_string, arsizeof(sql_string), "SELECT message_id, "
		"mid_string, mod_time, message_flags, received"
		" FROM messages");
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	auto pstmt1 = gx_sql_prep(pidb->psqlite, "SELECT message_id, mid_string,"
	              " mod_time, unsent, read FROM messages WHERE message_id=?");
	if (pstmt1 == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO messages (message_id, "
		"folder_id, mid_string, mod_time, uid, unsent, read, subject,"
		" sender, rcpt, size, received) VALUES (?, %llu, ?, ?, ?, ?, "
		"?, ?, ?, ?, ?, ?)", LLU{folder_id});
	auto pstmt2 = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt2 == nullptr)
		return FALSE;
	auto stm_upd_msg = gx_sql_prep(pidb->psqlite, "UPDATE messages"
	              " SET unsent=?, read=? WHERE message_id=?");
	if (stm_upd_msg == nullptr)
		return FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		uint64_t message_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			uidnext ++;
			mail_engine_insert_message(
				pstmt2, &uidnext, message_id,
				pstmt.col_text(1),
				sqlite3_column_int64(pstmt, 3),
				sqlite3_column_int64(pstmt, 4),
				sqlite3_column_int64(pstmt, 2));
		} else {
			mail_engine_sync_message(pidb,
				pstmt2, stm_upd_msg, &uidnext, message_id,
				sqlite3_column_int64(pstmt, 4),
				pstmt.col_text(1),
				pstmt1.col_text(1),
				sqlite3_column_int64(pstmt, 2),
				sqlite3_column_int64(pstmt1, 2),
				sqlite3_column_int64(pstmt, 3),
				sqlite3_column_int64(pstmt1, 3),
				sqlite3_column_int64(pstmt1, 4));
		}
		if (++procmsgs % 512 == 0)
			mlog(LV_NOTICE, "sync_contents %s fld %llu progress: %zu/%zu",
			        dir, LLU{folder_id}, procmsgs, totalmsgs);
	}
	if (procmsgs > 512)
		/* display final value */
			mlog(LV_NOTICE, "sync_contents %s fld %llu progress: %zu/%zu",
			        dir, LLU{folder_id}, procmsgs, totalmsgs);
	pstmt.finalize();
	pstmt1.finalize();
	pstmt2.finalize();
	stm_upd_msg.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT message_id FROM "
	          "messages WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	pstmt1 = gx_sql_prep(psqlite, "SELECT message_id"
	         " FROM messages WHERE message_id=?");
	if (pstmt1 == nullptr)
		return FALSE;

	std::vector<uint64_t> temp_list;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		uint64_t message_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			temp_list.push_back(message_id);
		}
	}
	pstmt.finalize();
	pstmt1.finalize();
	if (temp_list.size() > 0) {
		pstmt = gx_sql_prep(pidb->psqlite, "DELETE "
		        "FROM messages WHERE message_id=?");
		if (pstmt == nullptr)
			return FALSE;
		for (auto id : temp_list) {
			sqlite3_reset(pstmt);
			pstmt.bind_int64(1, id);
			if (sqlite3_step(pstmt) != SQLITE_DONE)
				return FALSE;
		}
		pstmt.finalize();
	}
	if (uidnext != uidnext1) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET uidnext=%u "
		        "WHERE folder_id=%llu", uidnext, LLU{folder_id});
		if (gx_sql_exec(pidb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	}
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET sort_field=%d "
	        "WHERE folder_id=%llu", FIELD_NONE, LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1208: ENOMEM");
	return false;
}

static unsigned int spname_to_fid(const char *s)
{
	if (strcasecmp(s, "inbox") == 0) return PRIVATE_FID_INBOX;
	if (strcasecmp(s, "draft") == 0) return PRIVATE_FID_DRAFT;
	if (strcasecmp(s, "sent") == 0) return PRIVATE_FID_SENT_ITEMS;
	if (strcasecmp(s, "trash") == 0) return PRIVATE_FID_DELETED_ITEMS;
	if (strcasecmp(s, "junk") == 0) return PRIVATE_FID_JUNK;
	return 0;
}

static const char *spfid_to_name(unsigned int z)
{
	switch (z) {
	case PRIVATE_FID_INBOX: return "inbox";
	case PRIVATE_FID_DRAFT: return "draft";
	case PRIVATE_FID_SENT_ITEMS: return "sent";
	case PRIVATE_FID_DELETED_ITEMS: return "trash";
	case PRIVATE_FID_JUNK: return "junk";
	default: return nullptr;
	}
}

static BOOL mail_engine_get_encoded_name(xstmt &pstmt,
    uint64_t folder_id, char *encoded_name) try
{
	char temp_name[512];

	if (auto x = spfid_to_name(folder_id)) {
		strcpy(encoded_name, x);
		return TRUE;
	}

	std::vector<std::string> temp_list;
	do {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, folder_id);
		if (sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		folder_id = sqlite3_column_int64(pstmt, 0);
		temp_list.emplace_back(pstmt.col_text(1));
	} while (PRIVATE_FID_IPMSUBTREE != folder_id);
	std::reverse(temp_list.begin(), temp_list.end());
	size_t offset = 0;
	for (const auto &name : temp_list) {
		auto length = name.size();
		if (length >= 256)
			return FALSE;
		if (0 != offset) {
			temp_name[offset] = '/';
			offset ++;
		}
		if (offset + length >= 512)
			return FALSE;
		memcpy(&temp_name[offset], name.c_str(), length);
		offset += length;
	}
	encode_hex_binary(temp_name, offset, encoded_name, 1024);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1207: ENOMEM");
	return false;
}

static uint64_t mail_engine_get_top_folder_id(
	sqlite3_stmt *pstmt, uint64_t folder_id)
{
	uint64_t parent_fid;
	
	while (true) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, folder_id);
		if (sqlite3_step(pstmt) != SQLITE_ROW)
			return 0;
		parent_fid = sqlite3_column_int64(pstmt, 0);
		if (parent_fid == PRIVATE_FID_IPMSUBTREE)
			return folder_id;
		folder_id = parent_fid;
	}
}

static bool skip_folder_class(const char *c)
{
	if (c == nullptr)
		/* Absent class means it's IPF.Note */
		return false;
	if (strncasecmp(c, "IPF.Note", 8) == 0 && (c[8] == '\0' || c[8] == '.'))
		return false;
	return true;
}

static BOOL mail_engine_sync_mailbox(IDB_ITEM *pidb,
    bool force_resync = false) try
{
	BOOL b_new;
	const char *dir;
	TARRAY_SET rows;
	sqlite3 *psqlite;
	uint32_t table_id;
	uint32_t row_count;
	uint64_t parent_fid;
	uint64_t commit_max;
	char sql_string[1280];
	PROPTAG_ARRAY proptags;
	char encoded_name[1024];
	uint32_t proptag_buff[6];
	
	dir = common_util_get_maildir();
	mlog(LV_NOTICE, "Running sync_mailbox for %s", dir);
	auto cl_err = make_scope_exit([&]() {
		mlog(LV_NOTICE, "sync_mailbox aborted for %s", dir);
	});
	if (!exmdb_client::load_hierarchy_table(dir,
	    rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE),
	    NULL, TABLE_FLAG_DEPTH|TABLE_FLAG_NONOTIFICATIONS,
	    NULL, &table_id, &row_count))
		return FALSE;	
	proptags.count = 6;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PidTagFolderId;
	proptag_buff[1] = PidTagParentFolderId;
	proptag_buff[2] = PR_ATTR_HIDDEN;
	proptag_buff[3] = PR_CONTAINER_CLASS;
	proptag_buff[4] = PR_DISPLAY_NAME;
	proptag_buff[5] = PR_LOCAL_COMMIT_TIME_MAX;
	if (!exmdb_client::query_table(dir, NULL,
		0, table_id, &proptags, 0, row_count, &rows)) {
		exmdb_client::unload_table(dir, table_id);
		return FALSE;
	}
	exmdb_client::unload_table(dir, table_id);
	if (sqlite3_open_v2(":memory:", &psqlite, SQLITE_OPEN_READWRITE |
	    SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK)
		return FALSE;
	{
	auto cl_0 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	auto sql_transact = gx_sql_begin_trans(psqlite);
	snprintf(sql_string, arsizeof(sql_string), "CREATE TABLE folders "
			"(folder_id INTEGER PRIMARY KEY,"
			"parent_fid INTEGER,"
			"display_name TEXT,"
			"commit_max INTEGER)");
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	auto pstmt = gx_sql_prep(psqlite, "INSERT INTO folders (folder_id, "
	             "parent_fid, display_name, commit_max) VALUES (?, ?, ?, ?)");
	if (pstmt == nullptr)
		return FALSE;
	for (size_t i = 0; i < rows.count; ++i) {
		auto num = rows.pparray[i]->get<const uint64_t>(PidTagFolderId);
		if (num == nullptr)
			continue;
		auto folder_id = rop_util_get_gc_value(*num);
		auto flag = rows.pparray[i]->get<const uint8_t>(PR_ATTR_HIDDEN);
		if (flag != nullptr && *flag != 0) {
			mlog(LV_NOTICE, "sync_mailbox %s fld %llu skipped: PR_ATTR_HIDDEN=1",
			        dir, LLU{folder_id});
			continue;
		}
		if (skip_folder_class(rows.pparray[i]->get<const char>(PR_CONTAINER_CLASS))) {
			mlog(LV_NOTICE, "sync_mailbox %s fld %llu skipped: PR_CONTAINER_CLASS not IPF.Note",
			        dir, LLU{folder_id});
			continue;
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, folder_id);
		num = rows.pparray[i]->get<uint64_t>(PidTagParentFolderId);
		if (num == nullptr)
			continue;
		parent_fid = rop_util_get_gc_value(*num);
		sqlite3_bind_int64(pstmt, 2, parent_fid);
		auto str = spfid_to_name(folder_id);
		if (str == nullptr) {
			str = rows.pparray[i]->get<char>(PR_DISPLAY_NAME);
			if (str == nullptr || strlen(str) >= 256)
				continue;
		}
		sqlite3_bind_text(pstmt, 3, str, -1, SQLITE_STATIC);
		num = rows.pparray[i]->get<uint64_t>(PR_LOCAL_COMMIT_TIME_MAX);
		sqlite3_bind_int64(pstmt, 4, num != nullptr ? *num : 0);
		if (sqlite3_step(pstmt) != SQLITE_DONE)
			return FALSE;
	}
	pstmt.finalize();
	sql_transact.commit();
	auto pidb_transact = gx_sql_begin_trans(pidb->psqlite);
	pstmt = gx_sql_prep(psqlite, "SELECT folder_id, "
	        "parent_fid, commit_max FROM folders");
	if (pstmt == nullptr)
		return false;
	auto pstmt1 = gx_sql_prep(pidb->psqlite, "SELECT folder_id, parent_fid, "
	              "commit_max, name FROM folders WHERE folder_id=?");
	if (pstmt1 == nullptr)
		return false;
	auto pstmt2 = gx_sql_prep(pidb->psqlite, "INSERT INTO folders (folder_id, "
				"parent_fid, commit_max, name) VALUES (?, ?, ?, ?)");
	if (pstmt2 == nullptr)
		return false;
	auto mem_sel_fld = gx_sql_prep(psqlite, "SELECT parent_fid, "
		"display_name FROM folders WHERE folder_id=?");
	if (mem_sel_fld == nullptr)
		return false;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		uint64_t folder_id = sqlite3_column_int64(pstmt, 0);
		switch (mail_engine_get_top_folder_id(mem_sel_fld, folder_id)) {
		case PRIVATE_FID_OUTBOX:
		case PRIVATE_FID_SYNC_ISSUES:
			continue;			
		}
		parent_fid = sqlite3_column_int64(pstmt, 1);
		commit_max = sqlite3_column_int64(pstmt, 2);
		if (!mail_engine_get_encoded_name(mem_sel_fld, folder_id, encoded_name))
			continue;
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, folder_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			sqlite3_reset(pstmt2);
			sqlite3_bind_int64(pstmt2, 1, folder_id);
			sqlite3_bind_int64(pstmt2, 2, parent_fid);
			sqlite3_bind_int64(pstmt2, 3, commit_max);
			sqlite3_bind_text(pstmt2, 4, encoded_name, -1, SQLITE_STATIC);
			if (sqlite3_step(pstmt2) != SQLITE_DONE)
				return false;
			b_new = TRUE;
		} else {
			if (gx_sql_col_uint64(pstmt1, 1) != parent_fid) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET "
					"parent_fid=%llu WHERE folder_id=%llu",
					LLU{parent_fid}, LLU{folder_id});
				gx_sql_exec(pidb->psqlite, sql_string);
			}
			if (strcmp(encoded_name, pstmt1.col_text(3)) != 0) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET name='%s' "
				        "WHERE folder_id=%llu", encoded_name, LLU{folder_id});
				gx_sql_exec(pidb->psqlite, sql_string);
			}
			if (gx_sql_col_uint64(pstmt1, 2) == commit_max && !force_resync)
				continue;	
			b_new = FALSE;
		}
		if (!mail_engine_sync_contents(pidb, folder_id))
			return false;
		if (!b_new) {
			snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET commit_max=%llu"
			        " WHERE folder_id=%llu", LLU{commit_max}, LLU{folder_id});
			gx_sql_exec(pidb->psqlite, sql_string);
		}
	}
	pstmt.finalize();
	pstmt1.finalize();
	pstmt2.finalize();
	mem_sel_fld.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM folders");
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return false;
	pstmt1 = gx_sql_prep(psqlite, "SELECT "
	         "folder_id FROM folders WHERE folder_id=?");
	if (pstmt1 == nullptr)
		return false;

	std::vector<uint64_t> temp_list;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		uint64_t folder_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, folder_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			temp_list.push_back(folder_id);
		}
	}
	pstmt.finalize();
	pstmt1.finalize();
	if (temp_list.size() > 0) {
		pstmt = gx_sql_prep(pidb->psqlite, "DELETE"
		        " FROM folders WHERE folder_id=?");
		if (pstmt == nullptr)
			return false;
		for (auto id : temp_list) {
			sqlite3_reset(pstmt);
			pstmt.bind_int64(1, id);
			if (sqlite3_step(pstmt) != SQLITE_DONE)
				return false;
		}
		pstmt.finalize();
	}
	pidb_transact.commit();
	}
	cl_err.release();
	if (!exmdb_client::subscribe_notification(dir,
	    NOTIFICATION_TYPE_OBJECTCREATED | NOTIFICATION_TYPE_OBJECTDELETED |
	    NOTIFICATION_TYPE_OBJECTMODIFIED | NOTIFICATION_TYPE_OBJECTMOVED |
	    NOTIFICATION_TYPE_OBJECTCOPIED | NOTIFICATION_TYPE_NEWMAIL, TRUE,
	    0, 0, &pidb->sub_id))
		pidb->sub_id = 0;	
	time(&pidb->load_time);
	mlog(LV_NOTICE, "Ended sync_mailbox for %s", dir);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1206: ENOMEM");
	return false;
}

static IDB_REF mail_engine_peek_idb(const char *path)
{
	std::unique_lock hhold(g_hash_lock);
	auto it = g_hash_table.find(path);
	if (it == g_hash_table.end())
		return {};
	auto pidb = &it->second;
	pidb->reference ++;
	hhold.unlock();
	pidb->lock.lock();
	if (pidb->psqlite != nullptr)
		return IDB_REF(pidb);
	pidb->last_time = 0;
	pidb->lock.unlock();
	hhold.lock();
	pidb->reference --;
	hhold.unlock();
	return {};
}

static int mail_engine_autoupgrade(sqlite3 *db, const char *filedesc)
{
	if (g_midb_schema_upgrades == MIDB_UPGRADE_NO)
		return 0;
	auto recent = dbop_sqlite_recentversion(sqlite_kind::midb);
	auto current = dbop_sqlite_schemaversion(db, sqlite_kind::midb);
	if (current >= recent)
		return 0;
	mlog(LV_NOTICE, "dbop_sqlite: %s: current schema EM-%d; upgrading to EM-%d.",
		filedesc, current, recent);
	auto ret = dbop_sqlite_upgrade(db, filedesc, sqlite_kind::midb, DBOP_VERBOSE);
	if (ret != 0) {
		mlog(LV_NOTICE, "dbop_sqlite upgrade %s: %s",
		        filedesc, strerror(-ret));
		return -1;
	}
	mlog(LV_NOTICE, "dbop_sqlite: upgrade %s: complete", filedesc);
	return 0;
}

static IDB_REF mail_engine_get_idb(const char *path, bool force_resync = false)
{
	BOOL b_load;
	char temp_path[256];
	char sql_string[1024];
	
	b_load = FALSE;
	std::unique_lock hhold(g_hash_lock);
	if (g_hash_table.size() >= g_table_size) {
		mlog(LV_WARN, "W-1295: too many sqlites referenced at once (midb.cfg:table_size=%zu)", g_table_size);
		return {};
	}
	decltype(g_hash_table.try_emplace(path)) xp;
	try {
		xp = g_hash_table.try_emplace(path);
	} catch (const std::bad_alloc &) {
		hhold.unlock();
		mlog(LV_ERR, "E-1294: mail_engine_get_idb ENOMEM");
		return {};
	}
	auto pidb = &xp.first->second;
	if (xp.second) {
		sprintf(temp_path, "%s/exmdb/midb.sqlite3", path);
		auto ret = sqlite3_open_v2(temp_path, &pidb->psqlite, SQLITE_OPEN_READWRITE, nullptr);
		if (ret != SQLITE_OK) {
			g_hash_table.erase(xp.first);
			mlog(LV_ERR, "E-1438: sqlite3_open %s: %s", temp_path, sqlite3_errstr(ret));
			return {};
		}
		ret = mail_engine_autoupgrade(pidb->psqlite, temp_path);
		if (ret != 0) {
			sqlite3_close(pidb->psqlite);
			pidb->psqlite = nullptr;
			return {};
		}
		gx_sql_exec(pidb->psqlite, "PRAGMA foreign_keys=ON");
		gx_sql_exec(pidb->psqlite, g_async ? "PRAGMA synchronous=ON" : "PRAGMA synchronous=OFF");
		gx_sql_exec(pidb->psqlite, g_wal ? "PRAGMA journal_mode=WAL" : "PRAGMA journal_mode=DELETE");
		if (0 != g_mmap_size) {
			snprintf(sql_string, sizeof(sql_string), "PRAGMA mmap_size=%llu", LLU{g_mmap_size});
			gx_sql_exec(pidb->psqlite, sql_string);
		}
		gx_sql_exec(pidb->psqlite, "DELETE FROM mapping");
		/* Delete obsolete field (old midb versions cannot use the db then however) */
		// gx_sql_exec(pidb->psqlite, "DELETE FROM configurations WHERE config_id=1");

		try {
			int user_id = 0;
			pidb->username.resize(UADDR_SIZE);
			if (!system_services_get_id_from_maildir(path, &user_id) ||
			    !system_services_get_username_from_id(user_id, pidb->username.data(), pidb->username.size())) {
				g_hash_table.erase(xp.first);
				return {};
			}
			pidb->username.resize(strlen(pidb->username.c_str()));
		} catch (const std::bad_alloc &) {
			g_hash_table.erase(xp.first);
			return {};
		}
		b_load = TRUE;
	} else if (pidb->reference > MAX_DB_WAITING_THREADS) {
		hhold.unlock();
		mlog(LV_DEBUG, "mail_engine: too many threads waiting on %s", path);
		return {};
	}
	pidb->reference ++;
	hhold.unlock();
	if (!pidb->lock.try_lock_for(DB_LOCK_TIMEOUT)) {
		hhold.lock();
		pidb->reference --;
		hhold.unlock();
		return {};
	}
	if (b_load || force_resync) {
		mail_engine_sync_mailbox(pidb, force_resync);
	} else if (pidb->psqlite == nullptr) {
		pidb->last_time = 0;
		pidb->lock.unlock();
		hhold.lock();
		pidb->reference--;
		hhold.unlock();
		return {};
	}
	return IDB_REF(pidb);
}

void idb_item_del::operator()(IDB_ITEM *pidb)
{
	time(&pidb->last_time);
	pidb->lock.unlock();
	std::lock_guard hhold(g_hash_lock);
	pidb->reference --;
}

IDB_ITEM::~IDB_ITEM()
{
	if (psqlite != nullptr)
		sqlite3_close(psqlite);
}

static void *midbme_scanwork(void *param)
{
	int count;
	time_t now_time;

	count = 0;
	while (!g_notify_stop) {
		std::vector<std::pair<std::string, uint32_t>> unsub_list;
		sleep(1);
		if (count < 10) {
			count ++;
			continue;
		}
		count = 0;
		std::unique_lock hhold(g_hash_lock);
		for (auto it = g_hash_table.begin(); it != g_hash_table.end(); ) {
			auto pidb = &it->second;
			time(&now_time);
			auto last_diff = now_time - pidb->last_time;
			auto load_diff = now_time - pidb->load_time;
			bool clean = pidb->reference == 0 &&
			             (pidb->sub_id == 0 ||
			             last_diff > g_midb_cache_interval ||
			             load_diff > g_midb_reload_interval);
			if (!clean) {
				++it;
				continue;
			}
			if (pidb->sub_id != 0) try {
				unsub_list.emplace_back(it->first.c_str(), pidb->sub_id);
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1622: ENOMEM");
			}
			mlog(LV_INFO, "I-2175: Closing user %s midb.sqlite3 (sub=%u, c=%lld, l=%lld)",
			        pidb->username.c_str(), pidb->sub_id,
			        static_cast<long long>(last_diff),
			        static_cast<long long>(load_diff));
			it = g_hash_table.erase(it);
		}
		hhold.unlock();
		for (auto &&e : unsub_list) {
			if (common_util_build_environment(e.first.c_str())) {
				exmdb_client::unsubscribe_notification(e.first.c_str(), e.second);
				common_util_free_environment();
			}
		}
	}
	std::unique_lock hhold(g_hash_lock);
	for (auto it = g_hash_table.begin(); it != g_hash_table.end(); ) {
		auto pidb = &it->second;
		if (pidb->sub_id != 0)
			exmdb_client::unsubscribe_notification(it->first.c_str(), pidb->sub_id);
		it = g_hash_table.erase(it);
	}
	hhold.unlock();
	return nullptr;
}
	
static int mail_engine_mckfl(int argc, char **argv, int sockd)
{
	uint64_t quota;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[2];
	
	if (argc != 2 || strlen(argv[1]) >= 256)
		return MIDB_E_PARAMETER_ERROR;
	proptags.count = 2;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PR_PROHIBIT_RECEIVE_QUOTA;
	tmp_proptags[1] = PR_MESSAGE_SIZE_EXTENDED;
	if (!exmdb_client::get_store_properties(argv[1], 0, &proptags, &propvals))
		return MIDB_E_MDB_GETSTOREPROPS;
	auto ptotal = propvals.get<uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	auto pmax   = propvals.get<uint32_t>(PR_PROHIBIT_RECEIVE_QUOTA);
	if (NULL != ptotal && NULL != pmax) {
		quota = *pmax;
		quota *= 1024;
		if (*ptotal >= quota)
			return cmd_write(sockd, "TRUE 1\r\n");
	}
	return cmd_write(sockd, "TRUE 0\r\n");
}

static int mail_engine_mping(int argc, char **argv, int sockd)
{
	if (argc != 2 || strlen(argv[1]) >= 256)
		return MIDB_E_PARAMETER_ERROR;
	mail_engine_get_idb(argv[1]);
	exmdb_client::ping_store(argv[1]);
	return cmd_write(sockd, "TRUE\r\n");
}

static int mail_engine_menum(int argc, char **argv, int sockd)
{
	int count;
	int offset;
	int temp_len;
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if (argc != 2 || strlen(argv[1]) >= 256)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id, name FROM folders");
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	temp_len = 32;
	count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (spfid_to_name(sqlite3_column_int64(pstmt, 0)) != nullptr)
			continue;
		temp_len += gx_snprintf(temp_buff + temp_len,
		            GX_ARRAY_SIZE(temp_buff) - temp_len, "%s\r\n",
					sqlite3_column_text(pstmt, 1));
		count ++;
	}
	pstmt.finalize();
	pidb.reset();
	offset = gx_snprintf(temp_buff, 32, "TRUE %d\r\n", count);
	memmove(temp_buff + 32 - offset, temp_buff, offset);
	return cmd_write(sockd, temp_buff + 32 - offset, offset + temp_len - 32);
}

static int kw_to_sort_field(const char *s)
{
	if (strcasecmp(s, "RCV") == 0) return FIELD_RECEIVED;
	if (strcasecmp(s, "SUB") == 0) return FIELD_SUBJECT;
	if (strcasecmp(s, "FRM") == 0) return FIELD_FROM;
	if (strcasecmp(s, "RCP") == 0) return FIELD_RCPT;
	if (strcasecmp(s, "SIZ") == 0) return FIELD_SIZE;
	if (strcasecmp(s, "RED") == 0) return FIELD_READ;
	if (strcasecmp(s, "FLG") == 0) return FIELD_FLAG;
	if (strcasecmp(s, "UID") == 0) return FIELD_UID;
	if (strcasecmp(s, "NON") == 0) return FIELD_NONE;
	return -1;
}

static bool kw_to_sort_order(const char *s, bool &out)
{
	out = strcasecmp(s, "ASC") == 0;
	if (out)
		return true;
	return strcasecmp(s, "DSC") == 0;
}

/*
 * List mails in folder, returning the digests.
 * Request:
 * 	M-LIST <dir> <folder> <sort-field> <ascdesc> <idx> <msgcount>
 * Response:
 * 	TRUE <msgcount>
 * 	<ext digest> (repeat x msgcount)
 */
static int mail_engine_mlist(int argc, char **argv, int sockd)
{
	int offset;
	int length;
	int temp_len;
	int idx1, idx2;
	int total_mail;
	char sql_string[1024];
	char temp_buff[MAX_DIGLEN];
	
	if ((argc != 5 && argc != 7) || strlen(argv[1]) >= 256 ||
	    strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto sort_field = kw_to_sort_field(argv[3]);
	if (sort_field < FIELD_NONE)
		return MIDB_E_PARAMETER_ERROR;
	bool b_asc;
	if (!kw_to_sort_order(argv[4], b_asc))
		return MIDB_E_PARAMETER_ERROR;
	if (7 == argc) {
		offset = strtol(argv[5], nullptr, 0);
		length = strtol(argv[6], nullptr, 0);
		if (length < 0)
			length = 0;
	} else {
		offset = 0;
		length = 0;
	}
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!mail_engine_sort_folder(pidb.get(), argv[2], sort_field))
		return MIDB_E_MNG_SORTFOLDER;
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) "
	          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return MIDB_E_SQLUNEXP;
	total_mail = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (b_asc) {
		if (offset < 0) {
			idx1 = std::max(1, total_mail + 1 + offset);
		} else {
			if (offset >= total_mail) {
				pidb.reset();
				return cmd_write(sockd, "TRUE 0\r\n");
			}
			idx1 = offset + 1;
		}
		if (length == 0 || total_mail - idx1 + 1 < length)
			length = total_mail - idx1 + 1;
		idx2 = idx1 + length - 1;
		snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string FROM messages "
			"WHERE folder_id=%llu AND idx>=%d AND idx<=%d ORDER BY idx",
			LLU{folder_id}, idx1, idx2);
	} else {
		if (offset < 0) {
			idx2 = std::min(-offset, total_mail);
		} else {
			if (offset >= total_mail) {
				pidb.reset();
				return cmd_write(sockd, "TRUE 0\r\n");
			}
			idx2 = total_mail - offset;
		}
		if (length == 0 || idx2 < length)
			length = idx2;
		idx1 = idx2 - length + 1;
		snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string FROM messages "
			"WHERE folder_id=%llu AND idx>=%d AND idx<=%d ORDER BY idx "
			"DESC", LLU{folder_id}, idx1, idx2);
	}
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	temp_len = sprintf(temp_buff, "TRUE %d\r\n", length);
	auto ret = cmd_write(sockd, temp_buff, temp_len);
	if (ret != 0)
		return ret;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (mail_engine_get_digest(pidb->psqlite,
		    pstmt.col_text(0), temp_buff) == 0)
			return MIDB_E_DIGEST;
		temp_len = strlen(temp_buff);
		temp_buff[temp_len] = '\r';
		temp_len ++;
		temp_buff[temp_len] = '\n';
		temp_len ++;
		ret = cmd_write(sockd, temp_buff, temp_len);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int mail_engine_muidl(int argc, char **argv, int sockd) try
{
	using idl_node = std::pair<std::string /* mid_string */, uint32_t /* size */>;
	int result;
	char sql_string[1024];
	char list_buff[256*1024];
	
	if (argc != 3 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string, size FROM"
	          " messages WHERE folder_id=%llu ORDER BY uid", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;

	std::vector<idl_node> tmp_list;
	while (SQLITE_ROW == (result = sqlite3_step(pstmt))) {
		tmp_list.emplace_back(pstmt.col_text(0), pstmt.col_int64(1));
	}
	pstmt.finalize();
	if (result != SQLITE_DONE)
		return MIDB_E_SQLUNEXP;
	auto offset = snprintf(list_buff, std::size(list_buff),
	              "TRUE %zu\r\n", tmp_list.size());
	for (const auto &idl : tmp_list) {
		char temp_line[512];
		auto temp_len = gx_snprintf(temp_line, std::size(temp_line), "%s %u\r\n",
		                idl.first.c_str(), idl.second);
		if (256*1024 - offset < temp_len) {
			auto ret = cmd_write(sockd, list_buff, offset);
			if (ret != 0)
				return ret;
			offset = 0;
		}
		memcpy(list_buff + offset, temp_line, temp_len);
		offset += temp_len;
	}
	return cmd_write(sockd, list_buff, offset);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1209: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

static bool system_services_lang_to_charset(const char *lang, char (&charset)[32])
{
	auto c = lang_to_charset(lang);
	if (c == nullptr)
		return false;
	gx_strlcpy(charset, lang, std::size(charset));
	return true;
}

static int mail_engine_minst(int argc, char **argv, int sockd)
{
	int tmp_len;
	int user_id;
	char lang[32];
	size_t mess_len;
	char charset[32], tmzone[64];
	uint32_t tmp_flags;
	char temp_path[256];
	uint64_t change_num;
	uint64_t message_id;
	char sql_string[1024];
	struct stat node_stat;
	char temp_buff[MAX_DIGLEN];
	
	if (argc != 6 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	uint8_t b_unsent = strchr(argv[4], 'U') != nullptr;
	uint8_t b_read = strchr(argv[4], 'S') != nullptr;
	if (strcmp(argv[2], "draft") == 0)
		b_unsent = 1;
	sprintf(temp_path, "%s/eml/%s", argv[1], argv[3]);
	wrapfd fd = open(temp_path, O_RDONLY);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-2071: Opening %s for reading failed: %s", temp_path, strerror(errno));
		return MIDB_E_DISK_ERROR;
	}
	if (fstat(fd.get(), &node_stat) != 0 || !S_ISREG(node_stat.st_mode)) {
		mlog(LV_ERR, "E-2072: fstat/type mismatch");
		return MIDB_E_DISK_ERROR;
	}
	std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(node_stat.st_size));
	if (pbuff == nullptr)
		return MIDB_E_NO_MEMORY;
	if (HXio_fullread(fd.get(), pbuff.get(), node_stat.st_size) != node_stat.st_size)
		return MIDB_E_SHORT_READ;
	fd.close_rd();

	MAIL imail(g_mime_pool);
	if (!imail.load_from_str_move(pbuff.get(), node_stat.st_size))
		return MIDB_E_IMAIL_RETRIEVE;
	tmp_len = sprintf(temp_buff, "{\"file\":\"\",");
	if (imail.get_digest(&mess_len, temp_buff + tmp_len, MAX_DIGLEN - tmp_len - 1) <= 0)
		return MIDB_E_IMAIL_DIGEST;
	tmp_len = strlen(temp_buff);
	temp_buff[tmp_len] = '}';
	tmp_len ++;
	temp_buff[tmp_len] = '\0';
	sprintf(temp_path, "%s/ext/%s", argv[1], argv[3]);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-2073: Opening %s for writing failed: %s", temp_path, strerror(errno));
		return MIDB_E_DISK_ERROR;
	}
	if (HXio_fullwrite(fd.get(), temp_buff, tmp_len) != tmp_len ||
	    fd.close_wr() < 0)
		mlog(LV_ERR, "E-2085: write %s: %s", temp_path, strerror(errno));
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!system_services_get_id_from_username(pidb->username.c_str(), &user_id))
		return MIDB_E_SSGETID;
	if (!system_services_get_user_lang(pidb->username.c_str(), lang,
	    arsizeof(lang)) || lang[0] == '\0' ||
	    !system_services_lang_to_charset(lang, charset) ||
	    *charset == '\0')
		strcpy(charset, g_default_charset);
	if (!system_services_get_timezone(pidb->username.c_str(), tmzone,
	    arsizeof(tmzone)) || tmzone[0] == '\0')
		strcpy(tmzone, GROMOX_FALLBACK_TIMEZONE);
	auto pmsgctnt = oxcmail_import(charset, tmzone, &imail,
	                common_util_alloc, common_util_get_propids_create);
	imail.clear();
	pbuff.reset();
	if (pmsgctnt == nullptr)
		return MIDB_E_OXCMAIL_IMPORT;
	auto cl_msg = make_scope_exit([&]() { message_content_free(pmsgctnt); });
	auto nt_time = rop_util_unix_to_nttime(strtol(argv[5], nullptr, 0));
	if (pmsgctnt->proplist.set(PR_MESSAGE_DELIVERY_TIME, &nt_time) != 0)
		return MIDB_E_NO_MEMORY;
	static_assert(std::is_same_v<decltype(b_read), uint8_t>);
	if (b_read && pmsgctnt->proplist.set(PR_READ, &b_read) != 0)
		return MIDB_E_NO_MEMORY;
	if (0 != b_unsent) {
		tmp_flags = MSGFLAG_UNSENT;
		if (pmsgctnt->proplist.set(PR_MESSAGE_FLAGS, &tmp_flags) != 0)
			return MIDB_E_NO_MEMORY;
	}
	if (!exmdb_client::allocate_message_id(argv[1],
		rop_util_make_eid_ex(1, folder_id), &message_id) ||
		!exmdb_client::allocate_cn(argv[1], &change_num)) {
		return MIDB_E_MDB_ALLOCID;
	}
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO mapping"
		" (message_id, mid_string, flag_string) VALUES"
		" (%llu, ?, ?)", LLU{rop_util_get_gc_value(message_id)});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 2, argv[4], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return MIDB_E_SQLUNEXP;
	pstmt.finalize();
	std::string username;
	try {
		username = pidb->username;
	} catch (const std::bad_alloc &) {
		return MIDB_E_NO_MEMORY;
	}
	pidb.reset();
	if (pmsgctnt->proplist.set(PidTagMid, &message_id) != 0 ||
	    pmsgctnt->proplist.set(PidTagChangeNumber, &change_num) != 0)
		return MIDB_E_NO_MEMORY;
	auto pbin = cu_xid_to_bin({rop_util_make_user_guid(user_id), change_num});
	if (pbin == nullptr ||
	    pmsgctnt->proplist.set(PR_CHANGE_KEY, pbin) != 0)
		return MIDB_E_NO_MEMORY;
	auto newval = common_util_pcl_append(NULL, pbin);
	if (newval == nullptr ||
	    pmsgctnt->proplist.set(PR_PREDECESSOR_CHANGE_LIST, newval) != 0)
		return MIDB_E_NO_MEMORY;
	auto cpid = cset_to_cpid(charset);
	if (cpid == 0)
		cpid = 1252;
	ec_error_t e_result = ecRpcFailed;
	if (!exmdb_client::write_message(argv[1], username.c_str(), cpid,
	    rop_util_make_eid_ex(1, folder_id), pmsgctnt, &e_result) ||
	    e_result != ecSuccess)
		return MIDB_E_MDB_WRITEMESSAGE;
	return cmd_write(sockd, "TRUE\r\n");
}

/*
 * Mail deletion
 *
 * M-DELE <dir> <folder> <midstr>
 */
static int mail_engine_mdele(int argc, char **argv, int sockd)
{
	int i;
	int user_id;
	BOOL b_partial;
	EID_ARRAY message_ids;

	if (argc < 4 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	message_ids.count = 0;
	message_ids.pids = cu_alloc<uint64_t>(argc - 3);
	if (message_ids.pids == nullptr)
		return MIDB_E_NO_MEMORY;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!system_services_get_id_from_username(pidb->username.c_str(), &user_id))
		return MIDB_E_SSGETID;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	for (i=3; i<argc; i++) {
		sqlite3_reset(pstmt);
		sqlite3_bind_text(pstmt, 1, argv[i], -1, SQLITE_STATIC);
		if (SQLITE_ROW != sqlite3_step(pstmt) ||
		    gx_sql_col_uint64(pstmt, 1) != folder_id)
			continue;
		message_ids.pids[message_ids.count++] =
			rop_util_make_eid_ex(1, sqlite3_column_int64(pstmt, 0));
	}
	pstmt.finalize();
	pidb.reset();
	if (!exmdb_client::delete_messages(argv[1],
	    user_id, 0, NULL, rop_util_make_eid_ex(1, folder_id),
	    &message_ids, TRUE, &b_partial))
		return MIDB_E_MDB_DELETEMESSAGES;
	return cmd_write(sockd, "TRUE\r\n");
}

static int mail_engine_mcopy(int argc, char **argv, int sockd)
{
	int user_id;
	char lang[32];
	int flags_len;
	uint64_t nt_time;
	char charset[32], tmzone[64];
	uint32_t tmp_flags;
	char flags_buff[16];
	uint64_t change_num;
	uint64_t message_id;
	char sql_string[1024];
	struct stat node_stat;

	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024 ||
	    strlen(argv[4]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	std::string eml_path;
	try {
		eml_path = argv[1] + "/eml/"s + argv[3];
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1486: ENOMEM");
		return MIDB_E_NO_MEMORY;
	}
	wrapfd fd = open(eml_path.c_str(), O_RDONLY);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-2074: Opening %s for reading failed: %s", eml_path.c_str(), strerror(errno));
		return MIDB_E_DISK_ERROR;
	}
	if (fstat(fd.get(), &node_stat) != 0 || !S_ISREG(node_stat.st_mode)) {
		mlog(LV_ERR, "E-2089: fstat/type mismatch");
		return MIDB_E_DISK_ERROR;
	}
	std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(node_stat.st_size));
	if (pbuff == nullptr)
		return MIDB_E_NO_MEMORY;
	if (HXio_fullread(fd.get(), pbuff.get(), node_stat.st_size) != node_stat.st_size)
		return MIDB_E_SHORT_READ;
	fd.close_rd();

	MAIL imail(g_mime_pool);
	if (!imail.load_from_str_move(pbuff.get(), node_stat.st_size))
		return MIDB_E_IMAIL_RETRIEVE;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto folder_id1 = mail_engine_get_folder_id(pidb.get(), argv[4]);
	if (folder_id1 == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id, mod_time, "
	             "uid, recent, read, unsent, flagged, replied, forwarded,"
	             "deleted, received, ext, folder_id, size FROM messages "
	             "WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW ||
	    gx_sql_col_uint64(pstmt, 12) != folder_id)
		return MIDB_E_NO_MESSAGE;
	flags_buff[0] = '(';
	flags_len = 1;
	if (pstmt.col_int64(7) != 0)
		flags_buff[flags_len++] = 'A';
	if (pstmt.col_int64(6) != 0)
		flags_buff[flags_len++] = 'F';
	if (pstmt.col_int64(8) != 0)
		flags_buff[flags_len++] = 'W';
	flags_buff[flags_len++] = ')';
	flags_buff[flags_len] = '\0';
	auto b_unsent = pstmt.col_int64(5) != 0;
	uint8_t b_read = pstmt.col_int64(4) != 0;
	nt_time = sqlite3_column_int64(pstmt, 10);
	pstmt.finalize();
	if (!system_services_get_id_from_username(pidb->username.c_str(), &user_id))
		return MIDB_E_SSGETID;
	if (!system_services_get_user_lang(pidb->username.c_str(), lang,
	    arsizeof(lang)) || lang[0] == '\0' ||
	    !system_services_lang_to_charset(lang, charset) ||
	    *charset == '\0')
		strcpy(charset, g_default_charset);
	if (!system_services_get_timezone(pidb->username.c_str(), tmzone,
	    arsizeof(tmzone)) || tmzone[0] == '\0')
		strcpy(tmzone, GROMOX_FALLBACK_TIMEZONE);
	auto pmsgctnt = oxcmail_import(charset, tmzone, &imail,
	                common_util_alloc, common_util_get_propids_create);
	imail.clear();
	pbuff.reset();
	if (pmsgctnt == nullptr)
		return MIDB_E_OXCMAIL_IMPORT;
	auto cl_msg = make_scope_exit([&]() { message_content_free(pmsgctnt); });
	if (pmsgctnt->proplist.set(PR_MESSAGE_DELIVERY_TIME, &nt_time) != 0)
		return MIDB_E_NO_MEMORY;
	static_assert(std::is_same_v<decltype(b_read), uint8_t>);
	if (b_read && pmsgctnt->proplist.set(PR_READ, &b_read) != 0)
		return MIDB_E_NO_MEMORY;
	if (0 != b_unsent) {
		tmp_flags = MSGFLAG_UNSENT;
		if (pmsgctnt->proplist.set(PR_MESSAGE_FLAGS, &tmp_flags) != 0)
			return MIDB_E_NO_MEMORY;
	}
	if (!exmdb_client::allocate_message_id(argv[1],
		rop_util_make_eid_ex(1, folder_id), &message_id) ||
		!exmdb_client::allocate_cn(argv[1], &change_num)) {
		return MIDB_E_MDB_ALLOCID;
	}
	std::string mid_string;
	try {
		mid_string = std::to_string(time(nullptr)) + "." +
		             std::to_string(++g_sequence_id) + ".midb";
		eml_path = argv[1] + "/eml/"s + argv[3];
		auto eml_path1 = argv[1] + "/eml/"s + mid_string;
		if (link(eml_path.c_str(), eml_path1.c_str()) != 0)
			mlog(LV_ERR, "E-2083: link %s %s: %s",
			        eml_path.c_str(), eml_path1.c_str(),
			        strerror(errno));
		eml_path = argv[1] + "/ext/"s + argv[3];
		eml_path1 = argv[1] + "/ext/"s + mid_string;
		if (link(eml_path.c_str(), eml_path1.c_str()) != 0)
			mlog(LV_ERR, "E-2084: link %s %s: %s",
			        eml_path.c_str(), eml_path1.c_str(),
			        strerror(errno));
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1487: ENOMEM");
		return MIDB_E_NO_MEMORY;
	}
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO mapping"
		" (message_id, mid_string, flag_string) VALUES"
		" (%llu, ?, ?)", LLU{rop_util_get_gc_value(message_id)});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, mid_string.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 2, flags_buff, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return MIDB_E_SQLUNEXP;
	pstmt.finalize();
	std::string username;
	try {
		username = pidb->username;
	} catch (const std::bad_alloc &) {
		return MIDB_E_NO_MEMORY;
	}
	pidb.reset();
	if (pmsgctnt->proplist.set(PidTagMid, &message_id) != 0 ||
	    pmsgctnt->proplist.set(PidTagChangeNumber, &change_num) != 0)
		return MIDB_E_NO_MEMORY;
	auto pbin = cu_xid_to_bin({rop_util_make_user_guid(user_id), change_num});
	if (pbin == nullptr ||
	    pmsgctnt->proplist.set(PR_CHANGE_KEY, pbin) != 0)
		return MIDB_E_NO_MEMORY;
	auto newval = common_util_pcl_append(NULL, pbin);
	if (newval == nullptr ||
	    pmsgctnt->proplist.set(PR_PREDECESSOR_CHANGE_LIST, newval) != 0)
		return MIDB_E_NO_MEMORY;
	auto cpid = cset_to_cpid(charset);
	if (cpid == 0)
		cpid = 1252;
	ec_error_t e_result = ecRpcFailed;
	if (!exmdb_client::write_message(argv[1], username.c_str(), cpid,
	    rop_util_make_eid_ex(1, folder_id1), pmsgctnt, &e_result) ||
	    e_result != ecSuccess)
		return MIDB_E_MDB_WRITEMESSAGE;
	cl_msg.release();
	message_content_free(pmsgctnt);
	try {
		mid_string.insert(0, "TRUE ");
		mid_string.append("\r\n");
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1488: ENOMEM");
		return MIDB_E_NO_MEMORY;
	}
	return cmd_write(sockd, mid_string.c_str(), mid_string.size());
}

static int mail_engine_mrenf(int argc, char **argv, int sockd)
{
	int user_id;
	BOOL b_exist;
	char *ptoken;
	BINARY *pbin1;
	char *ptoken1;
	BOOL b_partial;
	uint64_t nt_time;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t folder_id1;
	uint64_t folder_id2;
	uint64_t change_num;
	char temp_name[256];
	uint32_t tmp_proptag;
	PROPTAG_ARRAY proptags;
	char decoded_name[512];
	PROBLEM_ARRAY problems;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL propval_buff[5];

	if (argc != 4 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024 ||
	    strlen(argv[3]) >= 1024 || strcmp(argv[2], argv[3]) == 0)
		return MIDB_E_PARAMETER_ERROR;
	if (spname_to_fid(argv[2]) != 0)
		return MIDB_E_PARAMETER_ERROR;
	if (!decode_hex_binary(argv[3], decoded_name, arsizeof(decoded_name)))
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	if (!system_services_get_id_from_username(pidb->username.c_str(), &user_id))
		return MIDB_E_SSGETID;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " parent_fid FROM folders WHERE name=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[2], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return MIDB_E_SQLUNEXP;
	folder_id = sqlite3_column_int64(pstmt, 0);
	parent_id = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	if (mail_engine_get_folder_id(pidb.get(), argv[3]) != 0)
		return MIDB_E_FOLDER_EXISTS;
	ptoken = decoded_name;
	folder_id1 = PRIVATE_FID_IPMSUBTREE;
	while ((ptoken1 = strchr(ptoken, '/')) != NULL) {
		if (static_cast<size_t>(ptoken1 - ptoken) >= sizeof(temp_name))
			return MIDB_E_PARAMETER_ERROR;
		memcpy(temp_name, ptoken, ptoken1 - ptoken);
		temp_name[ptoken1 - ptoken] = '\0';
		auto next_fid = spname_to_fid(temp_name);
		if (next_fid != 0) {
			folder_id1 = next_fid;
		} else {
			encode_hex_binary(decoded_name, ptoken1 - decoded_name,
				encoded_name, 1024);
			folder_id2 = mail_engine_get_folder_id(pidb.get(), encoded_name);
			if (0 == folder_id2) {
				if (!common_util_create_folder(argv[1],
				    user_id, rop_util_make_eid_ex(1, folder_id1),
				    temp_name, &folder_id2))
					return MIDB_E_CREATEFOLDER;
				folder_id1 = rop_util_get_gc_value(folder_id2);
			} else {
				folder_id1 = folder_id2;
			}
		}
		ptoken = ptoken1 + 1;
	}
	pidb.reset();
	if (parent_id != folder_id1) {
		if (!exmdb_client::movecopy_folder(
		    argv[1], user_id, 0, FALSE, NULL,
		    rop_util_make_eid_ex(1, parent_id),
		    rop_util_make_eid_ex(1, folder_id),
		    rop_util_make_eid_ex(1, folder_id1),
		    ptoken, FALSE, &b_exist, &b_partial))
			return MIDB_E_MDB_MOVECOPY;
		if (b_exist)
			return MIDB_E_FOLDER_EXISTS;
		if (b_partial)
			return MIDB_E_MDB_PARTIAL;
	}
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PR_PREDECESSOR_CHANGE_LIST;
	if (!exmdb_client::allocate_cn(argv[1], &change_num))
		return MIDB_E_MDB_ALLOCID;
	if (!exmdb_client::get_folder_properties(argv[1], 0,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals) ||
	     (pbin1 = propvals.get<BINARY>(PR_PREDECESSOR_CHANGE_LIST)) == nullptr)
		return MIDB_E_MDB_GETFOLDERPROPS;
	propvals.count = parent_id == folder_id1 ? 5 : 4;
	propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PidTagChangeNumber;
	propval_buff[0].pvalue = &change_num;
	auto pbin = cu_xid_to_bin({rop_util_make_user_guid(user_id), change_num});
	if (pbin == nullptr)
		return MIDB_E_NO_MEMORY;
	propval_buff[1].proptag = PR_CHANGE_KEY;
	propval_buff[1].pvalue = pbin;
	propval_buff[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval_buff[2].pvalue = common_util_pcl_append(pbin1, pbin);
	if (propval_buff[2].pvalue == nullptr)
		return MIDB_E_NO_MEMORY;
	nt_time = rop_util_current_nttime();
	propval_buff[3].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[3].pvalue = &nt_time;
	if (parent_id == folder_id1) {
		propval_buff[4].proptag = PR_DISPLAY_NAME;
		propval_buff[4].pvalue = ptoken;
	}
	if (!exmdb_client::set_folder_properties(argv[1], 0,
	    rop_util_make_eid_ex(1, folder_id), &propvals, &problems))
		return MIDB_E_MDB_SETFOLDERPROPS;
	return cmd_write(sockd, "TRUE\r\n");
}

static int mail_engine_mmakf(int argc, char **argv, int sockd)
{
	int user_id;
	char *ptoken;
	char *ptoken1;
	uint64_t folder_id1;
	uint64_t folder_id2;
	char temp_name[256];
	char decoded_name[512];
	char encoded_name[1024];

	if (argc != 3 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	if (!decode_hex_binary(argv[2], decoded_name, arsizeof(decoded_name)))
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	if (!system_services_get_id_from_username(pidb->username.c_str(), &user_id))
		return MIDB_E_SSGETID;
	if (mail_engine_get_folder_id(pidb.get(), argv[2]) != 0)
		return MIDB_E_FOLDER_EXISTS;
	ptoken = decoded_name;
	folder_id1 = PRIVATE_FID_IPMSUBTREE;
	while ((ptoken1 = strchr(ptoken, '/')) != NULL) {
		if (static_cast<size_t>(ptoken1 - ptoken) >= sizeof(temp_name))
			return MIDB_E_PARAMETER_ERROR;
		memcpy(temp_name, ptoken, ptoken1 - ptoken);
		temp_name[ptoken1 - ptoken] = '\0';
		auto next_fid = spname_to_fid(temp_name);
		if (next_fid != 0) {
			folder_id1 = next_fid;
		} else {
			encode_hex_binary(decoded_name, ptoken1 - decoded_name,
				encoded_name, 1024);
			folder_id2 = mail_engine_get_folder_id(pidb.get(), encoded_name);
			if (0 == folder_id2) {
				if (!common_util_create_folder(argv[1],
				    user_id, rop_util_make_eid_ex(1, folder_id1),
				    temp_name, &folder_id2))
					return MIDB_E_CREATEFOLDER;
				folder_id1 = rop_util_get_gc_value(folder_id2);
			} else {
				folder_id1 = folder_id2;
			}
		}
		ptoken = ptoken1 + 1;
	}
	pidb.reset();
	if (!common_util_create_folder(argv[1],
	    user_id, rop_util_make_eid_ex(1, folder_id1),
	    ptoken, &folder_id2) || folder_id2 == 0)
		return MIDB_E_CREATEFOLDER;
	return cmd_write(sockd, "TRUE\r\n");
}

static int mail_engine_mremf(int argc, char **argv, int sockd)
{
	BOOL b_result;
	BOOL b_partial;
	
	if (argc != 3 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	if (spname_to_fid(argv[2]) != 0)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (0 == folder_id) {
		pidb.reset();
		return cmd_write(sockd, "TRUE\r\n");
	}
	pidb.reset();
	folder_id = rop_util_make_eid_ex(1, folder_id);
	if (!exmdb_client::empty_folder(argv[1], 0, NULL, folder_id,
	    TRUE, TRUE, TRUE, FALSE, &b_partial) || b_partial ||
	    !exmdb_client::empty_folder(argv[1], 0, NULL, folder_id,
	    TRUE, FALSE, FALSE, TRUE, &b_partial) || b_partial ||
	    !exmdb_client::delete_folder(argv[1], 0, folder_id, TRUE,
	    &b_result) || !b_result)
		return MIDB_E_MDB_DELETEFOLDER;
	return cmd_write(sockd, "TRUE\r\n");
}

static int mail_engine_pofst(int argc, char **argv, int sockd)
{
	int idx;
	int temp_len, total_mail = 0;
	char temp_buff[1024];
	char sql_string[1024];
	
	if (argc != 6 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto sort_field = kw_to_sort_field(argv[4]);
	if (sort_field < FIELD_NONE)
		return MIDB_E_PARAMETER_ERROR;
	bool b_asc;
	if (!kw_to_sort_order(argv[5], b_asc))
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!mail_engine_sort_folder(pidb.get(), argv[2], sort_field))
		return MIDB_E_MNG_SORTFOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " idx FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW ||
	    gx_sql_col_uint64(pstmt, 0) != folder_id)
		return MIDB_E_NO_MESSAGE;
	idx = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	if (!b_asc) {
		snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) "
		          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
		pstmt = gx_sql_prep(pidb->psqlite, sql_string);
		if (pstmt == nullptr)
			return MIDB_E_SQLPREP;
		if (sqlite3_step(pstmt) != SQLITE_ROW)
			return MIDB_E_NO_FOLDER;
		total_mail = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
	}
	pidb.reset();
	temp_len = sprintf(temp_buff, "TRUE %d\r\n", b_asc ? idx - 1 : total_mail - idx);
	return cmd_write(sockd, temp_buff, temp_len);
}

static int mail_engine_punid(int argc, char **argv, int sockd)
{
	int temp_len;
	uint32_t uid;
	char temp_buff[1024];

	if (argc != 4 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " uid FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW ||
	    gx_sql_col_uint64(pstmt, 0) != folder_id)
		return MIDB_E_NO_MESSAGE;
	uid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	pidb.reset();
	temp_len = sprintf(temp_buff, "TRUE %u\r\n", uid);
	return cmd_write(sockd, temp_buff, temp_len);
}

/*
 * Folder Details
 * Request:
 * 	P-FDDT <dir> <folder> <sortfield> <ascdesc>
 * Response:
 * 	TRUE <msgcount> <#recents> <#unreads> <uidvalidity(folder_id)> <uidnext> <offset>
 * offset is first unread msg. minus 1?!
 */
static int mail_engine_pfddt(int argc, char **argv, int sockd)
{
	int offset;
	int temp_len;
	uint32_t total;
	uint32_t uidnext;
	uint64_t uidvalid;
	uint64_t folder_id;
	char temp_buff[1024];
	char sql_string[1024];
	
	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	if (kw_to_sort_field(argv[3]) < FIELD_NONE)
		return MIDB_E_PARAMETER_ERROR;
	bool b_asc;
	if (!kw_to_sort_order(argv[4], b_asc))
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " uidnext FROM folders WHERE name=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[2], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return MIDB_E_NO_FOLDER;
	folder_id = sqlite3_column_int64(pstmt, 0);
	uidnext = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) "
	          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return MIDB_E_NO_FOLDER;
	total = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) FROM "
	          "messages WHERE folder_id=%llu AND read=0", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	uint32_t unreads = sqlite3_step(pstmt) ? sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) FROM"
	          " messages WHERE folder_id=%llu AND recent=0", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	uint32_t recents = sqlite3_step(pstmt) == SQLITE_ROW ? sqlite3_column_int64(pstmt, 0) : 0;
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT min(idx) FROM messages "
	          "WHERE folder_id=%llu AND read=0", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		offset = sqlite3_column_int64(pstmt, 0);
		if (!b_asc)
			offset = total - offset;
		else
			offset --;
	} else {
		offset = -1;
	}
	pstmt.finalize();
	pidb.reset();
	uidvalid = folder_id;
	temp_len = sprintf(temp_buff, "TRUE %u %u %u %llu %u %d\r\n",
	           total, recents, unreads, LLU{uidvalid}, uidnext + 1, offset);
	return cmd_write(sockd, temp_buff, temp_len);
}

static int mail_engine_psubf(int argc, char **argv, int sockd)
{
	char sql_string[1024];

	if (argc != 3 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET unsub=0"
	        " WHERE folder_id=%llu", LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

static int mail_engine_punsf(int argc, char **argv, int sockd)
{
	char sql_string[1024];

	if (argc != 3 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET unsub=1"
	        " WHERE folder_id=%llu", LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

static int mail_engine_psubl(int argc, char **argv, int sockd)
{
	int count;
	int offset;
	int temp_len;
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if (argc != 2 || strlen(argv[1]) >= 256)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	snprintf(sql_string, arsizeof(sql_string), "SELECT name FROM folders WHERE unsub=0");
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	count = 0;
	temp_len = 32;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		temp_len += gx_snprintf(temp_buff + temp_len,
		            GX_ARRAY_SIZE(temp_buff) - temp_len,  "%s\r\n",
					sqlite3_column_text(pstmt, 0));
		count ++;
	}
	pstmt.finalize();
	pidb.reset();
	offset = gx_snprintf(temp_buff, 32, "TRUE %d\r\n", count);
	memmove(temp_buff + 32 - offset, temp_buff, offset);
	return cmd_write(sockd, temp_buff + 32 - offset, offset + temp_len - 32);
}

/*
 * List mails in folder, returning the MIDs.
 * Request:
 * 	P-SIML <dir> <folder> <sort-field> <ascdesc> <idx> <msgcount>
 * Response:
 * 	TRUE <msgcount>
 * 	<mid> <uid> <flags> (repeat x msgcount)
 */
static int mail_engine_psiml(int argc, char **argv, int sockd)
{
	int offset;
	int length;
	int temp_len;
	int buff_len;
	uint32_t uid;
	int flags_len;
	int idx1, idx2;
	int total_mail;
	char flags_buff[16];
	char temp_line[1024];
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if ((argc != 5 && argc != 7) || strlen(argv[1]) >= 256 ||
	    strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto sort_field = kw_to_sort_field(argv[3]);
	if (sort_field < FIELD_NONE)
		return MIDB_E_PARAMETER_ERROR;
	bool b_asc;
	if (!kw_to_sort_order(argv[4], b_asc))
		return MIDB_E_PARAMETER_ERROR;
	if (7 == argc) {
		offset = strtol(argv[5], nullptr, 0);
		length = strtol(argv[6], nullptr, 0);
		if (length < 0)
			length = 0;
	} else {
		offset = 0;
		length = 0;
	}
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!mail_engine_sort_folder(pidb.get(), argv[2], sort_field))
		return MIDB_E_MNG_SORTFOLDER;
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) "
	          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return MIDB_E_NO_FOLDER;
	total_mail = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (b_asc) {
		if (offset < 0) {
			idx1 = std::max(1, total_mail + 1 + offset);
		} else {
			if (offset >= total_mail) {
				pidb.reset();
				return cmd_write(sockd, "TRUE 0\r\n");
			}
			idx1 = offset + 1;
		}
		if (length == 0 || total_mail - idx1 + 1 < length)
			length = total_mail - idx1 + 1;
		idx2 = idx1 + length - 1;
		snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string, uid, replied, "
				"unsent, flagged, deleted, read, recent, forwarded FROM "
				"messages WHERE folder_id=%llu AND idx>=%d AND idx<=%d "
				"ORDER BY idx", LLU{folder_id}, idx1, idx2);
	} else {
		if (offset < 0) {
			idx2 = std::min(-offset, total_mail);
		} else {
			if (offset >= total_mail) {
				pidb.reset();
				return cmd_write(sockd, "TRUE 0\r\n");
			}
			idx2 = total_mail - offset;
		}
		if (length == 0 || idx2 < length)
			length = idx2;
		idx1 = idx2 - length + 1;
		snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string, uid, replied, "
				"unsent, flagged, deleted, read, recent, forwarded FROM "
				"messages WHERE folder_id=%llu AND idx>=%d AND idx<=%d "
				"ORDER BY idx DESC", LLU{folder_id}, idx1, idx2);
	}
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	temp_len = sprintf(temp_buff, "TRUE %d\r\n", length);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		auto mid_string = pstmt.col_text(0);
		uid = sqlite3_column_int64(pstmt, 1);
		flags_buff[0] = '(';
		flags_len = 1;
		if (pstmt.col_int64(2) != 0)
			flags_buff[flags_len++] = 'A';
		if (pstmt.col_int64(3) != 0)
			flags_buff[flags_len++] = 'U';
		if (pstmt.col_int64(4) != 0)
			flags_buff[flags_len++] = 'F';
		if (pstmt.col_int64(5) != 0)
			flags_buff[flags_len++] = 'D';
		if (pstmt.col_int64(6) != 0)
			flags_buff[flags_len++] = 'S';
		if (pstmt.col_int64(7) != 0)
			flags_buff[flags_len++] = 'R';
		if (pstmt.col_int64(8) != 0)
			flags_buff[flags_len++] = 'W';
		flags_buff[flags_len++] = ')';
		flags_buff[flags_len] = '\0';
		buff_len = gx_snprintf(temp_line, GX_ARRAY_SIZE(temp_line),
			"%s %u %s\r\n", mid_string, uid,
			flags_buff);
		if (256*1024 - temp_len < buff_len) {
			auto ret = cmd_write(sockd, temp_buff, temp_len);
			if (ret != 0)
				return ret;
			temp_len = 0;
		}
		memcpy(temp_buff + temp_len, temp_line, buff_len);
		temp_len += buff_len;
	}
	pstmt.finalize();
	pidb.reset();
	return cmd_write(sockd, temp_buff, temp_len);
}

static int mail_engine_psimu(int argc, char **argv, int sockd) try
{
	struct simu_node {
		uint32_t idx, uid;
		char flags[10];
		std::string mid_string;
	};

	int total_mail = 0;
	char temp_line[1024];
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if (argc != 7 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto sort_field = kw_to_sort_field(argv[3]);
	if (sort_field < FIELD_NONE)
		return MIDB_E_PARAMETER_ERROR;
	bool b_asc;
	if (!kw_to_sort_order(argv[4], b_asc))
		return MIDB_E_PARAMETER_ERROR;
	seq_node::value_type first = strtol(argv[5], nullptr, 0), last = strtol(argv[6], nullptr, 0);
	if (first < 1 && first != seq_node::unset)
		return MIDB_E_PARAMETER_ERROR;
	if (last < 1 && last != seq_node::unset)
		return MIDB_E_PARAMETER_ERROR;
	if (first != seq_node::unset && last != seq_node::unset && last < first)
		std::swap(first, last);
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!mail_engine_sort_folder(pidb.get(), argv[2], sort_field))
		return MIDB_E_MNG_SORTFOLDER;
	if (b_asc) {
		if (first == seq_node::unset && last == seq_node::unset)
			/* "MAX:MAX" */
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
			         "FROM messages WHERE folder_id=%llu "
			         "ORDER BY idx DESC LIMIT 1", LLU{folder_id});
		else if (first == seq_node::unset)
			/* "MAX:99" */
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid<=%u ORDER BY idx DESC LIMIT 1",
				LLU{folder_id}, last);
		else if (last == seq_node::unset)
			/* "99:MAX" */
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u ORDER BY idx",
				LLU{folder_id}, first);
		else if (last == first)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid=%u",
				LLU{folder_id}, first);
		else
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND uid<=%u "
				"ORDER BY idx", LLU{folder_id}, first, last);
	} else {
		snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", LLU{folder_id});
		auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
		if (pstmt == nullptr)
			return MIDB_E_SQLPREP;
		if (sqlite3_step(pstmt) != SQLITE_ROW)
			return MIDB_E_NO_FOLDER;
		total_mail = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		if (first == seq_node::unset && last == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded"
				" FROM messages WHERE folder_id=%llu ORDER BY idx DESC LIMIT 1",
				LLU{folder_id});
		else if (first == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid<=%u ORDER BY idx"
				" DESC LIMIT 1", LLU{folder_id}, last);
		else if (last == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u ORDER BY idx"
				" DESC", LLU{folder_id}, first);
		else if (last == first)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid=%u",
				LLU{folder_id}, first);
		else
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND uid<=%u "
				"ORDER BY idx DESC", LLU{folder_id}, first, last);
	}

	std::vector<simu_node> temp_list;
	auto runq = [&pidb,&temp_list,total_mail,b_asc](const char *sql_string) -> int {

	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		simu_node sn;
		sn.idx = b_asc ? pstmt.col_int64(0) :
		         total_mail - pstmt.col_int64(0) + 1;
		sn.mid_string = pstmt.col_text(1);
		sn.uid = pstmt.col_int64(2);
		auto &flags_buff = sn.flags;
		flags_buff[0] = '(';
		uint8_t flags_len = 1;
		if (pstmt.col_int64(3) != 0)
			flags_buff[flags_len++] = 'A';
		if (pstmt.col_int64(4) != 0)
			flags_buff[flags_len++] = 'U';
		if (pstmt.col_int64(5) != 0)
			flags_buff[flags_len++] = 'F';
		if (pstmt.col_int64(6) != 0)
			flags_buff[flags_len++] = 'D';
		if (pstmt.col_int64(7) != 0)
			flags_buff[flags_len++] = 'S';
		if (pstmt.col_int64(8) != 0)
			flags_buff[flags_len++] = 'R';
		if (pstmt.col_int64(9) != 0)
			flags_buff[flags_len++] = 'W';
		flags_buff[flags_len++] = ')';
		flags_buff[flags_len] = '\0';
		temp_list.push_back(std::move(sn));
	}
	return 0;
	};
	auto iret = runq(sql_string);
	if (iret != 0)
		return iret;
	if (temp_list.size() == 0 && (first == seq_node::unset || last == seq_node::unset)) {
		/*
		 * RFC 3501: "a UID range of 559:* always includes the UID of
		 * the last message in the mailbox, even if 559 is higher than
		 * any assigned UID value".
		 */
		snprintf(sql_string, std::size(sql_string), "SELECT idx, mid_string, uid, "
		         "replied, unsent, flagged, deleted, read, recent, forwarded"
		         " FROM messages WHERE folder_id=%llu ORDER BY idx DESC LIMIT 1",
		         LLU{folder_id});
		iret = runq(sql_string);
		if (iret != 0)
			return iret;
	}

	auto temp_len = snprintf(temp_buff, std::size(temp_buff),
	                "TRUE %zu\r\n", temp_list.size());
	for (const auto &sn : temp_list) {
		auto buff_len = gx_snprintf(temp_line, std::size(temp_line), "%u %s %u %s\r\n",
		                sn.idx - 1, sn.mid_string.c_str(), sn.uid, sn.flags);
		if (256*1024 - temp_len < buff_len) {
			auto ret = cmd_write(sockd, temp_buff, temp_len);
			if (ret != 0)
				return ret;
			temp_len = 0;
		}
		memcpy(temp_buff + temp_len, temp_line, buff_len);
		temp_len += buff_len;
	}
	pidb.reset();
	return cmd_write(sockd, temp_buff, temp_len);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1204: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/*
 * List Deleted-flagged mails
 *
 * P-DELL <dir> <folder> <sort-field> <az>
 */
static int mail_engine_pdell(int argc, char **argv, int sockd)
{
	int length;
	int temp_len;
	int buff_len;
	uint32_t uid;
	uint32_t idx;
	char temp_line[1024];
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto sort_field = kw_to_sort_field(argv[3]);
	if (sort_field < FIELD_NONE)
		return MIDB_E_PARAMETER_ERROR;
	bool b_asc;
	if (!kw_to_sort_order(argv[4], b_asc))
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!mail_engine_sort_folder(pidb.get(), argv[2], sort_field))
		return MIDB_E_MNG_SORTFOLDER;
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) FROM "
		"messages WHERE folder_id=%llu AND deleted=1", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	if (sqlite3_step(pstmt) != SQLITE_ROW)
		return MIDB_E_NO_FOLDER;
	length = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), b_asc ?
	         "SELECT idx, mid_string, uid FROM messages WHERE folder_id=%llu AND deleted=1 ORDER BY idx" :
	         "SELECT idx, mid_string, uid FROM messages WHERE folder_id=%llu AND deleted=1 ORDER BY idx DESC",
	         LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	temp_len = sprintf(temp_buff, "TRUE %d\r\n", length);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		idx = sqlite3_column_int64(pstmt, 0);
		auto mid_string = pstmt.col_text(1);
		uid = sqlite3_column_int64(pstmt, 2);
		buff_len = gx_snprintf(temp_line, GX_ARRAY_SIZE(temp_line),
			"%u %s %u\r\n", idx - 1, mid_string, uid);
		if (256*1024 - temp_len < buff_len) {
			auto ret = cmd_write(sockd, temp_buff, temp_len);
			if (ret != 0)
				return ret;
			temp_len = 0;
		}
		memcpy(temp_buff + temp_len, temp_line, buff_len);
		temp_len += buff_len;
	}
	pstmt.finalize();
	pidb.reset();
	return cmd_write(sockd, temp_buff, temp_len);
}

static int mail_engine_pdtlu(int argc, char **argv, int sockd) try
{
	using dtlu_node = std::pair<std::string /* mid_string */, uint32_t /* idx */>;
	BOOL b_asc;
	int total_mail = 0;
	char sql_string[1024];
	char temp_buff[MAX_DIGLEN + 16];
	
	if (argc != 7 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto sort_field = kw_to_sort_field(argv[3]);
	if (sort_field < FIELD_NONE)
		return MIDB_E_PARAMETER_ERROR;
	if (strcasecmp(argv[4], "ASC") == 0)
		b_asc = TRUE;
	else if (strcasecmp(argv[4], "DSC") == 0)
		b_asc = FALSE;
	else
		return MIDB_E_PARAMETER_ERROR;

	seq_node::value_type first = strtol(argv[5], nullptr, 0), last = strtol(argv[6], nullptr, 0);
	if (first < 1 && first != seq_node::unset)
		return MIDB_E_PARAMETER_ERROR;
	if (last < 1 && last != seq_node::unset)
		return MIDB_E_PARAMETER_ERROR;
	if (first != seq_node::unset && last != seq_node::unset && last < first)
		std::swap(first, last);
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	if (!mail_engine_sort_folder(pidb.get(), argv[2], sort_field))
		return MIDB_E_MNG_SORTFOLDER;
	if (b_asc) {
		/* UNSET always means MAX, never MIN */
		if (first == seq_node::unset && last == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string"
				" FROM messages WHERE folder_id=%llu ORDER BY idx DESC LIMIT 1",
				LLU{folder_id});
		else if (first == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid<=%u "
					" ORDER BY idx DESC LIMIT 1", LLU{folder_id}, last);
		else if (last == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid>=%u"
					" ORDER BY idx", LLU{folder_id}, first);
		else if (last == first)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid=%u",
					LLU{folder_id}, first);
		else
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND"
				" uid<=%u ORDER BY idx", LLU{folder_id}, first, last);
	} else {
		snprintf(sql_string, arsizeof(sql_string), "SELECT count(message_id) "
		          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
		auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
		if (pstmt == nullptr)
			return MIDB_E_SQLPREP;
		if (sqlite3_step(pstmt) != SQLITE_ROW)
			return MIDB_E_NO_FOLDER;
		total_mail = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		if (first == seq_node::unset && last == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string"
				" FROM messages WHERE folder_id=%llu ORDER BY idx"
				" DESC LIMIT 1", LLU{folder_id});
		else if (first == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid<=%u"
					" ORDER BY idx DESC LIMIT 1", LLU{folder_id}, last);
		else if (last == seq_node::unset)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid>=%u"
			         " ORDER BY idx DESC", LLU{folder_id}, first);
		else if (last == first)
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid=%u",
					LLU{folder_id}, first);
		else
			snprintf(sql_string, arsizeof(sql_string), "SELECT idx, mid_string "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND "
				"uid<=%u ORDER BY idx DESC", LLU{folder_id}, first, last);
	}

	std::vector<dtlu_node> temp_list;
	auto runq = [&pidb,&temp_list,b_asc,total_mail](const char *sql_string) -> int {

	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		temp_list.emplace_back(pstmt.col_text(1),
			b_asc ? pstmt.col_int64(0) :
			total_mail - pstmt.col_int64(0) + 1);
	}
	return 0;
	};
	auto iret = runq(sql_string);
	if (iret != 0)
		return iret;
	if (temp_list.empty() && (first == seq_node::unset || last == seq_node::unset)) {
		/* Rerun like in pshru */
		snprintf(sql_string, std::size(sql_string), "SELECT idx, mid_string"
		         " FROM messages WHERE folder_id=%llu ORDER BY idx"
		         " DESC LIMIT 1", LLU{folder_id});
		iret = runq(sql_string);
		if (iret != 0)
			return iret;
	}

	auto temp_len = sprintf(temp_buff, "TRUE %zu\r\n", temp_list.size());
	auto ret = cmd_write(sockd, temp_buff, temp_len);
	if (ret != 0)
		return ret;
	for (const auto &dt : temp_list) {
		temp_len = snprintf(temp_buff, std::size(temp_buff), "%d ", dt.second - 1);
		if (mail_engine_get_digest(pidb->psqlite, dt.first.c_str(),
		    temp_buff + temp_len) == 0)
			return MIDB_E_DIGEST;
		temp_len = strlen(temp_buff);
		temp_buff[temp_len++] = '\r';
		temp_buff[temp_len++] = '\n';
		ret = cmd_write(sockd, temp_buff, temp_len);
		if (ret != 0)
			return ret;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1210: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/*
 * Set flags on message. For (S)een and (U)nsent, exmdb is contacted(!), which
 * is different from GFLG.
 *
 * Request:
 * 	P-SFLG <dir> <folder> <midstr> <flags>
 */
static int mail_engine_psflg(int argc, char **argv, int sockd)
{
	uint64_t read_cn;
	uint64_t message_id;
	uint32_t tmp_proptag;
	char sql_string[1024];
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;

	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
	    gx_sql_col_uint64(pstmt, 1) != folder_id)
		return MIDB_E_NO_MESSAGE;
	message_id = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (NULL != strchr(argv[4], 'A')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET replied=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'U')) {
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PR_MESSAGE_FLAGS;
		if (!exmdb_client::get_message_properties(argv[1], NULL,
		    0, rop_util_make_eid_ex(1, message_id),
		    &proptags, &propvals) || propvals.count == 0)
			return MIDB_E_MDB_GETMSGPROPS;
		auto message_flags = *static_cast<uint32_t *>(propvals.ppropval[0].pvalue);
		if (!(message_flags & MSGFLAG_UNSENT)) {
			message_flags |= MSGFLAG_UNSENT;
			propvals.ppropval[0].pvalue = &message_flags;
			if (!exmdb_client::set_message_properties(argv[1],
			    nullptr, 0, rop_util_make_eid_ex(1, message_id),
			    &propvals, &problems))
				return MIDB_E_MDB_SETMSGPROPS;
		}
	}
	if (NULL != strchr(argv[4], 'F')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET flagged=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'W')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET forwarded=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'D')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET deleted=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (strchr(argv[4], 'S') != nullptr &&
	    !exmdb_client::set_message_read_state(argv[1], nullptr,
	    rop_util_make_eid_ex(1, message_id), 1, &read_cn))
		return MIDB_E_MDB_SETMSGRD;
	if (NULL != strchr(argv[4], 'R')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET recent=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

/*
 * Remove flags on message. Flags (S)een and (U)nsent trigger contact to exmdb.
 *
 * Request:
 * 	P-RFLG <dir> <folder> <midstr> <flags>
 */
static int mail_engine_prflg(int argc, char **argv, int sockd)
{
	uint64_t read_cn;
	uint64_t message_id;
	uint32_t tmp_proptag;
	char sql_string[1024];
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;

	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
	    gx_sql_col_uint64(pstmt, 1) != folder_id)
		return MIDB_E_NO_MESSAGE;
	message_id = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (NULL != strchr(argv[4], 'A')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET replied=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'U')) {
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PR_MESSAGE_FLAGS;
		if (!exmdb_client::get_message_properties(argv[1], nullptr,
		    0, rop_util_make_eid_ex(1, message_id),
		    &proptags, &propvals) || propvals.count == 0)
			return MIDB_E_MDB_GETMSGPROPS;
		auto message_flags = *static_cast<uint32_t *>(propvals.ppropval[0].pvalue);
		if (message_flags & MSGFLAG_UNSENT) {
			message_flags &= ~MSGFLAG_UNSENT;
			propvals.ppropval[0].pvalue = &message_flags;
			if (!exmdb_client::set_message_properties(argv[1],
			    nullptr, 0, rop_util_make_eid_ex(1, message_id),
			    &propvals, &problems))
				return MIDB_E_MDB_SETMSGPROPS;
		}
	}
	if (NULL != strchr(argv[4], 'F')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET flagged=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'W')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET forwarded=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'D')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET deleted=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (strchr(argv[4], 'S') != nullptr &&
	    !exmdb_client::set_message_read_state(argv[1], nullptr,
	    rop_util_make_eid_ex(1, message_id), 0, &read_cn))
		return MIDB_E_MDB_SETMSGRD;
	if (NULL != strchr(argv[4], 'R')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET recent=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

/*
 * Get flags on message from midb.sqlite without contacting exmdb.
 * You better hope that the change notification socket is working,
 * because otherwise changes from SFLG/RFLG won't be visible.
 *
 * Request:
 * 	P-GFLG <dir> <folder> <midstr>
 * Response:
 * 	TRUE (<flags>)
 * flags e.g. Answered(A), Unsent(U), Flagged(F), Deleted(D), Read/Seen(S),
 * Recent(R), Forwarded(W)
 */
static int mail_engine_pgflg(int argc, char **argv, int sockd)
{
	int temp_len;
	int flags_len;
	char flags_buff[32];
	char temp_buff[1024];

	if (argc != 4 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id, recent, "
	             "read, unsent, flagged, replied, forwarded, deleted "
	             "FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
	    gx_sql_col_uint64(pstmt, 0) != folder_id)
		return MIDB_E_NO_MESSAGE;
	flags_buff[0] = '(';
	flags_len = 1;
	if (pstmt.col_int64(5) != 0)
		flags_buff[flags_len++] = 'A';
	if (pstmt.col_int64(3) != 0)
		flags_buff[flags_len++] = 'U';
	if (pstmt.col_int64(4) != 0)
		flags_buff[flags_len++] = 'F';
	if (pstmt.col_int64(6) != 0)
		flags_buff[flags_len++] = 'W';
	if (pstmt.col_int64(7) != 0)
		flags_buff[flags_len++] = 'D';
	if (pstmt.col_int64(2) != 0)
		flags_buff[flags_len++] = 'S';
	if (pstmt.col_int64(1) != 0)
		flags_buff[flags_len++] = 'R';
	pstmt.finalize();
	pidb.reset();
	flags_buff[flags_len++] = ')';
	flags_buff[flags_len] = '\0';
	temp_len = sprintf(temp_buff, "TRUE %s\r\n", flags_buff);
	return cmd_write(sockd, temp_buff, temp_len);
}

/*
 * Search and list messages
 *
 * Request:
 * 	P-SRHL <dir> <foldername> <charset> <condition-tree-spec>
 * ct-spec: \0 terminated list of strings (individually terminated by \0 too)
 * ct-spec e.g. "UNDELETED\x00\x00"
 * Response:
 * 	TRUE <uidlist>
 */
static int mail_engine_psrhl(int argc, char **argv, int sockd)
{
	char *parg;
	int tmp_argc;
	sqlite3 *psqlite;
	size_t decode_len;
	char temp_path[256];
	char* tmp_argv[1024];
	char tmp_buff[16*1024];
	char list_buff[256*1024];
	
	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto tmp_len = strlen(argv[4]);
	if (tmp_len >= sizeof(tmp_buff) ||
	    decode64(argv[4], tmp_len, tmp_buff, arsizeof(tmp_buff), &decode_len) != 0)
		return MIDB_E_PARAMETER_ERROR;
	tmp_argc = 0;
	parg = tmp_buff;
	while (*parg != '\0' && parg - tmp_buff >= 0 &&
	       static_cast<size_t>(parg - tmp_buff) < decode_len &&
	       static_cast<size_t>(tmp_argc) < sizeof(tmp_argv)) {
		tmp_argv[tmp_argc] = parg;
		parg += strlen(parg) + 1;
		tmp_argc ++;
	}
	if (tmp_argc == 0)
		return MIDB_E_PARAMETER_ERROR;
	auto ptree = mail_engine_ct_build(tmp_argc, tmp_argv);
	if (ptree == nullptr)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	pidb.reset();
	sprintf(temp_path, "%s/exmdb/midb.sqlite3", argv[1]);
	auto ret = sqlite3_open_v2(temp_path, &psqlite, SQLITE_OPEN_READWRITE, nullptr);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1439: sqlite3_open %s: %s", temp_path, sqlite3_errstr(ret));
		return MIDB_E_HASHTABLE_FULL;
	}
	auto presult = mail_engine_ct_match(argv[3], psqlite, folder_id, ptree.get(), false);
	if (!presult.has_value()) {
		sqlite3_close(psqlite);
		return MIDB_E_MNG_CTMATCH;
	}
	sqlite3_close(psqlite);
	tmp_len = 4;
	strcpy(list_buff, "TRUE");
	for (auto result : *presult) {
		tmp_len += gx_snprintf(list_buff + tmp_len,
		           GX_ARRAY_SIZE(list_buff) - tmp_len, " %d", result);
		if (tmp_len >= 255*1024) {
			ret = cmd_write(sockd, list_buff, tmp_len);
			if (ret != 0)
				return ret;
			tmp_len = 0;
		}
    }
    list_buff[tmp_len] = '\r';
	tmp_len ++;
    list_buff[tmp_len] = '\n';
	tmp_len ++;
	return cmd_write(sockd, list_buff, tmp_len);
}

/*
 * Search by UIDs
 *
 * Request:
 * 	P-SRHU <dir> <folder> <charset> <uid...>
 */
static int mail_engine_psrhu(int argc, char **argv, int sockd)
{
	char *parg;
	int tmp_argc;
	sqlite3 *psqlite;
	size_t decode_len;
	char temp_path[256];
	char* tmp_argv[1024];
	char tmp_buff[16*1024];
	char list_buff[256*1024];
	
	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto tmp_len = strlen(argv[4]);
	if (tmp_len >= sizeof(tmp_buff) ||
	    decode64(argv[4], tmp_len, tmp_buff, arsizeof(tmp_buff), &decode_len) != 0)
		return MIDB_E_PARAMETER_ERROR;
	tmp_argc = 0;
	parg = tmp_buff;
	while (*parg != '\0' && parg - tmp_buff >= 0 &&
	       static_cast<size_t>(parg - tmp_buff) < decode_len &&
	       static_cast<size_t>(tmp_argc) < sizeof(tmp_argv)) {
		tmp_argv[tmp_argc] = parg;
		parg += strlen(parg) + 1;
		tmp_argc ++;
	}
	if (tmp_argc == 0)
		return MIDB_E_PARAMETER_ERROR;
	auto ptree = mail_engine_ct_build(tmp_argc, tmp_argv);
	if (ptree == nullptr)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	pidb.reset();
	sprintf(temp_path, "%s/exmdb/midb.sqlite3", argv[1]);
	auto ret = sqlite3_open_v2(temp_path, &psqlite, SQLITE_OPEN_READWRITE, nullptr);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1505: sqlite3_open %s: %s", temp_path, sqlite3_errstr(ret));
		return MIDB_E_HASHTABLE_FULL;
	}
	auto presult = mail_engine_ct_match(argv[3], psqlite, folder_id, ptree.get(), TRUE);
	if (!presult.has_value()) {
		sqlite3_close(psqlite);
		return MIDB_E_MNG_CTMATCH;
	}
	sqlite3_close(psqlite);
	tmp_len = 4;
	strcpy(list_buff, "TRUE");
	for (auto result : *presult) {
		tmp_len += gx_snprintf(list_buff + tmp_len,
		           GX_ARRAY_SIZE(list_buff) - tmp_len, " %d", result);
		if (tmp_len >= 255*1024) {
			ret = cmd_write(sockd, list_buff, tmp_len);
			if (ret != 0)
				return ret;
			tmp_len = 0;
		}
    }
    list_buff[tmp_len] = '\r';
	tmp_len ++;
    list_buff[tmp_len] = '\n';
	tmp_len ++;
	return cmd_write(sockd, list_buff, tmp_len);
}

static int mail_engine_xunld(int argc, char **argv, int sockd)
{
	if (argc != 2)
		return MIDB_E_PARAMETER_ERROR;
	std::lock_guard hhold(g_hash_lock);
	auto it = g_hash_table.find(argv[1]);
	if (it == g_hash_table.end())
		return MIDB_E_STORE_NOT_LOADED;
	auto pidb = &it->second;
	if (pidb->reference != 0)
		return MIDB_E_STORE_BUSY;
	if (pidb->sub_id != 0)
		exmdb_client::unsubscribe_notification(argv[1], pidb->sub_id);
	g_hash_table.erase(it);
	return cmd_write(sockd, "TRUE 1\r\n");
}

static int mail_engine_xrsym(int argc, char **argv, int sockd)
{
	if (argc != 2)
		return MIDB_E_PARAMETER_ERROR;
	auto idb = mail_engine_peek_idb(argv[1]);
	if (idb == nullptr) {
		mail_engine_get_idb(argv[1], true);
		return cmd_write(sockd, "TRUE 2\r\n");
	} else if (!mail_engine_sync_mailbox(idb.get(), true)) {
		return cmd_write(sockd, "TRUE 0\r\n");
	} else {
		return cmd_write(sockd, "TRUE 1\r\n");
	}
}

static int mail_engine_xrsyf(int argc, char **argv, int sockd)
{
	if (argc != 3)
		return MIDB_E_PARAMETER_ERROR;
	auto idb = mail_engine_get_idb(argv[1]);
	if (idb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	if (!mail_engine_sync_contents(idb.get(), strtoul(argv[2], nullptr, 0)))
		return cmd_write(sockd, "FALSE 1\r\n");
	else
		return cmd_write(sockd, "TRUE 1\r\n");
}

static void mail_engine_add_notification_message(
	IDB_ITEM *pidb, uint64_t folder_id, uint64_t message_id)
{
	uint32_t uidnext;
	char flags_buff[16];
	char mid_string[128];
	char sql_string[1024];
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[4];
	
	proptags.count = 4;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PR_MESSAGE_DELIVERY_TIME;
	tmp_proptags[1] = PR_LAST_MODIFICATION_TIME;
	tmp_proptags[2] = PidTagMidString;
	tmp_proptags[3] = PR_MESSAGE_FLAGS;
	if (!exmdb_client::get_message_properties(common_util_get_maildir(),
	    nullptr, 0, rop_util_make_eid_ex(1, message_id),
	    &proptags, &propvals))
		return;		
	auto lnum = propvals.get<const uint64_t>(PR_LAST_MODIFICATION_TIME);
	auto mod_time = lnum != nullptr ? *lnum : 0;
	lnum = propvals.get<uint64_t>(PR_MESSAGE_DELIVERY_TIME);
	auto received_time = lnum != nullptr ? *lnum : 0;
	auto num = propvals.get<const uint32_t>(PR_MESSAGE_FLAGS);
	auto message_flags = num != nullptr ? *num : 0;
	flags_buff[0] = '\0';
	auto str = propvals.get<const char>(PidTagMidString);
	if (str == nullptr) {
		snprintf(sql_string, arsizeof(sql_string), "SELECT mid_string, flag_string"
		          " FROM mapping WHERE message_id=%llu", LLU{message_id});
		auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
		if (pstmt == nullptr)
			return;
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			gx_strlcpy(mid_string, pstmt.col_text(0), std::size(mid_string));
			str = pstmt.col_text(1);
			if (str != nullptr)
				gx_strlcpy(flags_buff, str, std::size(flags_buff));
			str = mid_string;
		}
		pstmt.finalize();
		if (str != nullptr) {
			snprintf(sql_string, arsizeof(sql_string), "DELETE FROM mapping"
			        " WHERE message_id=%llu", LLU{message_id});
			gx_sql_exec(pidb->psqlite, sql_string);
		}
	}
	snprintf(sql_string, arsizeof(sql_string), "SELECT uidnext FROM"
	          " folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return;
	uidnext = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET"
		" uidnext=uidnext+1, sort_field=%d "
		"WHERE folder_id=%llu", FIELD_NONE, LLU{folder_id});
	if (gx_sql_exec(pidb->psqlite, sql_string) != SQLITE_OK)
		return;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO messages ("
		"message_id, folder_id, mid_string, mod_time, uid, "
		"unsent, read, subject, sender, rcpt, size, received)"
		" VALUES (?, %llu, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return;	
	mail_engine_insert_message(pstmt, &uidnext, message_id, str,
		message_flags, received_time, mod_time);
	pstmt.finalize();
	if (NULL != strchr(flags_buff, 'F')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET "
		        "flagged=1 WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(flags_buff, 'A')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET "
		        "replied=1 WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(flags_buff, 'W')) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET "
		        "forwarded=1 WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
}

static void mail_engine_delete_notification_message(
	IDB_ITEM *pidb, uint64_t folder_id, uint64_t message_id)
{
	char sql_string[1024];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM "
	          "messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ||
	    gx_sql_col_uint64(pstmt, 0) != folder_id)
		return;
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "DELETE FROM messages"
	        " WHERE message_id=%llu", LLU{message_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET sort_field=%d "
	        "WHERE folder_id=%llu", FIELD_NONE, LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
}

static BOOL mail_engine_add_notification_folder(
	IDB_ITEM *pidb, uint64_t parent_id, uint64_t folder_id)
{
	char sql_string[1280];
	char decoded_name[512];
	PROPTAG_ARRAY proptags;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[4];
	
	if (auto x = spfid_to_name(parent_id)) {
		gx_strlcpy(decoded_name, x, arsizeof(decoded_name));
	} else if (parent_id == PRIVATE_FID_IPMSUBTREE) {
	} else {
		snprintf(sql_string, arsizeof(sql_string), "SELECT name FROM"
		          " folders WHERE folder_id=%llu", LLU{parent_id});
		auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ||
		    !decode_hex_binary(pstmt.col_text(0),
		    decoded_name, std::size(decoded_name)))
			return FALSE;
	}
	proptags.count = 4;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PR_DISPLAY_NAME;
	tmp_proptags[1] = PR_LOCAL_COMMIT_TIME_MAX;
	tmp_proptags[2] = PR_CONTAINER_CLASS;
	tmp_proptags[3] = PR_ATTR_HIDDEN;
	bool b_waited = false;
 REQUERY_FOLDER:
	if (!exmdb_client::get_folder_properties(common_util_get_maildir(), 0,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals))
		return FALSE;		
	auto flag = propvals.get<const uint8_t>(PR_ATTR_HIDDEN);
	if (flag != nullptr && *flag != 0)
		return FALSE;
	auto cont_class = propvals.get<const char>(PR_CONTAINER_CLASS);
	if (cont_class == nullptr && !b_waited) {
		/* outlook will set the PR_CONTAINER_CLASS
			after RopCreateFolder, so try to wait! */
		sleep(1);
		b_waited = true;
		goto REQUERY_FOLDER;
	}
	if (skip_folder_class(cont_class))
		return FALSE;
	auto lnum = propvals.get<const uint64_t>(PR_LOCAL_COMMIT_TIME_MAX);
	auto commit_max = lnum != nullptr ? *lnum : 0;
	auto str = propvals.get<const char>(PR_DISPLAY_NAME);
	if (str == nullptr)
		return FALSE;
	auto tmp_len = strlen(str);
	if (tmp_len >= 256)
		return FALSE;
	std::string temp_name;
	try {
		if (parent_id == PRIVATE_FID_IPMSUBTREE) {
			temp_name.assign(str, tmp_len);
		} else {
			if (tmp_len + strlen(decoded_name) >= 511)
				return FALSE;
			temp_name = decoded_name + "/"s + str;
		}
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1477: ENOMEM");
		return false;
	}
	encode_hex_binary(temp_name.c_str(), temp_name.size(), encoded_name, arsizeof(encoded_name));
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folders (folder_id, parent_fid, "
	        "commit_max, name) VALUES (%llu, %llu, %llu, '%s')", LLU{folder_id},
	        LLU{parent_id}, LLU{commit_max}, encoded_name);
	if (gx_sql_exec(pidb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

static void mail_engine_delete_notification_folder(
	IDB_ITEM *pidb, uint64_t folder_id)
{
	char sql_string[256];
	
	snprintf(sql_string, arsizeof(sql_string), "DELETE FROM folders "
	        "WHERE folder_id=%llu", LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
}

static void mail_engine_update_subfolders_name(IDB_ITEM *pidb,
	uint64_t parent_id, const char *parent_name)
{
	int tmp_len;
	char *ptoken;
	uint64_t folder_id;
	char temp_name[512];
	char sql_string[1280];
	char decoded_name[512];
	char encoded_name[1024];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id, name"
	          " FROM folders WHERE parent_fid=%llu", LLU{parent_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return;	
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		folder_id = sqlite3_column_int64(pstmt, 0);
		if (!decode_hex_binary(pstmt.col_text(1),
		    decoded_name, std::size(decoded_name)))
			continue;
		ptoken = strrchr(decoded_name, '/');
		if (ptoken == nullptr ||
		    strlen(ptoken) + strlen(parent_name) >= 512)
			continue;
		tmp_len = sprintf(temp_name, "%s%s", parent_name, ptoken);
		encode_hex_binary(temp_name, tmp_len, encoded_name, 1024);
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET name='%s' "
		        "WHERE folder_id=%llu", encoded_name, LLU{folder_id});
		gx_sql_exec(pidb->psqlite, sql_string);
		mail_engine_update_subfolders_name(pidb, folder_id, temp_name);
	}
}

static void mail_engine_move_notification_folder(
	IDB_ITEM *pidb, uint64_t parent_id, uint64_t folder_id)
{
	uint32_t tmp_proptag;
	char sql_string[1280];
	char decoded_name[512];
	PROPTAG_ARRAY proptags;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id "
	          "FROM folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return;	
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		pstmt.finalize();
		mail_engine_add_notification_folder(
				pidb, parent_id, folder_id);
		return;
	}
	pstmt.finalize();
	if (auto x = spfid_to_name(parent_id)) {
		gx_strlcpy(decoded_name, x, arsizeof(decoded_name));
	} else if (parent_id == PRIVATE_FID_IPMSUBTREE) {
	} else {
		snprintf(sql_string, arsizeof(sql_string), "SELECT name FROM"
		          " folders WHERE folder_id=%llu", LLU{parent_id});
		pstmt = gx_sql_prep(pidb->psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ||
		    !decode_hex_binary(pstmt.col_text(0),
		    decoded_name, std::size(decoded_name)))
			return;
		pstmt.finalize();
	}
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PR_DISPLAY_NAME;
	if (!exmdb_client::get_folder_properties(common_util_get_maildir(), 0,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals))
		return;		

	auto str = propvals.get<const char>(PR_DISPLAY_NAME);
	if (str == nullptr)
		return;
	auto tmp_len = strlen(str);
	if (tmp_len >= 256)
		return;
	std::string temp_name;
	try {
		if (parent_id == PRIVATE_FID_IPMSUBTREE) {
			temp_name.assign(str, tmp_len);
		} else {
			if (tmp_len + strlen(decoded_name) >= 511)
				return;
			temp_name = decoded_name + "/"s + str;
		}
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1478: ENOMEM");
	}
	encode_hex_binary(temp_name.c_str(), temp_name.size(), encoded_name, arsizeof(encoded_name));
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET parent_fid=%llu, name='%s' "
	        "WHERE folder_id=%llu", LLU{parent_id}, encoded_name, LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	mail_engine_update_subfolders_name(pidb, folder_id, temp_name.c_str());
}

static void mail_engine_modify_notification_folder(
	IDB_ITEM *pidb, uint64_t folder_id)
{
	char *pdisplayname;
	uint32_t tmp_proptag;
	char sql_string[1280];
	char decoded_name[512];
	PROPTAG_ARRAY proptags;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	
	if (spfid_to_name(folder_id) != nullptr || folder_id == PRIVATE_FID_IPMSUBTREE)
		return;
	snprintf(sql_string, arsizeof(sql_string), "SELECT name FROM"
	          " folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ||
	    !decode_hex_binary(pstmt.col_text(0),
	    decoded_name, std::size(decoded_name)))
		return;
	pstmt.finalize();
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PR_DISPLAY_NAME;
	if (!exmdb_client::get_folder_properties(common_util_get_maildir(), 0,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals))
		return;		
	auto str = propvals.get<const char>(PR_DISPLAY_NAME);
	if (str == nullptr)
		return;
	pdisplayname = strrchr(decoded_name, '/');
	if (pdisplayname == nullptr)
		pdisplayname = decoded_name;
	else
		pdisplayname ++;

	if (strcmp(pdisplayname, str) == 0)
		return;
	auto tmp_len = strlen(str);
	if (tmp_len >= 256)
		return;
	if (pdisplayname == decoded_name) {
		memcpy(decoded_name, str, tmp_len);
	} else {
		if (pdisplayname - decoded_name + tmp_len >= 512)
			return;
		strcpy(pdisplayname, str);
		tmp_len = strlen(decoded_name);
	}
	encode_hex_binary(decoded_name, tmp_len, encoded_name, 1024);
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET name='%s' "
	        "WHERE folder_id=%llu", encoded_name, LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	mail_engine_update_subfolders_name(pidb, folder_id, decoded_name);
}

static void mail_engine_modify_notification_message(
	IDB_ITEM *pidb, uint64_t folder_id, uint64_t message_id)
{
	char sql_string[256];
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[3];
	
	proptags.count = 3;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PR_MESSAGE_FLAGS;
	tmp_proptags[1] = PR_LAST_MODIFICATION_TIME;
	tmp_proptags[2] = PidTagMidString;
	if (!exmdb_client::get_message_properties(common_util_get_maildir(),
	    nullptr, 0, rop_util_make_eid_ex(1, message_id),
	    &proptags, &propvals))
		return;	
	auto num = propvals.get<const uint32_t>(PR_MESSAGE_FLAGS);
	auto message_flags = num != nullptr ? *num : 0;
	auto str = propvals.get<const char>(PidTagMidString);
	if (str != nullptr) {
 UPDATE_MESSAGE_FLAGS:
		auto b_unsent = !!(message_flags & MSGFLAG_UNSENT);
		auto b_read   = !!(message_flags & MSGFLAG_READ);
		snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET read=%d, unsent=%d"
		        " WHERE message_id=%llu", b_read, b_unsent, LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
		return;
	}
	auto ts = propvals.get<const uint64_t>(PR_LAST_MODIFICATION_TIME);
	auto mod_time = ts != nullptr ? *ts : 0;
	snprintf(sql_string, arsizeof(sql_string), "SELECT mod_time FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return;
	if (gx_sql_col_uint64(pstmt, 0) == mod_time) {
		pstmt.finalize();
		goto UPDATE_MESSAGE_FLAGS;
	}
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "DELETE FROM messages"
	        " WHERE message_id=%llu", LLU{message_id});
	if (gx_sql_exec(pidb->psqlite, sql_string) != SQLITE_OK)
		return;	
	return mail_engine_add_notification_message(
					pidb, folder_id, message_id);
}

static void mail_engine_notification_proc(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify)
{
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t message_id;
	char temp_buff[1280];
	char sql_string[1024];
	
	if (b_table)
		return;
	auto pidb = mail_engine_peek_idb(dir);
	if (pidb == nullptr || pidb->sub_id != notify_id)
		return;
	switch (pdb_notify->type) {
	case DB_NOTIFY_TYPE_NEW_MAIL: {
		auto n = static_cast<const DB_NOTIFY_NEW_MAIL *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id, message_id);
		snprintf(sql_string, arsizeof(sql_string), "SELECT name FROM"
		          " folders WHERE folder_id=%llu", LLU{folder_id});
		auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			break;
		snprintf(temp_buff, 1280, "FOLDER-TOUCH %s %s",
		         pidb->username.c_str(), pstmt.col_text(0));
		pstmt.finalize();
		system_services_broadcast_event(temp_buff);
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_CREATED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_CREATED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		parent_id = n->parent_id;
		mail_engine_add_notification_folder(pidb.get(), parent_id, folder_id);
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_CREATED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_DELETED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_DELETED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		mail_engine_delete_notification_folder(pidb.get(), folder_id);
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_DELETED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_DELETED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_delete_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MODIFIED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		mail_engine_modify_notification_folder(pidb.get(), folder_id);
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(pdb_notify->pdata);
		message_id = n->message_id;
		folder_id = n->folder_id;
		mail_engine_modify_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MOVED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		parent_id = n->parent_id;
		mail_engine_move_notification_folder(pidb.get(), parent_id, folder_id);
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_MOVED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pdb_notify->pdata);
		folder_id = n->old_folder_id;
		message_id = n->old_message_id;
		mail_engine_delete_notification_message(pidb.get(), folder_id, message_id);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_COPIED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		parent_id = n->parent_id;
		if (mail_engine_add_notification_folder(pidb.get(), parent_id, folder_id))
			mail_engine_sync_contents(pidb.get(), folder_id);
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_COPIED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	}
}

void mail_engine_init(const char *default_charset, const char *org_name,
    size_t table_size, BOOL b_async, BOOL b_wal,
    uint64_t mmap_size, int mime_num)
{
	g_sequence_id = 0;
	gx_strlcpy(g_default_charset, default_charset, GX_ARRAY_SIZE(g_default_charset));
	gx_strlcpy(g_org_name, org_name, GX_ARRAY_SIZE(g_org_name));
	g_async = b_async;
	g_wal = b_wal;
	g_mmap_size = mmap_size;
	g_table_size = table_size;
	g_mime_num = mime_num;
}

int mail_engine_run()
{
	if (sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK)
		mlog(LV_WARN, "mail_engine: failed to change "
			"to multiple thread mode for sqlite engine");
	if (sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0) != SQLITE_OK)
		mlog(LV_WARN, "mail_engine: failed to close"
			" memory statistic for sqlite engine");
	if (!oxcmail_init_library(g_org_name,
		system_services_get_user_ids, system_services_get_username_from_id)) {
		mlog(LV_ERR, "mail_engine: failed to init oxcmail library");
		return -1;
	}
	g_mime_pool = MIME_POOL::create(g_mime_num, FILENUM_PER_MIME,
	              "midb_mime_pool (midb.cfg:g_mime_num)");
	if (NULL == g_mime_pool) {
		mlog(LV_ERR, "mail_engine: failed to init MIME pool");
		return -3;
	}
	g_alloc_mjson = mjson_allocator_init(g_table_size * 10);
	g_notify_stop = false;
	auto ret = pthread_create4(&g_scan_tid, nullptr, midbme_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "mail_engine: failed to create scan thread: %s", strerror(ret));
		return -5;
	}
	pthread_setname_np(g_scan_tid, "mail_engine");
	cmd_parser_register_command("M-LIST", mail_engine_mlist);
	cmd_parser_register_command("M-UIDL", mail_engine_muidl);
	cmd_parser_register_command("M-INST", mail_engine_minst);
	cmd_parser_register_command("M-DELE", mail_engine_mdele);
	cmd_parser_register_command("M-COPY", mail_engine_mcopy);
	cmd_parser_register_command("M-MAKF", mail_engine_mmakf);
	cmd_parser_register_command("M-REMF", mail_engine_mremf);
	cmd_parser_register_command("M-RENF", mail_engine_mrenf);
	cmd_parser_register_command("M-ENUM", mail_engine_menum);
	cmd_parser_register_command("M-CKFL", mail_engine_mckfl);
	cmd_parser_register_command("M-PING", mail_engine_mping);
	cmd_parser_register_command("P-OFST", mail_engine_pofst);
	cmd_parser_register_command("P-UNID", mail_engine_punid);
	cmd_parser_register_command("P-FDDT", mail_engine_pfddt);
	cmd_parser_register_command("P-SUBF", mail_engine_psubf);
	cmd_parser_register_command("P-UNSF", mail_engine_punsf);
	cmd_parser_register_command("P-SUBL", mail_engine_psubl);
	cmd_parser_register_command("P-SIML", mail_engine_psiml);
	cmd_parser_register_command("P-SIMU", mail_engine_psimu);
	cmd_parser_register_command("P-DELL", mail_engine_pdell);
	cmd_parser_register_command("P-DTLU", mail_engine_pdtlu);
	cmd_parser_register_command("P-SFLG", mail_engine_psflg);
	cmd_parser_register_command("P-RFLG", mail_engine_prflg);
	cmd_parser_register_command("P-GFLG", mail_engine_pgflg);
	cmd_parser_register_command("P-SRHL", mail_engine_psrhl);
	cmd_parser_register_command("P-SRHU", mail_engine_psrhu);
	cmd_parser_register_command("X-UNLD", mail_engine_xunld);
	cmd_parser_register_command("X-RSYM", mail_engine_xrsym);
	cmd_parser_register_command("X-RSYF", mail_engine_xrsyf);
	exmdb_client_register_proc(reinterpret_cast<void *>(mail_engine_notification_proc));
	return 0;
}

void mail_engine_stop()
{
	g_notify_stop = true;
	if (!pthread_equal(g_scan_tid, {})) {
		pthread_kill(g_scan_tid, SIGALRM);
		pthread_join(g_scan_tid, NULL);
	}
	g_hash_table.clear();
	g_mime_pool.reset();
}
