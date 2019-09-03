#include "util.h"
#include "mail.h"
#include "mjson.h"
#include "oxcmail.h"
#include "rop_util.h"
#include "mem_file.h"
#include "str_hash.h"
#include "mail_func.h"
#include "mime_pool.h"
#include "cmd_parser.h"
#include "common_util.h"
#include "mail_engine.h"
#include "double_list.h"
#include "single_list.h"
#include "exmdb_client.h"
#include "tpropval_array.h"
#include "system_services.h"
#include <time.h>
#include <iconv.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sqlite3.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>


#define FILENUM_PER_MIME				8

#define CONFIG_ID_USERNAME				1

#define MAX_DIGLEN						256*1024

#define CONDITION_TREE					DOUBLE_LIST

#define RELOAD_INTERVAL					3600

#define DB_LOCK_TIMEOUT					60

#define MAX_DB_WAITING_THREADS			5


enum {
	CONDITION_ALL,
	CONDITION_ANSWERED,
	CONDITION_BCC,
	CONDITION_BEFORE,
	CONDITION_BODY,
	CONDITION_CC,
	CONDITION_DELETED,
	CONDITION_DRAFT,
	CONDITION_FLAGGED,
	CONDITION_FROM,
	CONDITION_HEADER,
	CONDITION_ID,
	CONDITION_KEYWORD,
	CONDITION_LARGER,
	CONDITION_NEW,
	CONDITION_OLD,
	CONDITION_ON,
	CONDITION_RECENT,
	CONDITION_SEEN,
	CONDITION_SENTBEFORE,
	CONDITION_SENTON,
	CONDITION_SENTSINCE,
	CONDITION_SINCE,
	CONDITION_SMALLER,
	CONDITION_SUBJECT,
	CONDITION_TEXT,
	CONDITION_TO,
	CONDITION_UNANSWERED,
	CONDITION_UID,
	CONDITION_UNDELETED,
	CONDITION_UNDRAFT,
	CONDITION_UNFLAGGED,
	CONDITION_UNKEYWORD,
	CONDITION_UNSEEN
};

enum {
	CONJUNCTION_AND,
	CONJUNCTION_OR,
	CONJUNCTION_NOT
};

typedef struct _CONDITION_RESULT {
	SINGLE_LIST list;
	SINGLE_LIST_NODE *pcur_node;
} CONDITION_RESULT;

typedef struct _CONDITION_TREE_NODE {
	DOUBLE_LIST_NODE node;
	int conjunction;
	DOUBLE_LIST *pbranch;
	int condition;
	void *pstatment;
} CONDITION_TREE_NODE;

typedef struct _SQUENCE_NODE {
	DOUBLE_LIST_NODE node;
	unsigned int min;
	unsigned int max;
} SQUENCE_NODE;

typedef struct _KEYWORD_ENUM {
	MJSON *pjson;
	BOOL b_result;
	const char *charset;
	const char *keyword;
} KEYWORD_ENUM;

typedef struct _IDB_ITEM {
	sqlite3 *psqlite;
	volatile int reference;	/* client reference count, item can be
							flushed into file system only count is 0 */
	char *username;
	time_t last_time;
	time_t load_time;
	uint32_t sub_id;
	pthread_mutex_t lock;
} IDB_ITEM;

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

typedef struct _IDL_NODE {
	DOUBLE_LIST_NODE node;
	char *mid_string;
	uint32_t size;
} IDL_NODE;

typedef struct _DTLU_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t idx;
	char *mid_string;
} DTLU_NODE;

typedef struct _SIMU_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t idx;
	uint32_t uid;
	char *mid_string;
	char *flags_buff;
} SIMU_NODE;

typedef struct _SUB_NODE {
	DOUBLE_LIST_NODE node;
	char maildir[256];
	uint32_t sub_id;
} SUB_NODE;


static BOOL g_wal;
static BOOL g_async;
static int g_mime_num;
static int g_table_size;              /* hash table size */
static int g_squence_id;
static BOOL g_notify_stop;            /* stop signal for scaning thread */
static int g_ping_interval;
static uint64_t g_mmap_size;
static pthread_t g_scan_tid;
static int g_cache_interval;          /* maximum living interval in table */
static char g_org_name[256];
static MIME_POOL *g_mime_pool;
static LIB_BUFFER *g_alloc_mjson;      /* mjson allocator */
static char g_default_charset[32];
static char g_default_timezone[64];
static pthread_mutex_t g_hash_lock;
static STR_HASH_TABLE *g_hash_table;
static pthread_mutex_t g_squence_lock;

static DOUBLE_LIST* mail_engine_ct_parse_squence(char *string);

static BOOL mail_engine_ct_hint_squence(DOUBLE_LIST *plist,
	unsigned int num, unsigned int max_uid);
	
static void mail_engine_ct_free_squence(DOUBLE_LIST *plist);

static int mail_engine_get_squence_id()
{
	int squence_id;
	
	pthread_mutex_lock(&g_squence_lock);
	if (0xFFFFFFF == g_squence_id) {
		g_squence_id = 0;
	}
	g_squence_id ++;
	squence_id = g_squence_id;
	pthread_mutex_unlock(&g_squence_lock);
	return squence_id;
}

static char* mail_engine_ct_to_utf8(const char *charset, const char *string)
{
	int length;
	iconv_t conv_id;
	char *ret_string;
	char *pin, *pout;
	size_t in_len, out_len;

	if (0 == strcasecmp(charset, "UTF-8") ||
		0 == strcasecmp(charset, "US-ASCII")) {
		return strdup(string);
	}	
	length = strlen(string) + 1;
	ret_string = malloc(2*length);
	if (NULL == ret_string) {
		return NULL;
	}
	conv_id = iconv_open("UTF-8", charset);
	if ((iconv_t)-1 == conv_id) {
		free(ret_string);
		return NULL;
	}
	pin = (char*)string;
	pout = ret_string;
	in_len = length;
	out_len = 2*length;
	if (-1 == iconv(conv_id, &pin, &in_len, &pout, &out_len)) {
		iconv_close(conv_id);
		free(ret_string);
		return NULL;
	}
	iconv_close(conv_id);
	return ret_string;
}

static uint64_t mail_engine_get_digest(sqlite3 *psqlite,
	const char *mid_string, char *digest_buff)
{
	int fd;
	MAIL imail;
	size_t size;
	int tmp_len;
	int sql_len;
	char *pbuff;
	char *ptoken;
	const char *pext;
	uint64_t folder_id;
	char tmp_buff[128];
	char temp_path[256];
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	struct stat node_stat;
	
	snprintf(temp_path, 256, "%s/ext/%s",
		common_util_get_maildir(), mid_string);
	if (0 != stat(temp_path, &node_stat)) {
		snprintf(temp_path, 256, "%s/eml/%s",
			common_util_get_maildir(), mid_string);
		if (0 != stat(temp_path, &node_stat) ||
			0 == S_ISREG(node_stat.st_mode)) {
			return 0;
		}
		pbuff = malloc(node_stat.st_size);
		if (NULL == pbuff) {
			return 0;
		}
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			free(pbuff);
			return 0;
		}
		if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
			close(fd);
			free(pbuff);
			return 0;
		}
		close(fd);
		mail_init(&imail, g_mime_pool);
		if (FALSE == mail_retrieve(&imail, pbuff, node_stat.st_size)) {
			mail_free(&imail);
			free(pbuff);
			return 0;
		}
		tmp_len = sprintf(digest_buff, "{\"file\":\"\",");
		if (mail_get_digest(&imail, &size, digest_buff + tmp_len,
			MAX_DIGLEN - tmp_len - 1) <= 0) {
			mail_free(&imail);
			free(pbuff);
			return 0;
		}
		mail_free(&imail);
		free(pbuff);
		tmp_len = strlen(digest_buff);
		memcpy(digest_buff + tmp_len, "}", 2);
		tmp_len ++;
		snprintf(temp_path, 256, "%s/ext/%s",
			common_util_get_maildir(), mid_string);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 != fd) {
			write(fd, digest_buff, tmp_len);
			close(fd);
		}
	} else {
		if (0 == S_ISREG(node_stat.st_mode) ||
			node_stat.st_size >= MAX_DIGLEN) {
			return 0;
		}
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			return 0;
		}
		if (node_stat.st_size != read(fd,
			digest_buff, node_stat.st_size)) {
			close(fd);
			return 0;
		}
		digest_buff[node_stat.st_size] = '\0';
		close(fd);
	}
	sql_len = sprintf(sql_string, "SELECT uid, recent, read,"
		" unsent, flagged, replied, forwarded, deleted, ext,"
		" folder_id FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return 0;
	}
	sqlite3_bind_text(pstmt, 1, mid_string, -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return 0;
	}
	folder_id = sqlite3_column_int64(pstmt, 9);
	sprintf(tmp_buff, "\"%s\"", mid_string);
	set_digest(digest_buff, MAX_DIGLEN, "file", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 0));
	set_digest(digest_buff, MAX_DIGLEN, "uid", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 1));
	set_digest(digest_buff, MAX_DIGLEN, "recent", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 2));
	set_digest(digest_buff, MAX_DIGLEN, "read", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 3));
	set_digest(digest_buff, MAX_DIGLEN, "unsent", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 4));
	set_digest(digest_buff, MAX_DIGLEN, "flag", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 5));
	set_digest(digest_buff, MAX_DIGLEN, "replied", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 6));
	set_digest(digest_buff, MAX_DIGLEN, "forwarded", tmp_buff);
	sprintf(tmp_buff, "%llu", sqlite3_column_int64(pstmt, 7));
	set_digest(digest_buff, MAX_DIGLEN, "deleted", tmp_buff);
	if (SQLITE_NULL == sqlite3_column_type(pstmt, 8)) {
		sqlite3_finalize(pstmt);
		return folder_id;
	}
	pext = sqlite3_column_text(pstmt, 8);
	ptoken = strrchr(digest_buff, '}');
	if (NULL == ptoken) {
		sqlite3_finalize(pstmt);
		return 0;
	}
	*ptoken = ',';
	if (ptoken + 1 - digest_buff + strlen(pext + 1) >= MAX_DIGLEN) {
		sqlite3_finalize(pstmt);
		return 0;
	}
	strcpy(ptoken + 1, pext + 1);
	sqlite3_finalize(pstmt);
	return folder_id;
}

static char* mail_engine_ct_decode_mime(
	const char *charset, const char *mime_string)
{
	BOOL b_decoded;
	int i, buff_len;
	int offset;
	size_t tmp_len, decode_len;
	int last_pos, begin_pos, end_pos;
	ENCODE_STRING encode_string;
	char *in_buff, *out_buff;
	char *ret_string, *tmp_string;
	char temp_buff[1024];

	buff_len = strlen(mime_string);
	ret_string = malloc(2*(buff_len + 1));
	if (NULL == ret_string) {
		return NULL;
	}
	
	in_buff = (char*)mime_string;
	out_buff = ret_string;
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
				ltrim_string(temp_buff);
				tmp_string = mail_engine_ct_to_utf8(charset, temp_buff);
				if (NULL == tmp_string) {
					free(ret_string);
					return NULL;
				}
				tmp_len = strlen(tmp_string);
				memcpy(out_buff + offset, tmp_string, tmp_len);
				free(tmp_string);
				offset += tmp_len;
				last_pos = i;
			}
		}
		if (-1 == end_pos && -1 != begin_pos && '?' == in_buff[i] &&
			'=' == in_buff[i + 1] && ('q' != in_buff[i - 1] &&
			'Q' != in_buff[i - 1] || '?' != in_buff[i - 2])) {
			end_pos = i + 1;
		}
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			tmp_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, tmp_len, temp_buff, &decode_len);
				temp_buff[decode_len] = '\0';
				tmp_string = mail_engine_ct_to_utf8(encode_string.charset, temp_buff);
			} else if (0 == strcmp(encode_string.encoding, "quoted-printable")){
				decode_len = qp_decode(temp_buff, encode_string.title, tmp_len);
				temp_buff[decode_len] = '\0';
				tmp_string = mail_engine_ct_to_utf8(encode_string.charset, temp_buff);
			} else {
				tmp_string = mail_engine_ct_to_utf8(charset, encode_string.title);
			}
			if (NULL == tmp_string) {
				free(ret_string);
				return NULL;
			}
			tmp_len = strlen(tmp_string);
			memcpy(out_buff + offset, tmp_string, tmp_len);
			free(tmp_string);
			offset += tmp_len;
			
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos) {
		tmp_string = mail_engine_ct_to_utf8(charset, in_buff + last_pos);
		if (NULL == tmp_string) {
			free(ret_string);
			return NULL;
		}
		tmp_len = strlen(tmp_string);
		memcpy(out_buff + offset, tmp_string, tmp_len);
		free(tmp_string);
		offset += tmp_len;
	} 
	out_buff[offset] = '\0';
	return ret_string;

}

static void mail_engine_ct_enum_mime(MJSON_MIME *pmime, KEYWORD_ENUM *penum)
{
	int fd;
	char *pbuff;
	size_t length;
	size_t temp_len;
	iconv_t conv_id;
	MJSON temp_mjson;
	char *pin, *pout;
	char *ret_string;
	const char *charset;
	const char *filename;
	
	if (TRUE == penum->b_result) {
		return;
	}
	if (MJSON_MIME_SINGLE != mjson_get_mime_mtype(pmime)) {
		return;
	}
	if (0 == strncmp(mjson_get_mime_ctype(pmime), "text/", 5)) {
		length = mjson_get_mime_length(pmime, MJSON_MIME_CONTENT);
		pbuff = malloc(2*length + 1);
		if (NULL == pbuff) {
			return;
		}
		fd = mjson_seek_fd(penum->pjson,
			mjson_get_mime_id(pmime), MJSON_MIME_CONTENT);
		if (-1 == fd) {
			free(pbuff);
			return;
		}
		if (length != read(fd, pbuff, length)) {
			free(pbuff);
			return;
		}
		if (0 == strcasecmp(mjson_get_mime_encoding(pmime), "base64")) {
			if (0 != decode64_ex(pbuff, length,
				pbuff + length, length, &temp_len)) {
				free(pbuff);
				return;
			}
			pbuff[length + temp_len] = '\0';
		} else if (0 == strcasecmp(
			mjson_get_mime_encoding(pmime), "quoted-printable")) {
			temp_len = qp_decode(pbuff + length, pbuff, length);
			pbuff[length + temp_len] = '\0';
		} else {
			memcpy(pbuff + length, pbuff, length);
			pbuff[2*length] = '\0';
		}
			
		charset = mjson_get_mime_charset(pmime);
		if ('\0' != charset[0]) {
			ret_string = mail_engine_ct_to_utf8(
						charset, pbuff + length);
		} else {
			ret_string = mail_engine_ct_to_utf8(
				penum->charset, pbuff + length);
		}
		if (NULL != ret_string) {
			if (NULL != search_string(ret_string,
				penum->keyword, strlen(ret_string))) {
				penum->b_result = TRUE;
			}
			free(ret_string);
		}
		free(pbuff);			
	} else {
		filename = mjson_get_mime_filename(pmime);
		if ('\0' != filename[0]) {
			ret_string = mail_engine_ct_decode_mime(
							penum->charset, filename);
			if (NULL != ret_string) {
				if (NULL != search_string(ret_string,
					penum->keyword, strlen(ret_string))) {
					penum->b_result = TRUE;
				}
				free(ret_string);
			}
		}
	}
}

static BOOL mail_engine_ct_search_head(const char *charset,
	const char *file_path, const char *tag, const char *value)
{
	FILE * fp;
	int tag_len;
	char *str_mime;
	BOOL stat_head;
	int head_offset;
	int offset, len;
	MIME_FIELD mime_field;
	char head_buff[64*1024];
	
	stat_head = FALSE;
	fp = fopen(file_path, "r");
	if (NULL == fp) {
		return FALSE;
	}
	head_offset = 0;
	while (NULL != fgets(head_buff + head_offset,
		64*1024 - head_offset, fp)) {
		len = strlen(head_buff + head_offset);
		head_offset += len;
		
		if (head_offset >= 64*1024 - 1) {
			break;
		}
		if (2 == len && 0 == strcmp("\r\n", head_buff + head_offset - 2)) {
			stat_head = TRUE;
			break;
		}
	}
	fclose(fp);
	if (FALSE == stat_head) {
		return FALSE;
	}
	offset = 0;
	tag_len = strlen(tag);
	while (len = parse_mime_field(head_buff + offset,
		head_offset - offset, &mime_field)) {
		offset += len;
		if (tag_len == mime_field.field_name_len &&
			0 == strncasecmp(tag, mime_field.field_name, tag_len)) {
			mime_field.field_value[mime_field.field_value_len] = '\0';
			str_mime = mail_engine_ct_decode_mime(
				charset, mime_field.field_value);
			if (NULL != str_mime) {
				if (NULL != search_string(str_mime,
					value, strlen(str_mime))) {
					free(str_mime);
					return TRUE;
				}
				free(str_mime);
			}
		}
	}
	return FALSE;
}

static BOOL mail_engine_ct_match_mail(sqlite3 *psqlite,
	const char *charset, sqlite3_stmt *pstmt_message,
	const char *mid_string, int id, int total_mail,
	uint32_t uidnext, CONDITION_TREE *ptree)
{
	int sp = 0;
	int sql_len;
	BOOL b_loaded;
	BOOL b_result;
	BOOL b_result1;
	int conjunction;
	time_t tmp_time;
	size_t temp_len;
	MJSON temp_mjson;
	char *ret_string;
	int results[1024];
	char temp_buff[1024];
	char sql_string[1024];
	char temp_buff1[1024];
	int conjunctions[1024];
	DOUBLE_LIST_NODE *pnode;
	KEYWORD_ENUM keyword_enum;
	CONDITION_TREE* trees[1024];
	char digest_buff[MAX_DIGLEN];
	DOUBLE_LIST_NODE* nodes[1024];
	CONDITION_TREE_NODE *ptree_node;
	
#define PUSH_MATCH(TREE, NODE, CONJUNCTION, RESULT) \
		{trees[sp]=TREE;nodes[sp]=NODE;conjunctions[sp]=CONJUNCTION;results[sp]=RESULT;sp++;}
	
#define POP_MATCH(TREE, NODE, CONJUNCTION, RESULT) \
		{sp--;TREE=trees[sp];NODE=nodes[sp];CONJUNCTION=conjunctions[sp];RESULT=results[sp];}

/* begine of rescursion procedure */

while (TRUE) {

PROC_BEGIN:
	b_result = TRUE;
	b_loaded = FALSE;
	for (pnode=double_list_get_head(ptree);	NULL!=pnode;
		pnode=double_list_get_after(ptree, pnode)) {
		ptree_node = (CONDITION_TREE_NODE*)pnode->pdata;
		conjunction = ptree_node->conjunction;
		if ((TRUE == b_result && CONJUNCTION_OR == conjunction) ||
			(FALSE == b_result && CONJUNCTION_AND == conjunction)) {
			continue;
		}
		b_result1 = FALSE;
		if (NULL != ptree_node->pbranch) {
			PUSH_MATCH(ptree, pnode, conjunction, b_result)
			ptree = ptree_node->pbranch;
			goto PROC_BEGIN;
		} else {
			switch (ptree_node->condition) {
			case CONDITION_ALL:
			case CONDITION_KEYWORD:
			case CONDITION_UNKEYWORD:
				b_result1 = TRUE;
				break;
			case CONDITION_ANSWERED:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 != sqlite3_column_int64(pstmt_message, 7)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_BCC:
				/* do not support BCC field in mail digest,
					BCC should not recorded in mail head */
				break;
			case CONDITION_BEFORE:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 10));
				if (tmp_time < (time_t)ptree_node->pstatment) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_BODY:
				if (FALSE == b_loaded) {
					if (0 == mail_engine_get_digest(
						psqlite, mid_string, digest_buff)) {
						break;
					}
					b_loaded = TRUE;
				}
				mjson_init(&temp_mjson, g_alloc_mjson);
				snprintf(temp_buff, 256, "%s/eml",
						common_util_get_maildir());
				if (TRUE == mjson_retrieve(&temp_mjson,
					digest_buff, strlen(digest_buff), temp_buff)) {
					keyword_enum.pjson = &temp_mjson;
					keyword_enum.b_result = FALSE;
					keyword_enum.charset = charset;
					keyword_enum.keyword = (const char*)ptree_node->pstatment;
					mjson_enum_mime(&temp_mjson, (MJSON_MIME_ENUM)
						mail_engine_ct_enum_mime, &keyword_enum);
					if (TRUE == keyword_enum.b_result) {
						b_result1 = TRUE;
					}
				}
				mjson_free(&temp_mjson);
				break;
			case CONDITION_CC:
				if (FALSE == b_loaded) {
					if (0 == mail_engine_get_digest(
						psqlite, mid_string, digest_buff)) {
						break;
					}
					b_loaded = TRUE;
				}
				if (TRUE == get_digest(digest_buff, "cc", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				break;
			case CONDITION_DELETED:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 != sqlite3_column_int64(pstmt_message, 9)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_DRAFT:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 != sqlite3_column_int64(pstmt_message, 5)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_FLAGGED:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 != sqlite3_column_int64(pstmt_message, 6)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_FROM:
				if (FALSE == b_loaded) {
					if (0 == mail_engine_get_digest(
						psqlite, mid_string, digest_buff)) {
						break;
					}
					b_loaded = TRUE;
				}
				if (TRUE == get_digest(digest_buff, "from", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				break;
			case CONDITION_HEADER:
				snprintf(temp_buff1, 256, "%s/eml/%s",
					common_util_get_maildir(), mid_string);
				b_result1 = mail_engine_ct_search_head(charset,
					temp_buff1, ((char**)ptree_node->pstatment)[0],
					((char**)ptree_node->pstatment)[1]);
				break;
			case CONDITION_ID:
				b_result1 = mail_engine_ct_hint_squence(
					(DOUBLE_LIST*)ptree_node->pstatment,
					id, total_mail);
				break;
			case CONDITION_LARGER:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (sqlite3_column_int64(pstmt_message,
					13) > (size_t)ptree_node->pstatment) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_NEW:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 != sqlite3_column_int64(pstmt_message, 3) &&
					0 == sqlite3_column_int64(pstmt_message, 4)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_OLD:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 == sqlite3_column_int64(pstmt_message, 3)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_ON:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 10));
				if (tmp_time >= (time_t)ptree_node->pstatment &&
					tmp_time < (time_t)ptree_node->pstatment + 24*60*60) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_RECENT:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 != sqlite3_column_int64(pstmt_message, 3)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_SEEN:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 != sqlite3_column_int64(pstmt_message, 4)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_SENTBEFORE:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 1));
				if (tmp_time < (time_t)ptree_node->pstatment) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_SENTON:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 1));
				if (tmp_time >= (time_t)ptree_node->pstatment &&
					tmp_time < (time_t)ptree_node->pstatment + 24*60*60) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_SENTSINCE:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 1));
				if (tmp_time >= (time_t)ptree_node->pstatment) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_SINCE:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, 10));
				if (tmp_time >= (time_t)ptree_node->pstatment) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_SMALLER:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (sqlite3_column_int64(pstmt_message,
					13) < (size_t)ptree_node->pstatment) {
					b_result1 = TRUE;
				} 
				break;
			case CONDITION_SUBJECT:
				if (FALSE == b_loaded) {
					if (0 == mail_engine_get_digest(
						psqlite, mid_string, digest_buff)) {
						break;
					}
					b_loaded = TRUE;
				}
				if (TRUE == get_digest(digest_buff, "subject", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				break;
			case CONDITION_TEXT:
				if (FALSE == b_loaded) {
					if (0 == mail_engine_get_digest(
						psqlite, mid_string, digest_buff)) {
						break;
					}
					b_loaded = TRUE;
				}
				if (TRUE == get_digest(digest_buff, "cc", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(
										charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				if (TRUE == b_result1) {
					break;
				}
				if (TRUE == get_digest(digest_buff, "from", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(
										charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				if (TRUE == b_result1) {
					break;
				}
				if (TRUE == get_digest(digest_buff, "subject", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(
										charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				if (TRUE == b_result1) {
					break;
				}
				if (TRUE == get_digest(digest_buff, "to", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(
										charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				if (TRUE == b_result1) {
					break;
				}
				mjson_init(&temp_mjson, g_alloc_mjson);
				snprintf(temp_buff, 256, "%s/eml",
						common_util_get_maildir());
				if (TRUE == mjson_retrieve(&temp_mjson,
					digest_buff, strlen(digest_buff), temp_buff)) {
					keyword_enum.pjson = &temp_mjson;
					keyword_enum.b_result = FALSE;
					keyword_enum.charset = charset;
					keyword_enum.keyword = (const char*)ptree_node->pstatment;
					mjson_enum_mime(&temp_mjson, (MJSON_MIME_ENUM)
						mail_engine_ct_enum_mime, &keyword_enum);
					if (TRUE == keyword_enum.b_result) {
						b_result1 = TRUE;
					}
				}
				mjson_free(&temp_mjson);
				break;
			case CONDITION_TO:
				if (FALSE == b_loaded) {
					if (0 == mail_engine_get_digest(
						psqlite, mid_string, digest_buff)) {
						break;
					}
					b_loaded = TRUE;
				}
				if (TRUE == get_digest(digest_buff, "to", temp_buff,
					sizeof(temp_buff)) && 0 == decode64(temp_buff,
					strlen(temp_buff), temp_buff1, &temp_len)) {
					temp_buff1[temp_len] = '\0';
					ret_string = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (NULL != ret_string) {
						if (NULL != search_string(ret_string, (char*)
							ptree_node->pstatment, strlen(ret_string))) {
							b_result1 = TRUE;
						}
						free(ret_string);
					}
				}
				break;
			case CONDITION_UNANSWERED:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 == sqlite3_column_int64(pstmt_message, 7)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_UID:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				b_result1 = mail_engine_ct_hint_squence(
					(DOUBLE_LIST*)ptree_node->pstatment,
					sqlite3_column_int64(pstmt_message, 2),
					uidnext);
				break;
			case CONDITION_UNDELETED:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 == sqlite3_column_int64(pstmt_message, 9)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_UNDRAFT:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 == sqlite3_column_int64(pstmt_message, 5)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_UNFLAGGED:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 == sqlite3_column_int64(pstmt_message, 6)) {
					b_result1 = TRUE;
				}
				break;
			case CONDITION_UNSEEN:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt_message)) {
					break;
				}
				if (0 == sqlite3_column_int64(pstmt_message, 4)) {
					b_result1 = TRUE;
				}
				break;
			default:
				debug_info("[mail_engine]: condition stat %d unknown!",
												ptree_node->condition);
				break;
			}
		}
		
RECURSION_POINT:
		switch (conjunction) {
		case CONJUNCTION_AND:
			b_result = (b_result&&b_result1)?TRUE:FALSE;
			break;
		case CONJUNCTION_OR:
			b_result = (b_result||b_result1)?TRUE:FALSE;
			break;
		case CONJUNCTION_NOT:
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
/* end of rescursion procedure */

}

static int mail_engine_ct_compile_criteria(int argc,
	char **argv, int offset, char **argv_out)
{
	int i;
	int tmp_argc;
	int tmp_argc1;
	
	i = offset;
	if (argc < i + 1) {
		return -1;
	}
	argv_out[0] = argv[i];
	if (0 == strcasecmp(argv[i], "OR")) {
		i ++;
		if (argc < i + 1) {
			return -1;
		}
		tmp_argc = mail_engine_ct_compile_criteria(
						argc, argv, i, argv_out + 1);
		if (-1 == tmp_argc) {
			return -1;
		}
		
		i += tmp_argc;
		if (argc < i + 1) {
			return -1;
		}
		tmp_argc1 = mail_engine_ct_compile_criteria(
			argc, argv, i, argv_out + 1 + tmp_argc);
		if (-1 == tmp_argc1) {
			return -1;
		}
		return tmp_argc + tmp_argc1 + 1;
	} else if (0 == strcasecmp(argv[i], "ALL") ||
		0 == strcasecmp(argv[i], "ANSWERED") ||
		0 == strcasecmp(argv[i], "DELETED") ||
		0 == strcasecmp(argv[i], "DRAFT") ||
		0 == strcasecmp(argv[i], "FLAGGED") ||
		0 == strcasecmp(argv[i], "NEW") ||
		0 == strcasecmp(argv[i], "OLD") ||
		0 == strcasecmp(argv[i], "RECENT") ||
		0 == strcasecmp(argv[i], "SEEN") ||
		0 == strcasecmp(argv[i], "UNANSWERED") ||
		0 == strcasecmp(argv[i], "UNDELETED") ||
		0 == strcasecmp(argv[i], "UNDRAFT") ||
		0 == strcasecmp(argv[i], "UNFLAGGED") ||
		0 == strcasecmp(argv[i], "UNSEEN")) {
		return 1;
	} else if (0 == strcasecmp(argv[i], "BCC") ||
		0 == strcasecmp(argv[i], "BEFORE") ||
		0 == strcasecmp(argv[i], "BODY") ||
		0 == strcasecmp(argv[i], "CC") ||
		0 == strcasecmp(argv[i], "FROM") ||
		0 == strcasecmp(argv[i], "KEYWORD") ||
		0 == strcasecmp(argv[i], "LARGER") ||
		0 == strcasecmp(argv[i], "ON") ||
		0 == strcasecmp(argv[i], "SENTBEFORE") ||
		0 == strcasecmp(argv[i], "SENTON") ||
		0 == strcasecmp(argv[i], "SENTSINCE") ||
		0 == strcasecmp(argv[i], "SINCE") ||
		0 == strcasecmp(argv[i], "SMALLER") ||
		0 == strcasecmp(argv[i], "SUBJECT") ||
		0 == strcasecmp(argv[i], "TEXT") ||
		0 == strcasecmp(argv[i], "TO") ||
		0 == strcasecmp(argv[i], "UID") ||
		0 == strcasecmp(argv[i], "UNKEYWORD")) {
		i ++;
		if (argc < i + 1) {
			return -1;
		}
		argv_out[1] = argv[i];
		return 2;
	} else if (0 == strcasecmp(argv[i], "HEADER")) {
		i ++;
		if (argc < i + 1) {
			return -1;
		}
		argv_out[1] = argv[i];
		i++;
		if (argc < i + 1) {
			return -1;
		}
		argv_out[2] = argv[i];
		return 3;
	} else if (0 == strcasecmp(argv[i], "NOT")) {
		i ++;
		if (argc < i + 1) {
			return -1;
		}
		tmp_argc = mail_engine_ct_compile_criteria(
						argc, argv, i, argv_out + 1);
		if (-1 == tmp_argc) {
			return -1;
		}
		return tmp_argc + 1;
	} else {
		/* <squence set> or () as default*/
		return 1;
	}
}

static void mail_engine_ct_destroy_internal(DOUBLE_LIST *plist)
{
	DOUBLE_LIST_NODE *pnode;
	CONDITION_TREE_NODE *ptree_node;
	
	while (pnode=double_list_get_from_head(plist)) {
		ptree_node = (CONDITION_TREE_NODE*)pnode->pdata;
		if (NULL != ptree_node->pbranch) {
			mail_engine_ct_destroy_internal(ptree_node->pbranch);
			ptree_node->pbranch = NULL;
		} else {
			if (CONDITION_ID == ptree_node->condition ||
				CONDITION_UID == ptree_node->condition) {
				mail_engine_ct_free_squence(
					(DOUBLE_LIST*)ptree_node->pstatment);
				ptree_node->pstatment = NULL;
			} else if (CONDITION_BCC == ptree_node->condition ||
				CONDITION_BODY == ptree_node->condition ||
				CONDITION_CC == ptree_node->condition ||
				CONDITION_FROM == ptree_node->condition ||
				CONDITION_KEYWORD == ptree_node->condition ||
				CONDITION_SUBJECT == ptree_node->condition ||
				CONDITION_TEXT == ptree_node->condition ||
				CONDITION_TO == ptree_node->condition ||
				CONDITION_UNKEYWORD == ptree_node->condition) {
				free(ptree_node->pstatment);
				ptree_node->pstatment = NULL;
			} else if (CONDITION_HEADER == ptree_node->condition) {
				free(((void**)ptree_node->pstatment)[0]);
				free(((void**)ptree_node->pstatment)[1]);
				free(ptree_node->pstatment);
				ptree_node->pstatment = NULL;
			}
		}
		free(ptree_node);
	}
	double_list_free(plist);
	free(plist);
}

static DOUBLE_LIST* mail_engine_ct_build_internal(
	const char *charset, int argc, char **argv)
{
	int i, len;
	int tmp_argc;
	int tmp_argc1;
	struct tm tmp_tm;
	char* tmp_argv[256];
	DOUBLE_LIST *plist;
	DOUBLE_LIST *plist1;
	DOUBLE_LIST_NODE *pnode;
	CONDITION_TREE_NODE *ptree_node;

	plist = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST));
	if (NULL == plist) {
		return NULL;
	}
	double_list_init(plist);
	for (i=0; i<argc; i++) {
		ptree_node = (CONDITION_TREE_NODE*)malloc(
					sizeof(CONDITION_TREE_NODE));
		if (NULL == ptree_node) {
			mail_engine_ct_destroy_internal(plist);
			return NULL;
		}
		ptree_node->node.pdata = ptree_node;
		ptree_node->pbranch = NULL;
		if (0 == strcasecmp(argv[i], "NOT")) {
			ptree_node->conjunction = CONJUNCTION_NOT;
			i ++;
			if (i >= argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
		} else {
			ptree_node->conjunction = CONJUNCTION_AND;
		}
		if (0 == strcasecmp(argv[i], "BCC") ||
			0 == strcasecmp(argv[i], "BODY") ||
			0 == strcasecmp(argv[i], "CC") ||
			0 == strcasecmp(argv[i], "FROM") ||
			0 == strcasecmp(argv[i], "KEYWORD") ||
			0 == strcasecmp(argv[i], "SUBJECT") ||
			0 == strcasecmp(argv[i], "TEXT") ||
			0 == strcasecmp(argv[i], "TO") ||
			0 == strcasecmp(argv[i], "UNKEYWORD")) {
			if (0 == strcasecmp(argv[i], "BCC")) {
				ptree_node->condition = CONDITION_BCC;
			} else if (0 == strcasecmp(argv[i], "BODY")) {
				ptree_node->condition = CONDITION_BODY;
			} else if (0 == strcasecmp(argv[i], "CC")) {
				ptree_node->condition = CONDITION_CC;
			} else if (0 == strcasecmp(argv[i], "FROM")) {
				ptree_node->condition = CONDITION_FROM;
			} else if (0 == strcasecmp(argv[i], "KEYWORD")) {
				ptree_node->condition = CONDITION_KEYWORD;
			} else if (0 == strcasecmp(argv[i], "SUBJECT")) {
				ptree_node->condition = CONDITION_SUBJECT;
			} else if (0 == strcasecmp(argv[i], "TEXT")) {
				ptree_node->condition = CONDITION_TEXT;
			} else if (0 == strcasecmp(argv[i], "TO")) {
				ptree_node->condition = CONDITION_TO;
			} else if (0 == strcasecmp(argv[i], "UNKEYWORD")) {
				ptree_node->condition = CONDITION_UNKEYWORD;
			}
			i ++;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			ptree_node->pstatment = mail_engine_ct_to_utf8(charset, argv[i]);
			if (NULL == ptree_node->pstatment) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
		} else if (0 == strcasecmp(argv[i], "BEFORE") ||
			0 == strcasecmp(argv[i], "ON") ||
			0 == strcasecmp(argv[i], "SENTBEFORE") ||
			0 == strcasecmp(argv[i], "SENTON") ||
			0 == strcasecmp(argv[i], "SENTSINCE") ||
			0 == strcasecmp(argv[i], "SINCE")) {
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			if (0 == strcasecmp(argv[i], "BEFORE")) {
				ptree_node->condition = CONDITION_BEFORE;
			} else if (0 == strcasecmp(argv[i], "ON")) {
				ptree_node->condition = CONDITION_ON;
			} else if (0 == strcasecmp(argv[i], "SENTBEFORE")) {
				ptree_node->condition = CONDITION_SENTBEFORE;
			} else if (0 == strcasecmp(argv[i], "SENTON")) {
				ptree_node->condition = CONDITION_SENTON;
			} else if (0 == strcasecmp(argv[i], "SENTSINCE")) {
				ptree_node->condition = CONDITION_SENTSINCE;
			} else if (0 == strcasecmp(argv[i], "SINCE")) {
				ptree_node->condition = CONDITION_SINCE;
			}
			i ++;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL == strptime(argv[i], "%d-%b-%Y", &tmp_tm)) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			ptree_node->pstatment = (void*)mktime(&tmp_tm);
		} else if ('(' == argv[i][0]) {
			len = strlen(argv[i]);
			argv[i][len - 1] = '\0';
			tmp_argc = parse_imap_args(argv[i] + 1,
				len - 2, tmp_argv, sizeof(tmp_argv));
			if (-1 == tmp_argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			plist1 = mail_engine_ct_build_internal(
						charset, tmp_argc, tmp_argv);
			if (NULL == plist1) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			ptree_node->pbranch = plist1;
		} else if (0 == strcasecmp(argv[i], "OR")) {
			i ++;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			tmp_argc = mail_engine_ct_compile_criteria(
								argc, argv, i, tmp_argv);
			if (-1 == tmp_argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			i += tmp_argc;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			tmp_argc1 = mail_engine_ct_compile_criteria(
					argc, argv, i, tmp_argv + tmp_argc);
			if (-1 == tmp_argc1) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			plist1 = mail_engine_ct_build_internal(charset,
							tmp_argc + tmp_argc1, tmp_argv);
			if (NULL == plist1) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			if (2 != double_list_get_nodes_num(plist1) ||
				NULL == (pnode = double_list_get_tail(plist1))) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				mail_engine_ct_destroy_internal(plist1);
				return NULL;
			}
			((CONDITION_TREE_NODE*)pnode->pdata)->conjunction = CONJUNCTION_OR;
			ptree_node->pbranch = plist1;
			i += tmp_argc1 - 1;
		} else if (0 == strcasecmp(argv[i], "ALL")) {
			ptree_node->condition = CONDITION_ALL;
		} else if (0 == strcasecmp(argv[i], "ANSWERED")) {
			ptree_node->condition = CONDITION_ANSWERED;
		} else if (0 == strcasecmp(argv[i], "DELETED")) {
			ptree_node->condition = CONDITION_DELETED;
		} else if (0 == strcasecmp(argv[i], "DRAFT")) {
			ptree_node->condition = CONDITION_DRAFT;
		} else if (0 == strcasecmp(argv[i], "FLAGGED")) {
			ptree_node->condition = CONDITION_FLAGGED;
		} else if (0 == strcasecmp(argv[i], "NEW")) {
			ptree_node->condition = CONDITION_NEW;
		} else if (0 == strcasecmp(argv[i], "OLD")) {
			ptree_node->condition = CONDITION_OLD;
		} else if (0 == strcasecmp(argv[i], "RECENT")) {
			ptree_node->condition = CONDITION_RECENT;
		} else if (0 == strcasecmp(argv[i], "SEEN")) {
			ptree_node->condition = CONDITION_SEEN;
		} else if (0 == strcasecmp(argv[i], "UNANSWERED")) {
			ptree_node->condition = CONDITION_UNANSWERED;
		} else if (0 == strcasecmp(argv[i], "UNDELETED")) {
			ptree_node->condition = CONDITION_UNDELETED;
		} else if (0 == strcasecmp(argv[i], "UNDRAFT")) {
			ptree_node->condition = CONDITION_UNDRAFT;
		} else if (0 == strcasecmp(argv[i], "UNFLAGGED")) {
			ptree_node->condition = CONDITION_UNFLAGGED;
		} else if (0 == strcasecmp(argv[i], "UNSEEN")) {
			ptree_node->condition = CONDITION_UNSEEN;
		} else if (0 == strcasecmp(argv[i], "HEADER")) {
			ptree_node->condition = CONDITION_HEADER;
			ptree_node->pstatment = malloc(2*sizeof(char*));
			if (NULL == ptree_node->pstatment) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			i ++;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			((char**)ptree_node->pstatment)[0] = strdup(argv[i]);
			i ++;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			((char**)ptree_node->pstatment)[1] = strdup(argv[i]);
		} else if (0 == strcasecmp(argv[i], "LARGER") ||
			0 == strcasecmp(argv[i], "SMALLER")) {
			if (0 == strcasecmp(argv[i], "LARGER")) {
				ptree_node->condition = CONDITION_LARGER;
			} else {
				ptree_node->condition = CONDITION_SMALLER;
			}
			i ++;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			ptree_node->pstatment = (void*)atol(argv[i]);
		} else if (0 == strcasecmp(argv[i], "UID")) {
			ptree_node->condition = CONDITION_UID;
			i ++;
			if (i + 1 > argc) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			plist1 = mail_engine_ct_parse_squence(argv[i]);
			if (NULL == plist1) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			ptree_node->pstatment = plist1;
		} else {
			plist1 = mail_engine_ct_parse_squence(argv[i]);
			if (NULL == plist1) {
				free(ptree_node);
				mail_engine_ct_destroy_internal(plist);
				return NULL;
			}
			ptree_node->condition = CONDITION_ID;
			ptree_node->pstatment = plist1;
		}
		double_list_append_as_tail(plist, &ptree_node->node);
	}
	return plist;
}

static CONDITION_TREE* mail_engine_ct_build(int argc, char **argv)
{
	if (0 == strcasecmp(argv[0], "CHARSET")) {
		if (argc < 3) {
			return NULL;
		}
		return mail_engine_ct_build_internal(argv[1], argc - 2, argv + 2);
		
	} else {
		return mail_engine_ct_build_internal("UTF-8", argc, argv);
	}
}

static void mail_engine_ct_destroy(CONDITION_TREE *ptree)
{
	mail_engine_ct_destroy_internal(ptree);
}

static DOUBLE_LIST* mail_engine_ct_parse_squence(char *string)
{
	int i, len, temp;
	char *last_colon;
	char *last_break;
	DOUBLE_LIST *plist;
	SQUENCE_NODE *pseq;
	
	len = strlen(string);
	if (',' == string[len - 1]) {
		len --;
	} else {
		string[len] = ',';
	}
	plist = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST));
	if (NULL == plist) {
		return NULL;
	}
	double_list_init(plist);
	last_break = string;
	last_colon = NULL;
	for (i=0; i<=len; i++) {
		if (0 == isdigit(string[i]) && '*' != string[i]
			&& ',' != string[i] && ':' != string[i]) {
			mail_engine_ct_free_squence(plist);
			return NULL;
		}
		if (':' == string[i]) {
			if (NULL != last_colon) {
				mail_engine_ct_free_squence(plist);
				return NULL;
			} else {
				last_colon = string + i;
				*last_colon = '\0';
			}
		} else if (',' == string[i]) {
			if (0 == string + i - last_break) {
				mail_engine_ct_free_squence(plist);
				return NULL;
			}
			string[i] = '\0';
			pseq = (SQUENCE_NODE*)malloc(sizeof(SQUENCE_NODE));
			if (NULL == pseq) {
				mail_engine_ct_free_squence(plist);
				return NULL;
			}
			pseq->node.pdata = pseq;
			if (NULL != last_colon) {
				if (0 == strcmp(last_break, "*")) {
					pseq->max = -1;
					if (0 == strcmp(last_colon + 1, "*")) {
						pseq->min = -1;
					} else {
						pseq->min = atoi(last_colon + 1);
						if (pseq->min <= 0) {
							free(pseq);
							mail_engine_ct_free_squence(plist);
							return NULL;
						}
					}
				} else {
					pseq->min = atoi(last_break);
					if (pseq->min <= 0) {
						free(pseq);
						mail_engine_ct_free_squence(plist);
						return NULL;
					}
					if (0 == strcmp(last_colon + 1, "*")) {
						pseq->max = -1;
					} else {
						pseq->max = atoi(last_colon + 1);
						if (pseq->max <= 0) {
							free(pseq);
							mail_engine_ct_free_squence(plist);
							return NULL;
						}
					}
				}
				last_colon = NULL;
			} else {
				if ('*' == *last_break ||
					(pseq->min = atoi(last_break)) <= 0) {
					free(pseq);
					mail_engine_ct_free_squence(plist);
					return NULL;
				}
				pseq->max = pseq->min;
			}
			if (pseq->max < pseq->min) {
				temp = pseq->max;
				pseq->max = pseq->min;
				pseq->min = temp;
			}
			last_break = string + i + 1;
			double_list_append_as_tail(plist, &pseq->node);
		}
	}
	return plist;
}

static void mail_engine_ct_free_squence(DOUBLE_LIST *plist)
{
	DOUBLE_LIST_NODE *pnode;
	
	while (pnode=double_list_get_from_head(plist)) {
		free(pnode->pdata);
	}
	double_list_free(plist);
	free(plist);
}

static BOOL mail_engine_ct_hint_squence(DOUBLE_LIST *plist,
	unsigned int num, unsigned int max_uid)
{
	SQUENCE_NODE *pseq;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pseq = (SQUENCE_NODE*)pnode->pdata;
		if (-1 == pseq->max) {
			if (-1 == pseq->min) {
				if (num == max_uid) {
					return TRUE;
				}
			} else {
				if (num >= pseq->min) {
					return TRUE;
				}
			}
		} else {
			if (pseq->max >= num && pseq->min <= num) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

static CONDITION_RESULT* mail_engine_ct_match(const char *charset,
	sqlite3 *psqlite, uint64_t folder_id, CONDITION_TREE *ptree,
	BOOL b_uid)
{
	int i;
	int sql_len;
	uint32_t uid;
	int total_mail;
	uint32_t uidnext;
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	const char *mid_string;
	SINGLE_LIST_NODE *pnode;
	CONDITION_RESULT *presult;
	sqlite3_stmt *pstmt_message;

	sql_len = sprintf(sql_string, "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return NULL;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return NULL;
	}
	total_mail = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT uidnext FROM"
			" folders WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return NULL;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return NULL;
	}
	uidnext = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT message_id, mod_time, "
		"uid, recent, read, unsent, flagged, replied, forwarded,"
		"deleted, received, ext, folder_id, size FROM messages "
		"WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt_message, NULL)) {
		return NULL;
	}
	presult = (CONDITION_RESULT*)malloc(sizeof(CONDITION_RESULT));
	if (NULL == presult) {
		sqlite3_finalize(pstmt_message);
		return NULL;
	}
	single_list_init(&presult->list);
	presult->pcur_node = NULL;
	sql_len = sprintf(sql_string, "SELECT mid_string, uid FROM "
		"messages WHERE folder_id=%llu ORDER BY uid", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		single_list_free(&presult->list);
		free(presult);
		sqlite3_finalize(pstmt_message);
		return NULL;
	}
	i = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		mid_string = sqlite3_column_text(pstmt, 0);
		uid = sqlite3_column_int64(pstmt, 1);
		if (TRUE == mail_engine_ct_match_mail(psqlite,
			charset, pstmt_message, mid_string, i + 1,
			total_mail, uidnext, ptree)) {
			pnode = malloc(sizeof(SINGLE_LIST_NODE));
			if (NULL == pnode) {
				continue;
			}
			if (FALSE == b_uid) {
				pnode->pdata = (void*)(long)(i + 1);
			} else {
				pnode->pdata = (void*)(long)uid;
			}
			single_list_append_as_tail(&presult->list, pnode);
		}
		i ++;
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt_message);
	return presult;
}

static int mail_engine_ct_fetch_result(CONDITION_RESULT *presult)
{
    SINGLE_LIST_NODE *pnode;

    if (NULL == presult->pcur_node) {
        pnode = single_list_get_head(&presult->list);
    } else {
        pnode = single_list_get_after(&presult->list, presult->pcur_node);
    }
    if (NULL == pnode) {
        return -1;
    } else {
        presult->pcur_node = pnode;
        return (int)(long)pnode->pdata;
    }
}

static void mail_engine_ct_free_result(CONDITION_RESULT *presult)
{
	SINGLE_LIST_NODE *pnode;
	
	while (pnode=single_list_get_from_head(&presult->list)) {
		free(pnode);
	}
	free(presult);
}

static uint64_t mail_engine_get_folder_id(IDB_ITEM *pidb, const char *name)
{
	int sql_len;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	
	sql_len = sprintf(sql_string, "SELECT "
		"folder_id FROM folders WHERE name=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return 0;
	}
	sqlite3_bind_text(pstmt, 1, name, -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return 0;
	}
	folder_id = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	return folder_id;
}

static BOOL mail_engine_sort_folder(IDB_ITEM *pidb,
	const char *folder_name, int sort_field)
{
	int sql_len;
	uint32_t idx;
	uint64_t folder_id;
	char field_name[16];
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[1024];
	
	switch (sort_field) {
	case FIELD_RECEIVED:
		strcpy(field_name, "received");
		break;
	case FIELD_SUBJECT:
		strcpy(field_name, "subject");
		break;
	case FIELD_FROM:
		strcpy(field_name, "sender");
		break;
	case FIELD_RCPT:
		strcpy(field_name, "rcpt");
		break;
	case FIELD_SIZE:
		strcpy(field_name, "size");
		break;
	case FIELD_READ:
		strcpy(field_name, "read");
		break;
	case FIELD_FLAG:
		strcpy(field_name, "flagged");
		break;
	default:
		strcpy(field_name, "uid");
		sort_field = FIELD_UID;
		break;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id,"
			" sort_field FROM folders WHERE name=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	sqlite3_bind_text(pstmt, 1, folder_name, -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	folder_id = sqlite3_column_int64(pstmt, 0);
	if (sort_field == sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		return TRUE;
	}
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT message_id FROM messages"
		" WHERE folder_id=%llu ORDER BY %s", folder_id, field_name);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	sql_len = sprintf(sql_string, "UPDATE messages"
				" SET idx=? WHERE message_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	idx = 1;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, idx);
		sqlite3_bind_int64(pstmt1, 2,
			sqlite3_column_int64(pstmt, 0));
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		idx ++;
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	sprintf(sql_string, "UPDATE folders SET sort_field=%d "
			"WHERE folder_id=%llu", sort_field, folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	return TRUE;
}

static void mail_engine_extract_digest_fields(const char *digest,
	char *subject, char *from, char *rcpt, size_t *psize)
{
	int i;
	size_t out_len;
	char temp_buff[64*1024];
	char temp_buff1[64*1024];
	EMAIL_ADDR temp_address;
	
	subject[0] = '\0';
	if (TRUE == get_digest(digest, "subject", temp_buff, 1024)) {
		decode64(temp_buff, strlen(temp_buff), subject, &out_len);
	}
	from[0] = '\0';
	if (TRUE == get_digest(digest, "from", temp_buff, 1024)) {
		if (0 == decode64(temp_buff, strlen(temp_buff),
			temp_buff1, &out_len)) {
			memset(&temp_address, 0, sizeof(temp_address));
			parse_email_addr(&temp_address, temp_buff1);
			snprintf(from, 256, "%s@%s",
				temp_address.local_part, temp_address.domain);
		}
	}
	rcpt[0] = '\0';
	if (TRUE == get_digest(digest, "to", temp_buff, 64*1024)) {
		if (0 == decode64(temp_buff, strlen(temp_buff),
			temp_buff1, &out_len)) {
			for (i=0; i<out_len; i++) {
				if (',' == temp_buff1[i] ||
					';' == temp_buff1[i]) {
					temp_buff1[i] = '\0';
					break;
				}
			}
			rtrim_string(temp_buff1);
			memset(&temp_address, 0, sizeof(temp_address));
			parse_email_addr(&temp_address, temp_buff1);
			snprintf(rcpt, 256, "%s@%s",
				temp_address.local_part, temp_address.domain);
		}
	}
	*psize = 0;
	if (TRUE == get_digest(digest, "size", temp_buff, 32)) {
		*psize = atol(temp_buff);
	}
}

static void mail_engine_insert_message(sqlite3_stmt *pstmt,
	uint32_t *puidnext, uint64_t message_id, const char *mid_string,
	uint32_t message_flags, uint64_t received_time, uint64_t mod_time)
{
	int fd;
	MAIL imail;
	size_t size;
	int tmp_len;
	char from[256];
	char rcpt[256];
	uint8_t b_read;
	const char *dir;
	uint8_t b_unsent;
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
		if (0 != stat(temp_path, &node_stat) ||
			node_stat.st_size >= MAX_DIGLEN) {
			return;
		}
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			return;
		}
		if (node_stat.st_size != read(fd, temp_buff, node_stat.st_size)) {
			close(fd);
			return;
		}
		close(fd);
		temp_buff[node_stat.st_size] = '\0';
	} else {
		if (FALSE == common_util_switch_allocator()) {
			return;
		}
		if (FALSE == exmdb_client_read_message(dir, NULL, 0,
			rop_util_make_eid_ex(1, message_id), &pmsgctnt)) {
			common_util_switch_allocator();
			return;
		}
		if (NULL == pmsgctnt) {
			common_util_switch_allocator();
			return;
		}
		if (FALSE == oxcmail_export(pmsgctnt, FALSE,
			OXCMAIL_BODY_PLAIN_AND_HTML, g_mime_pool, &imail,
			common_util_alloc, common_util_get_propids,
			common_util_get_propname)) {
			common_util_switch_allocator();
			return;
		}
		common_util_switch_allocator();
		tmp_len = sprintf(temp_buff, "{\"file\":\"\",");
		if (mail_get_digest(&imail, &size, temp_buff + tmp_len,
			MAX_DIGLEN - tmp_len - 1) <= 0) {
			mail_free(&imail);
			return;
		}
		tmp_len = strlen(temp_buff);
		memcpy(temp_buff + tmp_len, "}", 2);
		tmp_len ++;
		sprintf(mid_string1, "%ld.%d.midb", time(NULL),
			mail_engine_get_squence_id());
		mid_string = mid_string1;
		sprintf(temp_path, "%s/ext/%s", dir, mid_string1);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 == fd) {
			mail_free(&imail);
			return;
		}
		if (tmp_len != write(fd, temp_buff, tmp_len)) {
			close(fd);
			mail_free(&imail);
			return;
		}
		close(fd);
		sprintf(temp_path1, "%s/eml/%s", dir, mid_string1);
		fd = open(temp_path1, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 == fd) {
			mail_free(&imail);
			return;
		}
		if (FALSE == mail_to_file(&imail, fd)) {
			close(fd);
			mail_free(&imail);
			return;
		}
		close(fd);
		mail_free(&imail);
	}
	(*puidnext) ++;
	if (message_flags & MESSAGE_FLAG_UNSENT) {
		b_unsent = 1;
	} else {
		b_unsent = 0;
	}
	if (message_flags & MESSAGE_FLAG_READ) {
		b_read = 1;
	} else {
		b_read = 0;
	}
	mail_engine_extract_digest_fields(
		temp_buff, subject, from, rcpt, &size);
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
	sqlite3_step(pstmt);
}

static void mail_engine_sync_message(IDB_ITEM *pidb,
	sqlite3_stmt *pstmt, sqlite3_stmt *pstmt1, uint32_t *puidnext,
	uint64_t message_id, uint64_t received_time, const char *mid_string,
	const char *mid_string1, uint64_t mod_time, uint64_t mod_time1,
	uint32_t message_flags, uint8_t b_unsent, uint8_t b_read)
{
	uint8_t b_read1;
	uint8_t b_unsent1;
	char sql_string[256];
	
	if (NULL != mid_string || mod_time <= mod_time1) {
		if (message_flags & MESSAGE_FLAG_UNSENT) {
			b_unsent1 = 1;
		} else {
			b_unsent1 = 0;
		}
		if (message_flags & MESSAGE_FLAG_READ) {
			b_read1 = 1;
		} else {
			b_read1 = 0;
		}
		if (b_unsent != b_unsent1 || b_read != b_read1) {
			sqlite3_reset(pstmt1);
			sqlite3_bind_int64(pstmt1, 1, b_unsent1);
			sqlite3_bind_int64(pstmt1, 2, b_read1);
			sqlite3_bind_int64(pstmt1, 3, message_id);
			if (SQLITE_DONE != sqlite3_step(pstmt1)) {
				return;
			}
		}
		return;
	}
	sprintf(sql_string, "DELETE FROM messages"
		" WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_exec(pidb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return;	
	}
	mail_engine_insert_message(pstmt, puidnext, message_id,
			NULL, message_flags, received_time, mod_time);
}

static BOOL mail_engine_sync_contents(IDB_ITEM *pidb, uint64_t folder_id)
{
	int i;
	int sql_len;
	void *pvalue;
	const char *dir;
	TARRAY_SET rows;
	sqlite3 *psqlite;
	uint32_t uidnext;
	uint32_t uidnext1;
	uint64_t mod_time;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	sqlite3_stmt *pstmt3;
	DOUBLE_LIST temp_list;
	char sql_string[1024];
	uint32_t message_flags;
	uint64_t received_time;
	DOUBLE_LIST_NODE *pnode;
	
	dir = common_util_get_maildir();
	if (FALSE == exmdb_client_query_folder_messages(
		dir, rop_util_make_eid_ex(1, folder_id), &rows)) {
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT uidnext FROM"
			" folders WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return TRUE;
	}
	uidnext = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	uidnext1 = uidnext;
	if (SQLITE_OK != sqlite3_open_v2(":memory:", &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		return FALSE;
	}
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "CREATE TABLE messages "
			"(message_id INTEGER PRIMARY KEY,"
			"mid_string TEXT,"
			"mod_time INTEGER,"
			"message_flags INTEGER,"
			"received INTEGER)");
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_close(psqlite);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "INSERT INTO messages (message_id,"
			" mid_string, mod_time, message_flags, received) VALUES "
			"(?, ?, ?, ?, ?)");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return FALSE;
	}
	for (i=0; i<rows.count; i++) {
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_MID);
		if (NULL == pvalue) {
			continue;
		}
		message_id = rop_util_get_gc_value(*(uint64_t*)pvalue);
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_MESSAGEFLAGS);
		if (NULL == pvalue) {
			continue;
		}
		message_flags = *(uint64_t*)pvalue;
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_LASTMODIFICATIONTIME);
		if (NULL == pvalue) {
			mod_time = 0;
		} else {
			mod_time = *(uint64_t*)pvalue;
		}
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_MESSAGEDELIVERYTIME);
		if (NULL == pvalue) {
			received_time = mod_time;
		} else {
			received_time = *(uint64_t*)pvalue;
		}
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_MIDSTRING);
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, message_id);
		if (NULL == pvalue) {
			sqlite3_bind_null(pstmt, 2);
		} else {
			sqlite3_bind_text(pstmt, 2, pvalue, -1, SQLITE_STATIC);
		}
		sqlite3_bind_int64(pstmt, 3, mod_time);
		sqlite3_bind_int64(pstmt, 4, message_flags);
		sqlite3_bind_int64(pstmt, 5, received_time);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_close(psqlite);
			return FALSE;
		}
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT message_id, "
		"mid_string, mod_time, message_flags, received"
		" FROM messages");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT message_id, mid_string,"
		" mod_time, unsent, read FROM messages WHERE message_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "INSERT INTO messages (message_id, "
		"folder_id, mid_string, mod_time, uid, unsent, read, subject,"
		" sender, rcpt, size, received) VALUES (?, %llu, ?, ?, ?, ?, "
		"?, ?, ?, ?, ?, ?)", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt2, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		sqlite3_close(psqlite);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "UPDATE messages"
		" SET unsent=?, read=? WHERE message_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt3, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		sqlite3_finalize(pstmt2);
		sqlite3_close(psqlite);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		message_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			uidnext ++;
			mail_engine_insert_message(
				pstmt2, &uidnext, message_id,
				sqlite3_column_text(pstmt, 1),
				sqlite3_column_int64(pstmt, 3),
				sqlite3_column_int64(pstmt, 4),
				sqlite3_column_int64(pstmt, 2));
		} else {
			mail_engine_sync_message(pidb,
				pstmt2, pstmt3, &uidnext, message_id,
				sqlite3_column_int64(pstmt, 4),
				sqlite3_column_text(pstmt, 1),
				sqlite3_column_text(pstmt1, 1),
				sqlite3_column_int64(pstmt, 2),
				sqlite3_column_int64(pstmt1, 2),
				sqlite3_column_int64(pstmt, 3),
				sqlite3_column_int64(pstmt1, 3),
				sqlite3_column_int64(pstmt1, 4));
		}
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	sqlite3_finalize(pstmt2);
	sqlite3_finalize(pstmt3);
	sql_len = sprintf(sql_string, "SELECT message_id FROM "
				"messages WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT message_id"
				" FROM messages WHERE message_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		return FALSE;
	}
	double_list_init(&temp_list);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		message_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
			if (NULL == pnode) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_close(psqlite);
				return FALSE;
			}
			pnode->pdata = common_util_alloc(sizeof(uint64_t));
			if (NULL == pnode->pdata) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_close(psqlite);
				return FALSE;
			}
			*(uint64_t*)pnode->pdata = message_id;
			double_list_append_as_tail(&temp_list, pnode);
		}
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	if (0 != double_list_get_nodes_num(&temp_list)) {
		sql_len = sprintf(sql_string, "DELETE "
			"FROM messages WHERE message_id=?");
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			sqlite3_close(psqlite);
			return FALSE;
		}
		while (pnode=double_list_get_from_head(&temp_list)) {
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, *(uint64_t*)pnode->pdata);
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				sqlite3_close(psqlite);
				return FALSE;
			}
		}
		sqlite3_finalize(pstmt);
	}
	if (uidnext != uidnext1) {
		sprintf(sql_string, "UPDATE folders SET uidnext=%u "
				"WHERE folder_id=%llu", uidnext, folder_id);
		if (SQLITE_OK != sqlite3_exec(pidb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_close(psqlite);
			return FALSE;
		}
	}
	sqlite3_close(psqlite);
	sprintf(sql_string, "UPDATE folders SET sort_field=%d "
			"WHERE folder_id=%llu", FIELD_NONE, folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	return TRUE;
}

static BOOL mail_engine_get_encoded_name(sqlite3_stmt *pstmt,
	uint64_t folder_id, char *encoded_name)
{
	int length;
	int offset;
	char temp_name[512];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	
	switch (folder_id) {
	case PRIVATE_FID_INBOX:
		strcpy(encoded_name, "inbox");
		return TRUE;
	case PRIVATE_FID_DRAFT:
		strcpy(encoded_name, "draft");
		return TRUE;
	case PRIVATE_FID_SENT_ITEMS:
		strcpy(encoded_name, "sent");
		return TRUE;
	case PRIVATE_FID_DELETED_ITEMS:
		strcpy(encoded_name, "trash");
		return TRUE;
	case PRIVATE_FID_JUNK:
		strcpy(encoded_name, "junk");
		return TRUE;
	}
	double_list_init(&temp_list);
	do {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, folder_id);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			return FALSE;
		}
		pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			return FALSE;
		}
		folder_id = sqlite3_column_int64(pstmt, 0);
		pnode->pdata = common_util_dup(sqlite3_column_text(pstmt, 1));
		if (NULL == pnode->pdata) {
			return FALSE;
		}
		double_list_insert_as_head(&temp_list, pnode);
	} while (PRIVATE_FID_IPMSUBTREE != folder_id);
	offset = 0;
	for (pnode=double_list_get_head(&temp_list); NULL!=pnode;
		pnode=double_list_get_after(&temp_list, pnode)) {
		length = strlen(pnode->pdata);
		if (length >= 256) {
			return FALSE;
		}
		if (0 != offset) {
			temp_name[offset] = '/';
			offset ++;
		}
		if (offset + length >= 512) {
			return FALSE;
		}
		memcpy(temp_name + offset, pnode->pdata, length);
		offset += length;
	}
	encode_hex_binary(temp_name, offset, encoded_name, 1024);
	return TRUE;
}

static uint64_t mail_engine_get_top_folder_id(
	sqlite3_stmt *pstmt, uint64_t folder_id)
{
	uint64_t parent_fid;
	
	while (TRUE) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, folder_id);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			return 0;
		}
		parent_fid = sqlite3_column_int64(pstmt, 0);
		if (PRIVATE_FID_IPMSUBTREE == parent_fid) {
			return folder_id;
		}
		folder_id = parent_fid;
	}
}

static BOOL mail_engine_sync_mailbox(IDB_ITEM *pidb)
{
	int i;
	BOOL b_new;
	int sql_len;
	void *pvalue;
	const char *dir;
	TARRAY_SET rows;
	sqlite3 *psqlite;
	uint32_t table_id;
	uint32_t row_count;
	uint64_t folder_id;
	uint64_t parent_fid;
	uint64_t commit_max;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	sqlite3_stmt *pstmt3;
	char sql_string[1280];
	DOUBLE_LIST temp_list;
	PROPTAG_ARRAY proptags;
	DOUBLE_LIST_NODE *pnode;
	char encoded_name[1024];
	uint32_t proptag_buff[6];
	
	dir = common_util_get_maildir();
	if (FALSE == exmdb_client_load_hierarchy_table(dir,
		rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE),
		NULL, TABLE_FLAG_DEPTH|TABLE_FLAG_NONOTIFICATIONS,
		NULL, &table_id, &row_count)) {
		return FALSE;	
	}
	proptags.count = 6;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_FOLDERID;
	proptag_buff[1] = PROP_TAG_PARENTFOLDERID;
	proptag_buff[2] = PROP_TAG_ATTRIBUTEHIDDEN;
	proptag_buff[3] = PROP_TAG_CONTAINERCLASS;
	proptag_buff[4] = PROP_TAG_DISPLAYNAME;
	proptag_buff[5] = PROP_TAG_LOCALCOMMITTIMEMAX;
	if (FALSE == exmdb_client_query_table(dir, NULL,
		0, table_id, &proptags, 0, row_count, &rows)) {
		exmdb_client_unload_table(dir, table_id);
		return FALSE;
	}
	exmdb_client_unload_table(dir, table_id);
	if (SQLITE_OK != sqlite3_open_v2(":memory:", &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		return FALSE;
	}
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "CREATE TABLE folders "
			"(folder_id INTEGER PRIMARY KEY,"
			"parent_fid INTEGER,"
			"display_name TEXT,"
			"commit_max INTEGER)");
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_close(psqlite);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "INSERT INTO folders (folder_id, "
		"parent_fid, display_name, commit_max) VALUES (?, ?, ?, ?)");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return FALSE;
	}
	for (i=0; i<rows.count; i++) {
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_ATTRIBUTEHIDDEN);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			continue;
		}
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_CONTAINERCLASS);
		if (NULL == pvalue || 0 != strcasecmp(pvalue, "IPF.Note")) {
			continue;
		}
		sqlite3_reset(pstmt);
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_FOLDERID);
		if (NULL == pvalue) {
			continue;
		}
		folder_id = rop_util_get_gc_value(*(uint64_t*)pvalue);
		sqlite3_bind_int64(pstmt, 1, folder_id);
		pvalue = common_util_get_propvals(
			rows.pparray[i], PROP_TAG_PARENTFOLDERID);
		if (NULL == pvalue) {
			continue;
		}
		parent_fid = rop_util_get_gc_value(*(uint64_t*)pvalue);
		sqlite3_bind_int64(pstmt, 2, parent_fid);
		switch (folder_id) {
		case PRIVATE_FID_INBOX:
			pvalue = "inbox";
			break;
		case PRIVATE_FID_DRAFT:
			pvalue = "draft";
			break;
		case PRIVATE_FID_SENT_ITEMS:
			pvalue = "sent";
			break;
		case PRIVATE_FID_DELETED_ITEMS:
			pvalue = "trash";
			break;
		case PRIVATE_FID_JUNK:
			pvalue = "junk";
			break;
		default:
			pvalue = common_util_get_propvals(
				rows.pparray[i], PROP_TAG_DISPLAYNAME);
			if (NULL == pvalue || strlen(pvalue) >= 256) {
				continue;
			}
			break;
		}
		sqlite3_bind_text(pstmt, 3, pvalue, -1, SQLITE_STATIC);
		pvalue = common_util_get_propvals(rows.pparray[i],
							PROP_TAG_LOCALCOMMITTIMEMAX);
		if (NULL == pvalue) {
			sqlite3_bind_int64(pstmt, 4, 0);
		} else {
			sqlite3_bind_int64(pstmt, 4, *(uint64_t*)pvalue);
		}
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_close(psqlite);
			return FALSE;
		}
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	pstmt = NULL;
	pstmt1 = NULL;
	pstmt2 = NULL;
	pstmt3 = NULL;
	sqlite3_exec(pidb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT folder_id, "
				"parent_fid, commit_max FROM folders");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		goto SYNC_FAILURE;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id, parent_fid, "
				"commit_max, name FROM folders WHERE folder_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		goto SYNC_FAILURE;
	}
	sql_len = sprintf(sql_string, "INSERT INTO folders (folder_id, "
				"parent_fid, commit_max, name) VALUES (?, ?, ?, ?)");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt2, NULL)) {
		goto SYNC_FAILURE;
	}
	sql_len = sprintf(sql_string, "SELECT parent_fid, "
		"display_name FROM folders WHERE folder_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt3, NULL)) {
		goto SYNC_FAILURE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		folder_id = sqlite3_column_int64(pstmt, 0);
		switch (mail_engine_get_top_folder_id(pstmt3, folder_id)) {
		case PRIVATE_FID_OUTBOX:
		case PRIVATE_FID_SYNC_ISSUES:
			continue;			
		}
		parent_fid = sqlite3_column_int64(pstmt, 1);
		commit_max = sqlite3_column_int64(pstmt, 2);
		if (FALSE == mail_engine_get_encoded_name(
			pstmt3, folder_id, encoded_name)) {
			continue;
		}
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, folder_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			sqlite3_reset(pstmt2);
			sqlite3_bind_int64(pstmt2, 1, folder_id);
			sqlite3_bind_int64(pstmt2, 2, parent_fid);
			sqlite3_bind_int64(pstmt2, 3, commit_max);
			sqlite3_bind_text(pstmt2, 4, encoded_name, -1, SQLITE_STATIC);
			if (SQLITE_DONE != sqlite3_step(pstmt2)) {
				goto SYNC_FAILURE;
			}
			b_new = TRUE;
		} else {
			if (parent_fid != sqlite3_column_int64(pstmt1, 1)) {
				sprintf(sql_string, "UPDATE folders SET "
					"parent_fid=%llu WHERE folder_id=%llu",
					parent_fid, folder_id);
				sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
			}
			if (0 != strcmp(encoded_name, sqlite3_column_text(pstmt1, 3))) {
				sprintf(sql_string, "UPDATE folders SET name='%s' "
					"WHERE folder_id=%llu", encoded_name, folder_id);
				sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
			}
			if (commit_max == sqlite3_column_int64(pstmt1, 2)) {
				continue;	
			}
			b_new = FALSE;
		}
		if (FALSE == mail_engine_sync_contents(pidb, folder_id)) {
			goto SYNC_FAILURE;
		}
		if (FALSE == b_new) {
			sprintf(sql_string, "UPDATE folders SET commit_max=%llu"
					" WHERE folder_id=%llu", commit_max, folder_id);
			sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
		}
	}
	sqlite3_finalize(pstmt);
	pstmt = NULL;
	sqlite3_finalize(pstmt1);
	pstmt1 = NULL;
	sqlite3_finalize(pstmt2);
	pstmt2 = NULL;
	sqlite3_finalize(pstmt3);
	pstmt3 = NULL;
	sql_len = sprintf(sql_string, "SELECT folder_id FROM folders");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		goto SYNC_FAILURE;
	}
	sql_len = sprintf(sql_string, "SELECT "
		"folder_id FROM folders WHERE folder_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		goto SYNC_FAILURE;
	}
	double_list_init(&temp_list);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		folder_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, folder_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
			if (NULL == pnode) {
				goto SYNC_FAILURE;
			}
			pnode->pdata = common_util_alloc(sizeof(uint64_t));
			if (NULL == pnode->pdata) {
				goto SYNC_FAILURE;
			}
			*(uint64_t*)pnode->pdata = folder_id;
			double_list_append_as_tail(&temp_list, pnode);
		}
	}
	sqlite3_finalize(pstmt);
	pstmt = NULL;
	sqlite3_finalize(pstmt1);
	pstmt1 = NULL;
	if (0 != double_list_get_nodes_num(&temp_list)) {
		sql_len = sprintf(sql_string, "DELETE"
			" FROM folders WHERE folder_id=?");
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			goto SYNC_FAILURE;
		}
		while (pnode=double_list_get_from_head(&temp_list)) {
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, *(uint64_t*)pnode->pdata);
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				goto SYNC_FAILURE;
			}
		}
		sqlite3_finalize(pstmt);
	}
	sqlite3_exec(pidb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_close(psqlite);
	if (FALSE == exmdb_client_subscribe_notification(dir,
		NOTIFICATION_TYPE_OBJECTCREATED|NOTIFICATION_TYPE_OBJECTDELETED|
		NOTIFICATION_TYPE_OBJECTMODIFIED|NOTIFICATION_TYPE_OBJECTMOVED|
		NOTIFICATION_TYPE_OBJECTCOPIED|NOTIFICATION_TYPE_NEWMAIL, TRUE,
		0, 0, &pidb->sub_id)) {
		pidb->sub_id = 0;	
	}
	time(&pidb->load_time);
	return TRUE;

SYNC_FAILURE:
	if (NULL != pstmt) {
		sqlite3_finalize(pstmt);
	}
	if (NULL != pstmt1) {
		sqlite3_finalize(pstmt1);
	}
	if (NULL != pstmt2) {
		sqlite3_finalize(pstmt2);
	}
	if (NULL != pstmt3) {
		sqlite3_finalize(pstmt3);
	}
	sqlite3_close(psqlite);
	sqlite3_exec(pidb->psqlite, "ROLLBACK", NULL, NULL, NULL);
	return FALSE;
}

static IDB_ITEM* mail_engine_peek_idb(const char *path)
{
	IDB_ITEM *pidb;
	char htag[256];
	
	swap_string(htag, path);
	pthread_mutex_lock(&g_hash_lock);
	pidb = (IDB_ITEM*)str_hash_query(g_hash_table, htag);
	if (NULL == pidb) {
		pthread_mutex_unlock(&g_hash_lock);
		return NULL;
	}
	pidb->reference ++;
	pthread_mutex_unlock(&g_hash_lock);
	pthread_mutex_lock(&pidb->lock);
	if (NULL == pidb->psqlite) {
		pidb->last_time = 0;
		pthread_mutex_unlock(&pidb->lock);
		pthread_mutex_lock(&g_hash_lock);
		pidb->reference --;
		pthread_mutex_unlock(&g_hash_lock);
		return NULL;
	}
	return pidb;
}

static IDB_ITEM* mail_engine_get_idb(const char *path)
{
	int sql_len;
	BOOL b_load;
	char htag[256];
	sqlite3_stmt *pstmt;
	char temp_path[256];
	char sql_string[1024];
	IDB_ITEM *pidb, temp_idb;
	struct timespec timeout_tm;
	
	b_load = FALSE;
	swap_string(htag, path);
	pthread_mutex_lock(&g_hash_lock);
	pidb = (IDB_ITEM*)str_hash_query(g_hash_table, htag);
	if (NULL == pidb) {
		memset(&temp_idb, 0, sizeof(IDB_ITEM));
		if (1 != str_hash_add(g_hash_table, htag, &temp_idb)) {
			pthread_mutex_unlock(&g_hash_lock);
			debug_info("[mail_engine]: no room in idb hash table!");
			return NULL;
		}
		pidb = (IDB_ITEM*)str_hash_query(g_hash_table, htag);
		sprintf(temp_path, "%s/exmdb/midb.sqlite3", path);
		if (SQLITE_OK != sqlite3_open_v2(temp_path,
			&pidb->psqlite, SQLITE_OPEN_READWRITE, NULL)) {
			str_hash_remove(g_hash_table, htag);
			pthread_mutex_unlock(&g_hash_lock);
			return NULL;
		}
		sqlite3_exec(pidb->psqlite, "PRAGMA foreign_keys=ON",
			NULL, NULL, NULL);
		sqlite3_exec(pidb->psqlite, "PRAGMA journal_mode=OFF",
			NULL, NULL, NULL);
		if (FALSE == g_async) {
			sqlite3_exec(pidb->psqlite, "PRAGMA synchronous=OFF",
				NULL, NULL, NULL);
		} else {
			sqlite3_exec(pidb->psqlite, "PRAGMA synchronous=ON",
				NULL, NULL, NULL);
		}
		if (FALSE == g_wal) {
			sqlite3_exec(pidb->psqlite, "PRAGMA journal_mode=DELETE",
				NULL, NULL, NULL);
		} else {
			sqlite3_exec(pidb->psqlite, "PRAGMA journal_mode=WAL",
				NULL, NULL, NULL);
		}
		if (0 != g_mmap_size) {
			sprintf(sql_string, "PRAGMA mmap_size=%llu", g_mmap_size);
			sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
		}
		sqlite3_exec(pidb->psqlite, "DELETE FROM mapping", NULL, NULL, NULL);
		sql_len = sprintf(sql_string, "SELECT config_value FROM "
			"configurations WHERE config_id=%u", CONFIG_ID_USERNAME);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			sqlite3_close(pidb->psqlite);
			str_hash_remove(g_hash_table, htag);
			pthread_mutex_unlock(&g_hash_lock);
			return NULL;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_close(pidb->psqlite);
			str_hash_remove(g_hash_table, htag);
			pthread_mutex_unlock(&g_hash_lock);
			return NULL;
		}
		pidb->username = strdup(sqlite3_column_text(pstmt, 0));
		sqlite3_finalize(pstmt);
		if (NULL == pidb->username) {
			sqlite3_close(pidb->psqlite);
			str_hash_remove(g_hash_table, htag);
			pthread_mutex_unlock(&g_hash_lock);
			return NULL;
		}
		pthread_mutex_init(&pidb->lock, NULL);
		b_load = TRUE;
	} else if (pidb->reference > MAX_DB_WAITING_THREADS) {
		pthread_mutex_unlock(&g_hash_lock);
		debug_info("[mail_engine]: too many threads waiting on %s\n", path);
		return NULL;
	}
	pidb->reference ++;
	pthread_mutex_unlock(&g_hash_lock);
	clock_gettime(CLOCK_REALTIME, &timeout_tm);
    timeout_tm.tv_sec += DB_LOCK_TIMEOUT;
	if (0 != pthread_mutex_timedlock(&pidb->lock, &timeout_tm)) {
		pthread_mutex_lock(&g_hash_lock);
		pidb->reference --;
		pthread_mutex_unlock(&g_hash_lock);
		return NULL;
	}
	if (TRUE == b_load) {
		mail_engine_sync_mailbox(pidb);
	} else {
		if (NULL == pidb->psqlite) {
			pidb->last_time = 0;
			pthread_mutex_unlock(&pidb->lock);
			pthread_mutex_lock(&g_hash_lock);
			pidb->reference --;
			pthread_mutex_unlock(&g_hash_lock);
			return NULL;
		}
	}
	return pidb;
}

static void mail_engine_put_idb(IDB_ITEM *pidb)
{
	time(&pidb->last_time);
	pthread_mutex_unlock(&pidb->lock);
	pthread_mutex_lock(&g_hash_lock);
	pidb->reference --;
	pthread_mutex_unlock(&g_hash_lock);
}

static void mail_engine_free_idb(IDB_ITEM *pidb)
{
	pthread_mutex_destroy(&pidb->lock);
	if (NULL != pidb->username) {
		free(pidb->username);
	}
	if (NULL != pidb->psqlite) {
		sqlite3_close(pidb->psqlite);
	}
}

static void *scan_work_func(void *param)
{
	int count;
	char path[256];
	char htag[256];
	IDB_ITEM *pidb;
	SUB_NODE *psub;
	uint32_t sub_id;
	time_t now_time;
	STR_HASH_ITER *iter;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;

	count = 0;
	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		sleep(1);
		if (count < 10) {
			count ++;
			continue;
		}
		count = 0;
		pthread_mutex_lock(&g_hash_lock);
		iter = str_hash_iter_init(g_hash_table);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pidb = (IDB_ITEM*)str_hash_iter_get_value(iter, htag);
			time(&now_time);
			if (0 == pidb->reference && (0 == pidb->sub_id ||
				now_time - pidb->last_time > g_cache_interval ||
				now_time - pidb->load_time > RELOAD_INTERVAL)) {
				swap_string(path, htag);
				if (0 != pidb->sub_id) {
					psub = malloc(sizeof(SUB_NODE));
					if (NULL != psub) {
						psub->node.pdata = psub;
						strcpy(psub->maildir, path);
						psub->sub_id = pidb->sub_id;
						double_list_append_as_tail(
							&temp_list, &psub->node);
					}
				}
				mail_engine_free_idb(pidb);
				str_hash_iter_remove(iter);
			}
		}
		str_hash_iter_free(iter);
		pthread_mutex_unlock(&g_hash_lock);
		while (pnode=double_list_get_from_head(&temp_list)) {
			psub = (SUB_NODE*)pnode->pdata;
			if (TRUE == common_util_build_environment(psub->maildir)) {
				exmdb_client_unsubscribe_notification(
						psub->maildir, psub->sub_id);
				common_util_free_environment();
			}
			free(psub);
		}
	}
	pthread_mutex_lock(&g_hash_lock);
	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pidb = (IDB_ITEM*)str_hash_iter_get_value(iter, htag);
		swap_string(path, htag);
		if (0 != pidb->sub_id) {
			exmdb_client_unsubscribe_notification(
								path, pidb->sub_id);
		}
		mail_engine_free_idb(pidb);
		str_hash_iter_remove(iter);
	}
	str_hash_iter_free(iter);
	pthread_mutex_unlock(&g_hash_lock);
	double_list_free(&temp_list);
	pthread_exit(0);
}
	
static int mail_engine_mquta(int argc, char **argv, int sockd)
{
	int temp_len;
	uint32_t *pmax;
	uint64_t quota;
	uint32_t *pcount;
	uint64_t *ptotal;
	char temp_string[1024];
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[3];
	
	if (2 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	proptags.count = 3;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PROP_TAG_MESSAGESIZEEXTENDED;
	tmp_proptags[1] = PROP_TAG_PROHIBITRECEIVEQUOTA;
	tmp_proptags[2] = PROP_TAG_CONTENTCOUNT;
	if (FALSE == exmdb_client_get_store_properties(
		argv[1], 0, &proptags, &propvals)) {
		return 4;	
	}
	ptotal = common_util_get_propvals(&propvals,
					PROP_TAG_MESSAGESIZEEXTENDED);
	pmax = common_util_get_propvals(&propvals,
				PROP_TAG_PROHIBITRECEIVEQUOTA);
	pcount = common_util_get_propvals(&propvals,
						PROP_TAG_CONTENTCOUNT);
	if (NULL == ptotal || NULL == pmax || NULL == pcount) {
		return 4;
	}
	quota = *pmax;
	quota *= 1024;
	temp_len = sprintf(temp_string, "TRUE %llu %u %llu %d\r\n",
							*ptotal, *pcount, quota, 0x7FFFFFFF);
	write(sockd, temp_string, temp_len);
	return 0;
}

static int mail_engine_mckfl(int argc, char **argv, int sockd)
{
	uint32_t *pmax;
	uint64_t quota;
	uint64_t *ptotal;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[2];
	
	if (2 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	proptags.count = 2;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PROP_TAG_PROHIBITRECEIVEQUOTA;
	tmp_proptags[1] = PROP_TAG_MESSAGESIZEEXTENDED;
	if (FALSE == exmdb_client_get_store_properties(
		argv[1], 0, &proptags, &propvals)) {
		return 4;	
	}
	ptotal = common_util_get_propvals(&propvals,
					PROP_TAG_MESSAGESIZEEXTENDED);
	pmax = common_util_get_propvals(&propvals,
				PROP_TAG_PROHIBITRECEIVEQUOTA);
	if (NULL != ptotal && NULL != pmax) {
		quota = *pmax;
		quota *= 1024;
		if (*ptotal >= quota) {
			write(sockd, "TRUE 1\r\n", 8);
			return 0;
		}
	}
	write(sockd, "TRUE 0\r\n", 8);
	return 0;
}

static int mail_engine_mfree(int argc, char **argv, int sockd)
{
	IDB_ITEM *pidb;
	char htag[256];
	IDB_ITEM temp_idb;
	
	if (2 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	swap_string(htag, argv[1]);
	pthread_mutex_lock(&g_hash_lock);
	pidb = (IDB_ITEM*)str_hash_query(g_hash_table, htag);
	if (NULL == pidb) {
		memset(&temp_idb, 0, sizeof(IDB_ITEM));
		temp_idb.last_time = time(NULL) + g_cache_interval - 10;
		str_hash_add(g_hash_table, htag, &temp_idb);
		pthread_mutex_unlock(&g_hash_lock);
		write(sockd, "TRUE\r\n", 6);
		return 0;
	}
	pidb->reference ++;
	pthread_mutex_unlock(&g_hash_lock);
	pthread_mutex_lock(&pidb->lock);
	if (NULL != pidb->username) {
		free(pidb->username);
		pidb->username = NULL;
	}
	if (NULL != pidb->psqlite) {
		sqlite3_close(pidb->psqlite);
		pidb->psqlite = NULL;
	}
	pidb->last_time = time(NULL) - g_cache_interval - 10;
	pthread_mutex_unlock(&pidb->lock);
	pthread_mutex_lock(&g_hash_lock);
	pidb->reference --;
	pthread_mutex_unlock(&g_hash_lock);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mping(int argc, char **argv, int sockd)
{
	IDB_ITEM *pidb;
	IDB_ITEM temp_idb;
	
	if (2 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL != pidb) {
		mail_engine_put_idb(pidb);
	}
	exmdb_client_ping_store(argv[1]);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mweml(int argc, char **argv, int sockd)
{
	int fd;
	MAIL imail;
	size_t size;
	int sql_len;
	int tmp_len;
	IDB_ITEM *pidb;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	char temp_path[256];
	char sql_string[256];
	struct stat node_stat;
	MESSAGE_CONTENT *pmsgctnt;
	char temp_buff[MAX_DIGLEN];
	
	if (3 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	snprintf(temp_path, 256, "%s/eml/%s", argv[1], argv[2]);
	if (0 == stat(temp_path, &node_stat)) {
		write(sockd, "TRUE\r\n", 6);
		return 0;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	sql_len = sprintf(sql_string, "SELECT message_id"
				" FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[2], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 3;
	}
	message_id = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	if (FALSE == exmdb_client_read_message(argv[1],
		NULL, 0, rop_util_make_eid_ex(1, message_id),
		&pmsgctnt) || NULL == pmsgctnt) {
		return 4;
	}
	if (FALSE == oxcmail_export(pmsgctnt, FALSE,
		OXCMAIL_BODY_PLAIN_AND_HTML, g_mime_pool, &imail,
		common_util_alloc, common_util_get_propids,
		common_util_get_propname)) {
		return 4;
	}
	tmp_len = sprintf(temp_buff, "{\"file\":\"\",");
	if (mail_get_digest(&imail, &size, temp_buff + tmp_len,
		MAX_DIGLEN - tmp_len - 1) <= 0) {
		mail_free(&imail);
		return 4;
	}
	tmp_len = strlen(temp_buff);
	memcpy(temp_buff + tmp_len, "}", 2);
	tmp_len ++;
	sprintf(temp_path, "%s/ext/%s", argv[1], argv[2]);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		mail_free(&imail);
		return 4;
	}
	if (tmp_len != write(fd, temp_buff, tmp_len)) {
		close(fd);
		mail_free(&imail);
		return 4;
	}
	close(fd);
	sprintf(temp_path, "%s/eml/%s", argv[1], argv[2]);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		mail_free(&imail);
		return 4;
	}
	if (FALSE == mail_to_file(&imail, fd)) {
		close(fd);
		mail_free(&imail);
		return 4;
	}
	close(fd);
	mail_free(&imail);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_msumy(int argc, char **argv, int sockd)
{
	int sql_len;
	int temp_len;
	IDB_ITEM *pidb;
	uint32_t count;
	uint32_t unread;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	char temp_string[1024];
	
	if (3 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT count(message_id) FROM "
			"messages WHERE folder_id=%llu AND read=0", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 3;
	}
	unread = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT count(message_id)"
			" FROM messages WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 3;
	}
	count = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	temp_len = sprintf(temp_string, "TRUE %u %u\r\n", unread, count);
	mail_engine_put_idb(pidb);
	write(sockd, temp_string, temp_len);
	return 0;
}

static int mail_engine_minfo(int argc, char**argv, int sockd)
{
	int count;
	int offset;
	int sql_len;
	int temp_len;
	IDB_ITEM *pidb;
	uint32_t unreads;
	uint64_t folder_id;
	uint32_t total_mail;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if (2 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	temp_len = 32;
	count = 0;
	sql_len = sprintf(sql_string, "SELECT folder_id, name FROM folders");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT count(message_id) "
				"FROM messages WHERE folder_id=? AND read=0");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT count(message_id)"
						" FROM messages WHERE folder_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt2, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		mail_engine_put_idb(pidb);
		return 4;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		folder_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, folder_id);
		sqlite3_reset(pstmt2);
		sqlite3_bind_int64(pstmt2, 1, folder_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1) ||
			SQLITE_ROW != sqlite3_step(pstmt2)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_finalize(pstmt2);
			mail_engine_put_idb(pidb);
			return 4;
		}
		unreads = sqlite3_column_int64(pstmt1, 0);
		total_mail = sqlite3_column_int64(pstmt2, 0);
		temp_len += snprintf(temp_buff + temp_len,
				256*1024 - temp_len, "%s %u %u\r\n",
				sqlite3_column_text(pstmt, 1),
				unreads, total_mail);
		count ++;
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	sqlite3_finalize(pstmt2);
	mail_engine_put_idb(pidb);
	offset = snprintf(temp_buff, 32, "TRUE %d\r\n", count);
	memmove(temp_buff + 32 - offset, temp_buff, offset);
	write(sockd, temp_buff + 32 - offset, offset + temp_len - 32);
	return 0;
}

static int mail_engine_menum(int argc, char **argv, int sockd)
{
	int count;
	int offset;
	int sql_len;
	int temp_len;
	IDB_ITEM *pidb;
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if (2 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id, name FROM folders");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	temp_len = 32;
	count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		switch (sqlite3_column_int64(pstmt, 0)) {
		case PRIVATE_FID_INBOX:
		case PRIVATE_FID_DRAFT:
		case PRIVATE_FID_SENT_ITEMS:
		case PRIVATE_FID_DELETED_ITEMS:
		case PRIVATE_FID_JUNK:
			continue;
		}
		temp_len += snprintf(temp_buff + temp_len,
					256*1024 - temp_len, "%s\r\n",
					sqlite3_column_text(pstmt, 1));
		count ++;
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	offset = snprintf(temp_buff, 32, "TRUE %d\r\n", count);
	memmove(temp_buff + 32 - offset, temp_buff, offset);
	write(sockd, temp_buff + 32 - offset, offset + temp_len - 32);
	return 0;
}

static int mail_engine_mlist(int argc, char **argv, int sockd)
{
	BOOL b_asc;
	int offset;
	int length;
	int sql_len;
	int temp_len;
	int idx1, idx2;
	IDB_ITEM *pidb;
	int total_mail;
	int sort_field;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	char temp_buff[MAX_DIGLEN];
	
	if ((5 != argc && 7 != argc) || strlen(argv[1]) >= 256
		|| strlen(argv[2]) >= 1024) {
		return 1;	
	}
	if (0 == strcasecmp(argv[3], "RCV")) {
		sort_field = FIELD_RECEIVED;
	} else if (0 == strcasecmp(argv[3], "SUB")) {
		sort_field = FIELD_SUBJECT;	
	} else if (0 == strcasecmp(argv[3], "FRM")) {
		sort_field = FIELD_FROM;
	} else if (0 == strcasecmp(argv[3], "RCP")) {
		sort_field = FIELD_RCPT;
	} else if (0 == strcasecmp(argv[3], "SIZ")) {
		sort_field = FIELD_SIZE;
	} else if (0 == strcasecmp(argv[3], "RED")) {
		sort_field = FIELD_READ;
	} else if (0 == strcasecmp(argv[3], "FLG")) {
		sort_field = FIELD_FLAG;
	} else if (0 == strcasecmp(argv[3], "UID")) {
		sort_field = FIELD_UID;
	} else if (0 == strcasecmp(argv[3], "NON")) {
		sort_field = FIELD_NONE;
	} else {
		return 1;
	}
	if (0 == strcasecmp(argv[4], "ASC")) {
		b_asc = TRUE;
	} else if (0 == strcasecmp(argv[4], "DSC")) {
		b_asc = FALSE;
	} else {
		return 1;
	}
	if (7 == argc) {
		offset = atoi(argv[5]);
		length = atoi(argv[6]);
		if (length < 0) {
			length = 0;
		}
	} else {
		offset = 0;
		length = 0;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	if (FALSE == mail_engine_sort_folder(pidb, argv[2], sort_field)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 3;
	}
	total_mail = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	if (TRUE == b_asc) {
		if (offset < 0) {
			idx1 = total_mail + 1 + offset;
			if (idx1 < 1) {
				idx1 = 1;
			}
		} else {
			if (offset >= total_mail) {
				mail_engine_put_idb(pidb);
				write(sockd, "TRUE 0\r\n", 8);
				return 0;
			}
			idx1 = offset + 1;
		}
		if (0 == length || total_mail - idx1 + 1 < length) {
			length = total_mail - idx1 + 1;
		}
		idx2 = idx1 + length - 1;
		sql_len = sprintf(sql_string, "SELECT mid_string FROM messages "
			"WHERE folder_id=%llu AND idx>=%d AND idx<=%d ORDER BY idx",
			folder_id, idx1, idx2);
	} else {
		if (offset < 0) {
			idx2 = (-1)*offset;
			if (idx2 > total_mail) {
				idx2 = total_mail;
			}
		} else {
			if (offset >= total_mail) {
				mail_engine_put_idb(pidb);
				write(sockd, "TRUE 0\r\n", 8);
				return 0;
			}
			idx2 = total_mail - offset;
		}
		if (0 == length || idx2 < length) {
			length = idx2;
		}
		idx1 = idx2 - length + 1;
		sql_len = sprintf(sql_string, "SELECT mid_string FROM messages "
			"WHERE folder_id=%llu AND idx>=%d AND idx<=%d ORDER BY idx "
			"DESC", folder_id, idx1, idx2);
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	temp_len = sprintf(temp_buff, "TRUE %d\r\n", length);
	write(sockd, temp_buff, temp_len);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (0 == mail_engine_get_digest(pidb->psqlite,
			sqlite3_column_text(pstmt, 0), temp_buff)) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 6;
		}
		temp_len = strlen(temp_buff);
		temp_buff[temp_len] = '\r';
		temp_len ++;
		temp_buff[temp_len] = '\n';
		temp_len ++;
		write(sockd, temp_buff, temp_len);
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	return 0;
}

static int mail_engine_muidl(int argc, char **argv, int sockd)
{
	int result;
	int offset;
	int sql_len;
	int temp_len;
	IDB_ITEM *pidb;
	IDL_NODE *pinode;
	uint64_t folder_id;
	char temp_line[512];
	sqlite3_stmt *pstmt;
	DOUBLE_LIST tmp_list;
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	char list_buff[256*1024];
	
	if (3 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT mid_string, size FROM"
		" messages WHERE folder_id=%llu ORDER BY uid", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	double_list_init(&tmp_list);
	while (SQLITE_ROW == (result = sqlite3_step(pstmt))) {
		pinode = common_util_alloc(sizeof(IDL_NODE));
		if (NULL == pinode) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		pinode->node.pdata = pinode;
		pinode->mid_string = common_util_dup(
				sqlite3_column_text(pstmt, 0));
		if (NULL == pinode->mid_string) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		pinode->size = sqlite3_column_int64(pstmt, 1);
		double_list_append_as_tail(&tmp_list, &pinode->node);
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	if (SQLITE_DONE != result) {
		return 4;
	}
	offset = sprintf(list_buff, "TRUE %d\r\n",
		double_list_get_nodes_num(&tmp_list));
	while (pnode=double_list_get_from_head(&tmp_list)) {
		pinode = (IDL_NODE*)pnode->pdata;
		temp_len = snprintf(temp_line, 512, "%s %u\r\n",
						pinode->mid_string, pinode->size);
		if (256*1024 - offset < temp_len) {
			write(sockd, list_buff, offset);
			offset = 0;
		}
		memcpy(list_buff + offset, temp_line, temp_len);
		offset += temp_len;
	}
	write(sockd, list_buff, offset);
	return 0;
}

static int mail_engine_mmtch(int argc, char **argv, int sockd)
{
	int temp_len;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	uint64_t folder_id1;
	char temp_buff[MAX_DIGLEN + 7];

	if (4 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	folder_id1 = mail_engine_get_digest(
		pidb->psqlite, argv[3], temp_buff + 5);
	if (0 == folder_id1) {
		mail_engine_put_idb(pidb);
		return 6;
	}
	if (folder_id != folder_id1) {
		mail_engine_put_idb(pidb);
		return 5;
	}
	mail_engine_put_idb(pidb);
	memcpy(temp_buff, "TRUE ", 5);
	temp_len = strlen(temp_buff);
	memcpy(temp_buff + temp_len, "\r\n", 2);
	write(sockd, temp_buff, temp_len + 2);
	return 0;
}

static int mail_engine_minst(int argc, char **argv, int sockd)
{
	int fd;
	MAIL imail;
	int sql_len;
	XID tmp_xid;
	char *pbuff;
	int tmp_len;
	int user_id;
	BINARY *pbin;
	char lang[32];
	BOOL b_result;
	uint32_t cpid;
	IDB_ITEM *pidb;
	uint8_t b_read;
	size_t mess_len;
	uint64_t nt_time;
	char charset[32];
	uint8_t b_unsent;
	char timezone[64];
	char username[256];
	uint64_t folder_id;
	uint32_t tmp_flags;
	sqlite3_stmt *pstmt;
	char temp_path[256];
	uint64_t change_num;
	uint64_t message_id;
	char sql_string[1024];
	struct stat node_stat;
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pmsgctnt;
	char temp_buff[MAX_DIGLEN];
	
	if (6 != argc || strlen(argv[1]) >= 256
		|| strlen(argv[2]) >= 1024) {
		return 1;
	}
	if (NULL != strchr(argv[4], 'U')) {
		b_unsent = 1;
	} else {
		b_unsent = 0;
	}
	if (NULL != strchr(argv[4], 'S')) {
		b_read = 1;
	} else {
		b_read = 0;
	}
	if (0 == strcmp(argv[2], "draft")) {
		b_unsent = 1;
	}
	sprintf(temp_path, "%s/eml/%s", argv[1], argv[3]);
	if (0 != stat(temp_path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return 1;
	}
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return 4;
	}
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return 4;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		return 4;
	}
	close(fd);
	mail_init(&imail, g_mime_pool);
	if (FALSE == mail_retrieve(&imail, pbuff, node_stat.st_size)) {
		mail_free(&imail);
		free(pbuff);
		return 4;
	}
	tmp_len = sprintf(temp_buff, "{\"file\":\"\",");
	if (mail_get_digest(&imail, &mess_len, temp_buff + tmp_len,
		MAX_DIGLEN - tmp_len - 1) <= 0) {
		mail_free(&imail);
		free(pbuff);
		return 4;
	}
	tmp_len = strlen(temp_buff);
	temp_buff[tmp_len] = '}';
	tmp_len ++;
	temp_buff[tmp_len] = '\0';
	sprintf(temp_path, "%s/ext/%s", argv[1], argv[3]);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		mail_free(&imail);
		free(pbuff);
		return 4;
	}
	write(fd, temp_buff, tmp_len);
	close(fd);
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		mail_free(&imail);
		free(pbuff);
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		mail_free(&imail);
		free(pbuff);
		return 3;
	}
	if (FALSE == system_services_get_id_from_username(
		pidb->username, &user_id)) {
		mail_engine_put_idb(pidb);
		mail_free(&imail);
		free(pbuff);
		return 4;
	}
	if (FALSE == system_services_get_user_lang(
		pidb->username, lang) || '\0' == lang[0] ||
		FALSE == system_services_lang_to_charset(
		lang, charset) || '\0' == charset[0]) {
		strcpy(charset, g_default_charset);
	}
	if (FALSE == system_services_get_timezone(
		pidb->username, timezone) || '\0' == timezone[0]) {
		strcpy(timezone, g_default_timezone);
	}
	pmsgctnt = oxcmail_import(charset, timezone, &imail,
			common_util_alloc, common_util_get_propids);
	mail_free(&imail);
	free(pbuff);
	if (NULL == pmsgctnt) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	nt_time = rop_util_unix_to_nttime(atol(argv[5]));
	propval.proptag = PROP_TAG_MESSAGEDELIVERYTIME;
	propval.pvalue = &nt_time;
	tpropval_array_set_propval(&pmsgctnt->proplist, &propval);
	if (0 != b_read) {
		propval.proptag = PROP_TAG_READ;
		propval.pvalue = &b_read;
		tpropval_array_set_propval(&pmsgctnt->proplist, &propval);
	}
	if (0 != b_unsent) {
		propval.proptag = PROP_TAG_MESSAGEFLAGS;
		propval.pvalue = &tmp_flags;
		tmp_flags = MESSAGE_FLAG_UNSENT;
		tpropval_array_set_propval(&pmsgctnt->proplist, &propval);
	}
	if (FALSE == exmdb_client_allocate_message_id(argv[1],
		rop_util_make_eid_ex(1, folder_id), &message_id) ||
		FALSE == exmdb_client_allocate_cn(argv[1], &change_num)) {
		mail_engine_put_idb(pidb);
		message_content_free(pmsgctnt);
		return 4;
	}
	sql_len = sprintf(sql_string, "INSERT INTO mapping"
		" (message_id, mid_string, flag_string) VALUES"
		" (%llu, ?, ?)", rop_util_get_gc_value(message_id));
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		message_content_free(pmsgctnt);
		return 4;	
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 2, argv[4], -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		message_content_free(pmsgctnt);
		return 4;
	}
	sqlite3_finalize(pstmt);
	strcpy(username, pidb->username);
	mail_engine_put_idb(pidb);
	propval.proptag = PROP_TAG_MID;
	propval.pvalue = &message_id;
	if (FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	propval.proptag = PROP_TAG_CHANGENUMBER;
	propval.pvalue = &change_num;
	if (FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	tmp_xid.guid = rop_util_make_user_guid(user_id);
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == pbin) {
		message_content_free(pmsgctnt);
		return 4;
	}   
	propval.proptag = PROP_TAG_CHANGEKEY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	propval.proptag = PROP_TAG_PREDECESSORCHANGELIST;
	propval.pvalue = common_util_pcl_append(NULL, pbin);
	if (NULL == propval.pvalue ||
		FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	cpid = system_services_charset_to_cpid(charset);
	if (0 == cpid) {
		cpid = 1252;
	}
	if (FALSE == exmdb_client_write_message(argv[1], username,
		cpid, rop_util_make_eid_ex(1, folder_id), pmsgctnt, &b_result)
		|| FALSE == b_result) {
		message_content_free(pmsgctnt);
		return 4;
	}
	message_content_free(pmsgctnt);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mdele(int argc, char **argv, int sockd)
{
	int i;
	int user_id;
	int sql_len;
	BOOL b_partial;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	char temp_path[256];
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	EID_ARRAY message_ids;

	if (argc < 4 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	message_ids.count = 0;
	message_ids.pids = common_util_alloc(sizeof(uint64_t)*(argc - 3));
	if (NULL == message_ids.pids) {
		return 4;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	if (FALSE == system_services_get_id_from_username(
		pidb->username, &user_id)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT message_id,"
		" folder_id FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	for (i=3; i<argc; i++) {
		sqlite3_reset(pstmt);
		sqlite3_bind_text(pstmt, 1, argv[i], -1, SQLITE_STATIC);
		if (SQLITE_ROW != sqlite3_step(pstmt) ||
			folder_id != sqlite3_column_int64(pstmt, 1)) {
			continue;
		}
		message_ids.pids[message_ids.count] = rop_util_make_eid_ex(
								1, sqlite3_column_int64(pstmt, 0));
		message_ids.count ++;
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	if (FALSE == exmdb_client_delete_messages(argv[1],
		user_id, 0, NULL, rop_util_make_eid_ex(1, folder_id),
		&message_ids, TRUE, &b_partial)) {
		return 4;	
	}
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mupdt(int argc, char **argv, int sockd)
{
	int sql_len;
	int tmp_val;
	IDB_ITEM *pidb;
	uint8_t tmp_byte;
	const char *pext;
	uint64_t read_cn;
	uint64_t folder_id;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	uint32_t tmp_proptag;
	char temp_buff[1024];
	char sql_string[1024];
	uint32_t message_flags;
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;

	if (6 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	if (0 == strcasecmp(argv[4], "flag") ||
		0 == strcasecmp(argv[4], "read") ||
		0 == strcasecmp(argv[4], "unsent") ||
		0 == strcasecmp(argv[4], "recent") ||
		0 == strcasecmp(argv[4], "replied") ||
		0 == strcasecmp(argv[4], "deleted") ||
		0 == strcasecmp(argv[4], "forwarded")) {
		if (0 != strcmp(argv[5], "0") && 0 != strcmp(argv[5], "1")) {
			return 1;
		}
	} else {
		if (strlen(argv[5]) >= 128) {
			return 1;
		}
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT message_id,"
		" folder_id FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 5;
	}
	message_id = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	if (0 == strcasecmp(argv[4], "recent")) {
		tmp_val = atoi(argv[5]);
		sprintf(sql_string, "UPDATE messages SET recent=%d"
			" WHERE message_id=%llu", tmp_val, message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	} else if (0 == strcasecmp(argv[4], "unsent")) {
		mail_engine_put_idb(pidb);
		tmp_val = atoi(argv[5]);
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_MESSAGEFLAGS;
		if (FALSE == exmdb_client_get_message_properties(argv[1],
			NULL, 0, rop_util_make_eid_ex(1, message_id), &proptags,
			&propvals) || 0 == propvals.count) {
			return 4;
		}
		message_flags = *(uint32_t*)propvals.ppropval[0].pvalue;
		if (0 == tmp_val) {
			message_flags &= ~MESSAGE_FLAG_UNSENT;
		} else {
			message_flags |= MESSAGE_FLAG_UNSENT;
		}
		propvals.ppropval[0].pvalue = &message_flags;
		if (FALSE == exmdb_client_set_message_properties(argv[1],
			NULL, 0, rop_util_make_eid_ex(1, message_id), &propvals,
			&problems)) {
			return 4;
		}
		write(sockd, "TRUE\r\n", 6);
		return 0;
	} else if (0 == strcasecmp(argv[4], "read")) {
		mail_engine_put_idb(pidb);
		tmp_byte = atoi(argv[5]);
		if (FALSE == exmdb_client_set_message_read_state(argv[1],
			NULL, rop_util_make_eid_ex(1, message_id), tmp_byte,
			&read_cn)) {
			return 4;
		}
		write(sockd, "TRUE\r\n", 6);
		return 0;
	} else if (0 == strcasecmp(argv[4], "replied")) {
		tmp_val = atoi(argv[5]);
		sprintf(sql_string, "UPDATE messages SET replied=%d"
			" WHERE message_id=%llu", tmp_val, message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	} else if (0 == strcasecmp(argv[4], "forwarded")) {
		tmp_val = atoi(argv[5]);
		sprintf(sql_string, "UPDATE messages SET forwarded=%d"
				" WHERE message_id=%llu", tmp_val, message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	} else if (0 == strcasecmp(argv[4], "flag")) {
		tmp_val = atoi(argv[5]);
		sprintf(sql_string, "UPDATE messages SET flagged=%d "
				"WHERE message_id=%llu", tmp_val, message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	} else if (0 == strcasecmp(argv[4], "deleted")) {
		tmp_val = atoi(argv[5]);
		sprintf(sql_string, "UPDATE messages SET deleted=%d "
				"WHERE message_id=%llu", tmp_val, message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	} else {
		sql_len = sprintf(sql_string, "SELECT ext "
				"FROM messages WHERE mid_string=?");
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			mail_engine_put_idb(pidb);
			return 4;
		}
		sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		pext = sqlite3_column_text(pstmt, 0);
		if (NULL == pext) {
			sprintf(temp_buff, "{\"%s\":%s}", argv[4], argv[5]);
		} else {
			strncpy(temp_buff, pext, 1024);
			add_digest(temp_buff, 1024, argv[4], argv[5]);
		}
		sqlite3_finalize(pstmt);
		sql_len = sprintf(sql_string, "UPDATE messages SET"
				" ext=? WHERE message_id=%llu", message_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			mail_engine_put_idb(pidb);
			return 4;
		}
		sqlite3_bind_text(pstmt, 1, temp_buff, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		sqlite3_finalize(pstmt);
	}
	mail_engine_put_idb(pidb);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mmove(int argc, char **argv, int sockd)
{
	int user_id;
	int sql_len;
	IDB_ITEM *pidb;
	BOOL b_partial;
	uint64_t folder_id;
	uint64_t folder_id1;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	EID_ARRAY message_ids;
	char temp_buff[MAX_DIGLEN];

	if (5 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024
		|| strlen(argv[4]) >= 1024 || 0 == strcmp(argv[2], argv[4])) {
		return 1;		
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	if (FALSE == system_services_get_id_from_username(
		pidb->username, &user_id)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	folder_id1 = mail_engine_get_folder_id(pidb, argv[4]);
	if (0 == folder_id1) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT message_id,"
		" folder_id FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 5;
	}
	message_id = rop_util_make_eid_ex(1,
		sqlite3_column_int64(pstmt, 0));
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	message_ids.count = 1;
	message_ids.pids = &message_id;
	if (FALSE == exmdb_client_movecopy_messages(argv[1], user_id,
		0, FALSE, NULL, rop_util_make_eid_ex(1, folder_id),
		rop_util_make_eid_ex(1, folder_id1), FALSE, &message_ids,
		&b_partial) || TRUE == b_partial) {
		return 4;	
	}
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mcopy(int argc, char **argv, int sockd)
{
	int fd;
	MAIL imail;
	int tmp_len;
	int sql_len;
	XID tmp_xid;
	char *pbuff;
	int user_id;
	BINARY *pbin;
	char lang[32];
	BOOL b_result;
	uint32_t cpid;
	int flags_len;
	IDB_ITEM *pidb;
	uint8_t b_read;
	size_t mess_len;
	uint64_t nt_time;
	char charset[32];
	uint8_t b_unsent;
	char timezone[64];
	char username[256];
	uint32_t tmp_flags;
	uint64_t folder_id;
	uint64_t folder_id1;
	sqlite3_stmt *pstmt;
	char flags_buff[16];
	uint64_t change_num;
	uint64_t message_id;
	char temp_path[256];
	char temp_path1[256];
	char mid_string[128];
	char temp_buff[1024];
	char sql_string[1024];
	struct stat node_stat;
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pmsgctnt;

	if (5 != argc || strlen(argv[1]) >= 256 ||
		strlen(argv[2]) >= 1024 || strlen(argv[4]) >= 1024) {
		return 1;		
	}
	sprintf(temp_path, "%s/eml/%s", argv[1], argv[3]);
	if (0 != stat(temp_path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return 1;
	}
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return 4;
	}
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return 4;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		return 4;
	}
	close(fd);
	mail_init(&imail, g_mime_pool);
	if (FALSE == mail_retrieve(&imail, pbuff, node_stat.st_size)) {
		mail_free(&imail);
		free(pbuff);
		return 4;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		mail_free(&imail);
		free(pbuff);
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		mail_free(&imail);
		free(pbuff);
		return 3;
	}
	folder_id1 = mail_engine_get_folder_id(pidb, argv[4]);
	if (0 == folder_id1) {
		mail_engine_put_idb(pidb);
		mail_free(&imail);
		free(pbuff);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT message_id, mod_time, "
		"uid, recent, read, unsent, flagged, replied, forwarded,"
		"deleted, received, ext, folder_id, size FROM messages "
		"WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		mail_free(&imail);
		free(pbuff);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 12)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		mail_free(&imail);
		free(pbuff);
		return 5;
	}
	b_read = 0;
	b_unsent = 0;
	flags_buff[0] = '(';
	flags_len = 1;
	if (0 != sqlite3_column_int64(pstmt, 7)) {
		flags_buff[flags_len] = 'A';
		flags_len ++;
	}
	if (0 != sqlite3_column_int64(pstmt, 6)) {
		flags_buff[flags_len] = 'F';
		flags_len ++;
	}
	if (0 != sqlite3_column_int64(pstmt, 8)) {
		flags_buff[flags_len] = 'W';
		flags_len ++;
	}
	flags_buff[flags_len] = ')';
	flags_len ++;
	flags_buff[flags_len] = '\0';
	if (0 != sqlite3_column_int64(pstmt, 5)) {
		b_unsent = 1;
	}
	if (0 != sqlite3_column_int64(pstmt, 4)) {
		b_read = 1;
	}
	nt_time = sqlite3_column_int64(pstmt, 10);
	sqlite3_finalize(pstmt);
	if (FALSE == system_services_get_id_from_username(
		pidb->username, &user_id)) {
		mail_engine_put_idb(pidb);
		mail_free(&imail);
		free(pbuff);
		return 4;
	}
	if (FALSE == system_services_get_user_lang(
		pidb->username, lang) || '\0' == lang[0] ||
		FALSE == system_services_lang_to_charset(
		lang, charset) || '\0' == charset[0]) {
		strcpy(charset, g_default_charset);
	}
	if (FALSE == system_services_get_timezone(
		pidb->username, timezone) || '\0' == timezone[0]) {
		strcpy(timezone, g_default_timezone);
	}
	pmsgctnt = oxcmail_import(charset, timezone, &imail,
			common_util_alloc, common_util_get_propids);
	mail_free(&imail);
	free(pbuff);
	if (NULL == pmsgctnt) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	propval.proptag = PROP_TAG_MESSAGEDELIVERYTIME;
	propval.pvalue = &nt_time;
	tpropval_array_set_propval(&pmsgctnt->proplist, &propval);
	if (0 != b_read) {
		propval.proptag = PROP_TAG_READ;
		propval.pvalue = &b_read;
		tpropval_array_set_propval(&pmsgctnt->proplist, &propval);
	}
	if (0 != b_unsent) {
		propval.proptag = PROP_TAG_MESSAGEFLAGS;
		propval.pvalue = &tmp_flags;
		tmp_flags = MESSAGE_FLAG_UNSENT;
		tpropval_array_set_propval(&pmsgctnt->proplist, &propval);
	}
	if (FALSE == exmdb_client_allocate_message_id(argv[1],
		rop_util_make_eid_ex(1, folder_id), &message_id) ||
		FALSE == exmdb_client_allocate_cn(argv[1], &change_num)) {
		mail_engine_put_idb(pidb);
		message_content_free(pmsgctnt);
		return 4;
	}
	sprintf(mid_string, "%ld.%d.midb", time(NULL),
					mail_engine_get_squence_id());
	sprintf(temp_path, "%s/eml/%s", argv[1], argv[3]);
	sprintf(temp_path1, "%s/eml/%s", argv[1], mid_string);
	link(temp_path, temp_path1);
	sprintf(temp_path, "%s/ext/%s", argv[1], argv[3]);
	sprintf(temp_path1, "%s/ext/%s", argv[1], mid_string);
	link(temp_path, temp_path1);
	sql_len = sprintf(sql_string, "INSERT INTO mapping"
		" (message_id, mid_string, flag_string) VALUES"
		" (%llu, ?, ?)", rop_util_get_gc_value(message_id));
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		message_content_free(pmsgctnt);
		return 4;	
	}
	sqlite3_bind_text(pstmt, 1, mid_string, -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 2, flags_buff, -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		message_content_free(pmsgctnt);
		return 4;
	}
	sqlite3_finalize(pstmt);
	strcpy(username, pidb->username);
	mail_engine_put_idb(pidb);
	propval.proptag = PROP_TAG_MID;
	propval.pvalue = &message_id;
	if (FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	propval.proptag = PROP_TAG_CHANGENUMBER;
	propval.pvalue = &change_num;
	if (FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	tmp_xid.guid = rop_util_make_user_guid(user_id);
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == pbin) {
		message_content_free(pmsgctnt);
		return 4;
	}   
	propval.proptag = PROP_TAG_CHANGEKEY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	propval.proptag = PROP_TAG_PREDECESSORCHANGELIST;
	propval.pvalue = common_util_pcl_append(NULL, pbin);
	if (NULL == propval.pvalue ||
		FALSE == tpropval_array_set_propval(
		&pmsgctnt->proplist, &propval)) {
		message_content_free(pmsgctnt);
		return 4;
	}
	cpid = system_services_charset_to_cpid(charset);
	if (0 == cpid) {
		cpid = 1252;
	}
	if (FALSE == exmdb_client_write_message(argv[1], username,
		cpid, rop_util_make_eid_ex(1, folder_id1), pmsgctnt, &b_result)
		|| FALSE == b_result) {
		message_content_free(pmsgctnt);
		return 4;
	}
	message_content_free(pmsgctnt);
	tmp_len = sprintf(temp_buff, "TRUE %s\r\n", mid_string);
	write(sockd, temp_buff, tmp_len);
	return 0;
}

static int mail_engine_mrenf(int argc, char **argv, int sockd)
{
	int sql_len;
	int user_id;
	XID tmp_xid;
	BOOL b_exist;
	BINARY *pbin;
	char *ptoken;
	BINARY *pbin1;
	char *ptoken1;
	BOOL b_partial;
	IDB_ITEM *pidb;
	uint64_t nt_time;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t folder_id1;
	uint64_t folder_id2;
	uint64_t change_num;
	char temp_name[256];
	sqlite3_stmt *pstmt;
	uint32_t tmp_proptag;
	char sql_string[256];
	PROPTAG_ARRAY proptags;
	char decoded_name[512];
	PROBLEM_ARRAY problems;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL propval_buff[5];

	if (4 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024
		|| strlen(argv[3]) >= 1024 || 0 == strcmp(argv[2], argv[3])) {
		return 1;
	}
	if (0 == strcmp(argv[2], "inbox") ||
		0 == strcmp(argv[2], "draft") ||
		0 == strcmp(argv[2], "sent") ||
		0 == strcmp(argv[2], "trash") ||
		0 == strcmp(argv[2], "junk")) {
		return 1;
	}
	if (FALSE == decode_hex_binary(argv[3], decoded_name, 512)) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	if (FALSE == system_services_get_id_from_username(
		pidb->username, &user_id)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id,"
			" parent_fid FROM folders WHERE name=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;	
	}
	sqlite3_bind_text(pstmt, 1, argv[2], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 4;
	}
	folder_id = sqlite3_column_int64(pstmt, 0);
	parent_id = sqlite3_column_int64(pstmt, 1);
	sqlite3_finalize(pstmt);
	if (0 != mail_engine_get_folder_id(pidb, argv[3])) {
		mail_engine_put_idb(pidb);
		return 7;
	}
	ptoken = decoded_name;
	folder_id1 = PRIVATE_FID_IPMSUBTREE;
	while (ptoken1 = strchr(ptoken, '/')) {
		if (ptoken1 - ptoken >= sizeof(temp_name)) {
			mail_engine_put_idb(pidb);
			return 1;
		}
		memcpy(temp_name, ptoken, ptoken1 - ptoken);
		temp_name[ptoken1 - ptoken] = '\0';
		if (0 == strcmp(temp_name, "inbox")) {
			folder_id1 = PRIVATE_FID_INBOX;
		} else if (0 == strcmp(temp_name, "draft")) {
			folder_id1 = PRIVATE_FID_DRAFT;
		} else if (0 == strcmp(temp_name, "sent")) {
			folder_id1 = PRIVATE_FID_SENT_ITEMS;
		} else if (0 == strcmp(temp_name, "trash")) {
			folder_id1 = PRIVATE_FID_DELETED_ITEMS;
		} else if (0 == strcmp(temp_name, "junk")) {
			folder_id1 = PRIVATE_FID_JUNK;
		} else {
			encode_hex_binary(decoded_name, ptoken1 - decoded_name,
				encoded_name, 1024);
			folder_id2 = mail_engine_get_folder_id(pidb, encoded_name);
			if (0 == folder_id2) {
				if (FALSE == common_util_create_folder(argv[1],
					user_id, rop_util_make_eid_ex(1, folder_id1),
					temp_name, &folder_id2)) {
					mail_engine_put_idb(pidb);
					return 4;
				}
				folder_id1 = rop_util_get_gc_value(folder_id2);
			} else {
				folder_id1 = folder_id2;
			}
		}
		ptoken = ptoken1 + 1;
	}
	mail_engine_put_idb(pidb);
	if (parent_id != folder_id1) {
		if (FALSE == exmdb_client_movecopy_folder(
			argv[1], user_id, 0, FALSE, NULL,
			rop_util_make_eid_ex(1, parent_id),
			rop_util_make_eid_ex(1, folder_id),
			rop_util_make_eid_ex(1, folder_id1),
			ptoken, FALSE, &b_exist, &b_partial)) {
			return 4;	
		}
		if (TRUE == b_exist) {
			return 7;
		}
		if (TRUE == b_partial) {
			return 4;
		}
	}
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PROP_TAG_PREDECESSORCHANGELIST;
	if (FALSE == exmdb_client_allocate_cn(argv[1], &change_num)
		|| FALSE == exmdb_client_get_folder_properties(argv[1],
		0, rop_util_make_eid_ex(1, folder_id), &proptags, &propvals)
		|| NULL == (pbin1 = common_util_get_propvals(&propvals,
		PROP_TAG_PREDECESSORCHANGELIST))) {
		return 4;	
	}
	if (parent_id == folder_id1) {
		propvals.count = 5;
	} else {
		propvals.count = 4;
	}
	propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PROP_TAG_CHANGENUMBER;
	propval_buff[0].pvalue = &change_num;
	tmp_xid.guid = rop_util_make_user_guid(user_id);
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == pbin) {
		return 4;
	}
	propval_buff[1].proptag = PROP_TAG_CHANGEKEY;
	propval_buff[1].pvalue = pbin;
	propval_buff[2].proptag = PROP_TAG_PREDECESSORCHANGELIST;
	propval_buff[2].pvalue = common_util_pcl_append(pbin1, pbin);
	if (NULL == propval_buff[2].pvalue) {
		return 4;
	}
	nt_time = rop_util_current_nttime();
	propval_buff[3].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval_buff[3].pvalue = &nt_time;
	if (parent_id == folder_id1) {
		propval_buff[4].proptag = PROP_TAG_DISPLAYNAME;
		propval_buff[4].pvalue = ptoken;
	}
	if (FALSE == exmdb_client_set_folder_properties(
		argv[1], 0, rop_util_make_eid_ex(1, folder_id),
		&propvals, &problems)) {
		return 4;	
	}
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mmakf(int argc, char **argv, int sockd)
{
	int user_id;
	char *ptoken;
	char *ptoken1;
	IDB_ITEM *pidb;
	uint64_t folder_id1;
	uint64_t folder_id2;
	char temp_name[256];
	char decoded_name[512];
	char encoded_name[1024];

	if (3 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;		
	}
	if (FALSE == decode_hex_binary(argv[2], decoded_name, 512)) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	if (FALSE == system_services_get_id_from_username(
		pidb->username, &user_id)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (0 != mail_engine_get_folder_id(pidb, argv[2])) {
		mail_engine_put_idb(pidb);
		return 7;
	}
	ptoken = decoded_name;
	folder_id1 = PRIVATE_FID_IPMSUBTREE;
	while (ptoken1 = strchr(ptoken, '/')) {
		if (ptoken1 - ptoken >= sizeof(temp_name)) {
			mail_engine_put_idb(pidb);
			return 1;
		}
		memcpy(temp_name, ptoken, ptoken1 - ptoken);
		temp_name[ptoken1 - ptoken] = '\0';
		if (0 == strcmp(temp_name, "inbox")) {
			folder_id1 = PRIVATE_FID_INBOX;
		} else if (0 == strcmp(temp_name, "draft")) {
			folder_id1 = PRIVATE_FID_DRAFT;
		} else if (0 == strcmp(temp_name, "sent")) {
			folder_id1 = PRIVATE_FID_SENT_ITEMS;
		} else if (0 == strcmp(temp_name, "trash")) {
			folder_id1 = PRIVATE_FID_DELETED_ITEMS;
		} else if (0 == strcmp(temp_name, "junk")) {
			folder_id1 = PRIVATE_FID_JUNK;
		} else {
			encode_hex_binary(decoded_name, ptoken1 - decoded_name,
				encoded_name, 1024);
			folder_id2 = mail_engine_get_folder_id(pidb, encoded_name);
			if (0 == folder_id2) {
				if (FALSE == common_util_create_folder(argv[1],
					user_id, rop_util_make_eid_ex(1, folder_id1),
					temp_name, &folder_id2)) {
					mail_engine_put_idb(pidb);
					return 4;
				}
				folder_id1 = rop_util_get_gc_value(folder_id2);
			} else {
				folder_id1 = folder_id2;
			}
		}
		ptoken = ptoken1 + 1;
	}
	mail_engine_put_idb(pidb);
	if (FALSE == common_util_create_folder(argv[1],
		user_id, rop_util_make_eid_ex(1, folder_id1),
		ptoken, &folder_id2) || 0 == folder_id2) {
		return 4;	
	}
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_mremf(int argc, char **argv, int sockd)
{
	BOOL b_result;
	BOOL b_partial;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	
	if (3 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	if (0 == strcmp(argv[2], "inbox") ||
		0 == strcmp(argv[2], "draft") ||
		0 == strcmp(argv[2], "sent") ||
		0 == strcmp(argv[2], "trash") ||
		0 == strcmp(argv[2], "junk")) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		write(sockd, "TRUE\r\n", 6);
		return 0;
	}
	mail_engine_put_idb(pidb);
	folder_id = rop_util_make_eid_ex(1, folder_id);
	if (FALSE == exmdb_client_empty_folder(argv[1], 0, NULL, folder_id,
		TRUE, TRUE, TRUE, FALSE, &b_partial) || TRUE == b_partial ||
		FALSE == exmdb_client_empty_folder(argv[1], 0, NULL, folder_id,
		TRUE, FALSE, FALSE, TRUE, &b_partial) || TRUE == b_partial ||
		FALSE == exmdb_client_delete_folder(argv[1], 0, folder_id, TRUE,
		&b_result) || FALSE == b_result) {
		return 4;
	}
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_pofst(int argc, char **argv, int sockd)
{
	int idx;
	BOOL b_asc;
	int sql_len;
	int temp_len;
	int sort_field;
	IDB_ITEM *pidb;
	int total_mail;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char temp_buff[1024];
	char sql_string[1024];
	
	if (6 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;	
	}
	if (0 == strcasecmp(argv[4], "RCV")) {
		sort_field = FIELD_RECEIVED;
	} else if (0 == strcasecmp(argv[4], "SUB")) {
		sort_field = FIELD_SUBJECT;	
	} else if (0 == strcasecmp(argv[4], "FRM")) {
		sort_field = FIELD_FROM;
	} else if (0 == strcasecmp(argv[4], "RCP")) {
		sort_field = FIELD_RCPT;
	} else if (0 == strcasecmp(argv[4], "SIZ")) {
		sort_field = FIELD_SIZE;
	} else if (0 == strcasecmp(argv[4], "RED")) {
		sort_field = FIELD_READ;
	} else if (0 == strcasecmp(argv[4], "FLG")) {
		sort_field = FIELD_FLAG;
	} else if (0 == strcasecmp(argv[4], "UID")) {
		sort_field = FIELD_UID;
	} else if (0 == strcasecmp(argv[4], "NON")) {
		sort_field = FIELD_NONE;
	} else {
		return 1;
	}
	if (0 == strcasecmp(argv[5], "ASC")) {
		b_asc = TRUE;
	} else if (0 == strcasecmp(argv[5], "DSC")) {
		b_asc = FALSE;
	} else {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	if (FALSE == mail_engine_sort_folder(pidb, argv[2], sort_field)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id,"
			" idx FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 0)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 5;
	}
	idx = sqlite3_column_int64(pstmt, 1);
	sqlite3_finalize(pstmt);
	if (FALSE == b_asc) {
		sql_len = sprintf(sql_string, "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			mail_engine_put_idb(pidb);
			return 4;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 3;
		}
		total_mail = sqlite3_column_int64(pstmt, 0);
		sqlite3_finalize(pstmt);
	}
	mail_engine_put_idb(pidb);
	if (TRUE == b_asc) {
		temp_len = sprintf(temp_buff, "TRUE %d\r\n", idx - 1);
	} else {
		temp_len = sprintf(temp_buff, "TRUE %d\r\n", total_mail - idx);
	}
	write(sockd, temp_buff, temp_len);
	return 0;
}

static int mail_engine_punid(int argc, char **argv, int sockd)
{
	int sql_len;
	int temp_len;
	uint32_t uid;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char temp_buff[1024];
	char sql_string[1024];

	if (4 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id,"
			" uid FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 0)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 5;
	}
	uid = sqlite3_column_int64(pstmt, 1);
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	temp_len = sprintf(temp_buff, "TRUE %u\r\n", uid);
	write(sockd, temp_buff, temp_len);
	return 0;
}

static int mail_engine_pfddt(int argc, char **argv, int sockd)
{
	BOOL b_asc;
	int offset;
	int sql_len;
	int temp_len;
	IDB_ITEM *pidb;
	uint32_t total;
	uint32_t unreads;
	uint32_t recents;
	uint32_t uidnext;
	uint64_t uidvalid;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char temp_buff[1024];
	char sql_string[1024];
	
	if (5 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;	
	}
	if (0 == strcasecmp(argv[3], "RCV") ||
		0 == strcasecmp(argv[3], "SUB") ||
		0 == strcasecmp(argv[3], "FRM") ||
		0 == strcasecmp(argv[3], "RCP") ||
		0 == strcasecmp(argv[3], "SIZ") ||
		0 == strcasecmp(argv[3], "RED") ||
		0 == strcasecmp(argv[3], "FLG") ||
		0 == strcasecmp(argv[3], "UID") ||
		0 == strcasecmp(argv[3], "NON")) {
		/* do nothing */
	} else {
		return 1;
	}
	if (0 == strcasecmp(argv[4], "ASC")) {
		b_asc = TRUE;
	} else if (0 == strcasecmp(argv[4], "DSC")) {
		b_asc = FALSE;
	} else {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id,"
				" uidnext FROM folders WHERE name=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;	
	}
	sqlite3_bind_text(pstmt, 1, argv[2], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 4;
	}
	folder_id = sqlite3_column_int64(pstmt, 0);
	uidnext = sqlite3_column_int64(pstmt, 1);
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 3;
	}
	total = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT count(message_id) FROM "
			"messages WHERE folder_id=%llu AND read=0", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		unreads = sqlite3_column_int64(pstmt, 0);
	} else {
		unreads = 0;
	}
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT count(message_id) FROM"
		" messages WHERE folder_id=%llu AND recent=0", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		recents = sqlite3_column_int64(pstmt, 0);
	} else {
		recents = 0;
	}
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT min(idx) FROM messages "
					"WHERE folder_id=%llu AND read=0", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		offset = sqlite3_column_int64(pstmt, 0);
		if (FALSE == b_asc) {
			offset = total - offset;
		} else {
			offset --;
		}
	} else {
		offset = -1;
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	uidvalid = folder_id;
	temp_len = sprintf(temp_buff, "TRUE %u %u %u %llu %u %d\r\n",
		total, recents, unreads, uidvalid, uidnext + 1, offset);
	write(sockd, temp_buff, temp_len);
	return 0;
}

static int mail_engine_psubf(int argc, char **argv, int sockd)
{
	int sql_len;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	char sql_string[1024];

	if (3 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sprintf(sql_string, "UPDATE folders SET unsub=0"
				" WHERE folder_id=%llu", folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	mail_engine_put_idb(pidb);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_punsf(int argc, char **argv, int sockd)
{
	int sql_len;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	char sql_string[1024];

	if (3 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sprintf(sql_string, "UPDATE folders SET unsub=1"
				" WHERE folder_id=%llu", folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	mail_engine_put_idb(pidb);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_psubl(int argc, char **argv, int sockd)
{
	int count;
	int offset;
	int sql_len;
	int temp_len;
	IDB_ITEM *pidb;
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	char temp_buff[256*1024];
	
	if (2 != argc || strlen(argv[1]) >= 256) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	sql_len = sprintf(sql_string, "SELECT name FROM folders WHERE unsub=0");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 2;
	}
	count = 0;
	temp_len = 32;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		temp_len += snprintf(temp_buff + temp_len,
					256*1024 - temp_len,  "%s\r\n",
					sqlite3_column_text(pstmt, 0));
		count ++;
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	offset = snprintf(temp_buff, 32, "TRUE %d\r\n", count);
	memmove(temp_buff + 32 - offset, temp_buff, offset);
	write(sockd, temp_buff + 32 - offset, offset + temp_len - 32);
	return 0;
}

static int mail_engine_psiml(int argc, char **argv, int sockd)
{
	BOOL b_asc;
	int offset;
	int length;
	int sql_len;
	int temp_len;
	int buff_len;
	uint32_t uid;
	int flags_len;
	int idx1, idx2;
	IDB_ITEM *pidb;
	int total_mail;
	int sort_field;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char flags_buff[16];
	char temp_line[1024];
	char sql_string[1024];
	const char *mid_string;
	char temp_buff[256*1024];
	
	if ((5 != argc && 7 != argc) || strlen(argv[1]) >= 256
		|| strlen(argv[2]) >= 1024) {
		return 1;	
	}
	if (0 == strcasecmp(argv[3], "RCV")) {
		sort_field = FIELD_RECEIVED;
	} else if (0 == strcasecmp(argv[3], "SUB")) {
		sort_field = FIELD_SUBJECT;	
	} else if (0 == strcasecmp(argv[3], "FRM")) {
		sort_field = FIELD_FROM;
	} else if (0 == strcasecmp(argv[3], "RCP")) {
		sort_field = FIELD_RCPT;
	} else if (0 == strcasecmp(argv[3], "SIZ")) {
		sort_field = FIELD_SIZE;
	} else if (0 == strcasecmp(argv[3], "RED")) {
		sort_field = FIELD_READ;
	} else if (0 == strcasecmp(argv[3], "FLG")) {
		sort_field = FIELD_FLAG;
	} else if (0 == strcasecmp(argv[3], "UID")) {
		sort_field = FIELD_UID;
	} else if (0 == strcasecmp(argv[3], "NON")) {
		sort_field = FIELD_NONE;
	} else {
		return 1;
	}
	if (0 == strcasecmp(argv[4], "ASC")) {
		b_asc = TRUE;
	} else if (0 == strcasecmp(argv[4], "DSC")) {
		b_asc = FALSE;
	} else {
		return 1;
	}
	if (7 == argc) {
		offset = atoi(argv[5]);
		length = atoi(argv[6]);
		if (length < 0) {
			length = 0;
		}
	} else {
		offset = 0;
		length = 0;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	if (FALSE == mail_engine_sort_folder(pidb, argv[2], sort_field)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 3;
	}
	total_mail = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	if (TRUE == b_asc) {
		if (offset < 0) {
			idx1 = total_mail + 1 + offset;
			if (idx1 < 1) {
				idx1 = 1;
			}
		} else {
			if (offset >= total_mail) {
				mail_engine_put_idb(pidb);
				write(sockd, "TRUE 0\r\n", 8);
				return 0;
			}
			idx1 = offset + 1;
		}
		if (0 == length || total_mail - idx1 + 1 < length) {
			length = total_mail - idx1 + 1;
		}
		idx2 = idx1 + length - 1;
		sql_len = sprintf(sql_string, "SELECT mid_string, uid, replied, "
				"unsent, flagged, deleted, read, recent, forwarded FROM "
				"messages WHERE folder_id=%llu AND idx>=%d AND idx<=%d "
				"ORDER BY idx", folder_id, idx1, idx2);
	} else {
		if (offset < 0) {
			idx2 = offset*(-1);
			if (idx2 > total_mail) {
				idx2 = total_mail;
			}
		} else {
			if (offset >= total_mail) {
				mail_engine_put_idb(pidb);
				write(sockd, "TRUE 0\r\n", 8);
				return 0;
			}
			idx2 = total_mail - offset;
		}
		if (0 == length || idx2 < length) {
			length = idx2;
		}
		idx1 = idx2 - length + 1;
		sql_len = sprintf(sql_string, "SELECT mid_string, uid, replied, "
				"unsent, flagged, deleted, read, recent, forwarded FROM "
				"messages WHERE folder_id=%llu AND idx>=%d AND idx<=%d "
				"ORDER BY idx DESC", folder_id, idx1, idx2);
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	temp_len = sprintf(temp_buff, "TRUE %d\r\n", length);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		mid_string = sqlite3_column_text(pstmt, 0);
		uid = sqlite3_column_int64(pstmt, 1);
		flags_buff[0] = '(';
		flags_len = 1;
		if (0 != sqlite3_column_int64(pstmt, 2)) {
			flags_buff[flags_len] = 'A';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 3)) {
			flags_buff[flags_len] = 'U';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 4)) {
			flags_buff[flags_len] = 'F';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 5)) {
			flags_buff[flags_len] = 'D';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 6)) {
			flags_buff[flags_len] = 'S';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 7)) {
			flags_buff[flags_len] = 'R';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 8)) {
			flags_buff[flags_len] = 'W';
			flags_len ++;
		}
		flags_buff[flags_len] = ')';
		flags_len ++;
		flags_buff[flags_len] = '\0';
		buff_len = snprintf(temp_line, 512,
			"%s %u %s\r\n", mid_string, uid,
			flags_buff);
		if (256*1024 - temp_len < buff_len) {
			write(sockd, temp_buff, temp_len);
			temp_len = 0;
		}
		memcpy(temp_buff + temp_len, temp_line, buff_len);
		temp_len += buff_len;
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	write(sockd, temp_buff, temp_len);
	return 0;
}

static int mail_engine_psimu(int argc, char **argv, int sockd)
{
	int last;
	int first;
	BOOL b_asc;
	int sql_len;
	int buff_len;
	int temp_len;
	int flags_len;
	int total_mail;
	int sort_field;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	char flags_buff[16];
	sqlite3_stmt *pstmt;
	SIMU_NODE *psm_node;
	char temp_line[1024];
	char sql_string[1024];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	char temp_buff[256*1024];
	
	if (7 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;	
	}
	if (0 == strcasecmp(argv[3], "RCV")) {
		sort_field = FIELD_RECEIVED;
	} else if (0 == strcasecmp(argv[3], "SUB")) {
		sort_field = FIELD_SUBJECT;	
	} else if (0 == strcasecmp(argv[3], "FRM")) {
		sort_field = FIELD_FROM;
	} else if (0 == strcasecmp(argv[3], "RCP")) {
		sort_field = FIELD_RCPT;
	} else if (0 == strcasecmp(argv[3], "SIZ")) {
		sort_field = FIELD_SIZE;
	} else if (0 == strcasecmp(argv[3], "RED")) {
		sort_field = FIELD_READ;
	} else if (0 == strcasecmp(argv[3], "FLG")) {
		sort_field = FIELD_FLAG;
	} else if (0 == strcasecmp(argv[3], "UID")) {
		sort_field = FIELD_UID;
	} else if (0 == strcasecmp(argv[3], "NON")) {
		sort_field = FIELD_NONE;
	} else {
		return 1;
	}
	if (0 == strcasecmp(argv[4], "ASC")) {
		b_asc = TRUE;
	} else if (0 == strcasecmp(argv[4], "DSC")) {
		b_asc = FALSE;
	} else {
		return 1;
	}
	first = atoi(argv[5]);
	last = atoi(argv[6]);
	if ((first < 1 && -1 != first) || (last < 1 && -1 != last) ||
		(-1 == first && -1 != last) || (-1 != last && last < first)) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	if (FALSE == mail_engine_sort_folder(pidb, argv[2], sort_field)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (TRUE == b_asc) {
		if (-1 == first && -1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu ORDER BY idx", folder_id);
		} else if (-1 == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid<=%u ORDER BY idx",
				folder_id, last);
		} else if (-1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u ORDER BY idx",
				folder_id, first);
		} else if (last == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid=%u",
				folder_id, first);
		} else {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND uid<=%u "
				"ORDER BY idx", folder_id, first, last);
		}
	} else {
		sql_len = sprintf(sql_string, "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			mail_engine_put_idb(pidb);
			return 4;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 3;
		}
		total_mail = sqlite3_column_int64(pstmt, 0);
		sqlite3_finalize(pstmt);
		if (-1 == first && -1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded"
				" FROM messages WHERE folder_id=%llu ORDER BY idx DESC",
				folder_id);
		} else if (-1 == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid<=%u ORDER BY idx"
				" DESC", folder_id, last);
		} else if (-1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u ORDER BY idx"
				" DESC", folder_id, first);
		} else if (last == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid=%u",
				folder_id, first);
		} else {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid, "
				"replied, unsent, flagged, deleted, read, recent, forwarded "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND uid<=%u "
				"ORDER BY idx DESC", folder_id, first, last);
		}
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	double_list_init(&temp_list);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		psm_node = common_util_alloc(sizeof(SIMU_NODE));
		if (NULL == psm_node) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		psm_node->node.pdata = psm_node;
		if (TRUE == b_asc) {
			psm_node->idx = sqlite3_column_int64(pstmt, 0);
		} else {
			psm_node->idx = total_mail - sqlite3_column_int64(pstmt, 0) + 1;
		}
		psm_node->mid_string = common_util_dup(
				sqlite3_column_text(pstmt, 1));
		if (NULL == psm_node->mid_string) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		psm_node->uid = sqlite3_column_int64(pstmt, 2);
		flags_buff[0] = '(';
		flags_len = 1;
		if (0 != sqlite3_column_int64(pstmt, 3)) {
			flags_buff[flags_len] = 'A';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 4)) {
			flags_buff[flags_len] = 'U';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 5)) {
			flags_buff[flags_len] = 'F';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 6)) {
			flags_buff[flags_len] = 'D';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 7)) {
			flags_buff[flags_len] = 'S';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 8)) {
			flags_buff[flags_len] = 'R';
			flags_len ++;
		}
		if (0 != sqlite3_column_int64(pstmt, 9)) {
			flags_buff[flags_len] = 'W';
			flags_len ++;
		}
		flags_buff[flags_len] = ')';
		flags_len ++;
		flags_buff[flags_len] = '\0';
		psm_node->flags_buff = common_util_dup(flags_buff);
		if (NULL == psm_node->flags_buff) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		double_list_append_as_tail(&temp_list, &psm_node->node);
	}
	sqlite3_finalize(pstmt);
	temp_len = sprintf(temp_buff, "TRUE %d\r\n",
		double_list_get_nodes_num(&temp_list));
	for (pnode=double_list_get_head(&temp_list); NULL!=pnode;
		pnode=double_list_get_after(&temp_list, pnode)) {
		psm_node = (SIMU_NODE*)pnode->pdata;
		buff_len = snprintf(temp_line, 512, "%u %s %u %s\r\n",
					psm_node->idx - 1, psm_node->mid_string,
					psm_node->uid, psm_node->flags_buff);
		if (256*1024 - temp_len < buff_len) {
			write(sockd, temp_buff, temp_len);
			temp_len = 0;
		}
		memcpy(temp_buff + temp_len, temp_line, buff_len);
		temp_len += buff_len;
	}
	mail_engine_put_idb(pidb);
	write(sockd, temp_buff, temp_len);
	return 0;
}

static int mail_engine_pdell(int argc, char **argv, int sockd)
{
	BOOL b_asc;
	int length;
	int sql_len;
	int temp_len;
	int buff_len;
	uint32_t uid;
	uint32_t idx;
	int flags_len;
	IDB_ITEM *pidb;
	int sort_field;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char flags_buff[16];
	char temp_line[1024];
	char sql_string[1024];
	const char *mid_string;
	char temp_buff[256*1024];
	
	if (5 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;	
	}
	if (0 == strcasecmp(argv[3], "RCV")) {
		sort_field = FIELD_RECEIVED;
	} else if (0 == strcasecmp(argv[3], "SUB")) {
		sort_field = FIELD_SUBJECT;	
	} else if (0 == strcasecmp(argv[3], "FRM")) {
		sort_field = FIELD_FROM;
	} else if (0 == strcasecmp(argv[3], "RCP")) {
		sort_field = FIELD_RCPT;
	} else if (0 == strcasecmp(argv[3], "SIZ")) {
		sort_field = FIELD_SIZE;
	} else if (0 == strcasecmp(argv[3], "RED")) {
		sort_field = FIELD_READ;
	} else if (0 == strcasecmp(argv[3], "FLG")) {
		sort_field = FIELD_FLAG;
	} else if (0 == strcasecmp(argv[3], "UID")) {
		sort_field = FIELD_UID;
	} else if (0 == strcasecmp(argv[3], "NON")) {
		sort_field = FIELD_NONE;
	} else {
		return 1;
	}
	if (0 == strcasecmp(argv[4], "ASC")) {
		b_asc = TRUE;
	} else if (0 == strcasecmp(argv[4], "DSC")) {
		b_asc = FALSE;
	} else {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	if (FALSE == mail_engine_sort_folder(pidb, argv[2], sort_field)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sql_len = sprintf(sql_string, "SELECT count(message_id) FROM "
		"messages WHERE folder_id=%llu AND deleted=1", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 3;
	}
	length = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	if (TRUE == b_asc) {
		sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid FROM"
			" messages WHERE folder_id=%llu AND deleted=1 ORDER BY idx",
			folder_id);
	} else {
		sql_len = sprintf(sql_string, "SELECT idx, mid_string, uid FROM"
			" messages WHERE folder_id=%llu AND deleted=1 ORDER BY idx "
			"DESC", folder_id);
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	temp_len = sprintf(temp_buff, "TRUE %d\r\n", length);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		idx = sqlite3_column_int64(pstmt, 0);
		mid_string = sqlite3_column_text(pstmt, 1);
		uid = sqlite3_column_int64(pstmt, 2);
		buff_len = snprintf(temp_line, 512,
			"%u %s %u\r\n", idx - 1, mid_string, uid);
		if (256*1024 - temp_len < buff_len) {
			write(sockd, temp_buff, temp_len);
			temp_len = 0;
		}
		memcpy(temp_buff + temp_len, temp_line, buff_len);
		temp_len += buff_len;
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	write(sockd, temp_buff, temp_len);
	return 0;
}

static int mail_engine_pdtlu(int argc, char **argv, int sockd)
{
	int last;
	int first;
	BOOL b_asc;
	int sql_len;
	int temp_len;
	int total_mail;
	int sort_field;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	DTLU_NODE *pdt_node;
	char sql_string[1024];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	char temp_buff[MAX_DIGLEN + 16];
	
	if (7 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;	
	}
	if (0 == strcasecmp(argv[3], "RCV")) {
		sort_field = FIELD_RECEIVED;
	} else if (0 == strcasecmp(argv[3], "SUB")) {
		sort_field = FIELD_SUBJECT;	
	} else if (0 == strcasecmp(argv[3], "FRM")) {
		sort_field = FIELD_FROM;
	} else if (0 == strcasecmp(argv[3], "RCP")) {
		sort_field = FIELD_RCPT;
	} else if (0 == strcasecmp(argv[3], "SIZ")) {
		sort_field = FIELD_SIZE;
	} else if (0 == strcasecmp(argv[3], "RED")) {
		sort_field = FIELD_READ;
	} else if (0 == strcasecmp(argv[3], "FLG")) {
		sort_field = FIELD_FLAG;
	} else if (0 == strcasecmp(argv[3], "UID")) {
		sort_field = FIELD_UID;
	} else if (0 == strcasecmp(argv[3], "NON")) {
		sort_field = FIELD_NONE;
	} else {
		return 1;
	}
	if (0 == strcasecmp(argv[4], "ASC")) {
		b_asc = TRUE;
	} else if (0 == strcasecmp(argv[4], "DSC")) {
		b_asc = FALSE;
	} else {
		return 1;
	}
	first = atoi(argv[5]);
	last = atoi(argv[6]);
	if ((first < 1 && -1 != first) || (last < 1 && -1 != last) ||
		(-1 == first && -1 != last) || (-1 != last && last < first)) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	if (FALSE == mail_engine_sort_folder(pidb, argv[2], sort_field)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	if (TRUE == b_asc) {
		if (-1 == first && -1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string"
				" FROM messages WHERE folder_id=%llu ORDER BY idx",
				folder_id);
		} else if (-1 == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid<=%u"
					" ORDER BY idx", folder_id, last);
		} else if (-1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid>=%u"
					" ORDER BY idx", folder_id, first);
		} else if (last == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid=%u",
					folder_id, first);
		} else {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND"
				" uid<=%u ORDER BY idx", folder_id, first, last);
		}
	} else {
		sql_len = sprintf(sql_string, "SELECT count(message_id) "
			"FROM messages WHERE folder_id=%llu", folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			mail_engine_put_idb(pidb);
			return 4;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 3;
		}
		total_mail = sqlite3_column_int64(pstmt, 0);
		sqlite3_finalize(pstmt);
		if (-1 == first && -1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string"
				" FROM messages WHERE folder_id=%llu ORDER BY idx"
				" DESC", folder_id);
		} else if (-1 == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid<=%u"
					" ORDER BY idx DESC", folder_id, last);
		} else if (-1 == last) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid>=%u"
					" ORDER BY idx", folder_id, first);
		} else if (last == first) {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
					"FROM messages WHERE folder_id=%llu AND uid=%u",
					folder_id, first);
		} else {
			sql_len = sprintf(sql_string, "SELECT idx, mid_string "
				"FROM messages WHERE folder_id=%llu AND uid>=%u AND "
				"uid<=%u ORDER BY idx DESC", folder_id, first, last);
		}
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	double_list_init(&temp_list);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		pdt_node = common_util_alloc(sizeof(DTLU_NODE));
		if (NULL == pdt_node) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		pdt_node->node.pdata = pdt_node;
		if (TRUE == b_asc) {
			pdt_node->idx = sqlite3_column_int64(pstmt, 0);
		} else {
			pdt_node->idx = total_mail - sqlite3_column_int64(pstmt, 0) + 1;
		}
		pdt_node->mid_string = common_util_dup(
				sqlite3_column_text(pstmt, 1));
		if (NULL == pdt_node->mid_string) {
			sqlite3_finalize(pstmt);
			mail_engine_put_idb(pidb);
			return 4;
		}
		double_list_append_as_tail(&temp_list, &pdt_node->node);
	}
	sqlite3_finalize(pstmt);
	temp_len = sprintf(temp_buff, "TRUE %d\r\n",
		double_list_get_nodes_num(&temp_list));
	write(sockd, temp_buff, temp_len);
	for (pnode=double_list_get_head(&temp_list); NULL!=pnode;
		pnode=double_list_get_after(&temp_list, pnode)) {
		pdt_node = (DTLU_NODE*)pnode->pdata;
		temp_len = sprintf(temp_buff, "%d ", pdt_node->idx - 1);
		if (0 == mail_engine_get_digest(pidb->psqlite,
			pdt_node->mid_string, temp_buff + temp_len)) {
			mail_engine_put_idb(pidb);
			return 6;	
		}
		temp_len = strlen(temp_buff);
		temp_buff[temp_len] = '\r';
		temp_len ++;
		temp_buff[temp_len] = '\n';
		temp_len ++;	
		write(sockd, temp_buff, temp_len);
	}
	mail_engine_put_idb(pidb);
	return 0;
}

static int mail_engine_psflg(int argc, char **argv, int sockd)
{
	int sql_len;
	IDB_ITEM *pidb;
	uint64_t read_cn;
	uint64_t folder_id;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	uint32_t tmp_proptag;
	char sql_string[1024];
	uint32_t message_flags;
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;

	if (5 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT message_id,"
		" folder_id FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 5;
	}
	message_id = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	if (NULL != strchr(argv[4], 'A')) {
		sprintf(sql_string, "UPDATE messages SET replied=1"
					" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'U')) {
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_MESSAGEFLAGS;
		if (FALSE == exmdb_client_get_message_properties(argv[1], NULL,
			0, rop_util_make_eid_ex(1, message_id), &proptags, &propvals)
			|| 0 == propvals.count) {
			mail_engine_put_idb(pidb);
			return 4;
		}
		message_flags = *(uint32_t*)propvals.ppropval[0].pvalue;
		if (0 == (MESSAGE_FLAG_UNSENT & message_flags)) {
			message_flags |= MESSAGE_FLAG_UNSENT;
			propvals.ppropval[0].pvalue = &message_flags;
			if (FALSE == exmdb_client_set_message_properties(argv[1],
				NULL, 0, rop_util_make_eid_ex(1, message_id), &propvals,
				&problems)) {
				mail_engine_put_idb(pidb);
				return 4;
			}
		}
	}
	if (NULL != strchr(argv[4], 'F')) {
		sprintf(sql_string, "UPDATE messages SET flagged=1"
					" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'W')) {
		sprintf(sql_string, "UPDATE messages SET forwarded=1"
						" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'D')) {
		sprintf(sql_string, "UPDATE messages SET deleted=1"
						" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'S')) {
		if (FALSE == exmdb_client_set_message_read_state(argv[1],
			NULL, rop_util_make_eid_ex(1, message_id), 1, &read_cn)) {
			mail_engine_put_idb(pidb);
			return 4;
		}
	}
	if (NULL != strchr(argv[4], 'R')) {
		sprintf(sql_string, "UPDATE messages SET recent=1"
					" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	mail_engine_put_idb(pidb);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_prflg(int argc, char **argv, int sockd)
{
	int sql_len;
	IDB_ITEM *pidb;
	uint64_t read_cn;
	uint64_t folder_id;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	uint32_t tmp_proptag;
	char sql_string[1024];
	uint32_t message_flags;
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;

	if (5 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT message_id,"
		" folder_id FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 5;
	}
	message_id = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	if (NULL != strchr(argv[4], 'A')) {
		sprintf(sql_string, "UPDATE messages SET replied=0"
					" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'U')) {
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_MESSAGEFLAGS;
		if (FALSE == exmdb_client_get_message_properties(argv[1], NULL,
			0, rop_util_make_eid_ex(1, message_id), &proptags, &propvals)
			|| 0 == propvals.count) {
			mail_engine_put_idb(pidb);
			return 4;
		}
		message_flags = *(uint32_t*)propvals.ppropval[0].pvalue;
		if (MESSAGE_FLAG_UNSENT & message_flags) {
			message_flags &= ~MESSAGE_FLAG_UNSENT;
			propvals.ppropval[0].pvalue = &message_flags;
			if (FALSE == exmdb_client_set_message_properties(argv[1],
				NULL, 0, rop_util_make_eid_ex(1, message_id), &propvals,
				&problems)) {
				mail_engine_put_idb(pidb);
				return 4;
			}
		}
	}
	if (NULL != strchr(argv[4], 'F')) {
		sprintf(sql_string, "UPDATE messages SET flagged=0"
					" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'W')) {
		sprintf(sql_string, "UPDATE messages SET forwarded=0"
						" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'D')) {
		sprintf(sql_string, "UPDATE messages SET deleted=0"
						" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(argv[4], 'S')) {
		if (FALSE == exmdb_client_set_message_read_state(argv[1],
			NULL, rop_util_make_eid_ex(1, message_id), 0, &read_cn)) {
			mail_engine_put_idb(pidb);
			return 4;
		}
	}
	if (NULL != strchr(argv[4], 'R')) {
		sprintf(sql_string, "UPDATE messages SET recent=0"
					" WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	mail_engine_put_idb(pidb);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int mail_engine_pgflg(int argc, char **argv, int sockd)
{
	int sql_len;
	int temp_len;
	int flags_len;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char flags_buff[32];
	char sql_string[256];
	char temp_buff[1024];

	if (4 != argc || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		return 3;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id, recent, "
		"read, unsent, flagged, replied, forwarded, deleted, "
		"FROM messages WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		mail_engine_put_idb(pidb);
		return 4;
	}
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		folder_id != sqlite3_column_int64(pstmt, 0)) {
		sqlite3_finalize(pstmt);
		mail_engine_put_idb(pidb);
		return 5;
	}
	flags_buff[0] = '(';
	flags_len = 1;
	if (0 != sqlite3_column_int64(pstmt, 5)) {
		flags_buff[flags_len] = 'A';
		flags_len ++;
	}
	if (0 != sqlite3_column_int64(pstmt, 3)) {
		flags_buff[flags_len] = 'U';
		flags_len ++;
	}
	if (0 != sqlite3_column_int64(pstmt, 4)) {
		flags_buff[flags_len] = 'F';
		flags_len ++;
	}
	if (0 != sqlite3_column_int64(pstmt, 6)) {
		flags_buff[flags_len] = 'W';
		flags_len ++;
	}
	if (0 != sqlite3_column_int64(pstmt, 7)) {
		flags_buff[flags_len] = 'D';
		flags_len ++;	
	}
	if (0 != sqlite3_column_int64(pstmt, 2)) {
		flags_buff[flags_len] = 'S';
		flags_len ++;
	}
	if (0 != sqlite3_column_int64(pstmt, 1)) {
		flags_buff[flags_len] = 'R';
		flags_len ++;
	}
	sqlite3_finalize(pstmt);
	mail_engine_put_idb(pidb);
	flags_buff[flags_len] = ')';
	flags_len ++;
	flags_buff[flags_len] = '\0';
	temp_len = sprintf(temp_buff, "TRUE %s\r\n", flags_buff);
	write(sockd, temp_buff, temp_len);
	return 0;
}

static int mail_engine_psrhl(int argc, char **argv, int sockd)
{
	int result;
	char *parg;
	int tmp_len;
	int tmp_argc;
	IDB_ITEM *pidb;
	sqlite3 *psqlite;
	size_t decode_len;
	uint64_t folder_id;
	char temp_path[256];
	char* tmp_argv[1024];
	CONDITION_TREE *ptree;
	char tmp_buff[16*1024];
	char list_buff[256*1024];
	CONDITION_RESULT *presult;
	
	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	tmp_len = strlen(argv[4]);
	if (tmp_len >= sizeof(tmp_buff)) {
		return 1;
	}
	if (0 != decode64(argv[4], tmp_len, tmp_buff, &decode_len)) {
		return 1;
	}
	tmp_argc = 0;
	parg = tmp_buff;
	while ('\0' != *parg && parg - tmp_buff < decode_len
		&& tmp_argc < sizeof(tmp_argv)) {
		tmp_argv[tmp_argc] = parg;
		parg += strlen(parg) + 1;
		tmp_argc ++;
	}
	if (0 == tmp_argc) {
		return 1;
	}
	ptree = mail_engine_ct_build(tmp_argc, tmp_argv);
	if (NULL == ptree) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		mail_engine_ct_destroy(ptree);
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		mail_engine_ct_destroy(ptree);
		return 3;
	}
	mail_engine_put_idb(pidb);
	sprintf(temp_path, "%s/exmdb/midb.sqlite3", argv[1]);
	if (SQLITE_OK != sqlite3_open_v2(temp_path,
		&psqlite, SQLITE_OPEN_READWRITE, NULL)) {
		mail_engine_ct_destroy(ptree);
		return 2;
	}
	presult = mail_engine_ct_match(argv[3],
		psqlite, folder_id, ptree, FALSE);
	if (NULL == presult) {
		sqlite3_close(psqlite);
		mail_engine_ct_destroy(ptree);
		return 4;
	}
	sqlite3_close(psqlite);
	tmp_len = 4;
    memcpy(list_buff, "TRUE", 4);
    while (-1 != (result = mail_engine_ct_fetch_result(presult))) {
        tmp_len += snprintf(list_buff + tmp_len,
			256*1024 - tmp_len, " %d", result);
		if (tmp_len >= 255*1024) {
			write(sockd, list_buff, tmp_len);
			tmp_len = 0;
		}
    }
    mail_engine_ct_free_result(presult);
    mail_engine_ct_destroy(ptree);
    list_buff[tmp_len] = '\r';
	tmp_len ++;
    list_buff[tmp_len] = '\n';
	tmp_len ++;
	write(sockd, list_buff, tmp_len);
	return 0;
}

static int mail_engine_psrhu(int argc, char **argv, int sockd)
{
	int result;
	char *parg;
	int tmp_len;
	int tmp_argc;
	IDB_ITEM *pidb;
	sqlite3 *psqlite;
	size_t decode_len;
	uint64_t folder_id;
	char temp_path[256];
	char* tmp_argv[1024];
	CONDITION_TREE *ptree;
	char tmp_buff[16*1024];
	char list_buff[256*1024];
	CONDITION_RESULT *presult;
	
	if (argc != 5 || strlen(argv[1]) >= 256 || strlen(argv[2]) >= 1024) {
		return 1;
	}
	tmp_len = strlen(argv[4]);
	if (tmp_len >= sizeof(tmp_buff)) {
		return 1;
	}
	if (0 != decode64(argv[4], tmp_len, tmp_buff, &decode_len)) {
		return 1;
	}
	tmp_argc = 0;
	parg = tmp_buff;
	while ('\0' != *parg && parg - tmp_buff < decode_len
		&& tmp_argc < sizeof(tmp_argv)) {
		tmp_argv[tmp_argc] = parg;
		parg += strlen(parg) + 1;
		tmp_argc ++;
	}
	if (0 == tmp_argc) {
		return 1;
	}
	ptree = mail_engine_ct_build(tmp_argc, tmp_argv);
	if (NULL == ptree) {
		return 1;
	}
	pidb = mail_engine_get_idb(argv[1]);
	if (NULL == pidb) {
		mail_engine_ct_destroy(ptree);
		return 2;
	}
	folder_id = mail_engine_get_folder_id(pidb, argv[2]);
	if (0 == folder_id) {
		mail_engine_put_idb(pidb);
		mail_engine_ct_destroy(ptree);
		return 3;
	}
	mail_engine_put_idb(pidb);
	sprintf(temp_path, "%s/exmdb/midb.sqlite3", argv[1]);
	if (SQLITE_OK != sqlite3_open_v2(temp_path,
		&psqlite, SQLITE_OPEN_READWRITE, NULL)) {
		mail_engine_ct_destroy(ptree);
		return 2;
	}
	presult = mail_engine_ct_match(argv[3],
		psqlite, folder_id, ptree, TRUE);
	if (NULL == presult) {
		sqlite3_close(psqlite);
		mail_engine_ct_destroy(ptree);
		return 4;
	}
	sqlite3_close(psqlite);
	tmp_len = 4;
    memcpy(list_buff, "TRUE", 4);
    while (-1 != (result = mail_engine_ct_fetch_result(presult))) {
        tmp_len += snprintf(list_buff + tmp_len,
			256*1024 - tmp_len, " %d", result);
		if (tmp_len >= 255*1024) {
			write(sockd, list_buff, tmp_len);
			tmp_len = 0;
		}
    }
    mail_engine_ct_free_result(presult);
    mail_engine_ct_destroy(ptree);
    list_buff[tmp_len] = '\r';
	tmp_len ++;
    list_buff[tmp_len] = '\n';
	tmp_len ++;
	write(sockd, list_buff, tmp_len);
	return 0;
}

static void mail_engine_add_notification_message(
	IDB_ITEM *pidb, uint64_t folder_id, uint64_t message_id)
{
	int sql_len;
	uint32_t uidnext;
	uint64_t mod_time;
	const void *pvalue;
	sqlite3_stmt *pstmt;
	char flags_buff[16];
	char mid_string[128];
	char sql_string[1024];
	uint32_t message_flags;
	uint64_t received_time;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[4];
	
	proptags.count = 4;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PROP_TAG_MESSAGEDELIVERYTIME;
	tmp_proptags[1] = PROP_TAG_LASTMODIFICATIONTIME;
	tmp_proptags[2] = PROP_TAG_MIDSTRING;
	tmp_proptags[3] = PROP_TAG_MESSAGEFLAGS;
	if (FALSE == exmdb_client_get_message_properties(
		common_util_get_maildir(), NULL, 0,
		rop_util_make_eid_ex(1, message_id),
		&proptags, &propvals)) {
		return;		
	}
	pvalue = common_util_get_propvals(&propvals,
				PROP_TAG_LASTMODIFICATIONTIME);
	if (NULL == pvalue) {
		mod_time = 0;
	} else {
		mod_time = *(uint64_t*)pvalue;
	}
	pvalue = common_util_get_propvals(&propvals,
					PROP_TAG_MESSAGEDELIVERYTIME);
	if (NULL == pvalue) {
		received_time = mod_time;
	} else {
		received_time = *(uint64_t*)pvalue;
	}
	pvalue = common_util_get_propvals(
		&propvals, PROP_TAG_MESSAGEFLAGS);
	if (NULL == pvalue) {
		message_flags = 0;
	} else {
		message_flags = *(uint32_t*)pvalue;
	}
	flags_buff[0] = '\0';
	pvalue = common_util_get_propvals(&propvals, PROP_TAG_MIDSTRING);
	if (NULL == pvalue) {
		sql_len = sprintf(sql_string, "SELECT mid_string, flag_string"
					" FROM mapping WHERE message_id=%llu", message_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return;
		}
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			strcpy(mid_string, sqlite3_column_text(pstmt, 0));
			pvalue = sqlite3_column_text(pstmt, 1);
			if (NULL != pvalue) {
				strcpy(flags_buff, pvalue);
			}
			pvalue = mid_string;
		}
		sqlite3_finalize(pstmt);
		if (NULL != pvalue) {
			sprintf(sql_string, "DELETE FROM mapping"
				" WHERE message_id=%llu", message_id);
			sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
		}
	}
	sql_len = sprintf(sql_string, "SELECT uidnext FROM"
			" folders WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return;
	}
	uidnext = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	sprintf(sql_string, "UPDATE folders SET"
		" uidnext=uidnext+1, sort_field=%d "
		"WHERE folder_id=%llu", FIELD_NONE, folder_id);
	if (SQLITE_OK != sqlite3_exec(pidb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return;
	}
	sql_len = sprintf(sql_string, "INSERT INTO messages ("
		"message_id, folder_id, mid_string, mod_time, uid, "
		"unsent, read, subject, sender, rcpt, size, received)"
		" VALUES (?, %llu, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;	
	}
	mail_engine_insert_message(pstmt, &uidnext, message_id,
			pvalue, message_flags, received_time, mod_time);
	sqlite3_finalize(pstmt);
	if (NULL != strchr(flags_buff, 'F')) {
		sprintf(sql_string, "UPDATE messages SET "
			"flagged=1 WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(flags_buff, 'A')) {
		sprintf(sql_string, "UPDATE messages SET "
			"replied=1 WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
	if (NULL != strchr(flags_buff, 'W')) {
		sprintf(sql_string, "UPDATE messages SET "
			"forwarded=1 WHERE message_id=%llu", message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	}
}

static void mail_engine_delete_notification_message(
	IDB_ITEM *pidb, uint64_t folder_id, uint64_t message_id)
{
	int sql_len;
	sqlite3_stmt *pstmt;
	char sql_string[1024];
	
	sql_len = sprintf(sql_string, "SELECT folder_id FROM "
			"messages WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;	
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return;
	}
	if (folder_id != sqlite3_column_int64(pstmt, 0)) {
		sqlite3_finalize(pstmt);
		return;
	}
	sqlite3_finalize(pstmt);
	sprintf(sql_string, "DELETE FROM messages"
		" WHERE message_id=%llu", message_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	sprintf(sql_string, "UPDATE folders SET sort_field=%d "
			"WHERE folder_id=%llu", FIELD_NONE, folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
}

static BOOL mail_engine_add_notification_folder(
	IDB_ITEM *pidb, uint64_t parent_id, uint64_t folder_id)
{
	BOOL b_wait;
	int sql_len;
	int tmp_len;
	void *pvalue;
	uint64_t commit_max;
	sqlite3_stmt *pstmt;
	char temp_name[512];
	char sql_string[1280];
	char decoded_name[512];
	PROPTAG_ARRAY proptags;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[4];
	
	switch (parent_id) {
	case PRIVATE_FID_IPMSUBTREE:
		break;
	case PRIVATE_FID_INBOX:
		strcpy(decoded_name, "inbox");
		break;
	case PRIVATE_FID_DRAFT:
		strcpy(decoded_name, "draft");
		break;
	case PRIVATE_FID_SENT_ITEMS:
		strcpy(decoded_name, "sent");
		break;
	case PRIVATE_FID_DELETED_ITEMS:
		strcpy(decoded_name, "trash");
		break;
	case PRIVATE_FID_JUNK:
		strcpy(decoded_name, "junk");
		break;
	default:
		sql_len = sprintf(sql_string, "SELECT name FROM"
			" folders WHERE folder_id=%llu", parent_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;	
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		if (FALSE == decode_hex_binary(
			sqlite3_column_text(pstmt, 0),
			decoded_name, 512)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		sqlite3_finalize(pstmt);
	}
	proptags.count = 4;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PROP_TAG_DISPLAYNAME;
	tmp_proptags[1] = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_proptags[2] = PROP_TAG_CONTAINERCLASS;
	tmp_proptags[3] = PROP_TAG_ATTRIBUTEHIDDEN;
	b_wait = FALSE;
REQUERY_FOLDER:
	if (FALSE == exmdb_client_get_folder_properties(
		common_util_get_maildir(), 0,
		rop_util_make_eid_ex(1, folder_id),
		&proptags, &propvals)) {
		return FALSE;		
	}
	pvalue = common_util_get_propvals(
		&propvals, PROP_TAG_ATTRIBUTEHIDDEN);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		return FALSE;
	}
	pvalue = common_util_get_propvals(
		&propvals, PROP_TAG_CONTAINERCLASS);
	if (NULL == pvalue && FALSE == b_wait) {
		/* outlook will set the PROP_TAG_CONTAINERCLASS
			after RopCreateFolder, so try to wait! */
		sleep(1);
		b_wait = TRUE;
		goto REQUERY_FOLDER;
	}
	if (NULL == pvalue) {
		return FALSE;
	}
	if (0 != strcasecmp(pvalue, "IPF.Note")) {
		return FALSE;
	}
	pvalue = common_util_get_propvals(&propvals,
					PROP_TAG_LOCALCOMMITTIMEMAX);
	if (NULL == pvalue) {
		commit_max = 0;
	} else {
		commit_max = *(uint64_t*)pvalue;
	}
	pvalue = common_util_get_propvals(
		&propvals, PROP_TAG_DISPLAYNAME);
	if (NULL == pvalue) {
		return FALSE;
	}
	tmp_len = strlen(pvalue);
	if (tmp_len >= 256) {
		return FALSE;
	}
	if (PRIVATE_FID_IPMSUBTREE == parent_id) {
		memcpy(temp_name, pvalue, tmp_len);
	} else {
		if (tmp_len + strlen(decoded_name) >= 511) {
			return FALSE;
		}
		tmp_len = sprintf(temp_name, "%s/%s", decoded_name, pvalue);
	}
	encode_hex_binary(temp_name, tmp_len, encoded_name, 1024);
	sprintf(sql_string, "INSERT INTO folders (folder_id, parent_fid, "
		"commit_max, name) VALUES (%llu, %llu, %llu, '%s')", folder_id,
		parent_id, commit_max, encoded_name);
	if (SQLITE_OK != sqlite3_exec(pidb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	return TRUE;
}

static void mail_engine_delete_notification_folder(
	IDB_ITEM *pidb, uint64_t folder_id)
{
	char sql_string[256];
	
	sprintf(sql_string, "DELETE FROM folders "
			"WHERE folder_id=%llu", folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
}

static void mail_engine_update_subfolders_name(IDB_ITEM *pidb,
	uint64_t parent_id, const char *parent_name)
{
	int sql_len;
	int tmp_len;
	char *ptoken;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	char temp_name[512];
	char sql_string[1280];
	char decoded_name[512];
	char encoded_name[1024];
	
	sql_len = sprintf(sql_string, "SELECT folder_id, name"
		" FROM folders WHERE parent_fid=%llu", parent_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;	
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		folder_id = sqlite3_column_int64(pstmt, 0);
		if (FALSE == decode_hex_binary(
			sqlite3_column_text(pstmt, 1),
			decoded_name, 512)) {
			continue;
		}
		ptoken = strrchr(decoded_name, '/');
		if (NULL == ptoken) {
			continue;
		}
		if (strlen(ptoken) + strlen(parent_name) >= 512) {
			continue;
		}
		tmp_len = sprintf(temp_name, "%s%s", parent_name, ptoken);
		encode_hex_binary(temp_name, tmp_len, encoded_name, 1024);
		sprintf(sql_string, "UPDATE folders SET name='%s' "
			"WHERE folder_id=%llu", encoded_name, folder_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
		mail_engine_update_subfolders_name(pidb, folder_id, temp_name);
	}
	sqlite3_finalize(pstmt);
}

static void mail_engine_move_notification_folder(
	IDB_ITEM *pidb, uint64_t parent_id, uint64_t folder_id)
{
	int sql_len;
	int tmp_len;
	void *pvalue;
	uint64_t commit_max;
	sqlite3_stmt *pstmt;
	char temp_name[512];
	uint32_t tmp_proptag;
	char sql_string[1280];
	char decoded_name[512];
	PROPTAG_ARRAY proptags;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	
	sql_len = sprintf(sql_string, "SELECT folder_id "
		"FROM folders WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;	
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		mail_engine_add_notification_folder(
				pidb, parent_id, folder_id);
		return;
	}
	sqlite3_finalize(pstmt);
	switch (parent_id) {
	case PRIVATE_FID_IPMSUBTREE:
		break;
	case PRIVATE_FID_INBOX:
		strcpy(decoded_name, "inbox");
		break;
	case PRIVATE_FID_DRAFT:
		strcpy(decoded_name, "draft");
		break;
	case PRIVATE_FID_SENT_ITEMS:
		strcpy(decoded_name, "sent");
		break;
	case PRIVATE_FID_DELETED_ITEMS:
		strcpy(decoded_name, "trash");
		break;
	case PRIVATE_FID_JUNK:
		strcpy(decoded_name, "junk");
		break;
	default:
		sql_len = sprintf(sql_string, "SELECT name FROM"
			" folders WHERE folder_id=%llu", parent_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return;	
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			return;
		}
		if (FALSE == decode_hex_binary(
			sqlite3_column_text(pstmt, 0),
			decoded_name, 512)) {
			sqlite3_finalize(pstmt);
			return;
		}
		sqlite3_finalize(pstmt);
	}
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PROP_TAG_DISPLAYNAME;
	if (FALSE == exmdb_client_get_folder_properties(
		common_util_get_maildir(), 0,
		rop_util_make_eid_ex(1, folder_id),
		&proptags, &propvals)) {
		return;		
	}
	pvalue = common_util_get_propvals(
		&propvals, PROP_TAG_DISPLAYNAME);
	if (NULL == pvalue) {
		return;
	}
	tmp_len = strlen(pvalue);
	if (tmp_len >= 256) {
		return;
	}
	if (PRIVATE_FID_IPMSUBTREE == parent_id) {
		memcpy(temp_name, pvalue, tmp_len);
	} else {
		if (tmp_len + strlen(decoded_name) >= 511) {
			return;
		}
		tmp_len = sprintf(temp_name, "%s/%s", decoded_name, pvalue);
	}
	encode_hex_binary(temp_name, tmp_len, encoded_name, 1024);
	sprintf(sql_string, "UPDATE folders SET parent_fid=%llu, name='%s' "
			"WHERE folder_id=%llu", parent_id, encoded_name, folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	mail_engine_update_subfolders_name(pidb, folder_id, temp_name);
}

static void mail_engine_modify_notification_folder(
	IDB_ITEM *pidb, uint64_t folder_id)
{
	int sql_len;
	int tmp_len;
	void *pvalue;
	char *pdisplayname;
	sqlite3_stmt *pstmt;
	uint32_t tmp_proptag;
	char sql_string[1280];
	char decoded_name[512];
	PROPTAG_ARRAY proptags;
	char encoded_name[1024];
	TPROPVAL_ARRAY propvals;
	
	switch (folder_id) {	
	case PRIVATE_FID_IPMSUBTREE:
	case PRIVATE_FID_INBOX:
	case PRIVATE_FID_DRAFT:
	case PRIVATE_FID_SENT_ITEMS:
	case PRIVATE_FID_DELETED_ITEMS:
	case PRIVATE_FID_JUNK:
		return;
	}
	sql_len = sprintf(sql_string, "SELECT name FROM"
		" folders WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;	
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return;
	}
	if (FALSE == decode_hex_binary(
		sqlite3_column_text(pstmt, 0),
		decoded_name, 512)) {
		sqlite3_finalize(pstmt);
		return;
	}
	sqlite3_finalize(pstmt);
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PROP_TAG_DISPLAYNAME;
	if (FALSE == exmdb_client_get_folder_properties(
		common_util_get_maildir(), 0,
		rop_util_make_eid_ex(1, folder_id),
		&proptags, &propvals)) {
		return;		
	}
	pvalue = common_util_get_propvals(
		&propvals, PROP_TAG_DISPLAYNAME);
	if (NULL == pvalue) {
		return;
	}
	pdisplayname = strrchr(decoded_name, '/');
	if (NULL == pdisplayname) {
		pdisplayname = decoded_name;
	} else {
		pdisplayname ++;
	}
	if (0 == strcmp(pdisplayname, pvalue)) {
		return;
	}
	tmp_len = strlen(pvalue);
	if (tmp_len >= 256) {
		return;
	}
	if (pdisplayname == decoded_name) {
		memcpy(decoded_name, pvalue, tmp_len);
	} else {
		if (pdisplayname - decoded_name + tmp_len >= 512) {
			return;
		}
		strcpy(pdisplayname, pvalue);
		tmp_len = strlen(decoded_name);
	}
	encode_hex_binary(decoded_name, tmp_len, encoded_name, 1024);
	sprintf(sql_string, "UPDATE folders SET name='%s' "
		"WHERE folder_id=%llu", encoded_name, folder_id);
	sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
	mail_engine_update_subfolders_name(pidb, folder_id, decoded_name);
}

static void mail_engine_modify_notification_message(
	IDB_ITEM *pidb, uint64_t folder_id, uint64_t message_id)
{
	int sql_len;
	int b_read;
	int b_unsent;
	void *pvalue;
	uint64_t mod_time;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	uint32_t message_flags;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t tmp_proptags[3];
	
	proptags.count = 3;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = PROP_TAG_MESSAGEFLAGS;
	tmp_proptags[1] = PROP_TAG_LASTMODIFICATIONTIME;
	tmp_proptags[2] = PROP_TAG_MIDSTRING;
	if (FALSE == exmdb_client_get_message_properties(
		common_util_get_maildir(), NULL, 0,
		rop_util_make_eid_ex(1, message_id),
		&proptags, &propvals)) {
		return;	
	}
	pvalue = common_util_get_propvals(&propvals, PROP_TAG_MESSAGEFLAGS);
	if (NULL == pvalue) {
		message_flags = 0;
	} else {
		message_flags= *(uint32_t*)pvalue;
	}
	pvalue = common_util_get_propvals(&propvals, PROP_TAG_MIDSTRING);
	if (NULL != pvalue) {
UPDATE_MESSAGE_FLAGS:
		if (message_flags & MESSAGE_FLAG_UNSENT) {
			b_unsent = 1;
		} else {
			b_unsent = 0;
		}
		if (message_flags & MESSAGE_FLAG_READ) {
			b_read = 1;
		} else {
			b_read = 0;
		}
		sprintf(sql_string, "UPDATE messages SET read=%d, unsent=%d"
			" WHERE message_id=%llu", b_read, b_unsent, message_id);
		sqlite3_exec(pidb->psqlite, sql_string, NULL, NULL, NULL);
		return;
	}
	pvalue = common_util_get_propvals(&propvals,
				PROP_TAG_LASTMODIFICATIONTIME);
	if (NULL == pvalue) {
		mod_time = 0;
	} else {
		mod_time = *(uint64_t*)pvalue;
	}
	sql_len = sprintf(sql_string, "SELECT mod_time FROM"
		" messages WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;	
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return;
	}
	if (mod_time == sqlite3_column_int64(pstmt, 0)) {
		sqlite3_finalize(pstmt);
		goto UPDATE_MESSAGE_FLAGS;
	}
	sqlite3_finalize(pstmt);
	sprintf(sql_string, "DELETE FROM messages"
		" WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_exec(pidb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return;	
	}
	return mail_engine_add_notification_message(
					pidb, folder_id, message_id);
}

static void mail_engine_notification_proc(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify)
{
	int sql_len;
	IDB_ITEM *pidb;
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	uint32_t tmp_proptag;
	char temp_buff[1280];
	char sql_string[1024];
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	char encoded_name[1024];
	
	if (TRUE == b_table) {
		return;
	}
	pidb = mail_engine_peek_idb(dir);
	if (NULL == pidb) {
		return;
	}
	if (pidb->sub_id != notify_id) {
		mail_engine_put_idb(pidb);
		return;
	}
	switch (pdb_notify->type) {
	case DB_NOTIFY_TYPE_NEW_MAIL:
		folder_id = ((DB_NOTIFY_NEW_MAIL*)
			pdb_notify->pdata)->folder_id;
		message_id = ((DB_NOTIFY_NEW_MAIL*)
			pdb_notify->pdata)->message_id;
		mail_engine_add_notification_message(
				pidb, folder_id, message_id);
		sql_len = sprintf(sql_string, "SELECT name FROM"
			" folders WHERE folder_id=%llu", folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pidb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			break;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			break;
		}
		snprintf(temp_buff, 1280, "FOLDER-TOUCH %s %s",
			pidb->username, sqlite3_column_text(pstmt, 0));
		sqlite3_finalize(pstmt);
		system_services_broadcast_event(temp_buff);
		break;
	case DB_NOTIFY_TYPE_FOLDER_CREATED:
		folder_id = ((DB_NOTIFY_FOLDER_CREATED*)
					pdb_notify->pdata)->folder_id;
		parent_id = ((DB_NOTIFY_FOLDER_CREATED*)
					pdb_notify->pdata)->parent_id;
		mail_engine_add_notification_folder(
				pidb, parent_id, folder_id);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_CREATED:
		folder_id = ((DB_NOTIFY_MESSAGE_CREATED*)
					pdb_notify->pdata)->folder_id;
		message_id = ((DB_NOTIFY_MESSAGE_CREATED*)
					pdb_notify->pdata)->message_id;
		mail_engine_add_notification_message(
				pidb, folder_id, message_id);
		break;
	case DB_NOTIFY_TYPE_FOLDER_DELETED:
		folder_id = ((DB_NOTIFY_FOLDER_DELETED*)
					pdb_notify->pdata)->folder_id;
		mail_engine_delete_notification_folder(
								pidb, folder_id);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_DELETED:
		folder_id = ((DB_NOTIFY_MESSAGE_DELETED*)
					pdb_notify->pdata)->folder_id;
		message_id = ((DB_NOTIFY_MESSAGE_DELETED*)
					pdb_notify->pdata)->message_id;
		mail_engine_delete_notification_message(
					pidb, folder_id, message_id);
		break;
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED:
		folder_id = ((DB_NOTIFY_FOLDER_MODIFIED*)
					pdb_notify->pdata)->folder_id;
		mail_engine_modify_notification_folder(
								pidb, folder_id);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED:
		message_id = ((DB_NOTIFY_MESSAGE_MODIFIED*)
					pdb_notify->pdata)->message_id;
		folder_id = ((DB_NOTIFY_MESSAGE_MODIFIED*)
					pdb_notify->pdata)->folder_id;
		mail_engine_modify_notification_message(
					pidb, folder_id, message_id);
		break;
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
		folder_id = ((DB_NOTIFY_FOLDER_MVCP*)
				pdb_notify->pdata)->folder_id;
		parent_id = ((DB_NOTIFY_FOLDER_MVCP*)
				pdb_notify->pdata)->parent_id;
		mail_engine_move_notification_folder(
				pidb, parent_id, folder_id);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
		folder_id = ((DB_NOTIFY_MESSAGE_MVCP*)
			pdb_notify->pdata)->old_folder_id;
		message_id = ((DB_NOTIFY_MESSAGE_MVCP*)
			pdb_notify->pdata)->old_message_id;
		mail_engine_delete_notification_message(
					pidb, folder_id, message_id);
		folder_id = ((DB_NOTIFY_MESSAGE_MVCP*)
				pdb_notify->pdata)->folder_id;
		message_id = ((DB_NOTIFY_MESSAGE_MVCP*)
				pdb_notify->pdata)->message_id;
		mail_engine_add_notification_message(
				pidb, folder_id, message_id);
		break;
	case DB_NOTIFY_TYPE_FOLDER_COPIED:
		folder_id = ((DB_NOTIFY_FOLDER_MVCP*)
				pdb_notify->pdata)->folder_id;
		parent_id = ((DB_NOTIFY_FOLDER_MVCP*)
				pdb_notify->pdata)->parent_id;
		if (TRUE == mail_engine_add_notification_folder(
			pidb, parent_id, folder_id)) {
			mail_engine_sync_contents(pidb, folder_id);
		}
		break;
	case DB_NOTIFY_TYPE_MESSAGE_COPIED:
		folder_id = ((DB_NOTIFY_MESSAGE_MVCP*)
				pdb_notify->pdata)->folder_id;
		message_id = ((DB_NOTIFY_MESSAGE_MVCP*)
				pdb_notify->pdata)->message_id;
		mail_engine_add_notification_message(
				pidb, folder_id, message_id);
		break;
	}
	mail_engine_put_idb(pidb);
}

void mail_engine_init(const char *default_charset,
	const char *default_timezone, const char *org_name,
	int table_size, BOOL b_async, BOOL b_wal,
	uint64_t mmap_size, int cache_interval, int mime_num)
{
	g_squence_id = 0;
	strcpy(g_default_charset, default_charset);
	strcpy(g_default_timezone, default_timezone);
	strcpy(g_org_name, org_name);
	g_async = b_async;
	g_wal = b_wal;
	g_mmap_size = mmap_size;
	g_table_size = table_size;
	g_mime_num = mime_num;
	g_cache_interval = cache_interval;
	pthread_mutex_init(&g_hash_lock, NULL);
	pthread_mutex_init(&g_squence_lock, NULL);
}

int mail_engine_run()
{
	if (SQLITE_OK != sqlite3_config(SQLITE_CONFIG_MULTITHREAD)) {
		printf("[mail_engine]: warning! fail to change "
			"to multiple thread mode for sqlite engine\n");
	}
	if (SQLITE_OK != sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0)) {
		printf("[mail_engine]: warning! fail to close"
			" memory statistic for sqlite engine\n");
	}
	if (FALSE == oxcmail_init_library(g_org_name,
		system_services_get_user_ids, system_services_get_username_from_id,
		system_services_ltag_to_lcid, system_services_lcid_to_ltag,
		system_services_charset_to_cpid, system_services_cpid_to_charset,
		system_services_mime_to_extension, system_services_extension_to_mime)) {
		printf("[mail_engine]: fail to init oxcmail library\n");
		return -1;
	}
	g_hash_table = str_hash_init(g_table_size, sizeof(IDB_ITEM), NULL);
	if (NULL == g_hash_table) {
		printf("[mail_engine]: fail to init hash table\n");
		return -2;
	}
	g_mime_pool = mime_pool_init(g_mime_num, FILENUM_PER_MIME, TRUE);
	if (NULL == g_mime_pool) {
		str_hash_free(g_hash_table);
		printf("[mail_engine]: fail to init mime pool\n");
		return -3;
	}
	g_alloc_mjson = mjson_allocator_init(g_table_size*10, TRUE);
	if (NULL == g_alloc_mjson) {
		mime_pool_free(g_mime_pool);
		str_hash_free(g_hash_table);
		printf("[mail_engine]: fail to init buffer pool for mjson\n");
		return -4;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_scan_tid, NULL, scan_work_func, NULL)) {
		mime_pool_free(g_mime_pool);
		str_hash_free(g_hash_table);
		lib_buffer_free(g_alloc_mjson);
		printf("[mail_engine]: fail to create scan thread\n");
		return -5;
	}
	cmd_parser_register_command("M-QUTA", mail_engine_mquta);
	cmd_parser_register_command("M-SUMY", mail_engine_msumy);
	cmd_parser_register_command("M-LIST", mail_engine_mlist);
	cmd_parser_register_command("M-UIDL", mail_engine_muidl);
	cmd_parser_register_command("M-MTCH", mail_engine_mmtch);
	cmd_parser_register_command("M-INST", mail_engine_minst);
	cmd_parser_register_command("M-DELE", mail_engine_mdele);
	cmd_parser_register_command("M-MOVE", mail_engine_mmove);
	cmd_parser_register_command("M-COPY", mail_engine_mcopy);
	cmd_parser_register_command("M-UPDT", mail_engine_mupdt);
	cmd_parser_register_command("M-MAKF", mail_engine_mmakf);
	cmd_parser_register_command("M-REMF", mail_engine_mremf);
	cmd_parser_register_command("M-RENF", mail_engine_mrenf);
	cmd_parser_register_command("M-INFO", mail_engine_minfo);
	cmd_parser_register_command("M-ENUM", mail_engine_menum);
	cmd_parser_register_command("M-CKFL", mail_engine_mckfl);
	cmd_parser_register_command("M-FREE", mail_engine_mfree);
	cmd_parser_register_command("M-PING", mail_engine_mping);
	cmd_parser_register_command("M-WEML", mail_engine_mweml);
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
	exmdb_client_register_proc(mail_engine_notification_proc);
	return 0;
}

int mail_engine_stop()
{
	int i;

	g_notify_stop = TRUE;
	pthread_join(g_scan_tid, NULL);
	str_hash_free(g_hash_table);
	mime_pool_free(g_mime_pool);
	lib_buffer_free(g_alloc_mjson);
	return 0;
}

void mail_engine_free()
{
	pthread_mutex_destroy(&g_hash_lock);
	pthread_mutex_destroy(&g_squence_lock);
}

int mail_engine_get_param(int param)
{
	switch (param) {
	case MIDB_TABLE_SIZE:
		return g_table_size;
	case MIDB_TABLE_USED:
		return g_hash_table->item_num;
	default:
		return -1;
	}
}
