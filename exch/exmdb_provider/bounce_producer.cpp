// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstring>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "bounce_producer.h"
#include <gromox/database.h>
#include <gromox/fileio.h>
#include <gromox/svc_common.h>
#include "common_util.h"
#include <gromox/single_list.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include <gromox/dsn.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <cstdio>
#include <fcntl.h>
#include <ctime>

using namespace gromox;

enum{
	TAG_BEGIN,
	TAG_TIME,
	TAG_FROM,
	TAG_RCPT,
	TAG_SUBJECT,
	TAG_PARTS,
	TAG_LENGTH,
	TAG_END,
	TAG_TOTAL_LEN = TAG_END
};

struct FORMAT_DATA {
	int	position;
	int tag;
};

/*
 * <time> <from> <rcpt>
 * <subject> <parts> <length>
 */
struct RESOURCE_NODE {
	SINGLE_LIST_NODE	node;
	char				charset[32];
	char				from[BOUNCE_TOTAL_NUM][256];
	char				subject[BOUNCE_TOTAL_NUM][256];
	char				content_type[BOUNCE_TOTAL_NUM][256];
	char*				content[BOUNCE_TOTAL_NUM];
	FORMAT_DATA			format[BOUNCE_TOTAL_NUM][TAG_TOTAL_LEN + 1];
};

struct TAG_ITEM {
	const char	*name;
	int			length;
};

static char g_separator[16];
static SINGLE_LIST g_resource_list;
static RESOURCE_NODE *g_default_resource;
static pthread_rwlock_t g_list_lock;
static const char *g_resource_table[] = {
	"BOUNCE_AUTO_RESPONSE",
	"BOUNCE_MAIL_TOO_LARGE",
	"BOUNCE_CANNOT_DISPLAY",
	"BOUNCE_GENERIC_ERROR"
};
static TAG_ITEM g_tags[] = {
	{"<time>", 6},
	{"<from>", 6},
	{"<rcpt>", 6},
	{"<subject>", 9},
	{"<parts>", 7},
	{"<length>", 8}
};

static BOOL bounce_producer_check_subdir(const char *basedir, const char *dir_name);
static void bounce_producer_load_subdir(const char *basedir, const char *dir_name, SINGLE_LIST *plist);
static void bounce_producer_unload_list(SINGLE_LIST *plist);

void bounce_producer_init(const char* separator)
{
	strcpy(g_separator, separator);
	g_default_resource = NULL;
}

int bounce_producer_run(const char *data_path)
{
	single_list_init(&g_resource_list);
	pthread_rwlock_init(&g_list_lock, NULL);
	if (!bounce_producer_refresh(data_path))
		return -1;
	return 0;
}

static void bounce_producer_unload_list(SINGLE_LIST *plist)
{
	int i;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;

	while ((pnode = single_list_pop_front(plist)) != nullptr) {
		presource = (RESOURCE_NODE*)pnode->pdata;
		for (i=0; i<BOUNCE_TOTAL_NUM; i++) {
			free(presource->content[i]);
		}
		free(presource);
	}
}

/*
 *	refresh the current resource list
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
BOOL bounce_producer_refresh(const char *data_path)
{
	struct dirent *direntp;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;
	SINGLE_LIST resource_list, temp_list;
	RESOURCE_NODE *pdefault;

	single_list_init(&resource_list);
	auto dinfo = opendir_sd("mail_bounce", data_path);
	if (dinfo.m_dir == nullptr) {
		printf("[exmdb_provider]: opendir_sd(mail_bounce) %s: %s\n",
		       dinfo.m_path.c_str(), strerror(errno));
		return FALSE;
	}
	while ((direntp = readdir(dinfo.m_dir.get())) != nullptr) {
		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;
		if (!bounce_producer_check_subdir(dinfo.m_path.c_str(), direntp->d_name))
			continue;
		bounce_producer_load_subdir(dinfo.m_path.c_str(), direntp->d_name, &resource_list);
	}

	pdefault = NULL;
	/* check "ascii" charset */
	for (pnode=single_list_get_head(&resource_list); NULL!=pnode;
		pnode=single_list_get_after(&resource_list, pnode)) {
		presource = (RESOURCE_NODE*)pnode->pdata;
		if (0 == strcasecmp(presource->charset, "ascii")) {
			pdefault = presource;
			break;
		}
	}
	if (NULL == pdefault) {
		printf("[exmdb_provider]: there are no "
			"\"ascii\" bounce mail templates in %s\n", dinfo.m_path.c_str());
		bounce_producer_unload_list(&resource_list);
		single_list_free(&resource_list);
		return FALSE;
	}
	pthread_rwlock_wrlock(&g_list_lock);
	temp_list = g_resource_list;
	g_resource_list = resource_list;
	g_default_resource = pdefault;
	pthread_rwlock_unlock(&g_list_lock);
	bounce_producer_unload_list(&temp_list);
	single_list_free(&temp_list);
	return TRUE;
}

static BOOL bounce_producer_check_subdir(const char *basedir, const char *dir_name)
{
	DIR *sub_dirp;
	struct dirent *sub_direntp;
	struct stat node_stat;
	char dir_buff[256], sub_buff[256];
	int i, item_num;

	snprintf(dir_buff, GX_ARRAY_SIZE(dir_buff), "%s/%s", basedir, dir_name);
	if (0 != stat(dir_buff, &node_stat) ||
		0 == S_ISDIR(node_stat.st_mode)) {
		return FALSE;
	}
	sub_dirp = opendir(dir_buff);
	item_num = 0;
	while ((sub_direntp = readdir(sub_dirp)) != NULL) {
		if (strcmp(sub_direntp->d_name, ".") == 0 ||
		    strcmp(sub_direntp->d_name, "..") == 0)
			continue;
		snprintf(sub_buff, GX_ARRAY_SIZE(sub_buff), "%s/%s",
		         dir_buff, sub_direntp->d_name);
		if (0 != stat(sub_buff, &node_stat) ||
			0 == S_ISREG(node_stat.st_mode)) {
			continue;
		}
		for (i=0; i<BOUNCE_TOTAL_NUM; i++) {
			if (0 == strcmp(g_resource_table[i], sub_direntp->d_name) &&
				node_stat.st_size < 64*1024) {
				item_num ++;
				break;
			}
		}
	}
	closedir(sub_dirp);
	if (BOUNCE_TOTAL_NUM != item_num) {
		return FALSE;
	}
	return TRUE;
}

static void bounce_producer_load_subdir(const char *basedir,
    const char *dir_name, SINGLE_LIST *plist)
{
	DIR *sub_dirp;
	struct dirent *sub_direntp;
	struct stat node_stat;
	char dir_buff[256], sub_buff[256];
	int fd, i, j, k;
	int parsed_length, until_tag;
	FORMAT_DATA temp;
	MIME_FIELD mime_field;

	auto presource = me_alloc<RESOURCE_NODE>();
	if (NULL == presource) {
		printf("[exmdb_provider]: Failed to allocate resource node memory\n");
		return;
	}
	/* fill the struct with initial data */
	for (i=0; i<BOUNCE_TOTAL_NUM; i++) {
		presource->content[i] = NULL;
		for (j=0; j<TAG_TOTAL_LEN; j++) {
			presource->format[i][j].position = -1;
			presource->format[i][j].tag = j;
		}
	}
	presource->node.pdata = presource;
	snprintf(dir_buff, GX_ARRAY_SIZE(dir_buff), "%s/%s", basedir, dir_name);
	sub_dirp = opendir(dir_buff);
	while ((sub_direntp = readdir(sub_dirp)) != NULL) {
		if (strcmp(sub_direntp->d_name, ".") == 0 ||
		    strcmp(sub_direntp->d_name, "..") == 0)
			continue;
		snprintf(sub_buff, GX_ARRAY_SIZE(sub_buff), "%s/%s",
		         dir_buff, sub_direntp->d_name);
		if (0 != stat(sub_buff, &node_stat) ||
			0 == S_ISREG(node_stat.st_mode)) {
			continue;
		}
		/* compare file name with the resource table and get the index */
		for (i=0; i<BOUNCE_TOTAL_NUM; i++) {
			if (0 == strcmp(g_resource_table[i], sub_direntp->d_name)) {
				break;
			}
		}
		if (BOUNCE_TOTAL_NUM == i) {
			continue;
		}
		presource->content[i] = me_alloc<char>(node_stat.st_size);
		if (NULL == presource->content[i]) {
			closedir(sub_dirp);
			goto FREE_RESOURCE;
		}
		fd = open(sub_buff, O_RDONLY);
		if (-1 == fd) {
			closedir(sub_dirp);
			goto FREE_RESOURCE;
		}
		if (node_stat.st_size != read(fd, presource->content[i],
			node_stat.st_size)) {
			close(fd);
			closedir(sub_dirp);
			goto FREE_RESOURCE;
		}
		close(fd);
		fd = -1;
		
		j = 0;
		while (j < node_stat.st_size) {
			parsed_length = parse_mime_field(presource->content[i] + j,
						node_stat.st_size - j, &mime_field);
			j += parsed_length;
			if (0 != parsed_length) {
				if (0 == strncasecmp("Content-Type", 
					mime_field.field_name, 12)) {
					memcpy(presource->content_type[i],
						mime_field.field_value, mime_field.field_value_len);
					presource->content_type[i][mime_field.field_value_len] = 0;
				} else if (0 == strncasecmp("From",
					mime_field.field_name, 4)) {
					memcpy(presource->from[i],
						mime_field.field_value, mime_field.field_value_len);
					presource->from[i][mime_field.field_value_len] = 0;
				} else if (0 == strncasecmp("Subject",
					mime_field.field_name, 7)) {
					memcpy(presource->subject[i],
						mime_field.field_value, mime_field.field_value_len);
					presource->subject[i][mime_field.field_value_len] = 0;
				}
				if (presource->content[i][j] == '\n') {
					++j;
					break;
				} else if (presource->content[i][j] == '\r' &&
				    presource->content[i][j+1] == '\n') {
					j += 2;
					break;
				}
			} else {
				printf("[exmdb_provider]: bounce mail %s format error\n",
					sub_buff);
				closedir(sub_dirp);
				goto FREE_RESOURCE;
			}
		}
		/* find tags in file content and mark the position */
		presource->format[i][TAG_BEGIN].position = j;
		for (; j<node_stat.st_size; j++) {
			if ('<' == presource->content[i][j]) {
				for (k=0; k<TAG_TOTAL_LEN; k++) {
					if (0 == strncasecmp(presource->content[i] + j,
						g_tags[k].name, g_tags[k].length)) {
						presource->format[i][k + 1].position = j;
						break;
					}
				}
			}
		}
		presource->format[i][TAG_END].position = node_stat.st_size;
	
		until_tag = TAG_TOTAL_LEN;

		for (j=TAG_BEGIN+1; j<until_tag; j++) {
			if (-1 == presource->format[i][j].position) {
				printf("[exmdb_provider]: format error in %s, lack of "
						"tag %s\n", sub_buff, g_tags[j-1].name);
				closedir(sub_dirp);
				goto FREE_RESOURCE;
			}
		}

		/* sort the tags ascending */
		for (j=TAG_BEGIN+1; j<until_tag; j++) {
			for (k=TAG_BEGIN+1; k<until_tag; k++) {
				if (presource->format[i][j].position <
					presource->format[i][k].position) {
					temp = presource->format[i][j];
					presource->format[i][j] = presource->format[i][k];
					presource->format[i][k] = temp;
				}
			}
		}
	}
	closedir(sub_dirp);
	HX_strlcpy(presource->charset, dir_name, GX_ARRAY_SIZE(presource->charset));
	single_list_append_as_tail(plist, &presource->node);
	return;

 FREE_RESOURCE:
	for (i=0; i<BOUNCE_TOTAL_NUM; i++) {
		if (NULL != presource->content[i]) {
			free(presource->content[i]);
		}
	}
	free(presource);
}

void bounce_producer_stop()
{
	bounce_producer_unload_list(&g_resource_list);
	pthread_rwlock_destroy(&g_list_lock);
	single_list_free(&g_resource_list);
}

void bounce_producer_free()
{
	g_default_resource = NULL;
}

static int bounce_producer_get_mail_parts(sqlite3 *psqlite,
	uint64_t message_id, char *parts)
{
	int offset;
	int tmp_len;
	void *pvalue;
	BOOL b_first;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	uint64_t attachment_id;
	
	offset = 0;
	b_first = FALSE;
	sprintf(sql_string, "SELECT attachment_id FROM "
	        "attachments WHERE message_id=%llu", static_cast<unsigned long long>(message_id));
	if (!gx_sql_prep(psqlite, sql_string, &pstmt))
		return 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		attachment_id = sqlite3_column_int64(pstmt, 0);
		if (FALSE == common_util_get_property(
			ATTACHMENT_PROPERTIES_TABLE, attachment_id, 0,
			psqlite,PROP_TAG_ATTACHLONGFILENAME, &pvalue)) {
			sqlite3_finalize(pstmt);
			return 0;
		}
		if (NULL == pvalue) {
			continue;
		}
		tmp_len = strlen(static_cast<char *>(pvalue));
		if (offset + tmp_len < 128*1024) {
			if (TRUE == b_first) {
				strcpy(parts + offset, g_separator);
				offset += strlen(g_separator);
			}
			memcpy(parts + offset, pvalue, tmp_len);
			offset += tmp_len;
			b_first = TRUE;
		}
	}
	sqlite3_finalize(pstmt);
	return offset;
}

BOOL bounce_producer_make_content(const char *from,
	const char *rcpt, sqlite3 *psqlite, uint64_t message_id,
	int bounce_type, char *mime_from, char *subject,
	char *content_type, char *pcontent)
{
	char *ptr;
	void *pvalue;
	int prev_pos;
	time_t cur_time;
	char charset[32];
	char date_buff[128];
	struct tm time_buff;
	const char *pcharset;
	int i, len, until_tag;
	uint32_t message_size;
	const struct state *sp;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;
	char lang[32], time_zone[64];

	time(&cur_time);
	ptr = pcontent;
	charset[0] = '\0';
	time_zone[0] = '\0';
	if (TRUE == common_util_get_user_lang(from, lang)) {
		common_util_lang_to_charset(lang, charset);
		common_util_get_timezone(from, time_zone);
	}
	if('\0' != time_zone[0]) {
		sp = tz_alloc(time_zone);
		if (NULL == sp) {
			return FALSE;
		}
		tz_localtime_r(sp, &cur_time, &time_buff);
		tz_free(sp);
	} else {
		localtime_r(&cur_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	if (FALSE == common_util_get_property(
		MESSAGE_PROPERTIES_TABLE, message_id, 0,
		psqlite, PROP_TAG_MESSAGESIZE, &pvalue) ||
		NULL == pvalue) {
		return FALSE;
	}
	message_size = *(uint32_t*)pvalue;
	if ('\0' == charset[0]) {
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0,
			psqlite, PROP_TAG_INTERNETCODEPAGE, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue) {
			strcpy(charset, "ascii");
		} else {
			pcharset = common_util_cpid_to_charset(*(uint32_t*)pvalue);
			if (NULL == pcharset) {
				strcpy(charset, "ascii");
			} else {
				HX_strlcpy(charset, pcharset, GX_ARRAY_SIZE(charset));
			}
		}
	}
	presource = NULL;
	pthread_rwlock_rdlock(&g_list_lock);
	for (pnode=single_list_get_head(&g_resource_list); NULL!=pnode;
		pnode=single_list_get_after(&g_resource_list, pnode)) {
		if (0 == strcasecmp(((RESOURCE_NODE*)pnode->pdata)->charset, charset)) {
			presource = (RESOURCE_NODE*)pnode->pdata;
			break;
		}
	}
	if (NULL == presource) {
		presource = g_default_resource;
	}
	prev_pos = presource->format[bounce_type][TAG_BEGIN].position;
	until_tag = TAG_TOTAL_LEN;
	for (i=TAG_BEGIN+1; i<until_tag; i++) {
		len = presource->format[bounce_type][i].position - prev_pos;
		memcpy(ptr, presource->content[bounce_type] + prev_pos, len);
		prev_pos = presource->format[bounce_type][i].position +
					g_tags[presource->format[bounce_type][i].tag-1].length;
		ptr += len;
		switch (presource->format[bounce_type][i].tag) {
		case TAG_TIME:
			len = gx_snprintf(ptr, 128, "%s", date_buff);
			ptr += len;
			break;
		case TAG_FROM:
			strcpy(ptr, from);
			ptr += strlen(from);
			break;
		case TAG_RCPT:
			strcpy(ptr, rcpt);
			ptr += strlen(rcpt);
			break;
		case TAG_SUBJECT:
			if (FALSE == common_util_get_property(
				MESSAGE_PROPERTIES_TABLE, message_id, 0,
				psqlite, PROP_TAG_SUBJECT, &pvalue)) {
				pthread_rwlock_unlock(&g_list_lock);
				return FALSE;
			}
			if (NULL != pvalue) {
				len = strlen(static_cast<char *>(pvalue));
				memcpy(ptr, pvalue, len);
				 ptr += len;
			}
			break;
		case TAG_PARTS:
			len = bounce_producer_get_mail_parts(psqlite, message_id, ptr);
			ptr += len;
			break;
		case TAG_LENGTH:
			bytetoa(message_size, ptr);
			len = strlen(ptr);
			ptr += len;
			break;
		}
	}
	len = presource->format[bounce_type][TAG_END].position - prev_pos;
	memcpy(ptr, presource->content[bounce_type] + prev_pos, len);
	ptr += len;
	if (NULL != mime_from) {
		strcpy(mime_from, presource->from[bounce_type]);
	}
	if (NULL != subject) {
		strcpy(subject, presource->subject[bounce_type]);
	}
	if (NULL != content_type) {
		strcpy(content_type, presource->content_type[bounce_type]);
	}
	pthread_rwlock_unlock(&g_list_lock);
	*ptr = '\0';
	return TRUE;
}

BOOL bounce_producer_make(const char *from, const char *rcpt,
	sqlite3 *psqlite, uint64_t message_id, int bounce_type,
	MAIL *pmail)
{
	DSN dsn;
	MIME *pmime;
	MIME *phead;
	time_t cur_time;
	char subject[1024];
	struct tm time_buff;
	char mime_from[256];
	char tmp_buff[1024];
	char date_buff[128];
	char content_type[128];
	DSN_FIELDS *pdsn_fields;
	char content_buff[256*1024];
	
	if (FALSE == bounce_producer_make_content(from, rcpt,
		psqlite, message_id, bounce_type, mime_from,
		subject, content_type, content_buff)) {
		return FALSE;
	}
	phead = mail_add_head(pmail);
	if (NULL == phead) {
		return FALSE;
	}
	pmime = phead;
	mime_set_content_type(pmime, "multipart/report");
	mime_set_content_param(pmime, "report-type", "delivery-status");
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	mime_set_field(pmime, "From", mime_from);
	snprintf(tmp_buff, 256, "<%s>", from);
	mime_set_field(pmime, "To", tmp_buff);
	mime_set_field(pmime, "MIME-Version", "1.0");
	mime_set_field(pmime, "X-Auto-Response-Suppress", "All");
	time(&cur_time);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	mime_set_field(pmime, "Date", date_buff);
	mime_set_field(pmime, "Subject", subject);
	pmime = mail_add_child(pmail, phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		return FALSE;
	}
	mime_set_content_type(pmime, content_type);
	mime_set_content_param(pmime, "charset", "\"utf-8\"");
	if (FALSE == mime_write_content(pmime, content_buff,
		strlen(content_buff), MIME_ENCODING_BASE64)) {
		return FALSE;
	}
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn_append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	dsn_append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn_new_rcpt_fields(&dsn);
	if (NULL == pdsn_fields) {
		dsn_free(&dsn);
		return FALSE;
	}
	snprintf(tmp_buff, 1024, "rfc822;%s", rcpt);
	dsn_append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	dsn_append_field(pdsn_fields, "Action", "failed");
	dsn_append_field(pdsn_fields, "Status", "5.0.0");
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn_append_field(pdsn_fields, "Remote-MTA", tmp_buff);
	
	if (dsn_serialize(&dsn, content_buff, GX_ARRAY_SIZE(content_buff))) {
		pmime = mail_add_child(pmail, phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			mime_set_content_type(pmime, "message/delivery-status");
			mime_write_content(pmime, content_buff,
				strlen(content_buff), MIME_ENCODING_NONE);
		}
	}
	dsn_free(&dsn);
	return TRUE;
}
