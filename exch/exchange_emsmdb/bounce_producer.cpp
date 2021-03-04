// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstring>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "bounce_producer.h"
#include <gromox/fileio.h>
#include <gromox/proc_common.h>
#include "common_util.h"
#include <gromox/single_list.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/timezone.hpp>
#include <gromox/rop_util.hpp>
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
	TAG_RCPTS,
	TAG_USER,
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
 * <time> <from> <rcpts> <rcpt>
 * <subject> <parts> <length>
 */
struct RESOURCE_NODE {
	SINGLE_LIST_NODE	node;
	char				charset[32];
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
	"BOUNCE_NOTIFY_READ",
	"BOUNCE_NOTIFY_NON_READ"
};
static TAG_ITEM g_tags[] = {
	{"<time>", 6},
	{"<from>", 6},
	{"<user>", 6},
	{"<rcpts>", 7},
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
	auto dinfo = opendir_sd("notify_bounce", data_path);
	if (dinfo.m_dir == nullptr) {
		printf("[exmdb_provider]: opendir_sd(notify_bounce) %s: %s\n",
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

static void bounce_producer_load_subdir(const char *basedir, const char *dir_name, SINGLE_LIST *plist)
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

static int bounce_producer_get_mail_parts(
	ATTACHMENT_LIST *pattachments, char *parts)
{
	int i;
	int offset;
	int tmp_len;
	void *pvalue;
	BOOL b_first;
	
	offset = 0;
	b_first = FALSE;
	for (i=0; i<pattachments->count; i++) {
		pvalue = common_util_get_propvals(
			&pattachments->pplist[i]->proplist,
			PROP_TAG_ATTACHLONGFILENAME);
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
	return offset;
}

static int bounce_producer_get_rcpts(
	TARRAY_SET *prcpts, char *rcpts)
{
	int i;
	int offset;
	int tmp_len;
	void *pvalue;
	BOOL b_first;
	
	offset = 0;
	b_first = FALSE;
	for (i=0; i<prcpts->count; i++) {
		pvalue = common_util_get_propvals(
			prcpts->pparray[i], PROP_TAG_SMTPADDRESS);
		if (NULL == pvalue) {
			continue;
		}
		tmp_len = strlen(static_cast<char *>(pvalue));
		if (offset + tmp_len < 128*1024) {
			if (TRUE == b_first) {
				strcpy(rcpts + offset, g_separator);
				offset += strlen(g_separator);
			}
			memcpy(rcpts + offset, pvalue, tmp_len);
			offset += tmp_len;
			b_first = TRUE;
		}
	}
	return offset;
}

static BOOL bounce_producer_make_content(const char *username,
	MESSAGE_CONTENT *pbrief, int bounce_type, char *subject,
	char *content_type, char *pcontent)
{
	char *ptr;
	void *pvalue;
	int prev_pos;
	time_t tmp_time;
	char charset[32];
	const char *from;
	char date_buff[128];
	struct tm time_buff;
	const char *pcharset;
	int i, len, until_tag;
	uint32_t message_size;
	const struct state *sp;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;
	char lang[32], time_zone[64];

	ptr = pcontent;
	charset[0] = '\0';
	time_zone[0] = '\0';
	pvalue = common_util_get_propvals(
		&pbrief->proplist, PROP_TAG_CLIENTSUBMITTIME);
	if (NULL == pvalue) {
		time(&tmp_time);
	} else {
		tmp_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
	}
	from = static_cast<char *>(common_util_get_propvals(&pbrief->proplist,
	       PROP_TAG_SENTREPRESENTINGSMTPADDRESS));
	if (NULL == from) {
		from = "none@none";
	}
	if (TRUE == common_util_get_user_lang(from, lang)) {
		common_util_lang_to_charset(lang, charset);
		common_util_get_timezone(from, time_zone);
	}
	if('\0' != time_zone[0]) {
		sp = tz_alloc(time_zone);
		if (NULL == sp) {
			return FALSE;
		}
		tz_localtime_r(sp, &tmp_time, &time_buff);
		tz_free(sp);
	} else {
		localtime_r(&tmp_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	pvalue = common_util_get_propvals(
		&pbrief->proplist, PROP_TAG_MESSAGESIZE);
	if (NULL == pvalue) {
		return FALSE;
	}
	message_size = *(uint32_t*)pvalue;
	if ('\0' == charset[0]) {
		pvalue = common_util_get_propvals(
			&pbrief->proplist, PROP_TAG_INTERNETCODEPAGE);
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
		case TAG_USER:
			strcpy(ptr, username);
			ptr += strlen(username);
			break;
		case TAG_RCPTS:
			len = bounce_producer_get_rcpts(
				pbrief->children.prcpts, ptr);
			ptr += len;
			break;
		case TAG_SUBJECT:
			pvalue = common_util_get_propvals(
				&pbrief->proplist, PROP_TAG_SUBJECT);
			if (NULL != pvalue) {
				len = strlen(static_cast<char *>(pvalue));
				memcpy(ptr, pvalue, len);
				ptr += len;
			}
			break;
		case TAG_PARTS:
			len = bounce_producer_get_mail_parts(
				pbrief->children.pattachments, ptr);
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

BOOL bounce_producer_make(const char *username,
	MESSAGE_CONTENT *pbrief, int bounce_type, MAIL *pmail)
{
	DSN dsn;
	MIME *pmime;
	MIME *phead;
	void *pvalue;
	size_t out_len;
	time_t cur_time;
	char mime_to[1024];
	char subject[1024];
	char tmp_buff[1024];
	char date_buff[128];
	struct tm time_buff;
	char mime_from[1024];
	char content_type[128];
	DSN_FIELDS *pdsn_fields;
	char content_buff[256*1024];
	
	if (TRUE == common_util_get_user_displayname(
		username, tmp_buff) && '\0' != tmp_buff[0]) {
		memcpy(mime_from, "=?utf-8?b?", 10);
		encode64(tmp_buff, strlen(tmp_buff), mime_from + 10,
			sizeof(mime_from) - 13, &out_len);
		memcpy(mime_from + 10 + out_len, "?=", 3);
	} else {
		mime_from[0] = '\0';
	}
	if (FALSE == bounce_producer_make_content(username, pbrief,
		bounce_type, subject, content_type, content_buff)) {
		return FALSE;
	}
	phead = mail_add_head(pmail);
	if (NULL == phead) {
		return FALSE;
	}
	pmime = phead;
	mime_set_content_type(pmime, "multipart/report");
	mime_set_content_param(pmime, "report-type", "disposition-notification");
	pvalue = common_util_get_propvals(
		&pbrief->proplist, PROP_TAG_CONVERSATIONINDEX);
	if (NULL != pvalue) {
		if (0 == encode64(((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, tmp_buff,
			sizeof(tmp_buff), &out_len)) {
			mime_set_field(pmime, "Thread-Index", tmp_buff);
		}
	}
	snprintf(tmp_buff, sizeof(tmp_buff), "\"%s\" <%s>", mime_from, username);
	mime_set_field(pmime, "From", tmp_buff);
	snprintf(tmp_buff, 256, "<%s>", username);
	pvalue = common_util_get_propvals(&pbrief->proplist,
						PROP_TAG_SENTREPRESENTINGNAME);
	if (NULL != pvalue && '\0' != ((char*)pvalue)[0]) {
		memcpy(mime_to, "\"=?utf-8?b?", 11);
		encode64(pvalue, strlen(static_cast<char *>(pvalue)), mime_to + 11,
			sizeof(mime_to) - 15, &out_len);
		memcpy(mime_to + 11 + out_len, "?=\"", 4);
	} else {
		mime_to[0] = '\0';
	}
	pvalue = common_util_get_propvals(&pbrief->proplist,
				PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
	if (NULL != pvalue) {
		out_len = strlen(mime_to);
		if (0 != out_len) {
			mime_to[out_len] = ' ';
			out_len ++;
		}
		snprintf(mime_to + out_len, sizeof(mime_to) - out_len, "<%s>",
		         static_cast<const char *>(pvalue));
	}
	if ('\0' != mime_to[0]) {
		mime_set_field(pmime, "To", mime_to);
	}
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
	snprintf(tmp_buff, 1024, "rfc822;%s", username);
	dsn_append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	switch (bounce_type) {
	case BOUNCE_NOTIFY_READ:
		dsn_append_field(pdsn_fields, "Disposition",
			"automatic-action/MDN-sent-automatically; displayed");
		break;
	case BOUNCE_NOTIFY_NON_READ:
		dsn_append_field(pdsn_fields, "Disposition",
			"manual-action/MDN-sent-automatically; deleted");
		break;
	}
	pvalue = common_util_get_propvals(
		&pbrief->proplist, PROP_TAG_INTERNETMESSAGEID);
	if (NULL != pvalue) {
		dsn_append_field(pdsn_fields, "Original-Message-ID", static_cast<char *>(pvalue));
	}
	pvalue = common_util_get_propvals(
		&pbrief->proplist, PROP_TAG_PARENTKEY);
	if (NULL != pvalue) {
		encode64(((BINARY*)pvalue)->pb, ((BINARY*)pvalue)->cb,
			tmp_buff, sizeof(tmp_buff), &out_len);
		dsn_append_field(pdsn_fields,
			"X-MSExch-Correlation-Key", tmp_buff);
	}
	if ('\0' != mime_from[0]) {
		dsn_append_field(pdsn_fields, "X-Display-Name", mime_from);
	}
	if (dsn_serialize(&dsn, content_buff, GX_ARRAY_SIZE(content_buff))) {
		pmime = mail_add_child(pmail, phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			mime_set_content_type(pmime, "message/disposition-notification");
			mime_write_content(pmime, content_buff,
				strlen(content_buff), MIME_ENCODING_NONE);
		}
	}
	dsn_free(&dsn);
	return TRUE;
}
