// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "bounce_producer.h"
#include <gromox/fileio.h>
#include <gromox/proc_common.h>
#include "common_util.h"
#include <gromox/mail_func.hpp>
#include <gromox/timezone.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include <gromox/dsn.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#include <cstdio>
#include <fcntl.h>
#include <ctime>

using namespace std::string_literals;
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

namespace {

struct FORMAT_DATA {
	int	position;
	int tag;
};

/*
 * <time> <from> <rcpts> <rcpt>
 * <subject> <parts> <length>
 */
struct RESOURCE_NODE {
	char				charset[32];
	char				subject[BOUNCE_TOTAL_NUM][256];
	char				content_type[BOUNCE_TOTAL_NUM][256];
	std::unique_ptr<char[]> content[BOUNCE_TOTAL_NUM];
	FORMAT_DATA			format[BOUNCE_TOTAL_NUM][TAG_TOTAL_LEN + 1];
};

struct TAG_ITEM {
	const char	*name;
	int			length;
};

}

static char g_separator[16];
static std::vector<RESOURCE_NODE> g_resource_list;
static RESOURCE_NODE *g_default_resource;
static std::shared_mutex g_list_lock;
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
static void bounce_producer_load_subdir(const char *basedir, const char *dir_name, std::vector<RESOURCE_NODE> &);

void bounce_producer_init(const char* separator)
{
	gx_strlcpy(g_separator, separator, GX_ARRAY_SIZE(g_separator));
	g_default_resource = NULL;
}

int bounce_producer_run(const char *data_path)
{
	if (!bounce_producer_refresh(data_path))
		return -1;
	return 0;
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
	std::vector<RESOURCE_NODE> resource_list;

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
		bounce_producer_load_subdir(dinfo.m_path.c_str(), direntp->d_name, resource_list);
	}

	auto pdefault = std::find_if(resource_list.begin(), resource_list.end(),
	                [&](const RESOURCE_NODE &n) { return strcasecmp(n.charset, "ascii") == 0; });
	if (pdefault == resource_list.end()) {
		printf("[exmdb_provider]: there are no "
			"\"ascii\" bounce mail templates in %s\n", dinfo.m_path.c_str());
		return FALSE;
	}
	std::unique_lock wr_hold(g_list_lock);
	g_default_resource = &*pdefault;
	std::swap(g_resource_list, resource_list);
	return TRUE;
}

static BOOL bounce_producer_check_subdir(const char *basedir, const char *dir_name)
{
	struct dirent *sub_direntp;
	struct stat node_stat;
	char dir_buff[256], sub_buff[256];
	int i, item_num;

	snprintf(dir_buff, GX_ARRAY_SIZE(dir_buff), "%s/%s", basedir, dir_name);
	auto sub_dirp = opendir(dir_buff);
	if (sub_dirp == nullptr)
		return FALSE;
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
    const char *dir_name, std::vector<RESOURCE_NODE> &plist)
{
	DIR *sub_dirp;
	struct dirent *sub_direntp;
	struct stat node_stat;
	char dir_buff[256], sub_buff[256];
	int i, j, k, until_tag;
	FORMAT_DATA temp;
	MIME_FIELD mime_field;
	RESOURCE_NODE rnode, *presource = &rnode;

	/* fill the struct with initial data */
	for (i=0; i<BOUNCE_TOTAL_NUM; i++) {
		for (j=0; j<TAG_TOTAL_LEN; j++) {
			presource->format[i][j].position = -1;
			presource->format[i][j].tag = j;
		}
	}
	snprintf(dir_buff, GX_ARRAY_SIZE(dir_buff), "%s/%s", basedir, dir_name);
	sub_dirp = opendir(dir_buff);
	while ((sub_direntp = readdir(sub_dirp)) != NULL) {
		if (strcmp(sub_direntp->d_name, ".") == 0 ||
		    strcmp(sub_direntp->d_name, "..") == 0)
			continue;
		/* compare file name with the resource table and get the index */
		for (i=0; i<BOUNCE_TOTAL_NUM; i++) {
			if (0 == strcmp(g_resource_table[i], sub_direntp->d_name)) {
				break;
			}
		}
		if (BOUNCE_TOTAL_NUM == i) {
			continue;
		}
		snprintf(sub_buff, GX_ARRAY_SIZE(sub_buff), "%s/%s",
		         dir_buff, sub_direntp->d_name);
		wrapfd fd = open(sub_buff, O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
		    !S_ISREG(node_stat.st_mode))
			continue;
		try {
			presource->content[i] = std::make_unique<char[]>(node_stat.st_size);
		} catch (const std::bad_alloc &) {
			closedir(sub_dirp);
			return;
		}
		if (read(fd.get(), presource->content[i].get(), node_stat.st_size) != node_stat.st_size) {
			closedir(sub_dirp);
			return;
		}
		fd.close();
		j = 0;
		while (j < node_stat.st_size) {
			auto parsed_length = parse_mime_field(&presource->content[i][j],
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
				return;
			}
		}
		/* find tags in file content and mark the position */
		presource->format[i][TAG_BEGIN].position = j;
		for (; j<node_stat.st_size; j++) {
			if ('<' == presource->content[i][j]) {
				for (k=0; k<TAG_TOTAL_LEN; k++) {
					if (strncasecmp(&presource->content[i][j], g_tags[k].name, g_tags[k].length) == 0) {
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
				return;
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
	gx_strlcpy(presource->charset, dir_name, GX_ARRAY_SIZE(presource->charset));
	plist.push_back(std::move(rnode));
}

static int bounce_producer_get_mail_parts(
	ATTACHMENT_LIST *pattachments, char *parts)
{
	int i;
	int offset;
	int tmp_len;
	BOOL b_first;
	
	offset = 0;
	b_first = FALSE;
	for (i=0; i<pattachments->count; i++) {
		auto pvalue = common_util_get_propvals(&pattachments->pplist[i]->proplist, PR_ATTACH_LONG_FILENAME);
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

static size_t bounce_producer_get_rcpts(TARRAY_SET *prcpts, char *rcpts)
{
	size_t offset = 0;
	BOOL b_first;
	
	b_first = FALSE;
	for (size_t i = 0; i < prcpts->count; ++i) {
		auto pvalue = common_util_get_propvals(prcpts->pparray[i], PR_SMTP_ADDRESS);
		if (NULL == pvalue) {
			continue;
		}
		auto tmp_len = strlen(static_cast<char *>(pvalue));
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
	char lang[32], time_zone[64];

	ptr = pcontent;
	charset[0] = '\0';
	time_zone[0] = '\0';
	auto pvalue = common_util_get_propvals(&pbrief->proplist, PROP_TAG_CLIENTSUBMITTIME);
	tmp_time = pvalue == nullptr ? time(nullptr) :
	           rop_util_nttime_to_unix(*static_cast<uint64_t *>(pvalue));
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
	pvalue = common_util_get_propvals(&pbrief->proplist, PR_MESSAGE_SIZE);
	if (NULL == pvalue) {
		return FALSE;
	}
	message_size = *(uint32_t*)pvalue;
	if ('\0' == charset[0]) {
		pvalue = common_util_get_propvals(&pbrief->proplist, PR_INTERNET_CPID);
		if (NULL == pvalue) {
			strcpy(charset, "ascii");
		} else {
			pcharset = common_util_cpid_to_charset(*(uint32_t*)pvalue);
			gx_strlcpy(charset, pcharset != nullptr ? pcharset : "ascii", arsizeof(charset));
		}
	}
	std::shared_lock rd_hold(g_list_lock);
	auto it = std::find_if(g_resource_list.begin(), g_resource_list.end(),
	          [&](const RESOURCE_NODE &n) { return strcasecmp(n.charset, charset) == 0; });
	auto presource = it != g_resource_list.end() ? &*it : g_default_resource;
	prev_pos = presource->format[bounce_type][TAG_BEGIN].position;
	until_tag = TAG_TOTAL_LEN;
	for (i=TAG_BEGIN+1; i<until_tag; i++) {
		len = presource->format[bounce_type][i].position - prev_pos;
		memcpy(ptr, &presource->content[bounce_type][prev_pos], len);
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
			pvalue = common_util_get_propvals(&pbrief->proplist, PR_SUBJECT);
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
	memcpy(ptr, &presource->content[bounce_type][prev_pos], len);
	ptr += len;
	if (NULL != subject) {
		strcpy(subject, presource->subject[bounce_type]);
	}
	if (NULL != content_type) {
		strcpy(content_type, presource->content_type[bounce_type]);
	}
	*ptr = '\0';
	return TRUE;
}

BOOL bounce_producer_make(const char *username,
	MESSAGE_CONTENT *pbrief, int bounce_type, MAIL *pmail)
{
	DSN dsn;
	MIME *pmime;
	MIME *phead;
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
	auto pvalue = common_util_get_propvals(&pbrief->proplist, PROP_TAG_CONVERSATIONINDEX);
	if (NULL != pvalue) {
		if (0 == encode64(((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, tmp_buff,
			sizeof(tmp_buff), &out_len)) {
			mime_set_field(pmime, "Thread-Index", tmp_buff);
		}
	}
	std::string t_addr;
	try {
		t_addr = "\""s + mime_from + "\" <" + username + ">";
		mime_set_field(pmime, "From", t_addr.c_str());
		t_addr = "<"s + username + ">";
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1481: ENOMEM\n");
		return false;
	}
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
	try {
		t_addr = "rfc822;"s + username;
		dsn_append_field(pdsn_fields, "Final-Recipient", t_addr.c_str());
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1482: ENOMEM\n");
	}
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
	pvalue = common_util_get_propvals(&pbrief->proplist, PR_PARENT_KEY);
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
