// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"
#include "common_util.h"

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

namespace {

struct FORMAT_DATA {
	int	position;
	int tag;
};

/*
 * <time> <from> <rcpt>
 * <subject> <parts> <length>
 */
struct RESOURCE_NODE {
	char				charset[32];
	char from[BOUNCE_TOTAL_NUM][UADDR_SIZE];
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
static constexpr const char *g_resource_table[] = {
	"BOUNCE_AUTO_RESPONSE", "BOUNCE_MAIL_TOO_LARGE",
	"BOUNCE_CANNOT_DISPLAY", "BOUNCE_GENERIC_ERROR"
};
static constexpr TAG_ITEM g_tags[] = {
	{"<time>", 6},
	{"<from>", 6},
	{"<rcpt>", 6},
	{"<subject>", 9},
	{"<parts>", 7},
	{"<length>", 8}
};

static BOOL bounce_producer_check_subdir(const std::string &basedir, const char *dir_name);
static void bounce_producer_load_subdir(const std::string &basedir, const char *dir_name, std::vector<RESOURCE_NODE> &);

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
BOOL bounce_producer_refresh(const char *data_path) try
{
	struct dirent *direntp;
	std::vector<RESOURCE_NODE> resource_list;

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
		if (!bounce_producer_check_subdir(dinfo.m_path, direntp->d_name))
			continue;
		bounce_producer_load_subdir(dinfo.m_path, direntp->d_name, resource_list);
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
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1502: ENOMEM\n");
	return false;
}

static BOOL bounce_producer_check_subdir(const std::string &basedir,
    const char *dir_name)
{
	struct dirent *sub_direntp;
	struct stat node_stat;

	auto dir_buf = basedir + "/" + dir_name;
	auto sub_dirp = opendir_sd(dir_buf.c_str(), nullptr);
	if (sub_dirp.m_dir == nullptr)
		return FALSE;
	size_t item_num = 0;
	while ((sub_direntp = readdir(sub_dirp.m_dir.get())) != nullptr) {
		if (strcmp(sub_direntp->d_name, ".") == 0 ||
		    strcmp(sub_direntp->d_name, "..") == 0)
			continue;
		auto sub_buf = dir_buf + "/" + sub_direntp->d_name;
		if (stat(sub_buf.c_str(), &node_stat) != 0 ||
		    !S_ISREG(node_stat.st_mode))
			continue;
		for (size_t i = 0; i < BOUNCE_TOTAL_NUM; ++i) {
			if (0 == strcmp(g_resource_table[i], sub_direntp->d_name) &&
				node_stat.st_size < 64*1024) {
				item_num ++;
				break;
			}
		}
	}
	return item_num == BOUNCE_TOTAL_NUM ? TRUE : false;
}

static void bounce_producer_load_subdir(const std::string &basedir,
    const char *dir_name, std::vector<RESOURCE_NODE> &plist)
{
	struct dirent *sub_direntp;
	struct stat node_stat;
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
	auto dir_buf = basedir + "/" + dir_name;
	auto sub_dirp = opendir_sd(dir_buf.c_str(), nullptr);
	if (sub_dirp.m_dir != nullptr) while ((sub_direntp = readdir(sub_dirp.m_dir.get())) != nullptr) {
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
		auto sub_buf = dir_buf + "/" + sub_direntp->d_name;
		wrapfd fd = open(sub_buf.c_str(), O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
		    !S_ISREG(node_stat.st_mode))
			continue;
		presource->content[i] = std::make_unique<char[]>(node_stat.st_size);
		if (read(fd.get(), presource->content[i].get(),
		    node_stat.st_size) != node_stat.st_size)
			return;
		fd.close();
		j = 0;
		while (j < node_stat.st_size) {
			auto parsed_length = parse_mime_field(&presource->content[i][j],
			                     node_stat.st_size - j, &mime_field);
			j += parsed_length;
			if (0 != parsed_length) {
				if (strcasecmp(mime_field.name.c_str(), "Content-Type") == 0)
					gx_strlcpy(presource->content_type[i], mime_field.value.c_str(), std::size(presource->content_type[i]));
				else if (strcasecmp(mime_field.name.c_str(), "From") == 0)
					gx_strlcpy(presource->from[i], mime_field.value.c_str(), std::size(presource->from[i]));
				else if (strcasecmp(mime_field.name.c_str(), "Subject") == 0)
					gx_strlcpy(presource->subject[i], mime_field.value.c_str(), std::size(presource->subject[i]));
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
				       sub_buf.c_str());
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
				       "tag %s\n", sub_buf.c_str(), g_tags[j-1].name);
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
	gx_strlcpy(presource->charset, dir_name, GX_ARRAY_SIZE(presource->charset));
	plist.push_back(std::move(rnode));
}

static int bounce_producer_get_mail_parts(sqlite3 *psqlite,
	uint64_t message_id, char *parts)
{
	int offset;
	int tmp_len;
	void *pvalue;
	BOOL b_first;
	char sql_string[256];
	uint64_t attachment_id;
	
	offset = 0;
	b_first = FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT attachment_id FROM "
	        "attachments WHERE message_id=%llu", static_cast<unsigned long long>(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		attachment_id = sqlite3_column_int64(pstmt, 0);
		if (!cu_get_property(db_table::atx_props,
		    attachment_id, 0, psqlite, PR_ATTACH_LONG_FILENAME, &pvalue))
			return 0;
		if (NULL == pvalue) {
			continue;
		}
		tmp_len = strlen(static_cast<char *>(pvalue));
		if (offset + tmp_len < 128*1024) {
			if (b_first) {
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
	int i, len, until_tag;
	char lang[32], time_zone[64];

	time(&cur_time);
	ptr = pcontent;
	charset[0] = '\0';
	time_zone[0] = '\0';
	if (common_util_get_user_lang(from, lang, arsizeof(lang))) {
		gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
		common_util_get_timezone(from, time_zone, arsizeof(time_zone));
	}
	if('\0' != time_zone[0]) {
		auto sp = tz::tzalloc(time_zone);
		if (NULL == sp) {
			return FALSE;
		}
		tz::localtime_rz(sp, &cur_time, &time_buff);
		tz::tzfree(sp);
	} else {
		localtime_r(&cur_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	if (!cu_get_property(db_table::msg_props, message_id, 0,
	    psqlite, PR_MESSAGE_SIZE, &pvalue) || pvalue == nullptr)
		return FALSE;
	auto message_size = *static_cast<uint32_t *>(pvalue);
	if ('\0' == charset[0]) {
		if (!cu_get_property(db_table::msg_props,
		    message_id, 0, psqlite, PR_INTERNET_CPID, &pvalue))
			return FALSE;
		if (NULL == pvalue) {
			strcpy(charset, "ascii");
		} else {
			auto pcharset = cpid_to_cset(*static_cast<uint32_t *>(pvalue));
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
		case TAG_RCPT:
			strcpy(ptr, rcpt);
			ptr += strlen(rcpt);
			break;
		case TAG_SUBJECT:
			if (!cu_get_property(db_table::msg_props,
			    message_id, 0, psqlite, PR_SUBJECT, &pvalue))
				return FALSE;
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
			HX_unit_size(ptr, 128 /* yuck */, message_size, 1000, 0);
			len = strlen(ptr);
			ptr += len;
			break;
		}
	}
	len = presource->format[bounce_type][TAG_END].position - prev_pos;
	memcpy(ptr, &presource->content[bounce_type][prev_pos], len);
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
	*ptr = '\0';
	return TRUE;
}

BOOL bounce_producer_make(const char *from, const char *rcpt,
	sqlite3 *psqlite, uint64_t message_id, int bounce_type,
	MAIL *pmail)
{
	DSN dsn;
	MIME *pmime;
	time_t cur_time;
	char subject[1024];
	struct tm time_buff;
	char mime_from[UADDR_SIZE];
	char tmp_buff[1024];
	char date_buff[128];
	char content_type[128];
	DSN_FIELDS *pdsn_fields;
	char content_buff[256*1024];
	
	if (!bounce_producer_make_content(from, rcpt,
	    psqlite, message_id, bounce_type, mime_from,
	    subject, content_type, content_buff))
		return FALSE;
	auto phead = pmail->add_head();
	if (NULL == phead) {
		return FALSE;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "delivery-status");
	pmime->set_field("Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	pmime->set_field("From", mime_from);
	snprintf(tmp_buff, UADDR_SIZE + 2, "<%s>", from);
	pmime->set_field("To", tmp_buff);
	pmime->set_field("MIME-Version", "1.0");
	pmime->set_field("X-Auto-Response-Suppress", "All");
	time(&cur_time);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", subject);
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		return FALSE;
	}
	pmime->set_content_type(content_type);
	pmime->set_content_param("charset", "\"utf-8\"");
	if (!pmime->write_content(content_buff,
	    strlen(content_buff), mime_encoding::automatic))
		return FALSE;
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
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(content_buff,
				strlen(content_buff), mime_encoding::none);
		}
	}
	dsn_free(&dsn);
	return TRUE;
}
