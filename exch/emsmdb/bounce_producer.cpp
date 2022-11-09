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
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"
#include "common_util.h"

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
static constexpr const char *g_resource_table[] =
	{"BOUNCE_NOTIFY_READ", "BOUNCE_NOTIFY_NON_READ"};
static constexpr TAG_ITEM g_tags[] = {
	{"<time>", 6},
	{"<from>", 6},
	{"<user>", 6},
	{"<rcpts>", 7},
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

	auto dinfo = opendir_sd("notify_bounce", data_path);
	if (dinfo.m_dir == nullptr) {
		mlog(LV_ERR, "exmdb_provider: opendir_sd(notify_bounce) %s: %s",
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
		mlog(LV_ERR, "emsmdb: there are no "
			"\"ascii\" bounce mail templates in %s", dinfo.m_path.c_str());
		return FALSE;
	}
	std::unique_lock wr_hold(g_list_lock);
	g_default_resource = &*pdefault;
	std::swap(g_resource_list, resource_list);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1501: ENOMEM");
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
				mlog(LV_ERR, "exmdb_provider: bounce mail %s format error",
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
				mlog(LV_ERR, "exmdb_provider: format error in %s, lacking "
				       "tag %s", sub_buf.c_str(), g_tags[j-1].name);
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

static int bounce_producer_get_mail_parts(
	ATTACHMENT_LIST *pattachments, char *parts)
{
	int i;
	int offset;
	BOOL b_first;
	
	offset = 0;
	b_first = FALSE;
	for (i=0; i<pattachments->count; i++) {
		auto lfn = pattachments->pplist[i]->proplist.get<const char>(PR_ATTACH_LONG_FILENAME);
		if (lfn == nullptr)
			continue;
		auto tmp_len = strlen(lfn);
		if (offset + tmp_len < 128*1024) {
			if (b_first) {
				strcpy(parts + offset, g_separator);
				offset += strlen(g_separator);
			}
			memcpy(parts + offset, lfn, tmp_len);
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
		auto str = prcpts->pparray[i]->get<const char>(PR_SMTP_ADDRESS);
		if (str == nullptr)
			continue;
		auto tmp_len = strlen(str);
		if (offset + tmp_len < 128*1024) {
			if (b_first) {
				strcpy(rcpts + offset, g_separator);
				offset += strlen(g_separator);
			}
			memcpy(rcpts + offset, str, tmp_len);
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
	char date_buff[128];
	struct tm time_buff;
	int i, len, until_tag;
	char lang[32], time_zone[64];

	ptr = pcontent;
	charset[0] = '\0';
	time_zone[0] = '\0';
	auto ts = pbrief->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	tmp_time = ts == nullptr ? time(nullptr) : rop_util_nttime_to_unix(*ts);
	auto from = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (NULL == from) {
		from = "none@none";
	}
	if (common_util_get_user_lang(from, lang, arsizeof(lang))) {
		gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
		common_util_get_timezone(from, time_zone, arsizeof(time_zone));
	}
	if('\0' != time_zone[0]) {
		auto sp = tz::tzalloc(time_zone);
		if (NULL == sp) {
			return FALSE;
		}
		tz::localtime_rz(sp, &tmp_time, &time_buff);
		tz::tzfree(sp);
	} else {
		localtime_r(&tmp_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	auto message_size = pbrief->proplist.get<const uint32_t>(PR_MESSAGE_SIZE);
	if (message_size == nullptr)
		return FALSE;
	if ('\0' == charset[0]) {
		auto cpid = pbrief->proplist.get<uint32_t>(PR_INTERNET_CPID);
		if (cpid == nullptr) {
			strcpy(charset, "ascii");
		} else {
			auto pcharset = cpid_to_cset(*cpid);
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
		case TAG_SUBJECT: {
			auto subj = pbrief->proplist.get<const char>(PR_SUBJECT);
			if (subj != nullptr) {
				len = strlen(subj);
				memcpy(ptr, subj, len);
				ptr += len;
			}
			break;
		}
		case TAG_PARTS:
			len = bounce_producer_get_mail_parts(
				pbrief->children.pattachments, ptr);
			ptr += len;
			break;
		case TAG_LENGTH:
			HX_unit_size(ptr, 128 /* yuck */, *message_size, 1000, 0);
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
	
	if (common_util_get_user_displayname(username, tmp_buff,
	    arsizeof(tmp_buff)) && tmp_buff[0] != '\0') {
		strcpy(mime_from, "=?utf-8?b?");
		encode64(tmp_buff, strlen(tmp_buff), mime_from + 10,
			sizeof(mime_from) - 13, &out_len);
		strcpy(mime_from + 10 + out_len, "?=");
	} else {
		mime_from[0] = '\0';
	}
	if (!bounce_producer_make_content(username, pbrief,
	    bounce_type, subject, content_type, content_buff))
		return FALSE;
	auto phead = pmail->add_head();
	if (NULL == phead) {
		return FALSE;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "disposition-notification");
	auto bv = pbrief->proplist.get<const BINARY>(PR_CONVERSATION_INDEX);
	if (bv != nullptr && encode64(bv->pb, bv->cb, tmp_buff,
	    arsizeof(tmp_buff), &out_len) == 0)
		pmime->set_field("Thread-Index", tmp_buff);
	std::string t_addr;
	try {
		t_addr = "\""s + mime_from + "\" <" + username + ">";
		pmime->set_field("From", t_addr.c_str());
		t_addr = "<"s + username + ">";
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1481: ENOMEM");
		return false;
	}
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_NAME);
	if (str != nullptr && *str != '\0') {
		strcpy(mime_to, "\"=?utf-8?b?");
		encode64(str, strlen(str), mime_to + 11,
			sizeof(mime_to) - 15, &out_len);
		strcpy(mime_to + 11 + out_len, "?=\"");
	} else {
		mime_to[0] = '\0';
	}
	str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr) {
		out_len = strlen(mime_to);
		if (0 != out_len) {
			mime_to[out_len++] = ' ';
		}
		snprintf(mime_to + out_len, sizeof(mime_to) - out_len, "<%s>", str);
	}
	if ('\0' != mime_to[0]) {
		pmime->set_field("To", mime_to);
	}
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
	try {
		t_addr = "rfc822;"s + username;
		dsn_append_field(pdsn_fields, "Final-Recipient", t_addr.c_str());
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1482: ENOMEM");
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
	str = pbrief->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
	if (str != nullptr)
		dsn_append_field(pdsn_fields, "Original-Message-ID", str);
	bv = pbrief->proplist.get<BINARY>(PR_PARENT_KEY);
	if (bv != nullptr) {
		encode64(bv->pb, bv->cb, tmp_buff, arsizeof(tmp_buff), &out_len);
		dsn_append_field(pdsn_fields,
			"X-MSExch-Correlation-Key", tmp_buff);
	}
	if ('\0' != mime_from[0]) {
		dsn_append_field(pdsn_fields, "X-Display-Name", mime_from);
	}
	if (dsn_serialize(&dsn, content_buff, GX_ARRAY_SIZE(content_buff))) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/disposition-notification");
			pmime->write_content(content_buff,
				strlen(content_buff), mime_encoding::none);
		}
	}
	dsn_free(&dsn);
	return TRUE;
}
