// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"

using namespace gromox;

namespace {

struct bounce_template {
	char from[UADDR_SIZE]{}, subject[256]{}, content_type[256]{};
	std::unique_ptr<char[]> content;
	size_t body_start = 0;
};

}

static char g_separator[16];
using template_map = std::map<std::string, bounce_template>;
static std::map<std::string, template_map> g_resource_list;

static BOOL bounce_producer_refresh(const char *, const char *);
static void bounce_producer_load_subdir(const std::string &basedir, const char *dir_name, template_map &);

int bounce_producer_run(const char *separator, const char *data_path,
    const char *bounce_grp)
{
	gx_strlcpy(g_separator, separator, GX_ARRAY_SIZE(g_separator));
	return bounce_producer_refresh(data_path, bounce_grp) ? 0 : -1;
}

/*
 *	refresh the current resource list
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
static BOOL bounce_producer_refresh(const char *data_path,
    const char *bounce_grp) try
{
	struct dirent *direntp;

	auto dinfo = opendir_sd(bounce_grp, data_path);
	if (dinfo.m_dir == nullptr) {
		mlog(LV_ERR, "exmdb_provider: opendir_sd(%s) %s: %s",
			bounce_grp, dinfo.m_path.c_str(), strerror(errno));
		return FALSE;
	}
	while ((direntp = readdir(dinfo.m_dir.get())) != nullptr) {
		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;
		bounce_producer_load_subdir(dinfo.m_path, direntp->d_name,
			g_resource_list[direntp->d_name]);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1502: ENOMEM");
	return false;
}

static void bounce_producer_load_subdir(const std::string &basedir,
    const char *dir_name, template_map &plist)
{
	struct dirent *sub_direntp;
	struct stat node_stat;
	int j;
	MIME_FIELD mime_field;

	auto dir_buf = basedir + "/" + dir_name;
	auto sub_dirp = opendir_sd(dir_buf.c_str(), nullptr);
	if (sub_dirp.m_dir != nullptr) while ((sub_direntp = readdir(sub_dirp.m_dir.get())) != nullptr) {
		if (strcmp(sub_direntp->d_name, ".") == 0 ||
		    strcmp(sub_direntp->d_name, "..") == 0)
			continue;
		auto sub_buf = dir_buf + "/" + sub_direntp->d_name;
		wrapfd fd = open(sub_buf.c_str(), O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
		    !S_ISREG(node_stat.st_mode))
			continue;
		bounce_template tp;
		tp.content = std::make_unique<char[]>(node_stat.st_size);
		if (read(fd.get(), tp.content.get(),
		    node_stat.st_size) != node_stat.st_size)
			return;
		fd.close();
		j = 0;
		while (j < node_stat.st_size) {
			auto parsed_length = parse_mime_field(&tp.content[j],
			                     node_stat.st_size - j, &mime_field);
			j += parsed_length;
			if (0 != parsed_length) {
				if (strcasecmp(mime_field.name.c_str(), "Content-Type") == 0)
					gx_strlcpy(tp.content_type, mime_field.value.c_str(), std::size(tp.content_type));
				else if (strcasecmp(mime_field.name.c_str(), "From") == 0)
					gx_strlcpy(tp.from, mime_field.value.c_str(), std::size(tp.from));
				else if (strcasecmp(mime_field.name.c_str(), "Subject") == 0)
					gx_strlcpy(tp.subject, mime_field.value.c_str(), std::size(tp.subject));
				if (tp.content[j] == '\n') {
					++j;
					break;
				} else if (tp.content[j] == '\r' &&
				    tp.content[j+1] == '\n') {
					j += 2;
					break;
				}
			} else {
				mlog(LV_ERR, "exmdb_provider: bounce mail %s format error",
				       sub_buf.c_str());
				return;
			}
		}
		tp.body_start = j;
		plist.emplace(sub_direntp->d_name, std::move(tp));
	}
}

static std::string exmdb_bouncer_attachs(sqlite3 *psqlite, uint64_t message_id)
{
	std::string r;
	void *pvalue;
	char sql_string[256];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT attachment_id FROM "
	        "attachments WHERE message_id=%llu", static_cast<unsigned long long>(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		auto attachment_id = pstmt.col_uint64(0);
		if (!cu_get_property(db_table::atx_props,
		    attachment_id, 0, psqlite, PR_ATTACH_LONG_FILENAME, &pvalue))
			return 0;
		if (NULL == pvalue) {
			continue;
		}
		if (!r.empty())
			r += g_separator;
		r += static_cast<const char *>(pvalue);
	}
	return r;
}

BOOL exmdb_bouncer_make_content(const char *from, const char *rcpt,
    sqlite3 *psqlite, uint64_t message_id, const char *bounce_type,
    char *mime_from, char *subject, char *content_type, char *pcontent,
    size_t content_size) try
{
	void *pvalue;
	time_t cur_time;
	char charset[32];
	char date_buff[128];
	struct tm time_buff;
	int len;
	char lang[32], time_zone[64];

	time(&cur_time);
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
	auto it = g_resource_list.find(charset);
	if (it == g_resource_list.end())
		it = g_resource_list.find("ascii");
	if (it == g_resource_list.end())
		return false;
	auto it2 = it->second.find(bounce_type);
	if (it2 == it->second.end())
		return false;
	auto &tp = it2->second;

	auto fa = HXformat_init();
	if (fa == nullptr)
		return false;
	auto cl_0 = make_scope_exit([&]() { HXformat_free(fa); });
	unsigned int immed = HXFORMAT_IMMED;
	if (HXformat_add(fa, "time", date_buff,
	    HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "from", from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpt", rcpt, HXTYPE_STRING) < 0)
		return false;
	if (!cu_get_property(db_table::msg_props,
	    message_id, 0, psqlite, PR_SUBJECT, &pvalue))
		return FALSE;
	if (HXformat_add(fa, "subject", pvalue != nullptr ?
	    static_cast<const char *>(pvalue) : "", HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "parts",
	    exmdb_bouncer_attachs(psqlite, message_id).c_str(),
	    HXTYPE_STRING | immed) < 0)
		return false;
	HX_unit_size(date_buff, std::size(date_buff), message_size, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	if (HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]) < 0)
		return false;
	gx_strlcpy(pcontent, replaced, content_size);
	HXmc_free(replaced);
	if (NULL != mime_from) {
		strcpy(mime_from, tp.from);
	}
	if (NULL != subject) {
		strcpy(subject, tp.subject);
	}
	if (NULL != content_type) {
		strcpy(content_type, tp.content_type);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1219: ENOMEM");
	return false;
}

BOOL exmdb_bouncer_make(const char *from, const char *rcpt, sqlite3 *psqlite,
    uint64_t message_id, const char *bounce_type, MAIL *pmail)
{
	MIME *pmime;
	time_t cur_time;
	char subject[1024];
	struct tm time_buff;
	char mime_from[UADDR_SIZE];
	char tmp_buff[1024];
	char date_buff[128];
	char content_type[128];
	char content_buff[256*1024];
	
	if (!exmdb_bouncer_make_content(from, rcpt,
	    psqlite, message_id, bounce_type, mime_from,
	    subject, content_type, content_buff, std::size(content_buff)))
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

	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	dsn.append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn.new_rcpt_fields();
	if (NULL == pdsn_fields) {
		return FALSE;
	}
	snprintf(tmp_buff, 1024, "rfc822;%s", rcpt);
	dsn.append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	dsn.append_field(pdsn_fields, "Action", "failed");
	dsn.append_field(pdsn_fields, "Status", "5.0.0");
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Remote-MTA", tmp_buff);
	
	if (dsn.serialize(content_buff, GX_ARRAY_SIZE(content_buff))) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(content_buff,
				strlen(content_buff), mime_encoding::none);
		}
	}
	return TRUE;
}
