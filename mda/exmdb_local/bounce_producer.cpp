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
#include <gromox/bounce_gen.hpp>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

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

	errno = 0;
	auto dinfo = opendir_sd(bounce_grp, data_path);
	if (dinfo.m_dir != nullptr) {
		while ((direntp = readdir(dinfo.m_dir.get())) != nullptr) {
			if (strcmp(direntp->d_name, ".") == 0 ||
			    strcmp(direntp->d_name, "..") == 0)
				continue;
			bounce_producer_load_subdir(dinfo.m_path, direntp->d_name,
				g_resource_list[direntp->d_name]);
		}
	} else if (errno != ENOENT) {
		mlog(LV_ERR, "exmdb_local: opendir_sd %s: %s",
		       dinfo.m_path.c_str(), strerror(errno));
		return FALSE;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1527: ENOMEM");
	return false;
}

/*
 *	load sub directory into reasource list
 *	@param
 *		dir_name [in]			sub directory
 *		plist [out]				resource will be appended into this list
 */
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
		if (read(fd.get(), tp.content.get(), node_stat.st_size) != node_stat.st_size)
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
				mlog(LV_ERR, "exmdb_local: bounce mail %s format error",
					sub_buf.c_str());
				return;
			}
		}
		tp.body_start = j;
		plist.emplace(sub_direntp->d_name, std::move(tp));
	}
}

/*
 *	make a bounce mail
 *	@param
 *		bounce_type			type of bounce mail
 *		pmail [out]			bounce mail object
 */
bool exml_bouncer_make(const char *from, const char *rcpt_to,
    MAIL *pmail_original, time_t original_time, const char *bounce_type,
    MAIL *pmail) try
{
	MIME *pmime;
	time_t cur_time;
	char charset[32];
	char tmp_buff[1024];
	char date_buff[128];
	struct tm time_buff;
	int len;
	char lang[32], time_zone[64];

	charset[0] = '\0';
	time_zone[0] = '\0';
	auto pdomain = strchr(from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (exmdb_local_check_domain(pdomain) >= 1) {
			if (exmdb_local_get_lang(from, lang, arsizeof(lang)))
				gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
			exmdb_local_get_timezone(from, time_zone, arsizeof(time_zone));
		}
	}
	
	if('\0' != time_zone[0]) {
		auto sp = tz::tzalloc(time_zone);
		if (sp == nullptr)
			return false;
		tz::localtime_rz(sp, &original_time, &time_buff);
		tz::tzfree(sp);
	} else {
		localtime_r(&original_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	
	auto mcharset = bounce_gen_charset(*pmail_original);
	if ('\0' == charset[0]) {
		strcpy(charset, mcharset.c_str());
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
	if (HXformat_add(fa, "time", date_buff, HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "from", from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpt", rcpt_to, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpts", rcpt_to, HXTYPE_STRING) < 0)
		return false;
	auto str = bounce_gen_subject(*pmail_original, mcharset.c_str());
	if (HXformat_add(fa, "subject", str.c_str(), HXTYPE_STRING | immed) < 0)
		return false;
	str = bounce_gen_attachs(*pmail_original, mcharset.c_str(), g_separator);
	if (HXformat_add(fa, "parts", str.c_str(), HXTYPE_STRING | immed) < 0)
		return false;
	auto mail_len = pmail_original->get_length();
	if (mail_len < 0) {
		mlog(LV_ERR, "exmdb_local: failed to get mail length");
		mail_len = 0;
	}
	HX_unit_size(date_buff, std::size(date_buff), mail_len, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	auto aprint_len = HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]);
	if (aprint_len < 0)
		return false;
	auto cl_1 = make_scope_exit([&]() { HXmc_free(replaced); });

	auto phead = pmail->add_head();
	if (NULL == phead) {
		mlog(LV_ERR, "exmdb_local: MIME pool exhausted");
		return false;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "delivery-status");
	pmime->set_field("Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	str = bounce_gen_thrindex(*pmail_original);
	if (!str.empty())
		pmime->set_field("Thread-Index", str.c_str());
	pmime->set_field("From", tp.from);
	snprintf(tmp_buff, 256, "<%s>", from);
	pmime->set_field("To", tmp_buff);
	pmime->set_field("MIME-Version", "1.0");
	pmime->set_field("X-Auto-Response-Suppress", "All");
	time(&cur_time);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", tp.subject);
	
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		mlog(LV_ERR, "exmdb_local: MIME pool exhausted");
		return false;
	}
	parse_field_value(tp.content_type, strlen(tp.content_type),
		tmp_buff, 256, &pmime->f_type_params);
	pmime->set_content_type(tmp_buff);
	pmime->set_content_param("charset", "\"utf-8\"");
	if (!pmime->write_content(replaced, aprint_len,
	    mime_encoding::automatic)) {
	mlog(LV_ERR, "exmdb_local: failed to write content");
		return false;
	}
	
	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	localtime_r(&original_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	dsn.append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn.new_rcpt_fields();
	if (NULL == pdsn_fields) {
		return false;
	}
	snprintf(tmp_buff, 1024, "rfc822;%s", rcpt_to);
	dsn.append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	if (strcmp(bounce_type, "BOUNCE_MAIL_DELIVERED") != 0) {
		dsn.append_field(pdsn_fields, "Action", "failed");
		dsn.append_field(pdsn_fields, "Status", "5.0.0");
	} else {
		dsn.append_field(pdsn_fields, "Action", "delivered");
		dsn.append_field(pdsn_fields, "Status", "2.0.0");
	}
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Remote-MTA", tmp_buff);
	char original_ptr[256*1024];
	if (dsn.serialize(original_ptr, std::size(original_ptr))) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(original_ptr,
				strlen(original_ptr), mime_encoding::none);
		}
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1216: ENOMEM");
	return false;
}
