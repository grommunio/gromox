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
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

using namespace gromox;

enum{
	TAG_BEGIN,
	TAG_TIME,
	TAG_FROM,
	TAG_RCPT,
	TAG_RCPTS,
	TAG_SUBJECT,
	TAG_PARTS,
	TAG_LENGTH,
	TAG_END,
	TAG_TOTAL_LEN = TAG_END
};

namespace {

struct ENUM_CHARSET {
	BOOL b_found;
	char *charset;
};

struct ENUM_PARTS {
	int	 offset;
	char *ptr;
	char *charset;
	BOOL b_first;
};

struct FORMAT_DATA {
	int position = -1, tag = -1;
};

struct bounce_template {
	char from[UADDR_SIZE]{}, subject[256]{}, content_type[256]{};
	std::unique_ptr<char[]> content;
	FORMAT_DATA format[TAG_TOTAL_LEN+1];

	bounce_template() {
		for (size_t j = 0; j < std::size(format); ++j)
			format[j].tag = j;
	}
};

struct TAG_ITEM {
	const char	*name;
	int			length;
};

}

static char g_separator[16];
using template_map = std::map<std::string, bounce_template>;
static std::map<std::string, template_map> g_resource_list;
static constexpr TAG_ITEM g_tags[] = {
	{"%(time)", 7},
	{"%(from)", 7},
	{"%(rcpt)", 7},
	{"%(rcpts)", 8},
	{"%(subject)", 10},
	{"%(parts)", 8},
	{"%(length)", 9},
};

static void bounce_producer_enum_parts(const MIME *, void *);
static void bounce_producer_enum_charset(const MIME *, void *);
static int bp_get_subject(MAIL *, char *subject, size_t sbsize, const char *charset);
static int bounce_producer_get_mail_charset(MAIL *pmail, char *charset);

static int bounce_producer_get_mail_parts(MAIL *pmail, char *parts,
	char *charset);

static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff);
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
	int j, k, until_tag;
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
		/* find tags in file content and mark the position */
		tp.format[TAG_BEGIN].position = j;
		for (; j<node_stat.st_size; j++) {
			if (tp.content[j] == '%') {
				for (k=0; k<TAG_TOTAL_LEN; k++) {
					if (strncasecmp(&tp.content[j], g_tags[k].name, g_tags[k].length) == 0) {
						tp.format[k+1].position = j;
						break;
					}
				}
			}
		}
		tp.format[TAG_END].position = node_stat.st_size;
		until_tag = TAG_TOTAL_LEN;

		for (j=TAG_BEGIN+1; j<until_tag; j++) {
			if (tp.format[j].position == -1) {
				mlog(LV_ERR, "exmdb_local: format error in %s, lacking "
				       "tag %s", sub_buf.c_str(), g_tags[j-1].name);
				return;
			}
		}

		/* sort the tags ascending */
		for (j=TAG_BEGIN+1; j<until_tag; j++) {
			for (k=TAG_BEGIN+1; k<until_tag; k++) {
				if (tp.format[j].position < tp.format[k].position)
					std::swap(tp.format[j], tp.format[k]);
			}
		}
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
    MAIL *pmail)
{
	DSN dsn;
	char *ptr;
	MIME *pmime;
	time_t cur_time;
	char charset[32];
	char mcharset[32];
	char tmp_buff[1024];
	char date_buff[128];
	struct tm time_buff;
	int i, len, until_tag;
	DSN_FIELDS *pdsn_fields;
	char original_ptr[256*1024];
	char lang[32], time_zone[64];

	ptr = original_ptr;
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
	
	bounce_producer_get_mail_charset(pmail_original, mcharset);
	
	if ('\0' == charset[0]) {
		strcpy(charset, mcharset);
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
	int prev_pos = tp.format[TAG_BEGIN].position;
	until_tag = TAG_TOTAL_LEN;
	for (i=TAG_BEGIN+1; i<until_tag; i++) {
		len = tp.format[i].position - prev_pos;
		memcpy(ptr, &tp.content[prev_pos], len);
		prev_pos = tp.format[i].position + g_tags[tp.format[i].tag-1].length;
		ptr += len;
		switch (tp.format[i].tag) {
		case TAG_TIME:
			len = gx_snprintf(ptr, 128, "%s", date_buff);
			ptr += len;
			break;
		case TAG_FROM:
			strcpy(ptr, from);
			ptr += strlen(from);
			break;	
    	case TAG_RCPT:
			strcpy(ptr, rcpt_to);
        	ptr += strlen(rcpt_to);
			break;
    	case TAG_RCPTS:
			strcpy(ptr, rcpt_to);
        	ptr += strlen(rcpt_to);
			break;
    	case TAG_SUBJECT:
			len = bp_get_subject(pmail_original, ptr,
			      std::size(original_ptr) - (ptr - original_ptr), mcharset);
            ptr += len;
            break;
    	case TAG_PARTS:
			len = bounce_producer_get_mail_parts(pmail_original, ptr, mcharset);
			ptr += len;
            break;
		case TAG_LENGTH: {
			auto mail_len = pmail_original->get_length();
			if (mail_len < 0) {
				mlog(LV_ERR, "exmdb_local: failed to get mail length");
				mail_len = 0;
			}
			HX_unit_size(ptr, 128 /* yuck */, mail_len, 1000, 0);
			len = strlen(ptr);
			ptr += len;
			break;
		}
		}
	}
	len = tp.format[TAG_END].position - prev_pos;
	memcpy(ptr, &tp.content[prev_pos], len);
	ptr += len;
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
	if (bounce_producer_get_mail_thread_index(pmail_original, tmp_buff))
		pmime->set_field("Thread-Index", tmp_buff);
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
	if (!pmime->write_content(original_ptr,
	    ptr - original_ptr, mime_encoding::automatic)) {
	mlog(LV_ERR, "exmdb_local: failed to write content");
		return false;
	}
	
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn_append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	localtime_r(&original_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	dsn_append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn_new_rcpt_fields(&dsn);
	if (NULL == pdsn_fields) {
		dsn_free(&dsn);
		return false;
	}
	snprintf(tmp_buff, 1024, "rfc822;%s", rcpt_to);
	dsn_append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	if (strcmp(bounce_type, "BOUNCE_MAIL_DELIVERED") != 0) {
		dsn_append_field(pdsn_fields, "Action", "failed");
		dsn_append_field(pdsn_fields, "Status", "5.0.0");
	} else {
		dsn_append_field(pdsn_fields, "Action", "delivered");
		dsn_append_field(pdsn_fields, "Status", "2.0.0");
	}
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn_append_field(pdsn_fields, "Remote-MTA", tmp_buff);
	if (dsn_serialize(&dsn, original_ptr, 256 * 1024)) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(original_ptr,
				strlen(original_ptr), mime_encoding::none);
		}
	}
	dsn_free(&dsn);
	return true;
}

static int bounce_producer_get_mail_parts(MAIL *pmail, char *parts,
	char *charset)
{
	ENUM_PARTS enum_parts;

	enum_parts.ptr = parts;
	enum_parts.offset = 0;
	enum_parts.charset = charset;
	enum_parts.b_first = FALSE;
	pmail->enum_mime(bounce_producer_enum_parts, &enum_parts);
	return enum_parts.offset;
}

static void bounce_producer_enum_parts(const MIME *pmime, void *param)
{
	auto penum = static_cast<ENUM_PARTS *>(param);
	int attach_len;
	char name[256];
	char temp_name[512];
	
	if (!pmime->get_filename(name, std::size(name)))
		return;
	if (!mime_string_to_utf8(penum->charset, name, temp_name,
	    std::size(temp_name)))
		return;
	attach_len = strlen(temp_name);
	if (penum->offset + attach_len >= 128 * 1024)
		return;
	if (penum->b_first) {
		strcpy(penum->ptr + penum->offset, g_separator);
		penum->offset += strlen(g_separator);
	}
	memcpy(penum->ptr + penum->offset, temp_name, attach_len);
	penum->offset += attach_len;
	penum->b_first = TRUE;
}

static int bp_get_subject(MAIL *pmail, char *subject, size_t sbsize,
    const char *charset)
{
	char tmp_buff[1024];
	auto pmime = pmail->get_head();
	if (!pmime->get_field("Subject", tmp_buff, arsizeof(tmp_buff))) {
		*subject = '\0';
		return 0;
	}
	if (!mime_string_to_utf8(charset, tmp_buff, subject, sbsize))
		return 0;
	return strlen(subject);
}

/*
 *	get mail content charset
 *	@param
 *		pmail [in]				indicate the mail object
 *		charset [out]			for retrieving the charset
 *	@return
 *		string length
 */
static int bounce_producer_get_mail_charset(MAIL *pmail, char *charset)
{
	ENUM_CHARSET enum_charset;

	enum_charset.b_found = FALSE;
	enum_charset.charset = charset;
	pmail->enum_mime(bounce_producer_enum_charset, &enum_charset);
	if (!enum_charset.b_found)
		strcpy(charset, "ascii");
	return strlen(charset);
}

static void bounce_producer_enum_charset(const MIME *pmime, void *param)
{
	auto penum = static_cast<ENUM_CHARSET *>(param);
	char charset[32];
	char *begin, *end;
	int len;
	
	if (penum->b_found)
		return;
	if (!pmime->get_content_param("charset", charset, 32))
		return;
	len = strlen(charset);
	if (len <= 2) {
		return;
	}
	begin = strchr(charset, '"');
	if (NULL != begin) {
		end = strchr(begin + 1, '"');
		if (NULL == end) {
			return;
		}
		len = end - begin - 1;
		memcpy(penum->charset, begin + 1, len);
		penum->charset[len] = '\0';
	} else {
		strcpy(penum->charset, charset);
	}
	penum->b_found = TRUE;
}

static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff)
{
	auto phead = pmail->get_head();
	if (NULL == phead) {
		return FALSE;
	}
	return phead->get_field("Thread-Index", pbuff, 128);
}
