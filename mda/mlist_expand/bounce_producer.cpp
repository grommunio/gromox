// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <array>
#include "bounce_producer.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/hook_common.h>
#include <gromox/mail_func.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include <libHX/string.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>

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

/*
 * <time> <from> <rcpt> <rcpts>
 * <subject> <parts> <length>
 */
struct RESOURCE_NODE {
	char				charset[32];
	std::array<bounce_template, BOUNCE_TOTAL_NUM> tp;
};

struct TAG_ITEM {
	const char	*name;
	int			length;
};

}

static char g_separator[16];
static std::vector<RESOURCE_NODE> g_resource_list;
static RESOURCE_NODE *g_default_resource;
static constexpr const char *g_resource_table[] = {
	"BOUNCE_MLIST_SPECIFIED", "BOUNCE_MLIST_INTERNAL",
	"BOUNCE_MLIST_DOMAIN",
};
static constexpr TAG_ITEM g_tags[] = {
	{"<time>", 6},
	{"<from>", 6},
	{"<rcpt>", 6},
	{"<rcpts>", 7},
	{"<subject>", 9},
	{"<parts>", 7},
	{"<length>", 8}
};

int (*bounce_producer_check_domain)(const char *domainname);
bool (*bounce_producer_get_lang)(const char *username, char *lang, size_t);
bool (*bounce_producer_get_timezone)(const char *username, char *timezone, size_t);
static void bounce_producer_enum_parts(const MIME *, void *);
static void bounce_producer_enum_charset(const MIME *, void *);
static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff);
static int bp_get_subject(MAIL *, char *subject, size_t sbsize, const char *charset);
static int bounce_producer_get_mail_charset(MAIL *pmail, char *charset);

static int bounce_producer_get_mail_parts(MAIL *pmail, char *parts,
	char *charset);
static BOOL bounce_producer_refresh(const char *, const char *);
static BOOL bounce_producer_check_subdir(const std::string &basedir, const char *dir_name);
static void bounce_producer_load_subdir(const std::string &basedir, const char *dir_name, std::vector<RESOURCE_NODE> &);

int bounce_producer_run(const char *separator, const char *data_path,
    const char *bounce_grp)
{
	gx_strlcpy(g_separator, separator, GX_ARRAY_SIZE(g_separator));
	g_default_resource = NULL;

#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "mlist_expand: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(bounce_producer_check_domain, "domain_list_query");
	E(bounce_producer_get_lang, "get_user_lang");
	E(bounce_producer_get_timezone, "get_timezone");
#undef E
	return bounce_producer_refresh(data_path, bounce_grp) ? 0 : -1;
}

/*
 *	refresh the current resource list
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
static BOOL bounce_producer_refresh(const char *datadir, const char *bounce_grp)
{
    struct dirent *direntp;
	std::vector<RESOURCE_NODE> resource_list;

	auto dinfo = opendir_sd(bounce_grp, datadir);
	if (dinfo.m_dir == nullptr) {
		mlog(LV_ERR, "mlist_expand: opendir_sd(%s) %s: %s",
			bounce_grp, dinfo.m_path.c_str(), strerror(errno));
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
		mlog(LV_ERR, "mlist_expand: there are no \"ascii\" bounce mail "
			"templates in %s", dinfo.m_path.c_str());
		return FALSE;
	}
	g_default_resource = &*pdefault;
	g_resource_list = std::move(resource_list);
	return TRUE;
}

/*
 *	check if the sub directory has all necessary files
 *	@param
 *		dir_name [in]			sub directory
 *	@return
 *		TRUE					OK
 *		FALSE					illegal
 */
static BOOL bounce_producer_check_subdir(const std::string &basedir,
    const char *dir_name)
{
    struct dirent *sub_direntp;
	struct stat node_stat;

	auto dir_buf = basedir + "/" + dir_name;
	auto sub_dirp = opendir_sd(dir_buf.c_str(), nullptr);
	if (sub_dirp.m_dir == nullptr)
		return false;
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

/*
 *	load sub directory into reasource list
 *	@param
 *		dir_name [in]			sub directory
 *		plist [out]				resource will be appended into this list
 */
static void bounce_producer_load_subdir(const std::string &basedir,
    const char *dir_name, std::vector<RESOURCE_NODE> &plist)
{
    struct dirent *sub_direntp;
	struct stat node_stat;
	int i, j, k, until_tag;
	MIME_FIELD mime_field;
	RESOURCE_NODE rnode, *presource = &rnode;

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
		auto &tp = presource->tp[i];
		tp.content = std::make_unique<char[]>(node_stat.st_size);
		if (read(fd.get(), tp.content.get(), node_stat.st_size) != node_stat.st_size) {
			return;
		}
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
				mlog(LV_ERR, "mlist_expand: bounce mail %s format error",
				       sub_buf.c_str());
				return;
			}
		}
		/* find tags in file content and mark the position */
		tp.format[TAG_BEGIN].position = j;
		for (; j<node_stat.st_size; j++) {
			if (tp.content[j] == '<') {
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
				mlog(LV_ERR, "mlist_expand: format error in %s, lacking "
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
	}
	gx_strlcpy(presource->charset, dir_name, GX_ARRAY_SIZE(presource->charset));
	plist.push_back(std::move(rnode));
}

/*
 *	make a bounce mail
 *	@param
 *		bounce_type			type of bounce mail
 *		pmail [out]			bounce mail object
 */
bool bounce_producer_make(const char *from, const char *rcpt_to,
    MAIL *pmail_original, unsigned int bounce_type, MAIL *pmail)
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
	
	
	time(&cur_time);
	ptr = original_ptr;
	charset[0] = '\0';
	time_zone[0] = '\0';
	auto pdomain = strchr(from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		auto lcldom = bounce_producer_check_domain(pdomain);
		if (lcldom < 0) {
			mlog(LV_ERR, "bounce_producer: check_domain: %s",
			        strerror(-lcldom));
			return false;
		}
		if (lcldom > 0) {
			if (bounce_producer_get_lang(from, lang, arsizeof(lang)))
				gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
			bounce_producer_get_timezone(from, time_zone, arsizeof(time_zone));
		}
	}
	
	if('\0' != time_zone[0]) {
		auto sp = tz::tzalloc(time_zone);
		if (sp == nullptr)
			return false;
		tz::localtime_rz(sp, &cur_time, &time_buff);
		tz::tzfree(sp);
	} else {
		localtime_r(&cur_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	
	bounce_producer_get_mail_charset(pmail_original, mcharset);
	
	if ('\0' == charset[0]) {
		strcpy(charset, mcharset);
	}
	auto it = std::find_if(g_resource_list.begin(), g_resource_list.end(),
	          [&](const RESOURCE_NODE &n) { return strcasecmp(n.charset, charset) == 0; });
	auto presource = it != g_resource_list.end() ? &*it : g_default_resource;
	if (bounce_type >= BOUNCE_TOTAL_NUM)
		return false;
	auto &tp = presource->tp[bounce_type];
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
				mlog(LV_ERR, "mlist_expand: failed to get mail length");
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
		mlog(LV_ERR, "mlist_expand: MIME pool exhausted");
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
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", tp.subject);
	
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		mlog(LV_ERR, "mlist_expand: MIME pool exhausted");
		return false;
	}
	parse_field_value(tp.content_type, strlen(tp.content_type),
		tmp_buff, 256, &pmime->f_type_params);
	pmime->set_content_type(tmp_buff);
	pmime->set_content_param("charset", "\"utf-8\"");
	if (!pmime->write_content(original_ptr,
	    ptr - original_ptr, mime_encoding::automatic)) {
        mlog(LV_ERR, "mlist_expand: failed to write content");
		return false;
	}
	
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn_append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	dsn_append_field(pdsn_fields, "Arrival-Date", date_buff);
	
	pdsn_fields = dsn_new_rcpt_fields(&dsn);
	if (NULL == pdsn_fields) {
		dsn_free(&dsn);
		return false;
	}
	snprintf(tmp_buff, 1024, "rfc822;%s", rcpt_to);
	dsn_append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	dsn_append_field(pdsn_fields, "Action", "failed");
	dsn_append_field(pdsn_fields, "Status", "5.0.0");
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

/*
 *	enum the mail attachment
 */
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
	if (!pmime->get_field("Subject", tmp_buff, 1024)) {
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

