// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
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
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include <libHX/string.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
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
	int	position;
	int tag;
};

/*
 * <time> <from> <rcpt> <rcpts>
 * <subject> <parts> <length>
 */
struct RESOURCE_NODE {
	char				charset[32];
	char				from[BOUNCE_TOTAL_NUM][256];
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
BOOL (*bounce_producer_lang_to_charset)(const char *lang, char *charset);
static void bounce_producer_enum_parts(MIME *, void *);
static void bounce_producer_enum_charset(MIME *, void *);
static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff);

static int bounce_producer_get_mail_subject(MAIL *pmail, char *subject,
	char *charset);

static int bounce_producer_get_mail_charset(MAIL *pmail, char *charset);

static int bounce_producer_get_mail_parts(MAIL *pmail, char *parts,
	char *charset);
static BOOL bounce_producer_check_subdir(const std::string &basedir, const char *dir_name);
static void bounce_producer_load_subdir(const std::string &basedir, const char *dir_name, std::vector<RESOURCE_NODE> &);

void bounce_producer_init(const char* separator)
{
	gx_strlcpy(g_separator, separator, GX_ARRAY_SIZE(g_separator));
	g_default_resource = NULL;
}

/*
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int bounce_producer_run(const char *datadir)
{
#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "mlist_expand", (s)); \
		return -1; \
	} \
} while (false)

	E(bounce_producer_check_domain, "domain_list_query");
	E(bounce_producer_get_lang, "get_user_lang");
	E(bounce_producer_get_timezone, "get_timezone");
	E(bounce_producer_lang_to_charset, "lang_to_charset");
#undef E
	if (!bounce_producer_refresh(datadir))
		return -5;
	return 0;
}

/*
 *	refresh the current resource list
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
BOOL bounce_producer_refresh(const char *datadir)
{
    struct dirent *direntp;
	std::vector<RESOURCE_NODE> resource_list;

	auto dinfo = opendir_sd("mlist_bounce", datadir);
	if (dinfo.m_dir == nullptr) {
		printf("[mlist_expand]: opendir_sd(mlist_expand) %s: %s\n",
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
		printf("[mlist_expand]: there are no \"ascii\" bounce mail "
			"templates in %s\n", dinfo.m_path.c_str());
		return FALSE;
	}
	std::unique_lock wr_hold(g_list_lock);
	g_default_resource = &*pdefault;
	std::swap(g_resource_list, resource_list);
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
		try {
			presource->content[i] = std::make_unique<char[]>(node_stat.st_size);
		} catch (const std::bad_alloc &) {
			return;
		}
		if (read(fd.get(), presource->content[i].get(), node_stat.st_size) != node_stat.st_size) {
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
				printf("[mlist_expand]: bounce mail %s format error\n",
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
				printf("[mlist_expand]: format error in %s, lack of "
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

/*
 *	make a bounce mail
 *	@param
 *		bounce_type			type of bounce mail
 *		pmail [out]			bounce mail object
 */
void bounce_producer_make(const char *from, const char *rcpt_to,
	MAIL *pmail_original, int bounce_type, MAIL *pmail)
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
			fprintf(stderr, "bounce_producer: check_domain: %s\n",
			        strerror(-lcldom));
			return;
		}
		if (lcldom > 0) {
			if (bounce_producer_get_lang(from, lang, arsizeof(lang)))
				bounce_producer_lang_to_charset(lang, charset);
			bounce_producer_get_timezone(from, time_zone, arsizeof(time_zone));
		}
	}
	
	if('\0' != time_zone[0]) {
		auto sp = tz::tz_alloc(time_zone);
		tz::tz_localtime_r(sp, &cur_time, &time_buff);
		tz::tz_free(sp);
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
	std::shared_lock rd_hold(g_list_lock);
	auto it = std::find_if(g_resource_list.begin(), g_resource_list.end(),
	          [&](const RESOURCE_NODE &n) { return strcasecmp(n.charset, charset) == 0; });
	auto presource = it != g_resource_list.end() ? &*it : g_default_resource;
	int prev_pos = presource->format[bounce_type][TAG_BEGIN].position;
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
			strcpy(ptr, rcpt_to);
        	ptr += strlen(rcpt_to);
			break;
    	case TAG_RCPTS:
			strcpy(ptr, rcpt_to);
        	ptr += strlen(rcpt_to);
			break;
    	case TAG_SUBJECT:
			len = bounce_producer_get_mail_subject(pmail_original, ptr, mcharset);
            ptr += len;
            break;
    	case TAG_PARTS:
			len = bounce_producer_get_mail_parts(pmail_original, ptr, mcharset);
			ptr += len;
            break;
		case TAG_LENGTH: {
			auto mail_len = pmail_original->get_length();
			if (mail_len < 0) {
				printf("[mlist_expand]: fail to get mail length\n");
				mail_len = 0;
			}
			HX_unit_size(ptr, 128 /* yuck */, mail_len, 1000, 0);
			len = strlen(ptr);
			ptr += len;
			break;
		}
		}
	}
	len = presource->format[bounce_type][TAG_END].position - prev_pos;
	memcpy(ptr, &presource->content[bounce_type][prev_pos], len);
	ptr += len;
	auto phead = pmail->add_head();
	if (NULL == phead) {
		printf("[mlist_expand]: fatal error, there's no mime "
			"in mime pool\n");
		return;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "delivery-status");
	pmime->set_field("Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	if (bounce_producer_get_mail_thread_index(pmail_original, tmp_buff))
		pmime->set_field("Thread-Index", tmp_buff);
	pmime->set_field("From", presource->from[bounce_type]);
	snprintf(tmp_buff, 256, "<%s>", from);
	pmime->set_field("To", tmp_buff);
	pmime->set_field("MIME-Version", "1.0");
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", presource->subject[bounce_type]);
	
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		printf("[mlist_expand]: fatal error, there's no mime "
			"in mime pool\n");
		return;
	}
	parse_field_value(presource->content_type[bounce_type],
		strlen(presource->content_type[bounce_type]),
		tmp_buff, 256, &pmime->f_type_params);
	pmime->set_content_type(tmp_buff);
	rd_hold.unlock();
	pmime->set_content_param("charset", "\"utf-8\"");
	if (!pmime->write_content(original_ptr,
		ptr - original_ptr, MIME_ENCODING_BASE64)) {
        printf("[mlist_expand]: fatal error, fail to write content\n");
        return;
	}
	
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn_append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	dsn_append_field(pdsn_fields, "Arrival-Date", date_buff);
	
	pdsn_fields = dsn_new_rcpt_fields(&dsn);
	if (NULL == pdsn_fields) {
		dsn_free(&dsn);
		return;
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
				strlen(original_ptr), MIME_ENCODING_NONE);
		}
	}
	dsn_free(&dsn);
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
 *	enum the mail attachement
 */
static void bounce_producer_enum_parts(MIME *pmime, void *param)
{
	auto penum = static_cast<ENUM_PARTS *>(param);
	int attach_len;
	char name[256];
	char temp_name[512];
	
	if (!pmime->get_filename(name))
		return;
	if (mime_string_to_utf8(penum->charset, name, temp_name)) {
		attach_len = strlen(temp_name);
		if (penum->offset + attach_len < 128*1024) {
			if (penum->b_first) {
				strcpy(penum->ptr + penum->offset, g_separator);
				penum->offset += strlen(g_separator);
			}
			memcpy(penum->ptr + penum->offset, temp_name, attach_len);
			penum->offset += attach_len;
			penum->b_first = TRUE;
		}
	}
}

static int bounce_producer_get_mail_subject(MAIL *pmail, char *subject,
	char *charset)
{
	char tmp_buff[1024];
	auto pmime = pmail->get_head();
	if (!pmime->get_field("Subject", tmp_buff, 1024)) {
		*subject = '\0';
		return 0;
	}
	if (!mime_string_to_utf8(charset, tmp_buff, subject))
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

static void bounce_producer_enum_charset(MIME *pmime, void *param)
{
	auto penum = static_cast<ENUM_CHARSET *>(param);
	char charset[32];
	char *begin, *end;
	int len;
	
	if (penum->b_found)
		return;
	if (pmime->get_content_param("charset", charset, 32)) {
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
}

static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff)
{
	auto phead = pmail->get_head();
	if (NULL == phead) {
		return FALSE;
	}
	return phead->get_field("Thread-Index", pbuff, 128);
}

