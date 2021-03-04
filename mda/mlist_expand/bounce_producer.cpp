// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstring>
#include <typeinfo>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "bounce_producer.h"
#include <gromox/single_list.hpp>
#include <gromox/fileio.h>
#include <gromox/hook_common.h>
#include <gromox/mail_func.hpp>
#include <gromox/scope.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include <gromox/dsn.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <ctime>

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
	"BOUNCE_MLIST_SPECIFIED",
    "BOUNCE_MLIST_INTERNAL",
    "BOUNCE_MLIST_DOMAIN"
};
static TAG_ITEM g_tags[] = {
	{"<time>", 6},
	{"<from>", 6},
	{"<rcpt>", 6},
	{"<rcpts>", 7},
	{"<subject>", 9},
	{"<parts>", 7},
	{"<length>", 8}
};

BOOL (*bounce_producer_check_domain)(const char *domainname);

BOOL (*bounce_producer_get_lang)(const char *username, char *lang);

BOOL (*bounce_producer_get_timezone)(const char *username, char *timezone);

BOOL (*bounce_producer_lang_to_charset)(const char *lang, char *charset);

static void bounce_producer_enum_parts(MIME *pmime, ENUM_PARTS *penum);

static void bounce_producer_enum_charset(MIME *pmime, ENUM_CHARSET *penum);

static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff);

static int bounce_producer_get_mail_subject(MAIL *pmail, char *subject,
	char *charset);

static int bounce_producer_get_mail_charset(MAIL *pmail, char *charset);

static int bounce_producer_get_mail_parts(MAIL *pmail, char *parts,
	char *charset);
static BOOL bounce_producer_check_subdir(const char *basedir, const char *dir_name);
static void bounce_producer_load_subdir(const char *basedir, const char *dir_name, SINGLE_LIST *plist);
static void bounce_producer_unload_list(SINGLE_LIST *plist);

/*
 *	bounce producer's construct function
 *	@param
 *		path [in]			path of resource
 *		separator [in]		separator character for rcpts and attachements
 */
void bounce_producer_init(const char* separator)
{
	strcpy(g_separator, separator);
	g_default_resource = NULL;
}

/*
 *	run the bounce producer module
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

	single_list_init(&g_resource_list);
	pthread_rwlock_init(&g_list_lock, NULL);
	if (!bounce_producer_refresh(datadir))
		return -5;
	return 0;
}

/*
 *	unload the list of resource
 *	@param
 *		plist [in]			list object
 */
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
BOOL bounce_producer_refresh(const char *datadir)
{
    struct dirent *direntp;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;
	SINGLE_LIST resource_list, temp_list;
	RESOURCE_NODE *pdefault;

	single_list_init(&resource_list);
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
		printf("[mlist_expand]: there are no \"ascii\" bounce mail "
			"templates in %s\n", dinfo.m_path.c_str());
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

/*
 *	check if the sub directory has all necessary files
 *	@param
 *		dir_name [in]			sub directory
 *	@return
 *		TRUE					OK
 *		FALSE					illegal
 */
static BOOL bounce_producer_check_subdir(const char *basedir, const char *dir_name)
{
	DIR *sub_dirp;
    struct dirent *sub_direntp;
	struct stat node_stat;
	char dir_buff[256], sub_buff[256];
	int i, item_num;

	snprintf(dir_buff, GX_ARRAY_SIZE(dir_buff), "%s/%s", basedir, dir_name);
	sub_dirp = opendir(dir_buff);
	if (sub_dirp == nullptr)
		return false;
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

/*
 *	load sub directory into reasource list
 *	@param
 *		dir_name [in]			sub directory
 *		plist [out]				resource will be appended into this list
 */
static void bounce_producer_load_subdir(const char *basedir,
    const char *dir_name, SINGLE_LIST *plist)
{
	DIR *sub_dirp;
	RESOURCE_NODE *presource;
    struct dirent *sub_direntp;
	struct stat node_stat;
    char dir_buff[256], sub_buff[256];
	int i, j, k, parsed_length, until_tag;
	FORMAT_DATA temp;
	MIME_FIELD mime_field;

	presource = (RESOURCE_NODE*)malloc(sizeof(RESOURCE_NODE));
	if (NULL == presource) {
		printf("[mlist_expand]: Failed to allocate resource node memory\n");
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
		wrapfd fd = open(sub_buff, O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
		    !S_ISREG(node_stat.st_mode))
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
		presource->content[i] = static_cast<char *>(malloc(node_stat.st_size));
		if (NULL == presource->content[i]) {
    		closedir(sub_dirp);
			goto FREE_RESOURCE;
		}
		if (read(fd.get(), presource->content[i], node_stat.st_size) != node_stat.st_size) {
    		closedir(sub_dirp);
			goto FREE_RESOURCE;
		}
		fd.close();
		
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
				printf("[mlist_expand]: bounce mail %s format error\n",
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
				printf("[mlist_expand]: format error in %s, lack of "
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

/*
 *	stop the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
void bounce_producer_stop()
{
	bounce_producer_unload_list(&g_resource_list);
	pthread_rwlock_destroy(&g_list_lock);
	single_list_free(&g_resource_list);
}

/*
 *	bounce producer's destruct function
 */
void bounce_producer_free()
{
	g_default_resource = NULL;
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
	MIME *phead;
	time_t cur_time;
	char charset[32];
	char mcharset[32];
	char tmp_buff[1024];
	char date_buff[128];
	struct tm time_buff;
	int i, len, until_tag;
	const struct state *sp;
	int prev_pos, mail_len;
	DSN_FIELDS *pdsn_fields;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;
	char original_ptr[256*1024];
	char lang[32], time_zone[64];
	
	
	time(&cur_time);
	ptr = original_ptr;
	charset[0] = '\0';
	time_zone[0] = '\0';
	auto pdomain = strchr(from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (TRUE == bounce_producer_check_domain(pdomain)) {
			if (TRUE == bounce_producer_get_lang(from, lang)) {
				bounce_producer_lang_to_charset(lang, charset);
			}
			bounce_producer_get_timezone(from, time_zone);
		}
	}
	
	if('\0' != time_zone[0]) {
		sp = tz_alloc(time_zone);
		tz_localtime_r(sp, &cur_time, &time_buff);
		tz_free(sp);
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
    	case TAG_LENGTH:
			mail_len = mail_get_length(pmail_original);
			if (-1 == mail_len) {
				printf("[mlist_expand]: fail to get mail length\n");
				mail_len = 0;
			}
			bytetoa(mail_len, ptr);
			len = strlen(ptr);
			ptr += len;
			break;
		}
	}
	len = presource->format[bounce_type][TAG_END].position - prev_pos;
	memcpy(ptr, presource->content[bounce_type] + prev_pos, len);
	ptr += len;
	phead = mail_add_head(pmail);
	if (NULL == phead) {
		pthread_rwlock_unlock(&g_list_lock);
		printf("[mlist_expand]: fatal error, there's no mime "
			"in mime pool\n");
		return;
	}
	pmime = phead;
	mime_set_content_type(pmime, "multipart/report");
	mime_set_content_param(pmime, "report-type", "delivery-status");
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	if (TRUE == bounce_producer_get_mail_thread_index(
		pmail_original, tmp_buff)) {
		mime_set_field(pmime, "Thread-Index", tmp_buff);
	}
	mime_set_field(pmime, "From", presource->from[bounce_type]);
	snprintf(tmp_buff, 256, "<%s>", from);
	mime_set_field(pmime, "To", tmp_buff);
	mime_set_field(pmime, "MIME-Version", "1.0");
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	mime_set_field(pmime, "Date", date_buff);
	mime_set_field(pmime, "Subject", presource->subject[bounce_type]);
	
	pmime = mail_add_child(pmail, phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		pthread_rwlock_unlock(&g_list_lock);
		printf("[mlist_expand]: fatal error, there's no mime "
			"in mime pool\n");
		return;
	}
	parse_field_value(presource->content_type[bounce_type],
		strlen(presource->content_type[bounce_type]),
		tmp_buff, 256, &pmime->f_type_params);
	mime_set_content_type(pmime, tmp_buff);
	pthread_rwlock_unlock(&g_list_lock);
	mime_set_content_param(pmime, "charset", "\"utf-8\"");
	if (FALSE == mime_write_content(pmime, original_ptr,
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
		pmime = mail_add_child(pmail, phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			mime_set_content_type(pmime, "message/delivery-status");
			mime_write_content(pmime, original_ptr,
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
	mail_enum_mime(pmail, (MAIL_MIME_ENUM)bounce_producer_enum_parts,
		&enum_parts);
	return enum_parts.offset;
}

/*
 *	enum the mail attachement
 */
static void bounce_producer_enum_parts(MIME *pmime, ENUM_PARTS *penum)
{
	int attach_len;
	char name[256];
	char temp_name[512];
	
	if (FALSE == mime_get_filename(pmime, name)) {
		return;
	}
	if (TRUE == mime_string_to_utf8(penum->charset, name, temp_name)) {
		attach_len = strlen(temp_name);
		if (penum->offset + attach_len < 128*1024) {
			if (TRUE == penum->b_first) {
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
	MIME *pmime;
	char tmp_buff[1024];


	pmime = mail_get_head(pmail);
	if (FALSE == mime_get_field(pmime, "Subject", tmp_buff, 1024)) {
		*subject = '\0';
		return 0;
	}
	if (FALSE == mime_string_to_utf8(charset, tmp_buff, subject)) {
		return 0;
	}
	
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
	mail_enum_mime(pmail, (MAIL_MIME_ENUM)bounce_producer_enum_charset,
		&enum_charset);
	if (FALSE == enum_charset.b_found) {
		strcpy(charset, "ascii");
	}
	return strlen(charset);
}

static void bounce_producer_enum_charset(MIME *pmime, ENUM_CHARSET *penum)
{
	char charset[32];
	char *begin, *end;
	int len;
	
	if (TRUE == penum->b_found) {
		return;
	}
	if (TRUE == mime_get_content_param(pmime, "charset", charset, 32)) {
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
	MIME *phead;
	
	phead = mail_get_head(pmail);
	if (NULL == phead) {
		return FALSE;
	}
	return mime_get_field(phead, "Thread-Index", pbuff, 128);
}

