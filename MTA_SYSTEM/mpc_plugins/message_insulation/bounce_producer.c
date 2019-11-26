#include "bounce_producer.h"
#include "single_list.h"
#include "mail_func.h"
#include "timezone.h"
#include "util.h"
#include "dsn.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <iconv.h>
#include <time.h>

enum{
	TAG_BEGIN,
	TAG_TIME,
	TAG_FROM,
	TAG_RCPTS,
	TAG_SUBJECT,
	TAG_PARTS,
	TAG_LENGTH,
	TAG_END,
	TAG_TOTAL_LEN = TAG_END
};

typedef struct _ENUM_CHARSET {
	BOOL b_found;
	char *charset;
} ENUM_CHARSET;


typedef struct _ENUM_PARTS {
	int	 offset;
	char *ptr;
	char *charset;
	BOOL b_first;
} ENUM_PARTS;

typedef struct _FORMAT_DATA {
	int	position;
	int tag;
} FORMAT_DATA;

/*
 * <time> <from>
 * <rcpts> <subject>
 * <parts> <length>
 */
typedef struct _RESOURCE_NODE{
	SINGLE_LIST_NODE	node;
	char				charset[32];
	char				from[256];
	char				subject[256];
	char				content_type[256];
	char				*content;	
	FORMAT_DATA			format[TAG_TOTAL_LEN + 1];
} RESOURCE_NODE;

typedef struct _TAG_ITEM{
	const char	*name;
	int			length;
} TAG_ITEM;

static char g_path[256];
static char g_separator[16];
static SINGLE_LIST g_resource_list;
static RESOURCE_NODE *g_default_resource;
static pthread_rwlock_t g_list_lock;
static TAG_ITEM g_tags[] = {
	{"<time>", 6},
	{"<from>", 6},
	{"<rcpts>", 7},
	{"<subject>", 9},
	{"<parts>", 7},
	{"<length>", 8}
};


BOOL (*bounce_producer_get_lang)(const char *username, char *lang);

BOOL (*bounce_producer_get_timezone)(const char *username, char *timezone);

BOOL (*bounce_producer_lang_to_charset)(const char *lang, char *charset);

static void bounce_producer_enum_parts(MIME *pmime, ENUM_PARTS *penum);

static void bounce_producer_enum_charset(MIME *pmime, ENUM_CHARSET *penum);

static int bounce_producer_get_mail_subject(MAIL *pmail, char *subject,
	char *charset);

static int bounce_producer_get_mail_charset(MAIL *pmail, char *charset);

static int bounce_producer_get_mail_parts(MAIL *pmail, char *parts,
	char *charset);

static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff);

static void bounce_producer_load_template(const char *temp_name, SINGLE_LIST *plist);

static void bounce_producer_unload_list(SINGLE_LIST *plist);


/*
 *	bounce producer's construct function
 *	@param
 *		path [in]			path of resource
 *		separator [in]		separator character for rcpts and attachements
 */
void bounce_producer_init(const char *path, const char* separator)
{
	strcpy(g_path, path);
	strcpy(g_separator, separator);
	g_default_resource = NULL;
}

/*
 *	run the bounce producer module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int bounce_producer_run()
{
	bounce_producer_get_lang = query_service("get_user_lang");
	bounce_producer_get_timezone = query_service("get_user_timezone");
	bounce_producer_lang_to_charset = query_service("lang_to_charset");


	single_list_init(&g_resource_list);
	pthread_rwlock_init(&g_list_lock, NULL);
	if (FALSE == bounce_producer_refresh()) {
		return -1;
	}
	return 0;
}

/*
 *	unload the list of resource
 *	@param
 *		plist [in]			list object
 */
static void bounce_producer_unload_list(SINGLE_LIST *plist)
{
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;

	while (pnode = single_list_get_from_head(plist)) {
		presource = (RESOURCE_NODE*)pnode->pdata;
        free(presource->content);
		free(presource);
	}
}

/*
 *	refresh the current resource list
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
BOOL bounce_producer_refresh()
{
	DIR *dirp;
	SINGLE_LIST_NODE *pnode;
    struct dirent *direntp;
	RESOURCE_NODE *pdefault;
	RESOURCE_NODE *presource;
	SINGLE_LIST resource_list, temp_list;

	single_list_init(&resource_list);
	dirp = opendir(g_path);
	if (NULL == dirp) {
		printf("[message_insulation]: fail to open directory %s\n", g_path);
		return FALSE;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		bounce_producer_load_template(direntp->d_name, &resource_list);
    }
	closedir(dirp);

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
		printf("[message_insulation]: there's no \"ascii\" bounce mail "
			"templates\n");
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
 *	load template into reasource list
 *	@param
 *		temp_name [in]			template name
 *		plist [out]				resource will be appended into this list
 */
static void bounce_producer_load_template(const char *temp_name, SINGLE_LIST *plist)
{
    int fd, i, j;
	int parsed_length;
    char dir_buff[256];
	FORMAT_DATA temp;
	struct stat node_stat;
	MIME_FIELD mime_field;
	RESOURCE_NODE *presource;

	presource = (RESOURCE_NODE*)malloc(sizeof(RESOURCE_NODE));
	if (NULL == presource) {
		printf("[message_insulation]: fail to allocate resource node memory\n");
		return;
	}
	/* fill the struct with initial data */
	presource->content = NULL;
	for (i=0; i<TAG_TOTAL_LEN; i++) {
		presource->format[i].position = -1;
		presource->format[i].tag = i;
	}
	presource->node.pdata = presource;
    sprintf(dir_buff, "%s/%s", g_path, temp_name);
    if (0 != stat(dir_buff, &node_stat) ||
        0 == S_ISREG(node_stat.st_mode)) {
		return;
    }
	presource->content = malloc(node_stat.st_size);
	if (NULL == presource->content) {
		free(presource);
		return;
	}
	fd = open(dir_buff, O_RDONLY);
	if (-1 == fd) {
		free(presource->content);
		free(presource);
		return;
	}
	if (node_stat.st_size != read(fd, presource->content,
		node_stat.st_size)) {
		close(fd);
		free(presource->content);
		free(presource);
		return;
	}
	close(fd);
	fd = -1;
		
	i = 0;
	while (i < node_stat.st_size) {
        parsed_length = parse_mime_field(presource->content + i,
		                   node_stat.st_size - i, &mime_field);
        i += parsed_length;
        if (0 != parsed_length) {
			if (0 == strncasecmp("Content-Type", mime_field.field_name, 12)) {
				memcpy(presource->content_type, mime_field.field_value,
					mime_field.field_value_len);
				presource->content_type[mime_field.field_value_len] = 0;
			} else if (0 == strncasecmp("From", mime_field.field_name, 4)) {
				memcpy(presource->from, mime_field.field_value,
					mime_field.field_value_len);
                presource->from[mime_field.field_value_len] = 0;
			} else if (0 == strncasecmp("Subject", mime_field.field_name, 7)) {
				memcpy(presource->subject, mime_field.field_value,
					mime_field.field_value_len);
                presource->subject[mime_field.field_value_len] = 0;
			}
			if ('\r' == presource->content[i]) {
				i += 2;
				break;
			}
		} else {
			printf("[message_insulation]: bounce mail %s format error!!!\n",
				dir_buff);
			free(presource->content);
			free(presource);
			return;
		}
	}
		
	/* find tags in file content and mark the position */
	presource->format[TAG_BEGIN].position = i;
	for (; i<node_stat.st_size; i++) {
		if ('<' == presource->content[i]) {
			for (j=0; j<TAG_TOTAL_LEN; j++) {
				if (0 == strncasecmp(presource->content + i,
					g_tags[j].name, g_tags[j].length)) {
					presource->format[j + 1].position = i;
					break;
				}
			}
		}
	}
	presource->format[TAG_END].position = node_stat.st_size;
	
	for (i=TAG_BEGIN+1; i<TAG_TOTAL_LEN; i++) {
		if (-1 == presource->format[i].position) {
			printf("[message_insulation]: format error in %s, lack of "
					"tag %s\n", dir_buff, g_tags[i-1].name);
			free(presource->content);
			free(presource);
			return;
		}
	}

	/* sort the tags ascending */
	for (i=TAG_BEGIN+1; i<TAG_TOTAL_LEN; i++) {
		for (j=TAG_BEGIN+1; j<TAG_TOTAL_LEN; j++) {
			if (presource->format[i].position <
				presource->format[j].position) {
				temp = presource->format[i];
				presource->format[i] = presource->format[j];
				presource->format[j]= temp;
			}
		}
	}
	
	strcpy(presource->charset, temp_name);
	single_list_append_as_tail(plist, &presource->node);
	return;

}

/*
 *	stop the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
void bounce_producer_stop(void)
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
	g_path[0] = '\0';
	g_default_resource = NULL;
}

void bounce_producer_make(MESSAGE_CONTEXT *pcontext,
	time_t original_time, MAIL *pmail)
{
	DSN dsn;
	char *ptr;
	int i, len;
	MIME *pmime;
	MIME *phead;
	char *pdomain;
	time_t cur_time;
	char charset[32];
	char mcharset[32];
	char tmp_buff[1024];
	char date_buff[128];
	struct tm time_buff;
	int prev_pos, mail_len;
	const struct state *sp;
	DSN_FIELDS *pdsn_fields;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;
	char original_ptr[256*1024];
	char lang[32], time_zone[64];
	
	
	ptr = original_ptr;
	charset[0] = '\0';
	time_zone[0] = '\0';
	pdomain = strchr(pcontext->pcontrol->from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (TRUE == is_domainlist_valid() && TRUE == check_domain(pdomain)) {
			if (NULL != bounce_producer_get_lang &&
				TRUE == bounce_producer_get_lang(pcontext->pcontrol->from, lang)) {
				if (NULL != bounce_producer_lang_to_charset) {
					bounce_producer_lang_to_charset(lang, charset);
				}
			}
			if (NULL != bounce_producer_get_timezone) {
				bounce_producer_get_timezone(pcontext->pcontrol->from, time_zone);
			}
		}
	}
	
	if('\0' != time_zone[0]) {
		sp = tz_alloc(time_zone);
		tz_localtime_r(sp, &original_time, &time_buff);
		tz_free(sp);
	} else {
		localtime_r(&original_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	
	bounce_producer_get_mail_charset(pcontext->pmail, mcharset);
	
	if ('\0' == charset[0]) {
		strcpy(charset, mcharset);
	}
	presource = NULL;
	pthread_rwlock_rdlock(&g_list_lock);
	for (pnode=single_list_get_head(&g_resource_list); NULL!=pnode;
        pnode=single_list_get_after(&g_resource_list, pnode)) {
        if (0 == strcasecmp(((RESOURCE_NODE*)pnode->pdata)->charset,
			charset)) {
			presource = (RESOURCE_NODE*)pnode->pdata;
			break;
		}
    }
	if (NULL == presource) {
		presource = g_default_resource;
	}
	prev_pos = presource->format[TAG_BEGIN].position;
	for (i=TAG_BEGIN+1; i<TAG_TOTAL_LEN; i++) {
		len = presource->format[i].position - prev_pos;
		memcpy(ptr, presource->content + prev_pos, len);
		prev_pos = presource->format[i].position +
					g_tags[presource->format[i].tag-1].length;
		ptr += len;
		switch (presource->format[i].tag) {
		case TAG_TIME:
			len = snprintf(ptr, 128, "%s", date_buff);
			ptr += len;
			break;
		case TAG_FROM:
			strcpy(ptr, pcontext->pcontrol->from);
			ptr += strlen(pcontext->pcontrol->from);
			break;	
    	case TAG_RCPTS:
			mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
				MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
			while (MEM_END_OF_FILE != (len = mem_file_readline(
				&pcontext->pcontrol->f_rcpt_to, ptr, 256))) {
        		ptr += len;
				strcpy(ptr, g_separator);
        		ptr += strlen(g_separator);
			}
			break;
    	case TAG_SUBJECT:
			len = bounce_producer_get_mail_subject(pcontext->pmail, ptr, mcharset);
            ptr += len;
            break;
    	case TAG_PARTS:
			len = bounce_producer_get_mail_parts(pcontext->pmail, ptr, mcharset);
			ptr += len;
            break;
    	case TAG_LENGTH:
			mail_len = mail_get_length(pcontext->pmail);
			if (-1 == mail_len) {
				printf("[message_insulation]: fail to get mail length\n");
				mail_len = 0;
			}
			bytetoa(mail_len, ptr);
			len = strlen(ptr);
			ptr += len;
			break;
		}
	}
	len = presource->format[TAG_END].position - prev_pos;
	memcpy(ptr, presource->content + prev_pos, len);
	ptr += len;
	phead = mail_add_head(pmail);
	if (NULL == phead) {
		pthread_rwlock_unlock(&g_list_lock);
		printf("[message_insulation]: fatal error, there's no mime in mime "
			"pool\n");
		return;
	}
	pmime = phead;
	mime_set_content_type(pmime, "multipart/report");
	mime_set_content_param(pmime, "report-type", "delivery-status");
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
					"(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
	if (TRUE == bounce_producer_get_mail_thread_index(
		pcontext->pmail, tmp_buff)) {
		mime_set_field(pmime, "Thread-Index", tmp_buff);
	}
	mime_set_field(pmime, "From", presource->from);
	snprintf(tmp_buff, 256, "<%s>", pcontext->pcontrol->from);
	mime_set_field(pmime, "To", tmp_buff);
	mime_set_field(pmime, "MIME-Version", "1.0");
	time(&cur_time);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	mime_set_field(pmime, "Date", date_buff);
	mime_set_field(pmime, "Subject", presource->subject);
	
	pmime = mail_add_child(pmail, phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		pthread_rwlock_unlock(&g_list_lock);
		printf("[message_insulation]: fatal error, there's no mime "
			"in mime pool\n");
		return;
	}
	parse_field_value(presource->content_type,
		strlen(presource->content_type),
		tmp_buff, 256, &pmime->f_type_params);
	mime_set_content_type(pmime, tmp_buff);
	pthread_rwlock_unlock(&g_list_lock);
	mime_set_content_param(pmime, "charset", "\"utf-8\"");
	if (FALSE == mime_write_content(pmime, original_ptr,
		ptr - original_ptr, MIME_ENCODING_BASE64)) {
        printf("[message_insulation]: fatal error, fail to write content\n");
        return;
	}
	
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn_append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	localtime_r(&original_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	dsn_append_field(pdsn_fields, "Arrival-Date", date_buff);
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, tmp_buff + 7, 256)) {
		pdsn_fields = dsn_new_rcpt_fields(&dsn);
		if (NULL == pdsn_fields) {
			continue;
		}
		memcpy(tmp_buff, "rfc822;", 7);
		dsn_append_field(pdsn_fields, "Final-Recipient", tmp_buff);
		dsn_append_field(pdsn_fields, "Action", "failed");
		dsn_append_field(pdsn_fields, "Status", "5.0.0");
		snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
		dsn_append_field(pdsn_fields, "Remote-MTA", tmp_buff);
	}
	if (TRUE == dsn_serialize(&dsn, original_ptr, 256*1024)) {
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
