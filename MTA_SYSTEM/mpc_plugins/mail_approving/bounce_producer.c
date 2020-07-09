#include <errno.h>
#include <string.h>
#include "bounce_producer.h"
#include "single_list.h"
#include "mail_func.h"
#include "util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <iconv.h>

enum{
	TAG_BEGIN,
	TAG_TIME,
	TAG_FROM,
	TAG_RCPTS,
	TAG_SUBJECT,
	TAG_PARTS,
	TAG_LENGTH,
	TAG_URL1,
	TAG_URL2,
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
 * <time> <from> <rcpts> <subject>
 * <parts> <length> <url1> <url2>
 */
typedef struct _RESOURCE_NODE{
	SINGLE_LIST_NODE	node;
	char				language[32];
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
	{"<length>", 8},
	{"<url1>", 6},
	{"<url2>", 6}
};

static void bounce_producer_enum_parts(MIME *pmime, ENUM_PARTS *penum);

static int bounce_producer_get_mail_subject(MAIL *pmail, char *subject,
	char *charset);

static int bounce_producer_get_mail_parts(MAIL *pmail, char *parts,
	char *charset);

static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff);

static void bounce_producer_load_template(const char *temp_name, SINGLE_LIST *plist);

static void bounce_producer_unload_list(SINGLE_LIST *plist);

static int bounce_producer_get_mail_charset(MAIL *pmail, char *charset);

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

	while ((pnode = single_list_get_from_head(plist)) != NULL) {
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
		printf("[mail_approving]: failed to open directory %s: %s\n",
			g_path, strerror(errno));
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
	/* check "en" language */
	for (pnode=single_list_get_head(&resource_list); NULL!=pnode;
		pnode=single_list_get_after(&resource_list, pnode)) {
		presource = (RESOURCE_NODE*)pnode->pdata;
		if (0 == strcasecmp(presource->language, "en")) {
			pdefault = presource;
			break;
		}
	}
	if (NULL == pdefault) {
		printf("[mail_approving]: there's no \"en\" bounce mail "
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
		printf("[mail_approving]: fail to allocate resource node memory\n");
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
			if (presource->content[i] == '\n') {
				++i;
				break;
			} else if (presource->content[i] == '\r' &&
			    presource->content[i+1] == '\n') {
				i += 2;
				break;
			}
		} else {
			printf("[mail_approving]: bounce mail %s format error\n",
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
			printf("[mail_approving]: format error in %s, lack of "
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
	
	strcpy(presource->language, temp_name);
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

void bounce_producer_make(MESSAGE_CONTEXT *pcontext, char *forward_to,
	char *language, char *url, MAIL *pmail)
{
	char *ptr;
	int i, len;
	BOOL b_first;
	time_t now_time;
	char charset[32];
	char to_buff[256];
	char tmp_buff[256];
	char date_buff[128];
	struct tm *datetime;
	struct tm time_buff;
	int prev_pos, mail_len;
	SINGLE_LIST_NODE *pnode;
	RESOURCE_NODE *presource;
	MIME *pmime, *pmime_child;
	char original_ptr[256*1024];
	
	
	bounce_producer_get_mail_charset(pcontext->pmail, charset);
	ptr = original_ptr;
	presource = NULL;
	pthread_rwlock_rdlock(&g_list_lock);
	for (pnode=single_list_get_head(&g_resource_list); NULL!=pnode;
		pnode=single_list_get_after(&g_resource_list, pnode)) {
		if (0 == strcasecmp(((RESOURCE_NODE*)pnode->pdata)->language,
			language)) {
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
			time(&now_time);
			datetime = localtime_r(&now_time, &time_buff);
			len = strftime(ptr, 255, "%x %X", datetime);
			ptr += len;
			break;
		case TAG_FROM:
			strcpy(ptr, pcontext->pcontrol->from);
			ptr += strlen(pcontext->pcontrol->from);
			break;	
		case TAG_RCPTS:
			b_first = FALSE;
			mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
				MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
			while (MEM_END_OF_FILE != (len = mem_file_readline(
				&pcontext->pcontrol->f_rcpt_to, to_buff, 256))) {
				if (TRUE == b_first) {
					strcpy(ptr, g_separator);
					ptr += strlen(g_separator);
				}
				memcpy(ptr, to_buff, len);
        		ptr += len;
				b_first = TRUE;
			}
			break;
		case TAG_SUBJECT:
			len = bounce_producer_get_mail_subject(pcontext->pmail, ptr, charset);
			ptr += len;
			break;
		case TAG_PARTS:
			len = bounce_producer_get_mail_parts(pcontext->pmail, ptr, charset);
			ptr += len;
			break;
		case TAG_LENGTH:
			mail_len = mail_get_length(pcontext->pmail);
			if (-1 == mail_len) {
				printf("[mail_approving]: fail to get mail length\n");
				mail_len = 0;
			}
			bytetoa(mail_len, ptr);
			len = strlen(ptr);
			ptr += len;
			break;
		case TAG_URL1:
			strcpy(ptr, url);
			ptr += strlen(url);
			break;
		case TAG_URL2:
			strcpy(ptr, url);
			ptr += strlen(url);
			break;
		}
	}
	len = presource->format[TAG_END].position - prev_pos;
	memcpy(ptr, presource->content + prev_pos, len);
	ptr += len;
	pmime = mail_add_head(pmail);
	if (NULL == pmime) {
		pthread_rwlock_unlock(&g_list_lock);
		printf("[mail_approving]: fatal error, there's no mime "
			"in mime pool\n");
		return;
	}
	
	mime_set_content_type(pmime, "multipart/mixed");
	pmime_child = mail_add_child(pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		pthread_rwlock_unlock(&g_list_lock);
		printf("[mail_approving]: fatal error, there's no mime "
			"in mime pool\n");
		return;
	}
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	if (TRUE == bounce_producer_get_mail_thread_index(
		pcontext->pmail, tmp_buff)) {
		mime_set_field(pmime, "Thread-Index", tmp_buff);
	}
	mime_set_field(pmime, "From", presource->from);
	snprintf(to_buff, 256, "<%s>", forward_to);
	mime_set_field(pmime, "To", to_buff);
	mime_set_field(pmime, "MIME-Version", "1.0");
	time(&now_time);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
		localtime_r(&now_time, &time_buff));
	mime_set_field(pmime, "Date", date_buff);
	mime_set_field(pmime, "Subject", presource->subject);

	parse_field_value(presource->content_type,
		strlen(presource->content_type),
		tmp_buff, 256, &pmime->f_type_params);
	mime_set_content_type(pmime, tmp_buff);
	pthread_rwlock_unlock(&g_list_lock);
	mime_set_content_param(pmime_child, "charset", "\"UTF-8\"");
	if (FALSE == mime_write_content(pmime_child, original_ptr,
		ptr - original_ptr, MIME_ENCODING_BASE64)) {
		printf("[mail_approving]: fatal error, fail to write content\n");
		return;
	}
	pmime_child = mail_add_child(pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		return;
	}
	mime_set_content_type(pmime_child, "message/rfc822");
	mime_write_mail(pmime_child, pcontext->pmail);
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

static BOOL bounce_producer_get_mail_thread_index(MAIL *pmail, char *pbuff)
{
	MIME *phead;
	
	phead = mail_get_head(pmail);
	if (NULL == phead) {
		return FALSE;
	}
	return mime_get_field(phead, "Thread-Index", pbuff, 128);
}
