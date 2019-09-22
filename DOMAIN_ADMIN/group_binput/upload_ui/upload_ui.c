#include "util.h"
#include "midb_tool.h"
#include "upload_ui.h"
#include "list_file.h"
#include "system_log.h"
#include "exmdb_tool.h"
#include "double_list.h"
#include "exmdb_client.h"
#include "lang_resource.h"
#include "locker_client.h"
#include <libxls/xls.h>
#include <time.h>
#include <iconv.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <mysql/mysql.h>


#define HTML_COMMON_1	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>"

/* fill html title here */

#define HTML_COMMON_2	\
"</TITLE><LINK href=\"../data/css/result.css\" type=text/css rel=stylesheet>\n\
<META http-equiv=Content-Type content=\"text/html; charset="

/* fill charset here */

#define HTML_COMMON_3	\
"\"><META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\n\
marginheight=\"0\" marginwidth=\"0\"><CENTER>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0>\n\
<TBODY><TR><TD noWrap align=middle background=\"../data/picture/di1.gif\"\n\
height=55><SPAN class=ReportTitle> "

/* fill result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE>\n\
<BR><BR><P align=right><A href=../data/script/template_gp.xls>%s</A>\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</P>\n\
<BR><BR><BR><BR><BR><BR><BR><BR>\n\
<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"group\" value=\"%s\" />\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"input\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM>\n\
<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"group\" value=\"%s\" />\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"delete\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM><BR></CENTER></BODY></HTML>"

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE>\n\
<BR><BR><BR><BR><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"75%\" border=0><TBODY>\n"

#define HTML_RESULT_6	\
"</TBODY></TABLE><BR></CENTER></BODY></HTML>"

#define HTML_BACK_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><INPUT type=submit value=\"    %s    \" \n\
onclick=\"window.history.back();\"/></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=group_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_RESULT_ITEM	"<TR class=%s><TD>%s</TD><TD>%s</TD></TR>\n"

#define CSS_ITEM_EVEN			"ItemEven"

#define CSS_ITEM_ODD			"ItemOdd"

#define CSS_ITEM_OVERQUOTA		"ItemOverquota"

#define ADDRESS_TYPE_NORMAL		0

#define DOMAIN_TYPE_NORMAL		0

#define VDIR_PER_PARTITION      200

#define MAILDIR_PER_VDIR        250

#define DIGEST_BUFLEN           256

#define GROUP_PRIVILEGE_ACCOUNT	0x8

#define DEF_MODE                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

enum {
	INPUT_RESULT_OK,
	INPUT_RESULT_ALIASED,
	INPUT_RESULT_NODOMAIN,
	INPUT_RESULT_DOMAINNOTMAIN,
	INPUT_RESULT_NOGROUP,
	INPUT_RESULT_GROUPUSERFULL,
	INPUT_RESULT_GROUPSIZEFULL,
	INPUT_RESULT_DOMAINUSERFULL,
	INPUT_RESULT_DOMAINSIZEFULL,
	INPUT_RESULT_DOMAINMIGRATING
};

enum {
	DELETE_RESULT_OK,
	DELETE_RESULT_NODOMAIN,
	DELETE_RESULT_DOMAINNOTMAIN,
	DELETE_RESULT_NOGROUP,
	DELETE_RESULT_DOMAINMIGRATING
};

enum {
	XLS_RESULT_OK,
	XLS_RESULT_OPENFAIL,
	XLS_RESULT_NOSHEET,
	XLS_RESULT_NOROWS,
	XLS_RESULT_COLERROR,
	XLS_RESULT_TOUCHED
};

enum {
	ITEM_RESULT_NONE = 0,
	ITEM_UPDATE_USERERR,
	ITEM_UPDATE_USERTYPE,
	ITEM_CREATE_PASSWD,
	ITEM_CREATE_MAILDIR,
	ITEM_INPUT_SQL,
	ITEM_DELETE_SQL,
	ITEM_DELETE_NOUSER,
	ITEM_DELETE_USERTYPE,
	ITEM_DELETE_USERERR,
	ITEM_XLS_ADDRESS,
	ITEM_XLS_ADDRLEN,
	ITEM_XLS_ADDRSAME,
	ITEM_XLS_DOMAIN,
	ITEM_XLS_PASSWDLEN,
	ITEM_XLS_REALNAMELEN,
	ITEM_XLS_NICKNAMELEN,
	ITEM_XLS_TELLEN,
	ITEM_XLS_CELLLEN,
	ITEM_XLS_HOMELEN,
	ITEM_XLS_MEMOLEN,
	ITEM_XLS_TITLELEN,
	ITEM_XLS_SIZE,
	ITEM_UPDATE_OK,
	ITEM_CREATE_OK,
	ITEM_DELETE_OK
};


typedef struct _AREA_ITEM {
	char type[12];
	char master[256];
	char slave[256];
	int space;
	int files;
} AREA_ITEM;

typedef struct _AREA_NODE {
	DOUBLE_LIST_NODE node;
	char master[256];
	char database[256];
	char slave[256];
	int max_space;
	int used_space;
	int used_files;
	int homes;
} AREA_NODE;

typedef struct _USER_ITEM {
	DOUBLE_LIST_NODE node;
	BOOL b_exist;
	char username[128];
	char password[40];
	char maildir[256];
	int size;
	int result;
	char title[128];
	char real_name[128];
	char nickname[128];
	char tel[20];
	char cell[20];
	char homeaddress[128];
	char memo[128];
	char lang[32];
	DOUBLE_LIST class_list;
} USER_ITEM;

typedef struct _CLASS_ITEM {
	DOUBLE_LIST_NODE node;
	int class_id;
	char classname[128];
} CLASS_ITEM;

static void upload_ui_error_html(const char *error_string);

static void upload_ui_main_html(const char *groupname, const char *session);

static void upload_ui_operation_error_html(const char *error_string);

static void upload_ui_result_input(DOUBLE_LIST *plist);

static void upload_ui_result_delete(DOUBLE_LIST *plist);

static void upload_ui_error_xls(DOUBLE_LIST *plist);

static BOOL upload_ui_get_self(char *url_buff, int length);

static void upload_ui_unencode(char *src, char *last, char *dest);

static void upload_ui_encode_squote(const char *in, char *out);

static BOOL upload_ui_allocate_dir(const char *media_area,
	char *path_buff, int max_size, int max_file);

static void upload_ui_free_dir(BOOL b_media, const char *maildir);

static void upload_ui_partition_info(char *s,
	int *pmegas, int *pfiles, int *phomes);

static void upload_ui_remove_inode(const char *path);

static BOOL upload_ui_info_group(const char *groupname,
	int *pprivilege_bits, char *domain_path);

static BOOL upload_ui_batch_input(const char *groupname,
	DOUBLE_LIST *plist, int *presult);

static BOOL upload_ui_batch_delete(const char *groupname,
	DOUBLE_LIST *plist, int *presult);

static BOOL upload_ui_xls_input(const char *domainname,
	const char *path, DOUBLE_LIST *plist, int *presult);

static BOOL upload_ui_xls_delete(const char *domainname,
	const char *path, DOUBLE_LIST *plist, int *presult);

static BOOL upload_ui_check_address(const char *address);

static void upload_ui_free_ulist(DOUBLE_LIST *plist);

static void upload_ui_from_utf8(char *src, char *dst, size_t len);

static void upload_ui_to_utf8(char *src, char *dst, size_t len);

static int g_port;
static int g_max_file;
static char g_logo_link[1024];
static char g_list_path[256];
static char g_host[256];
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];
static char g_resource_path[256];
static char g_thumbnail_path[256];
static LANG_RESOURCE *g_lang_resource;

void upload_ui_init(const char *list_path, int max_file, const char *url_link,
	const char *host, int port, const char *user, const char *password,
	const char *db_name, const char *resource_path, const char *thumbnail_path)
{
	g_max_file = max_file;
	strcpy(g_list_path, list_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_host, host);
	g_port = port;
	strcpy(g_user, user);
	if (NULL == password || '\0' == password[0]) {
		g_password = NULL;
	} else {
		strcpy(g_password_buff, password);
		g_password = g_password_buff;
	}
	strcpy(g_db_name, db_name);
	strcpy(g_resource_path, resource_path);
	strcpy(g_thumbnail_path, thumbnail_path);
}


int upload_ui_run()
{
	int len, fd;
	int offset;
	int i, result;
	int bnd_len;
	int privilege_bits;
	char *query;
	char *request;
	char *language;
	char *pdomain;
	char *ptr1, *ptr2;
	char boundary[128];
	char temp_buff[1024];
	char groupname[128];
	char session[256];
	char post_buff[1024];
	char search_buff[4096];
	char domain_path[256];
	char temp_path[256], type[32];
	DOUBLE_LIST user_list;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		upload_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[upload_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[upload_ui]: fail to "
			"get  REQUEST_METHOD environment!");
		return -2;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		if (len > 127) {
			goto POST_ERROR;
		}
		strcpy(boundary, post_buff);
		bnd_len = strlen(boundary);
		if ('\n' == boundary[bnd_len - 1]) {
			bnd_len --;
		}
		if ('\r' == boundary[bnd_len - 1]) {
			bnd_len --;
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		upload_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			goto POST_ERROR;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2 || ptr2 - ptr1 > 32) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "group")) {
			goto POST_ERROR;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		if (len >= 128) {
			goto POST_ERROR;
		}
		memset(groupname, 0, 128);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				groupname[i] = '\0';
				break;
			} else {
				groupname[i] = post_buff[i];
			}
		}
		lower_string(groupname);
		pdomain = strchr(groupname, '@');
		if (NULL == pdomain) {
			goto POST_ERROR;
		}
		pdomain ++;

		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
			
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		upload_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			goto POST_ERROR;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2 || ptr2 - ptr1 > 32) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "session")) {
			goto POST_ERROR;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		if (len >= 128) {
			goto POST_ERROR;
		}
		memset(session, 0, 128);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				session[i] = '\0';
				break;
			} else {
				session[i] = post_buff[i];
			}
		}

		if (FALSE == session_client_check(groupname, session)) {
			upload_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_SESSION", language));
			return 0;
		}
		
		if (FALSE == upload_ui_info_group(groupname,
			&privilege_bits, domain_path)) {
			upload_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_INTERNAL", language));
			return 0;
		}
		if ((privilege_bits&GROUP_PRIVILEGE_ACCOUNT) == 0) {
			upload_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_PRIVILEGE", language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
		
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		upload_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			goto POST_ERROR;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2 || ptr2 - ptr1 >= 32) {
			goto POST_ERROR;
		}
		memcpy(type, ptr1, ptr2 - ptr1);
		type[ptr2 - ptr1] = '\0';
		strcpy(temp_buff, groupname);
		*strchr(temp_buff, '@') = '\0';
		if (0 == strcasecmp(type, "input")) {
			sprintf(temp_path, "%s/%s/tmp/input.%s.xls", domain_path,
				temp_buff, session);
		} else if (0 == strcasecmp(type, "delete")) {
			sprintf(temp_path, "/%s/%s/tmp/delete.%s.xls", domain_path,
				temp_buff, session);
		} else {
			goto POST_ERROR;
		}
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);	
		if (-1 == fd) {
			system_log_info("[upload_ui]: fail to "
				"create list file for %s\n", temp_path);
			upload_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_INTERNAL", language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		offset = 0;
		while (len = fread(post_buff + offset, 1, 1024 - offset, stdin)) {
			offset += len;
			if (offset >= bnd_len + 2) {
				write(fd, post_buff, offset - bnd_len - 2);
				memmove(post_buff, post_buff + offset - bnd_len - 2,
					bnd_len + 2);
				offset = bnd_len + 2;
			} else {
				continue;
			}
			
			if ('\r' == post_buff[0] && '\r' == post_buff[1] &&
				0 == strncmp(post_buff + 2, boundary, bnd_len)) {
				break;
			}
		}
		
		close(fd);
		double_list_init(&user_list);
		if (0 == strcasecmp(type, "input")) {
			if (FALSE == upload_ui_xls_input(pdomain, temp_path,
				&user_list, &result)) {
				double_list_free(&user_list);
				switch (result) {
				case XLS_RESULT_OPENFAIL:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_OPENFAIL", language));
					break;
				case XLS_RESULT_NOSHEET:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_NOSHEET", language));
					break;
				case XLS_RESULT_NOROWS:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_NOROWS", language));
					break;
				case XLS_RESULT_COLERROR:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_COLERROR", language));
					break;
				}
				remove(temp_path);
				return 0;
			}
			remove(temp_path);
			if (XLS_RESULT_TOUCHED == result) {
				upload_ui_error_xls(&user_list);
				upload_ui_free_ulist(&user_list);
				double_list_free(&user_list);
				return 0;
			}
			if (FALSE == upload_ui_batch_input(groupname,
				&user_list, &result)) {
				upload_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_INTERNAL", language));
				upload_ui_free_ulist(&user_list);
				double_list_free(&user_list);
				return 0;
			}
			switch (result) {
			case INPUT_RESULT_OK:
				upload_ui_result_input(&user_list);
				break;
			case INPUT_RESULT_ALIASED:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_ALIASED", language));
				break;
			case INPUT_RESULT_NODOMAIN:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_NODOMAIN", language));
				break;
			case INPUT_RESULT_DOMAINNOTMAIN:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_DOMAINNOTMAIN", language));
				break;
			case INPUT_RESULT_NOGROUP:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_NOGROUP", language));
				break;
			case INPUT_RESULT_GROUPUSERFULL:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_GROUPUSERFULL", language));
				break;
			case INPUT_RESULT_GROUPSIZEFULL:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_GROUPSIZEFULL", language));
				break;
			case INPUT_RESULT_DOMAINUSERFULL:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_DOMAINUSERFULL", language));
				break;
			case INPUT_RESULT_DOMAINSIZEFULL:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_DOMAINSIZEFULL", language));
				break;
			case INPUT_RESULT_DOMAINMIGRATING:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "INPUT_ERROR_DOMAINMIGRATING", language));
				break;
			}
		} else {
			if (FALSE == upload_ui_xls_delete(pdomain, temp_path,
				&user_list, &result)) {
				double_list_free(&user_list);
				switch (result) {
				case XLS_RESULT_OPENFAIL:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_OPENFAIL", language));
					break;
				case XLS_RESULT_NOSHEET:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_NOSHEET", language));
					break;
				case XLS_RESULT_NOROWS:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_NOROWS", language));
					break;
				case XLS_RESULT_COLERROR:
					upload_ui_operation_error_html(lang_resource_get(
						g_lang_resource, "XLS_ERROR_COLERROR", language));
					break;
				}
				remove(temp_path);
				return 0;
			}
			remove(temp_path);
			if (XLS_RESULT_TOUCHED == result) {
				upload_ui_error_xls(&user_list);
				upload_ui_free_ulist(&user_list);
				double_list_free(&user_list);
				return 0;
			}
			if (FALSE == upload_ui_batch_delete(groupname,
				&user_list, &result)) {
				upload_ui_error_html(lang_resource_get(
					g_lang_resource,"ERROR_INTERNAL", language));
				upload_ui_free_ulist(&user_list);
				double_list_free(&user_list);
				return 0;
			}
			switch (result) {
			case DELETE_RESULT_OK:
				upload_ui_result_delete(&user_list);
				break;
			case DELETE_RESULT_NODOMAIN:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "DELETE_ERROR_NODOMAIN", language));
				break;
			case DELETE_RESULT_DOMAINNOTMAIN:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "DELETE_ERROR_DOMAINNOTMAIN", language));
				break;
			case DELETE_RESULT_NOGROUP:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "DELETE_ERROR_NOGROUP", language));
				break;
			case DELETE_RESULT_DOMAINMIGRATING:
				upload_ui_operation_error_html(lang_resource_get(
					g_lang_resource, "DELETE_ERROR_DOMAINMIGRATING", language));
				break;
			}
		}
		upload_ui_free_ulist(&user_list);
		double_list_free(&user_list);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[upload_ui]: fail to"
				" get QUERY_STRING environment!");
			upload_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 4096) {
				system_log_info("[upload_ui]: query string too long!");
				upload_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			upload_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			if ('\n' == search_buff[len - 1]) {
				len --;
				search_buff[len] = '\0';
			}
			ptr1 = search_string(search_buff, "group=", len);
			if (NULL == ptr1) {
				goto GET_ERROR;
			}
			ptr1 += 6;
			ptr2 = search_string(search_buff, "&session=", len);
			if (NULL == ptr2 || ptr2 - ptr1 > 127) {
				goto GET_ERROR;
			}
			memcpy(groupname, ptr1, ptr2 - ptr1);
			groupname[ptr2 - ptr1] = '\0';
			lower_string(groupname);

			ptr1 = ptr2 + 9;
			if (strlen(ptr1) > 127) {
				goto GET_ERROR;
			}
			strcpy(session, ptr1);
			if (FALSE == session_client_check(groupname, session)) {
				upload_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_SESSION", language));
				return 0;
			}
			if (FALSE == upload_ui_info_group(groupname,
				&privilege_bits, NULL)) {
				upload_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_INTERNAL", language));
				return 0;
			}
			if ((privilege_bits&GROUP_PRIVILEGE_ACCOUNT) == 0) {
				upload_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_PRIVILEGE", language));
				return 0;
			}
			upload_ui_main_html(groupname, session);
			return 0;
		}
	} else {
		system_log_info("[upload_ui]: unrecognized"
				" REQUEST_METHOD \"%s\"!", request);
		upload_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return 0;
	}
GET_ERROR:
	system_log_info("[upload_ui]: query string of GET format error");
	upload_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_REQUEST", language));
	return 0;
POST_ERROR:
	system_log_info("[upload_ui]: query string of POST format error");
	upload_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_REQUEST", language));
	return 0;
}

static BOOL upload_ui_info_group(const char *groupname,
	int *pprivilege_bits, char * domain_path)
{
	int i;
	char *pdomain;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;

	*pprivilege_bits = 0;
	i = 0;
	
RETRYING:
	if (i > 3) {
		return FALSE;
	}

	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[upload_ui]: fail to connect to "
				"mysql server, reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}

	if (NULL != domain_path) {
		pdomain = strchr(groupname, '@') + 1;
		upload_ui_encode_squote(pdomain, temp_name);
		sprintf(sql_string, "SELECT homedir FROM domains"
					" WHERE domainname='%s'", temp_name);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			system_log_info("[upload_ui]: fail to query mysql"
					" server, reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
		
		if (1 == mysql_num_rows(pmyres)) {
			myrow = mysql_fetch_row(pmyres);
			strcpy(domain_path, myrow[0]);
		} else {
			strcpy(domain_path, "/tmp");
		}
		mysql_free_result(pmyres);
	}

	upload_ui_encode_squote(groupname, temp_name);
	sprintf(sql_string, "SELECT privilege_bits FROM "
			"groups WHERE groupname='%s'", temp_name);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
			" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	if (1 == mysql_num_rows(pmyres)) {
		myrow = mysql_fetch_row(pmyres);
		*pprivilege_bits = atoi(myrow[0]);
	}

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}


static BOOL upload_ui_batch_input(const char *groupname,
	DOUBLE_LIST *plist, int *presult)
{
	int user_id;
	int i, rows;
	int group_id;
	int domain_id;
	int group_user;
	int group_size;
	int group_privilege;
	int domain_user;
	int domain_size;
	int domain_privilege;
	int privilege_bits;
	int max_size;
	int user_num;
	int current_size;
	int total_users;
	int total_size;
	time_t now_time;
	uint64_t tmp_int64;
	char *pdomain;
	char *ptr1, *ptr2;
	char maildir[256];
	char mediadir[256];
	char size_buff[16];
	char temp_buff[256];
	char temp_title[256];
	char temp_real[256];
	char temp_nick[256];
	char temp_tel[40];
	char temp_cell[40];
	char temp_home[256];
	char temp_memo[256];
	char new_title[128];
	char new_real[128];
	char new_nick[128];
	char new_tel[20];
	char new_cell[20];
	char new_home[128];
	char new_memo[128];
	char str_create[32];
	char media_area[128];
	char temp_password[40];
	char sql_string[1024];
	char resource_name[256];
	struct tm tmp_tm;
	LOCKD lockd;
	MYSQL *pmysql;
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	USER_ITEM *pitem_user;
	CLASS_ITEM *pitem_class;
	CLASS_ITEM *pitem_class1;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST_NODE *pnode2;
	DOUBLE_LIST class_list;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL propval_buff[2];
	

	time(&now_time);
	localtime_r(&now_time, &tmp_tm);
	strftime(str_create, 16, "%Y-%m-%d", &tmp_tm);
	
	pdomain = strchr(groupname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		system_log_info("[upload_ui]: fail to connect "
			"mysql servce, reason:%s", mysql_error(pmysql));
		locker_client_unlock(lockd);
		return FALSE;
	}

	upload_ui_encode_squote(pdomain, temp_buff);
	snprintf(sql_string, 1024, "SELECT aliasname FROM"
			" aliases WHERE mainname='%s'", temp_buff);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return FALSE;
	} 
	if (0 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = INPUT_RESULT_ALIASED;
		locker_client_unlock(lockd);
		return TRUE;
	}
	mysql_free_result(pmyres);
	
	snprintf(sql_string, 1024, "SELECT id, domain_type, max_size,"
			" max_user, privilege_bits, media FROM domains WHERE "
			"domainname='%s'", temp_buff);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return FALSE;
	} 
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = INPUT_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);

	if (DOMAIN_TYPE_NORMAL != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = INPUT_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (0 == strncmp(myrow[5], "<<", 2) ||
		0 == strncmp(myrow[5], ">>", 2)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = INPUT_RESULT_DOMAINMIGRATING;
		locker_client_unlock(lockd);
		return TRUE;
	} else {
		media_area[0] = '\0';
		if ('\0' != myrow[5][0]) {
			if (0 == strncmp(myrow[5], "<=", 2)) {
				strcpy(media_area, myrow[5] + 2);
			} else if (0 != strncmp(myrow[5], "=>", 2)) {
				strcpy(media_area, myrow[5]);
			}
		}
	}
	
	domain_id = atoi(myrow[0]);
	domain_size = atoi(myrow[2]);
	domain_user = atoi(myrow[3]);
	domain_privilege = atoi(myrow[4]);
	mysql_free_result(pmyres);
	
	upload_ui_encode_squote(groupname, temp_buff);
	snprintf(sql_string, 1024, "SELECT id, max_size, max_user, "
		"privilege_bits FROM groups WHERE groupname='%s'", temp_buff);	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return FALSE;
	} 
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = INPUT_RESULT_NOGROUP;
		locker_client_unlock(lockd);
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	group_id = atoi(myrow[0]);
	group_size = atoi(myrow[1]);
	group_user = atoi(myrow[2]);
	group_privilege = atoi(myrow[3]);
	mysql_free_result(pmyres);

	privilege_bits = (domain_privilege << 16) | (group_privilege << 8) | 0xFF;
	
	max_size = 0;
	current_size = 0;
	user_num = 0;
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pitem_user = (USER_ITEM*)pnode->pdata;
		upload_ui_encode_squote(pitem_user->username, temp_buff);
		snprintf(sql_string, 1024, "SELECT max_size, domain_id, group_id, "
			"address_type, maildir FROM users WHERE username='%s'", temp_buff);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			system_log_info("[upload_ui]: fail to query mysql"
					" server, reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			locker_client_unlock(lockd);
			return FALSE;		
		}
		if (1 == mysql_num_rows(pmyres)) {
			pitem_user->b_exist = TRUE;
			if (domain_id != atoi(myrow[1]) ||
				group_id != atoi(myrow[2])) {
				pitem_user->result = ITEM_UPDATE_USERERR;
			} else {
				if (ADDRESS_TYPE_NORMAL != atoi(myrow[3])) {
					pitem_user->result = ITEM_UPDATE_USERTYPE;
				} else {
					current_size += atoi(myrow[0]);	
					max_size += pitem_user->size;
					strcpy(pitem_user->maildir, myrow[4]);
				}
			}
		} else {
			pitem_user->b_exist = FALSE;
			if ('\0' == pitem_user->password[0]) {
				pitem_user->result = ITEM_CREATE_PASSWD;
			} else {
				user_num ++;
				max_size += pitem_user->size;
			}
		}
		mysql_free_result(pmyres);
	}
	
	sprintf(sql_string, "SELECT max_size, address_type"
			" FROM users WHERE group_id=%d", group_id);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return FALSE;
	}

	total_users = 0;
	total_size = 0;

	rows = mysql_num_rows(pmyres);
	for (i=0; i<rows; i++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL != atoi(myrow[1])) {
			continue;
		}
		total_users ++;
		total_size += atoi(myrow[0]);
	}
	mysql_free_result(pmyres);

	if (total_users + user_num > group_user) {
		*presult = INPUT_RESULT_GROUPUSERFULL;
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (total_size - current_size + max_size > group_size) {
		*presult = INPUT_RESULT_GROUPSIZEFULL;
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}

	sprintf(sql_string, "SELECT max_size, address_type"
			" FROM users WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return FALSE;
	}

	total_users = 0;
	total_size = 0;

	rows = mysql_num_rows(pmyres);
	for (i=0; i<rows; i++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL != atoi(myrow[1])) {
			continue;
		}
		total_users ++;
		total_size += atoi(myrow[0]);
	}
	mysql_free_result(pmyres);

	if (total_users + user_num > domain_user) {
		*presult = INPUT_RESULT_DOMAINUSERFULL;
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (total_size - current_size + max_size > domain_size) {
		*presult = INPUT_RESULT_DOMAINSIZEFULL;
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
		
	double_list_init(&class_list);
	
	snprintf(sql_string, 1024, "SELECT id, classname"
		" FROM classes WHERE group_id=%d", group_id);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
			" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		double_list_free(&class_list);
		locker_client_unlock(lockd);
		return FALSE;
	} 
	rows = mysql_num_rows(pmyres);
	for (i=0; i<rows; i++) {
		myrow = mysql_fetch_row(pmyres);
		pitem_class = (CLASS_ITEM*)malloc(sizeof(CLASS_ITEM));
		if (NULL == pitem_class) {
			continue;
		}
		pitem_class->node.pdata = pitem_class;
		pitem_class->class_id = atoi(myrow[0]);
		upload_ui_from_utf8(myrow[1], pitem_class->classname, 128);
		double_list_append_as_tail(&class_list, &pitem_class->node);
	}
	mysql_free_result(pmyres);
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pitem_user = (USER_ITEM*)pnode->pdata;

		if (0 != pitem_user->result) {
			continue;
		}

		for (pnode1=double_list_get_head(&pitem_user->class_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pitem_user->class_list, pnode1)) {
			pitem_class = (CLASS_ITEM*)pnode1->pdata;
			for (pnode2=double_list_get_head(&class_list); NULL!=pnode2;
				pnode2=double_list_get_after(&class_list, pnode2)) {
				pitem_class1 = (CLASS_ITEM*)pnode2->pdata;
				if (0 == strcasecmp(pitem_class->classname,
					pitem_class1->classname)) {
					pitem_class->class_id = pitem_class1->class_id;
				}
			}
		}
		upload_ui_to_utf8(pitem_user->title, new_title, 128);
		upload_ui_to_utf8(pitem_user->real_name, new_real, 128);
		upload_ui_to_utf8(pitem_user->nickname, new_nick, 128);
		upload_ui_to_utf8(pitem_user->tel, new_tel, 20);
		upload_ui_to_utf8(pitem_user->cell, new_cell, 20);
		upload_ui_to_utf8(pitem_user->homeaddress, new_home, 128);
		upload_ui_to_utf8(pitem_user->memo, new_memo, 128);
		upload_ui_encode_squote(pitem_user->username, temp_buff);
		upload_ui_encode_squote(new_title, temp_title);
		upload_ui_encode_squote(new_real, temp_real);
		upload_ui_encode_squote(new_nick, temp_nick);
		upload_ui_encode_squote(new_tel, temp_tel);
		upload_ui_encode_squote(new_cell, temp_cell);
		upload_ui_encode_squote(new_home, temp_home);
		upload_ui_encode_squote(new_memo, temp_memo);
		if (FALSE == pitem_user->b_exist) {	
			if (FALSE == upload_ui_allocate_dir(NULL,
				maildir, pitem_user->size, g_max_file)) {
				pitem_user->result = ITEM_CREATE_MAILDIR;
				continue;
			}

			if ('\0' != media_area[0]) {
				if (FALSE == upload_ui_allocate_dir(media_area,
					mediadir, pitem_user->size, g_max_file)) {
					upload_ui_free_dir(FALSE, maildir);
					pitem_user->result = ITEM_CREATE_MAILDIR;
					continue;
				}
			}

			if (0 != strcmp(pitem_user->password, "NO")) {
				strcpy(temp_password, md5_crypt_wrapper(pitem_user->password));
			} else {
				temp_password[0] = '\0';
			}
			snprintf(sql_string, 1024, "INSERT INTO users (username, "
				"password, title, real_name, nickname, tel, cell, homeaddress,"
				" memo, domain_id, group_id, maildir, max_size, max_file, "
				"privilege_bits, create_day) VALUES ('%s', '%s', '%s', '%s', "
				"'%s', '%s', '%s', '%s', '%s', %d, %d, '%s', %d, %d, %d, "
				"'%s')", temp_buff, temp_password, temp_title, temp_real,
				temp_nick, temp_tel, temp_cell, temp_home, temp_memo,
				domain_id, group_id, maildir, pitem_user->size, g_max_file,
				privilege_bits, str_create);
	
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[upload_ui]: fail to query mysql"
						" server, reason: %s", mysql_error(pmysql));
				upload_ui_free_dir(FALSE, maildir);
				if ('\0' != media_area[0]) {
					upload_ui_free_dir(TRUE, mediadir);
				}
				pitem_user->result = ITEM_INPUT_SQL;
				continue;
			}
			user_id = mysql_insert_id(pmysql);
			if ('\0' != media_area[0]) {
				upload_ui_remove_inode(maildir);
				symlink(mediadir, maildir);
			}
			exmdb_tool_create(maildir,
				((uint64_t)pitem_user->size)*1024,
				pitem_user->lang, user_id);
			midb_tool_create(maildir, pitem_user->username);
			pitem_user->result = ITEM_CREATE_OK;
		} else {
			if ('\0' != pitem_user->password[0]) {
				strcpy(temp_password, md5_crypt_wrapper(pitem_user->password));
				snprintf(sql_string, 1024, "UPDATE users SET password='%s'"
						" WHERE username='%s'", temp_password, temp_buff);
				if (0 != mysql_query(pmysql, sql_string)) {
					system_log_info("[upload_ui]: fail to query mysql "
							"server, reason: %s", mysql_error(pmysql));
					pitem_user->result = ITEM_INPUT_SQL;
					continue;
				}
			}

			snprintf(sql_string, 1024, "UPDATE users SET title='%s', "
				"real_name='%s', nickname='%s', tel='%s', cell='%s', "
				"homeaddress='%s', memo='%s', max_size=%d WHERE "
				"username='%s'", temp_title, temp_real, temp_nick,
				temp_tel, temp_cell, temp_home, temp_memo,
				pitem_user->size, temp_buff);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[upload_ui]: fail to query mysql"
						" server, reason: %s", mysql_error(pmysql));
				pitem_user->result = ITEM_INPUT_SQL;
				continue;
			}
			
			tmp_int64 = pitem_user->size*1024;
			propvals.count = 2;
			propvals.ppropval = propval_buff;
			propval_buff[0].proptag = PROP_TAG_PROHIBITRECEIVEQUOTA;
			propval_buff[0].pvalue = &tmp_int64;
			propval_buff[1].proptag = PROP_TAG_PROHIBITSENDQUOTA;
			propval_buff[1].pvalue = &tmp_int64;
			exmdb_client_set_store_properties(
				pitem_user->maildir, 0, &propvals, &problems);

			snprintf(sql_string, 1024, "SELECT aliasname "
				"FROM aliases WHERE mainname='%s'", temp_buff);
			
			if (0 == mysql_query(pmysql, sql_string) &&
				NULL != (pmyres = mysql_store_result(pmysql))) {
				rows = mysql_num_rows(pmyres);
				for (i=0; i<rows; i++) {
					myrow = mysql_fetch_row(pmyres);
					upload_ui_encode_squote(myrow[0], temp_buff);
					if ('\0' != pitem_user->password[0]) {
						strcpy(temp_password,
							md5_crypt_wrapper(pitem_user->password));
						snprintf(sql_string, 1024, "UPDATE users SET"
							" password='%s' WHERE username='%s'",
							temp_password, temp_buff);
						if (0 != mysql_query(pmysql, sql_string)) {
							system_log_info("[upload_ui]: fail to query mysql"
								" server, reason: %s", mysql_error(pmysql));
						}
					}

					snprintf(sql_string, 1024, "UPDATE users SET title='%s',"
						" real_name='%s', nickname='%s', tel='%s', cell='%s',"
						" homeaddress='%s', memo='%s', max_size=%d WHERE "
						"username='%s'", temp_title, temp_real, temp_nick,
						temp_tel, temp_cell, temp_home, temp_memo,
						pitem_user->size, temp_buff);
					if (0 != mysql_query(pmysql, sql_string)) {
						system_log_info("[upload_ui]: fail to query mysql"
								" server, reason: %s", mysql_error(pmysql));
					}
				}
				mysql_free_result(pmyres);
			}
			pitem_user->result = ITEM_UPDATE_OK;
		}
		
		upload_ui_encode_squote(pitem_user->username, temp_buff);
		snprintf(sql_string, 1024, "DELETE FROM members"
					" WHERE username='%s'", temp_buff);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
			continue;
		}

		for (pnode1=double_list_get_head(&pitem_user->class_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pitem_user->class_list, pnode1)) {
			pitem_class = (CLASS_ITEM*)pnode1->pdata;
			if (0 == pitem_class->class_id) {
				continue;
			}
			snprintf(sql_string, 1024, "INSERT INTO members "
				"(class_id, username, domain_id, group_id) VALUES "
				"(%d, '%s', %d, %d)", pitem_class->class_id, temp_buff,
				domain_id, group_id);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[upload_ui]: fail to query mysql"
						" server, reason: %s", mysql_error(pmysql));
			}
		}
	}
	
	locker_client_unlock(lockd);
	mysql_close(pmysql);
	while (pnode=double_list_get_from_head(&class_list)) {
		free(pnode->pdata);
	}
	double_list_free(&class_list);
	*presult = INPUT_RESULT_OK;
	return TRUE;
}


static BOOL upload_ui_batch_delete(const char *groupname,
	DOUBLE_LIST *plist, int *presult)
{
	int i, rows;
	int group_id;
	int domain_id;
	LOCKD lockd;
	char *pdomain;
	char maildir[256];
	char mediadir[256];
	char temp_buff[256];
	char media_area[128];
	char sql_string[1024];
	char resource_name[256];
	MYSQL *pmysql;
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	struct stat node_stat;
	USER_ITEM *pitem_user;
	DOUBLE_LIST_NODE *pnode;
	

	pdomain = strchr(groupname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host,
		g_user, g_password, g_db_name, g_port, NULL, 0)) {
		system_log_info("[upload_ui]: fail to connect "
			"mysql servce, reason:%s", mysql_error(pmysql));
		locker_client_unlock(lockd);
		return FALSE;
	}

	upload_ui_encode_squote(pdomain, temp_buff);
	snprintf(sql_string, 1024, "SELECT id, domain_type, media"
			" FROM domains WHERE domainname='%s'", temp_buff);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return FALSE;
	} 
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = DELETE_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = DELETE_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	if (0 == strncmp(myrow[2], "<<", 2) ||
		0 == strncmp(myrow[2], ">>", 2)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = DELETE_RESULT_DOMAINMIGRATING;
		locker_client_unlock(lockd);
		return TRUE;
	} else {
		media_area[0] = '\0';
		if ('\0' != myrow[2][0]) {
			if (0 == strncmp(myrow[2], "<=", 2)) {
				strcpy(media_area, myrow[2] + 2);
			} else if (0 != strncmp(myrow[2], "=>", 2)) {
				strcpy(media_area, myrow[2]);
			}
		}
	}
	
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);
	
	upload_ui_encode_squote(groupname, temp_buff);
	snprintf(sql_string, 1024, "SELECT id FROM groups "
		"WHERE groupname='%s'", temp_buff);	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return FALSE;
	} 
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = DELETE_RESULT_NOGROUP;
		locker_client_unlock(lockd);
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	group_id = atoi(myrow[0]);
	mysql_free_result(pmyres);
	
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pitem_user = (USER_ITEM*)pnode->pdata;
		upload_ui_encode_squote(pitem_user->username, temp_buff);
		
		snprintf(sql_string, 1024, "SELECT address_type, maildir,"
			" domain_id, group_id FROM users WHERE username='%s'",
			temp_buff);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
			pitem_user->result = ITEM_DELETE_SQL;
			continue;
		}
		if (1 != mysql_num_rows(pmyres)) {
			mysql_free_result(pmyres);
			pitem_user->result = ITEM_DELETE_NOUSER;
			continue;
		}
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL != atoi(myrow[0])) {
			mysql_free_result(pmyres);
			pitem_user->result = ITEM_DELETE_USERTYPE;
			continue;
		}
		if (domain_id != atoi(myrow[2]) ||
			group_id != atoi(myrow[3])) {
			mysql_free_result(pmyres);
			pitem_user->result = ITEM_DELETE_USERERR;
			continue;
		}
		strcpy(maildir, myrow[1]);
		mysql_free_result(pmyres);
		
		snprintf(sql_string, 1024, "SELECT aliasname FROM"
				" aliases WHERE mainname='%s'", temp_buff);
		if (0 == mysql_query(pmysql, sql_string) &&
			NULL != (pmyres = mysql_store_result(pmysql))) {
			rows = mysql_num_rows(pmyres);
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				upload_ui_encode_squote(myrow[0], temp_buff);
				snprintf(sql_string, 1024, "DELETE FROM "
					"users WHERE username='%s'", temp_buff);
				if (0 != mysql_query(pmysql, sql_string)) {
					system_log_info("[upload_ui]: fail to query mysql"
							" server, reason: %s", mysql_error(pmysql));
				}
			}
			mysql_free_result(pmyres);
		}
		
		exmdb_client_unload_store(maildir);
		if (0 == lstat(maildir, &node_stat) &&
			0 != S_ISLNK(node_stat.st_mode)) {
			memset(mediadir, 0, 128);
			if (readlink(maildir, mediadir, 128) > 0) {
				upload_ui_free_dir(TRUE, mediadir);
				remove(maildir);
				mkdir(maildir, 0777);
			}
		}

		upload_ui_free_dir(FALSE, maildir);
		
		upload_ui_encode_squote(pitem_user->username, temp_buff);
		snprintf(sql_string, 1024, "DELETE FROM users"
					" WHERE username='%s'", temp_buff);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[upload_ui]: fail to query mysql"
					" server, reason: %s", mysql_error(pmysql));
			pitem_user->result = ITEM_DELETE_SQL;
			continue;
		}
		snprintf(sql_string, 1024, "DELETE FROM forwards"
						" WHERE username='%s'", temp_buff);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[upload_ui]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		}
		snprintf(sql_string, 1024, "DELETE FROM members"
					" WHERE username='%s'", temp_buff);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[upload_ui]: fail to query mysql"
					" server, reason: %s", mysql_error(pmysql));
		}
		snprintf(sql_string, 1024, "DELETE FROM associations WHERE "
			"username='%s'", temp_buff);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[upload_ui]: fail to query mysql"
					" server, reason: %s", mysql_error(pmysql));
		}
		pitem_user->result = ITEM_DELETE_OK;
	}
	
	mysql_close(pmysql);
	*presult = DELETE_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

static BOOL upload_ui_xls_input(const char *domainname,
	const char *path, DOUBLE_LIST *plist, int *presult)
{
	int i;
	char *pat;
	char *ptr1;
	char *ptr2;
	char *language;
	BOOL b_touched;
	xlsWorkBook *pWB;
	xlsWorkSheet *pWS;
	struct st_row_data* row;
	USER_ITEM *pitem;
	CLASS_ITEM *pitem1;
	DOUBLE_LIST_NODE *pnode;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		language = "en";
	}
	pWB = xls_open((char*)path, (char*)lang_resource_get(
					g_lang_resource, "CHARSET", language));
	if (NULL == pWB) {
		*presult = XLS_RESULT_OPENFAIL;
		return FALSE;
	}
	
	if (pWB->sheets.count < 1) {
		*presult = XLS_RESULT_NOSHEET;
		xls_close(pWB);
		return FALSE;
	}
	
	pWS = xls_getWorkSheet(pWB, 0);
	xls_parseWorkSheet(pWS);
	
	if (pWS->rows.lastrow <= 0) {
		*presult = XLS_RESULT_NOROWS;
		xls_close(pWB);
		return FALSE;
	}

	if (pWS->rows.lastcol < 4) {
		*presult = XLS_RESULT_COLERROR;
		xls_close(pWB);
		return FALSE;
	}
	
	b_touched = FALSE;
	for (i=1; i<=pWS->rows.lastrow; i++) {
		row = &pWS->rows.row[i];
		if (NULL == row->cells.cell[0].str ||
			'\0' == row->cells.cell[0].str[0]) {
			continue;
		}
		pitem = (USER_ITEM*)malloc(sizeof(USER_ITEM));
		if (NULL == pitem) {
			continue;
		}
		memset(pitem, 0, sizeof(USER_ITEM));
		pitem->node.pdata = pitem;
		double_list_init(&pitem->class_list);
		if (FALSE == upload_ui_check_address(row->cells.cell[0].str)) {
			strncpy(pitem->username, row->cells.cell[0].str, 127);
			pitem->result = ITEM_XLS_ADDRESS;
			b_touched = TRUE;
			double_list_append_as_tail(plist, &pitem->node);
			continue;
		}
		pat = strchr(row->cells.cell[0].str, '@');
		if (NULL == pat) {
			if (strlen(row->cells.cell[0].str) + strlen(domainname) > 127) {
				strncpy(pitem->username, row->cells.cell[0].str, 127);
				pitem->result = ITEM_XLS_ADDRLEN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;
			}
			strcpy(pitem->username, row->cells.cell[0].str);
			strcat(pitem->username, "@");
			strcat(pitem->username, domainname);
		} else {
			if (strlen(row->cells.cell[0].str) > 127) {
				strncpy(pitem->username, row->cells.cell[0].str, 127);
				pitem->result = ITEM_XLS_ADDRLEN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;
			}
			if (0 != strcasecmp(pat + 1, domainname)) {
				strncpy(pitem->username, row->cells.cell[0].str, 127);
				pitem->result = ITEM_XLS_DOMAIN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;			
			}
			strcpy(pitem->username, row->cells.cell[0].str);
		}
		lower_string(pitem->username);
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			if (0 == strcasecmp(pitem->username,
				((USER_ITEM*)pnode->pdata)->username)) {
				break;
			}
		}
		if (NULL != pnode) {
			pitem->result = ITEM_XLS_ADDRSAME;
			b_touched = TRUE;
			double_list_append_as_tail(plist, &pitem->node);
			continue;
		}
		
		if (NULL != row->cells.cell[1].str) {
			if (strlen(row->cells.cell[1].str) > 32) {
				pitem->result = ITEM_XLS_PASSWDLEN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;
			}
			strcpy(pitem->password, row->cells.cell[1].str);
		}
		if (NULL != row->cells.cell[2].str) {
			if (strlen(row->cells.cell[2].str) > 128) {
				pitem->result = ITEM_XLS_REALNAMELEN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;
			}
			strcpy(pitem->real_name, row->cells.cell[2].str);
		}

		if (pWS->rows.lastcol >= 5) {
			if (NULL != row->cells.cell[5].str) {
				if (strlen(row->cells.cell[5].str) >= 128) {
					pitem->result = ITEM_XLS_MEMOLEN;
					b_touched = TRUE;
					double_list_append_as_tail(plist, &pitem->node);
					continue;
				}
				strcpy(pitem->memo, row->cells.cell[5].str);
			}
		}

		if (pWS->rows.lastcol >= 6) {
			if (NULL != row->cells.cell[6].str) {
				if (strlen(row->cells.cell[6].str) >= 128) {
					pitem->result = ITEM_XLS_NICKNAMELEN;
					b_touched = TRUE;
					double_list_append_as_tail(plist, &pitem->node);
					continue;
				}
				strcpy(pitem->nickname, row->cells.cell[6].str);
			}
		}

		if (pWS->rows.lastcol >= 7) {
			if (NULL != row->cells.cell[7].str) {
				if (strlen(row->cells.cell[7].str) >= 20) {
					pitem->result = ITEM_XLS_TELLEN;
					b_touched = TRUE;
					double_list_append_as_tail(plist, &pitem->node);
					continue;
				}
				strcpy(pitem->tel, row->cells.cell[7].str);
				ptr1 = strrchr(pitem->tel, '.');
				if (NULL != ptr1) {
					*ptr1 = '\0';
				}
			}
		}

		if (pWS->rows.lastcol >= 8) {
			if (NULL != row->cells.cell[8].str) {
				if (strlen(row->cells.cell[8].str) >= 20) {
					pitem->result = ITEM_XLS_CELLLEN;
					b_touched = TRUE;
					double_list_append_as_tail(plist, &pitem->node);
					continue;
				}
				strcpy(pitem->cell, row->cells.cell[8].str);
				ptr1 = strrchr(pitem->cell, '.');
				if (NULL != ptr1) {
					*ptr1 = '\0';
				}
			}
		}

		if (pWS->rows.lastcol >= 9) {
			if (NULL != row->cells.cell[9].str) {
				if (strlen(row->cells.cell[9].str) >= 128) {
					pitem->result = ITEM_XLS_HOMELEN;
					b_touched = TRUE;
					double_list_append_as_tail(plist, &pitem->node);
					continue;
				}
				strcpy(pitem->homeaddress, row->cells.cell[9].str);
			}
		}
		
		if (pWS->rows.lastcol >= 10) {
			if (NULL != row->cells.cell[10].str) {
				if (strlen(row->cells.cell[10].str) >= 128) {
					pitem->result = ITEM_XLS_TITLELEN;
					b_touched = TRUE;
					double_list_append_as_tail(plist, &pitem->node);
					continue;
				}
				strcpy(pitem->title, row->cells.cell[10].str);
			}
		}
		
		strcpy(pitem->lang, "en");
		if (pWS->rows.lastcol >= 11) {
			if (NULL != row->cells.cell[11].str &&
				strlen(row->cells.cell[11].str) < 32) {
				strcpy(pitem->lang, row->cells.cell[11].str);
			}
		}

		if (NULL == row->cells.cell[3].str) {
			pitem->result = ITEM_XLS_SIZE;
			b_touched = TRUE;
			double_list_append_as_tail(plist, &pitem->node);
			continue;
		}
		pitem->size = atoi(row->cells.cell[3].str)*1024;
		if (pitem->size <= 0 || pitem->size > 1024000) {
			pitem->result = ITEM_XLS_SIZE;
			b_touched = TRUE;
			double_list_append_as_tail(plist, &pitem->node);
			continue;
		}
		ptr1 = row->cells.cell[4].str;
		while (NULL != ptr1) {
			if (' ' == *ptr1) {
				ptr1 ++;
				continue;
			}
			ptr2 = strchr(ptr1, ' ');
			if (NULL == ptr2) {
				ptr2 = row->cells.cell[4].str + strlen(row->cells.cell[4].str);
			}
			if (ptr2 - ptr1 >= 32) {
				ptr1 = ptr2 + 1;
				continue;
			}
			pitem1 = (CLASS_ITEM*)malloc(sizeof(CLASS_ITEM));
			if (NULL == pitem1) {
				break;
			}
			pitem1->node.pdata = pitem1;
			pitem1->class_id = 0;
			memcpy(pitem1->classname, ptr1, ptr2 - ptr1);
			pitem1->classname[ptr2 - ptr1] = '\0';
			double_list_append_as_tail(&pitem->class_list, &pitem1->node);
			if ('\0' == *ptr2) {
				break;
			} else {
				ptr1 = ptr2 + 1;
			}
		}
		double_list_append_as_tail(plist, &pitem->node);
	}

	if (FALSE == b_touched) {
		*presult = XLS_RESULT_OK;
	} else {
		*presult = XLS_RESULT_TOUCHED;
	}
	xls_close(pWB);
	return TRUE;
}

static BOOL upload_ui_xls_delete(const char *domainname,
	const char *path, DOUBLE_LIST *plist, int *presult)
{
	int i;
	char *pat;
	char *language;
	BOOL b_touched;
	xlsWorkBook *pWB;
	xlsWorkSheet *pWS;
	struct st_row_data* row;
	USER_ITEM *pitem;
	
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		language = "en";
	}
	
	pWB = xls_open((char*)path, (char*)lang_resource_get(
					g_lang_resource, "CHARSET", language));
	if (NULL == pWB) {
		*presult = XLS_RESULT_OPENFAIL;
		return FALSE;
	}
	
	if (pWB->sheets.count < 1) {
		*presult = XLS_RESULT_NOSHEET;
		xls_close(pWB);
		return FALSE;
	}
	
	pWS = xls_getWorkSheet(pWB, 0);
	xls_parseWorkSheet(pWS);
	
	if (pWS->rows.lastrow <= 0) {
		*presult = XLS_RESULT_NOROWS;
		xls_close(pWB);
		return FALSE;
	}

	if (pWS->rows.lastcol < 1) {
		*presult = XLS_RESULT_COLERROR;
		xls_close(pWB);
		return FALSE;
	}
	
	b_touched = FALSE;
	for (i=1; i<=pWS->rows.lastrow; i++) {
		row = &pWS->rows.row[i];
		if (NULL == row->cells.cell[0].str ||
			'\0' == row->cells.cell[0].str[0]) {
			continue;
		}
		pitem = (USER_ITEM*)malloc(sizeof(USER_ITEM));
		if (NULL == pitem) {
			continue;
		}
		memset(pitem, 0, sizeof(USER_ITEM));
		pitem->node.pdata = pitem;
		double_list_init(&pitem->class_list);
		if (FALSE == upload_ui_check_address(row->cells.cell[0].str)) {
			strncpy(pitem->username, row->cells.cell[0].str, 127);
			pitem->result = ITEM_XLS_ADDRESS;
			b_touched = TRUE;
			double_list_append_as_tail(plist, &pitem->node);
			continue;
		}
		pat = strchr(row->cells.cell[0].str, '@');
		if (NULL == pat) {
			if (strlen(row->cells.cell[0].str) + strlen(domainname) > 127) {
				strncpy(pitem->username, row->cells.cell[0].str, 127);
				pitem->result = ITEM_XLS_ADDRLEN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;
			}
			strcpy(pitem->username, row->cells.cell[0].str);
			strcat(pitem->username, "@");
			strcat(pitem->username, domainname);
		} else {
			if (strlen(row->cells.cell[0].str) > 127) {
				strncpy(pitem->username, row->cells.cell[0].str, 127);
				pitem->result = ITEM_XLS_ADDRLEN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;
			}
			if (0 != strcasecmp(pat + 1, domainname)) {
				strncpy(pitem->username, row->cells.cell[0].str, 127);
				pitem->result = ITEM_XLS_DOMAIN;
				b_touched = TRUE;
				double_list_append_as_tail(plist, &pitem->node);
				continue;
			}
			strcpy(pitem->username, row->cells.cell[0].str);
		}
		lower_string(pitem->username);
		double_list_append_as_tail(plist, &pitem->node);
	}
	
	if (TRUE == b_touched) {
		*presult = XLS_RESULT_TOUCHED;
	} else {
		*presult = XLS_RESULT_OK;
	}
	xls_close(pWB);
	return TRUE;
}

static void upload_ui_free_ulist(DOUBLE_LIST *plist)
{
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	USER_ITEM *pitem;

	while (pnode = double_list_get_from_head(plist)) {
		pitem = (USER_ITEM*)pnode->pdata;
		while (pnode1 = double_list_get_from_head(&pitem->class_list)) {
			free(pnode1->pdata);
		}
		double_list_free(&pitem->class_list);
		free(pitem);
	}
}

static BOOL upload_ui_check_address(const char *address)
{
	const char *ptr;

	for (ptr=address; '\0'!=*ptr; ptr++) {
		if ('.' == *ptr || '-' == *ptr || '_' == *ptr ||
			'@' == *ptr || isdigit(*ptr) || isalpha(*ptr)) {
			continue;
		}
		return FALSE;
	}
	return TRUE;
}

int upload_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void upload_ui_free()
{
	/* do nothing */
}

static BOOL upload_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[ui_main]: fail to get HTTP_HOST or SCRIPT_NAME "
				"environment!");
		return FALSE;
	}
	if (NULL == https || 0 != strcasecmp(https, "ON")) {
		snprintf(url_buff, length, "http://%s%s", host, script);
	} else {
		snprintf(url_buff, length, "https://%s%s", host, script);
	}
	return TRUE;
}

static void upload_ui_error_html(const char *error_string)
{
	char *language;
	
	if (NULL == error_string) {
		error_string = "fatal error!!!";
	}
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		language = "en";
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ERROR_5, lang_resource_get(g_lang_resource,"BACK_LABEL", language),
		error_string);
}

static void upload_ui_operation_error_html(const char *error_string)
{
	char *language;

	language = getenv("HTTP_ACCEPT_LANGUAGE");

	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"OPERATION_ERROR_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(error_string);
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, error_string,
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void upload_ui_result_input(DOUBLE_LIST *plist)
{
	int row;
	char *language;
	char result_string[256];
	USER_ITEM *pitem;
	DOUBLE_LIST_NODE *pnode;

	language = getenv("HTTP_ACCEPT_LANGUAGE");

	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"INPUT_RESULT_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"INPUT_RESULT_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_RESULT_5);
	
	row = 1;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pitem = (USER_ITEM*)pnode->pdata;
		switch (pitem->result) {
		case ITEM_UPDATE_OK:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_UPDATE_OK", language));
			break;
		case ITEM_UPDATE_USERERR:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_UPDATE_USERERR", language));
			break;
		case ITEM_UPDATE_USERTYPE:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_UPDATE_USERTYPE", language));
			break;
		case ITEM_CREATE_OK:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_CREATE_OK", language));
			break;
		case ITEM_CREATE_PASSWD:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_CREATE_PASSWD", language));
			break;
		case ITEM_CREATE_MAILDIR:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_CREATE_MAILDIR", language));
			break;
		case ITEM_INPUT_SQL:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_INPUT_SQL", language));
			break;
		}
		row ++;
		if (ITEM_CREATE_OK != pitem->result &&
			ITEM_UPDATE_OK != pitem->result) {
			printf(HTML_RESULT_ITEM, CSS_ITEM_OVERQUOTA,
				pitem->username, result_string);
		} else {
			if (0 == row % 2) {
				printf(HTML_RESULT_ITEM, CSS_ITEM_EVEN,
					pitem->username, result_string);
			} else {
				printf(HTML_RESULT_ITEM, CSS_ITEM_ODD,
					pitem->username, result_string);
			}
		}
	}
	printf(HTML_RESULT_6);
}

static void upload_ui_result_delete(DOUBLE_LIST *plist)
{
	int row;
	char *language;
	char result_string[256];
	USER_ITEM *pitem;
	DOUBLE_LIST_NODE *pnode;

	language = getenv("HTTP_ACCEPT_LANGUAGE");

	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"DELETE_RESULT_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"DELETE_RESULT_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_RESULT_5);
	
	row = 1;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pitem = (USER_ITEM*)pnode->pdata;
		switch (pitem->result) {
		case ITEM_DELETE_OK:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_DELETE_OK", language));
			break;
		case ITEM_DELETE_USERERR:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_DELETE_USERERR", language));
			break;
		
		case ITEM_DELETE_USERTYPE:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_DELETE_USERTYPE", language));
			break;
		case ITEM_DELETE_NOUSER:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_DELETE_NOUSER", language));
			break;
		case ITEM_DELETE_SQL:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_DELETE_SQL", language));
			break;
		}
		row ++;
		if (ITEM_DELETE_OK != pitem->result) {
			printf(HTML_RESULT_ITEM, CSS_ITEM_OVERQUOTA,
						pitem->username, result_string);
		} else {
			if (0 == row % 2) {
				printf(HTML_RESULT_ITEM, CSS_ITEM_EVEN,
						pitem->username, result_string);
			} else {
				printf(HTML_RESULT_ITEM, CSS_ITEM_ODD,
						pitem->username, result_string);
			}
		}
	}
	printf(HTML_RESULT_6);
}

static void upload_ui_error_xls(DOUBLE_LIST *plist)
{
	int row;
	char *language;
	char result_string[256];
	USER_ITEM *pitem;
	DOUBLE_LIST_NODE *pnode;

	language = getenv("HTTP_ACCEPT_LANGUAGE");

	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"XLS_RESULT_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"XLS_RESULT_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_RESULT_5);
	
	row = 1;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pitem = (USER_ITEM*)pnode->pdata;
		result_string[0] = '\0';
		switch (pitem->result) {
		case ITEM_XLS_ADDRESS:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_ADDRESS", language));
			break;
		case ITEM_XLS_ADDRLEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_ADDRLEN", language));
			break;
		case ITEM_XLS_ADDRSAME:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_ADDRSAME", language));
			break;
		case ITEM_XLS_DOMAIN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_DOMAIN", language));
			break;
		case ITEM_XLS_PASSWDLEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_PASSWDLEN", language));
			break;
		case ITEM_XLS_REALNAMELEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_REALNAMELEN", language));
			break;
		case ITEM_XLS_NICKNAMELEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_NICKNAMELEN", language));
			break;
		case ITEM_XLS_TELLEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_TELLEN", language));
			break;
		case ITEM_XLS_CELLLEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_CELLLEN", language));
			break;
		case ITEM_XLS_HOMELEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_HOMELEN", language));
			break;
		case ITEM_XLS_TITLELEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_TITLELEN", language));
			break;
		case ITEM_XLS_MEMOLEN:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_MEMOLEN", language));
			break;
		case ITEM_XLS_SIZE:
			strcpy(result_string, lang_resource_get(
				g_lang_resource, "RESULT_XLS_SIZE", language));
			break;
		}
		if ('\0' == result_string[0]) {
			continue;
		}
		row ++;
		if (0 == row % 2) {
			printf(HTML_RESULT_ITEM, CSS_ITEM_EVEN,
					pitem->username, result_string);
		} else {
			printf(HTML_RESULT_ITEM, CSS_ITEM_ODD,
					pitem->username, result_string);
		}
	}
	printf(HTML_RESULT_6);
}

static void upload_ui_main_html(const char *groupname, const char *session)
{
	char *language;
	char url_buff[1024];
	char temp_buff[1024];
	const char *str_submit;
	
	
	if (FALSE == upload_ui_get_self(url_buff, 1024)) {
		upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	str_submit = lang_resource_get(g_lang_resource,"SUBMIT_LABEL", language);
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"MAIN_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"MAIN_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_MAIN_5, lang_resource_get(g_lang_resource,"MAIN_DOWNLOAD", language),
		url_buff, lang_resource_get(g_lang_resource,"MAIN_BATCH_INPUT", language),
		groupname, session, str_submit, url_buff,
		lang_resource_get(g_lang_resource,"MAIN_BATCH_DELETE", language),
		groupname, session, str_submit);
	return;
}

static void upload_ui_unencode(char *src, char *last, char *dest)
{
	int code;
	
	for (; src != last; src++, dest++) {
		if (*src == '+') {
			*dest = ' ';
		} else if (*src == '%') {
			if (sscanf(src+1, "%2x", &code) != 1) {
				code = '?';
			}
			*dest = code;
			src +=2;
		} else {
			*dest = *src;
		}
	}
	*dest = '\n';
	*++dest = '\0';
}

static void upload_ui_copy_file(const char *src_file, const char *dst_file)
{
	int fd;
	char *pbuff;
	struct stat node_stat;

	if (0 != stat(src_file, &node_stat)) {
		return;
	}
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return;
	}
	fd = open(src_file, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		free(pbuff);
		close(fd);
		return;
	}
	close(fd);
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	write(fd, pbuff, node_stat.st_size);
	free(pbuff);
	close(fd);
}

static BOOL upload_ui_allocate_dir(const char *media_area,
	char *path_buff, int max_size, int max_file)
{
	time_t cur_time;
	LOCKD lockd;
	int v_index;
	int mini_vdir;
	int mini_homes;
	int total_space;
	int total_used;
	int total_homes;
	int i, fd, len, item_num;
	int space, files, homes;
	int average_space;
	char *pdb_storage;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[DIGEST_BUFLEN];
	struct stat node_stat;
	LIST_FILE *pfile;
	AREA_ITEM *pitem;
	AREA_NODE *parea;
	DOUBLE_LIST_NODE *pnode;
	AREA_NODE *pleast_area;
	DOUBLE_LIST temp_list;
	
	
	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");

	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to init list file %s",
			g_list_path);
		return FALSE;
	}
	if (NULL == media_area) {
		lockd = locker_client_lock("USER-AREA");
	} else {
		lockd = locker_client_lock("MEDIA-AREA");
	}
	total_space = 0;
	total_used = 0;
	total_homes = 0;
	double_list_init(&temp_list);
	pitem = (AREA_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (NULL == media_area) {
			if (0 != strcmp(pitem[i].type, "USER")) {
				continue;
			}
		} else {
			if (0 != strcmp(pitem[i].type, "MEDIA") ||
				0 != strcmp(pitem[i].master, media_area)) {
				continue;
			}
		}
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL != pdb_storage) {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		sprintf(temp_path, "%s/pinfo", pitem[i].master);
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			continue;
		}
		len = read(fd, temp_buff, 1024);
		close(fd);
		if (len <= 0) {
			close(fd);
			continue;
		}
		temp_buff[len] = '\0';
		
		upload_ui_partition_info(temp_buff, &space, &files, &homes);
		
		if (-1 == space || -1 == files || -1 == homes) {
			continue;
		}
		total_space += pitem[i].space;
		total_used += space;
		total_homes += homes;
		if (space < pitem[i].space && files < pitem[i].files &&
			homes < VDIR_PER_PARTITION*MAILDIR_PER_VDIR) {
			parea = (AREA_NODE*)malloc(sizeof(AREA_NODE));
			if (NULL == parea) {
				continue;
			}
			parea->node.pdata = parea;
			strcpy(parea->master, pitem[i].master);
			if (NULL != pdb_storage) {
				strcpy(parea->database, pdb_storage);
			} else {
				parea->database[0] = '\0';
			}
			parea->max_space = pitem[i].space;
			parea->used_space = space;
			parea->used_files = files;
			parea->homes = homes;
			double_list_append_as_tail(&temp_list, &parea->node);
		}
	}
	list_file_free(pfile);
	
	if (0 == double_list_get_nodes_num(&temp_list)) {
		double_list_free(&temp_list);
		system_log_info("[list_ui]: cannot find"
			" a available data area for user");
		locker_client_unlock(lockd);
		return FALSE;
	}
	if (0 == total_homes) {
		average_space = 1;
	} else {
		average_space = total_space / total_homes;
	}
	if (average_space < 1) {
		average_space = 1;
	}
	pleast_area = NULL;
	for (pnode=double_list_get_head(&temp_list); NULL!=pnode;
		pnode=double_list_get_after(&temp_list, pnode)) {
		parea = (AREA_NODE*)pnode->pdata;
		if (NULL == pleast_area) {
			pleast_area = parea;
		} else {
			if (parea->homes/(((double)parea->max_space)/average_space) <
				pleast_area->homes/(((double)pleast_area->max_space)/average_space)) {
				pleast_area = parea;
			}
		}
	}
	mini_homes = -1;
	for (i=1; i<=VDIR_PER_PARTITION; i++) {
		sprintf(temp_path, "%s/v%d/vinfo", pleast_area->master, i);
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			continue;
		}

		len = read(fd, temp_buff, 1024);
		
		close(fd);
		
		if (len <= 0) {
			continue;
		}
		temp_buff[len] = '\0';
		homes = atoi(temp_buff);
		if (mini_homes < 0) {
			mini_homes = homes;
			mini_vdir = i;
		} else if (mini_homes > homes) {
			mini_homes = homes;
			mini_vdir = i;
		}
	}
	if (-1 == mini_homes || mini_homes >= MAILDIR_PER_VDIR) {
		system_log_info("[list_ui]: seems allocation information of data"
			" area %s or it's vdir information error, please check it!",
			pleast_area->master);
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		locker_client_unlock(lockd);
		return FALSE;
	}
	
	for (i=1; i<=MAILDIR_PER_VDIR; i++) {
		sprintf(temp_path, "%s/v%d/%d", pleast_area->master, mini_vdir, i);
		if (0 != lstat(temp_path, &node_stat)) {
			break;
		}
	}
	if (i > MAILDIR_PER_VDIR) {
		system_log_info("[list_ui]: seems allocation information of vdir"
			" %d under data area %s error, please check it!", mini_vdir,
			pleast_area->master);
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		locker_client_unlock(lockd);
		return FALSE;	
	}
	
	v_index = i;
	
	time(&cur_time);
	sprintf(temp_path, "%s/v%d/vinfo.%d", pleast_area->master,
		mini_vdir, cur_time);
	sprintf(temp_path1, "%s/v%d/vinfo", pleast_area->master, mini_vdir);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		len = sprintf(temp_buff, "%dH", mini_homes + 1);
		write(fd, temp_buff, len);
		close(fd);
		rename(temp_path, temp_path1);
	}
	sprintf(temp_path, "%s/pinfo.%d", pleast_area->master, cur_time);
	sprintf(temp_path1, "%s/pinfo", pleast_area->master);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		len = sprintf(temp_buff, "%dM,%dC,%dH", pleast_area->used_space,
				pleast_area->used_files, pleast_area->homes + 1);
		write(fd, temp_buff, len);
		close(fd);
		rename(temp_path, temp_path1);
	}
	
	sprintf(temp_path, "%s/v%d/%d", pleast_area->master, mini_vdir, v_index);
	
	if ('\0' != pleast_area->database[0]) {
		sprintf(temp_path1, "%s/v%d/%d", pleast_area->database, mini_vdir, v_index);
		if (0 == mkdir(temp_path1, 0777)) {
			locker_client_unlock(lockd);
			while (pnode=double_list_get_from_head(&temp_list)) {
				free(pnode->pdata);
			}
			double_list_free(&temp_list);
			system_log_info("[list_ui]: fail to make directory "
				"under %s/v%d", pleast_area->database, mini_vdir);
			return FALSE;
		}
	}
	
	if (0 == mkdir(temp_path, 0777)) {
		strcpy(path_buff, temp_path);
		sprintf(temp_path, "%s/exmdb", path_buff);
		if ('\0' != pleast_area->database[0]) {
			symlink(temp_path1, temp_path);
		} else {
			mkdir(temp_path, 0777);
		}
		sprintf(temp_path, "%s/tmp", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/tmp/imap.rfc822", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/tmp/faststream", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/eml", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/ext", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/cid", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/disk", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/config", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/config/portrait.jpg", path_buff);
		srand(time(NULL));
		sprintf(temp_path1, "%s/%d.jpg", g_thumbnail_path, rand()%100 + 1);
		upload_ui_copy_file(temp_path1, temp_path);
		strcpy(temp_buff, "{\"size\":0,\"files\":0}");
		memset(temp_buff + 20, ' ', 512 - 20);
		sprintf(temp_path, "%s/disk/index", path_buff);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 != fd) {
			write(fd, temp_buff, 512);
			close(fd);
		}
		locker_client_unlock(lockd);
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		return TRUE;
	} else {
		locker_client_unlock(lockd);
		if ('\0' != pleast_area->database[0]) {
			remove(temp_path1);
		}
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		system_log_info("[list_ui]: fail to make directory "
			"under %s/v%d", pleast_area->master, mini_vdir);
		return FALSE;
	}
}

static void upload_ui_free_dir(BOOL b_media, const char *maildir)
{	
	LOCKD lockd;
	time_t cur_time;
	int fd, len;
	int space, files, homes;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[1024];
	struct stat node_stat;

	if (TRUE == b_media) {
		lockd = locker_client_lock("MEDIA-AREA");
	} else {
		lockd = locker_client_lock("USER-AREA");
	}
	if (0 != lstat(maildir, &node_stat)) {
		locker_client_unlock(lockd);
		return;
	}


	time(&cur_time);
	sprintf(temp_path, "%s/../vinfo", maildir);
	sprintf(temp_path1, "%s/../vinfo.%d", maildir, cur_time);
	fd = open(temp_path, O_RDONLY);
	
	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}
	
	len = read(fd, temp_buff, 1024);
	close(fd);
	if (len <= 0) {
		locker_client_unlock(lockd);
		return;
	}
	temp_buff[len] = '\0';
	homes = atoi(temp_buff);
	
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}
	len = sprintf(temp_buff, "%dH", homes - 1);
	write(fd, temp_buff, len);
	close(fd);
	rename(temp_path1, temp_path);
	
	sprintf(temp_path, "%s/../../pinfo", maildir);
	sprintf(temp_path1, "%s/../../pinfo.%d", maildir, cur_time);
	fd = open(temp_path, O_RDONLY);

	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}
	
	len = read(fd, temp_buff, 1024);
	close(fd);
	if (len <= 0) {
		locker_client_unlock(lockd);
		return;
	}
	temp_buff[len] = '\0';
	
	upload_ui_partition_info(temp_buff, &space, &files, &homes);
	if (-1 == space || -1== files || -1 == homes) {
		locker_client_unlock(lockd);
		return;
	}
	
	fd = open(temp_path1, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}

	len = sprintf(temp_buff, "%dM,%dC,%dH", space, files, homes - 1);
	write(fd, temp_buff, len);
	close(fd);
	rename(temp_path1, temp_path);
	
	sprintf(temp_path, "%s/exmdb", maildir);
	if (0 == lstat(temp_path, &node_stat) &&
		0 != S_ISLNK(node_stat.st_mode)) {
		memset(temp_path1, 0, 256);
		if (readlink(temp_path, temp_path1, 256) > 0) {
			upload_ui_remove_inode(temp_path1);
		}
	}
	upload_ui_remove_inode(maildir);
	
	locker_client_unlock(lockd);
}

static void upload_ui_partition_info(char *s,
	int *pmegas, int *pfiles, int *phomes)
{
	char *plast;
	char *ptoken;

	plast = s;
	ptoken = strchr(plast, 'M');
	if (NULL == ptoken) {
		*pmegas = -1;
	} else {
		*ptoken = '\0';
		*pmegas = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'C');
	if (NULL == ptoken) {
		*pfiles = -1;
	} else {
		*ptoken = '\0';
		*pfiles = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'H');
	if (NULL == ptoken) {
		*phomes = -1;
	} else {
		*ptoken = '\0';
		*phomes = atoi(plast);
	}
}

static void upload_ui_remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

	if (0 != lstat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 256, "%s/%s", path, direntp->d_name);
		upload_ui_remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}

static void upload_ui_encode_squote(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if ('\'' == in[i] || '\\' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

static void upload_ui_from_utf8(char *src, char *dst, size_t len)
{
    size_t in_len;
    char *pin, *pout;
    iconv_t conv_id;

    conv_id = iconv_open(lang_resource_get(g_lang_resource,"CHARSET",
                getenv("HTTP_ACCEPT_LANGUAGE")), "UTF-8");
    pin = src;
    pout = dst;
    in_len = strlen(src);
    memset(dst, 0, len);
    iconv(conv_id, &pin, &in_len, &pout, &len);
    iconv_close(conv_id);
}

static void upload_ui_to_utf8(char *src, char *dst, size_t len)
{
    size_t in_len;
    char *pin, *pout;
    iconv_t conv_id;

    conv_id = iconv_open("UTF-8", lang_resource_get(g_lang_resource,"CHARSET",
                getenv("HTTP_ACCEPT_LANGUAGE")));
    pin = src;
    pout = dst;
    in_len = strlen(src);
    memset(dst, 0, len);
    iconv(conv_id, &pin, &in_len, &pout, &len);
    iconv_close(conv_id);
}
