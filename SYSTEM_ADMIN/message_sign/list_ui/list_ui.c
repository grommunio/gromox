#include "list_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "reload_control.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

/* fill whitelist title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE>\n\
<BR><BR><SCRIPT language=\"JavaScript\">\n\
function DeleteItem(filename) {location.href='%s?session=%s&delete=' + filename;}\n\
function OpenItem(filename) {window.open('%s?session=%s&open=' + filename, 'TEXT', 'height=200, width=400, toolbar=no, menubar=no, location=no, status=no');}\n\
</SCRIPT><FORM method=post enctype=\"multipart/form-data\" class=SearchForm name=opeform action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=charset /></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\
<SELECT name=type><OPTION value=\"plain\" selected>%s</OPTION>\n\
<OPTION value=\"html\">%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=file name=\"text_file\" /></TD></TR>\
<TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=3 value=\"   %s   \" \
onclick=\"if (0 == opeform.charset.value.length || 0 == opeform.text_file.value.length) {return false;} return true;\" />\n\
</TD></TR><TR><TD colSpan=3>%s</TD></TR></TABLE></FORM>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\nborder=0><TBODY>\n\
<TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill list title here */

#define HTML_MAIN_7	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_MAIN_8	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;<A href=\"javascript:OpenItem('%s')\">%s</A> | \
<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *session);

static void list_ui_remove_item(char *filename);

static void list_ui_item_html(char *filename);

static void list_ui_broadcast_dir();

static void list_ui_unencode(char *src, char *last, char *dest);

static BOOL list_ui_get_self(char *url_buff, int length);

static char g_sign_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void list_ui_init(const char *sign_path, const char *mount_path,
	const char *url_link, const char *resource_path)
{
	strcpy(g_sign_path, sign_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int list_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char type[32];
	char charset[32];
	char session[256];
	char password[256];
	char boundary[1024];
	char temp_path[256];
	char temp_buff[1024];
	char post_buff[1024];
	char search_buff[1024];
	int bnd_len, fd, i, len;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		list_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[list_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[list_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[list_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[list_ui]: post buffer too long");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
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
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		len = strlen(post_buff);
		ptr1 = search_string(post_buff, "name=\"", len);
		if (NULL == ptr1) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "session")) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		len = strlen(post_buff);
		memset(session, 0, 256);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				session[i] = '\0';
				break;
			} else {
				session[i] = post_buff[i];
			}
		}

		switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_MISC)) {
		case ACL_SESSION_OK:
			break;
		case ACL_SESSION_TIMEOUT:
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT", language));
			return 0;
		case ACL_SESSION_PRIVILEGE:
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
				language));
			return 0;
		default:
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION", language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		len = strlen(post_buff);
		ptr1 = search_string(post_buff, "name=\"", len);
		if (NULL == ptr1) {
			system_log_info("[list_ui]: query string of POST format error");
		    list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "charset")) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 32, stdin)) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		len = strlen(post_buff);
		memset(charset, 0, 32);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				charset[i] = '\0';
				break;
			} else {
				charset[i] = post_buff[i];
			}
		}
		lower_string(charset);
		if (strlen(charset) == 0) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}

		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		len = strlen(post_buff);
		ptr1 = search_string(post_buff, "name=\"", len);
		if (NULL == ptr1) {
			system_log_info("[list_ui]: query string of POST format error");
		    list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "type")) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 32, stdin)) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		len = strlen(post_buff);
		memset(type, 0, 32);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				type[i] = '\0';
				break;
			} else {
				type[i] = post_buff[i];
			}
		}
		lower_string(type);
		if (0 != strcmp(type, "plain") && 0 != strcmp(type, "html")) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		sprintf(temp_path, "%s/%s.%s", g_sign_path, charset, type);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[list_ui]: fail to create list file for %s\n",
				temp_path);
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			return 0;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strncmp(post_buff, boundary, bnd_len)) {
				break;
			}
			len = strlen(post_buff);
			write(fd, post_buff, len);
		}
		close(fd);
		list_ui_broadcast_dir();
		reload_control_notify();
		list_ui_main_html(session);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[list_ui]: fail to get QUERY_STRING "
				"environment!");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 1024) {
				system_log_info("[list_ui]: query string too long!");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			list_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			if (NULL != (ptr2 = search_string(search_buff, "&open=", len))) {
				if ((ptr2 - ptr1 > 255)) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, ptr2 - ptr1);
				session[ptr2 - ptr1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_MISC)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				ptr1 = ptr2 + 6;
				if (search_buff + len - ptr1 - 1 > 40) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_path, ptr1, search_buff + len - ptr1 - 1);
				temp_path[search_buff + len - ptr1 - 1] = '\0';
				list_ui_item_html(temp_path);
				return 0;
			} else if (NULL != (ptr2 = search_string(search_buff, "&delete=", len))) {
				if ((ptr2 - ptr1 > 255)) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, ptr2 - ptr1);
				session[ptr2 - ptr1] = '\0';
				ptr1 = ptr2 + 8;
				if (search_buff + len - ptr1 - 1 > 40) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_path, ptr1, search_buff + len - ptr1 - 1);
				temp_path[search_buff + len - ptr1 - 1] = '\0';
				
				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_MISC)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}

				list_ui_remove_item(temp_path);
				list_ui_main_html(session);
				return 0;
			} else {
				if (search_buff + len - ptr1 - 1 > 255) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_MISC)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				list_ui_main_html(session);
				return 0;
			}
		}
	} else {
		system_log_info("[list_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int list_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void list_ui_free()
{
	/* do nothing */
}

static BOOL list_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[list_ui]: fail to get "
			"HTTP_HOST or SCRIPT_NAME environment!");
		return FALSE;
	}
	if (NULL == https || 0 != strcasecmp(https, "ON")) {
		snprintf(url_buff, length, "http://%s%s", host, script);
	} else {
		snprintf(url_buff, length, "https://%s%s", host, script);
	}
	return TRUE;
}

static void list_ui_error_html(const char *error_string)
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

static void list_ui_remove_item(char *filename)
{
	char temp_path[256];

	sprintf(temp_path, "%s/%s", g_sign_path, filename);
	remove(temp_path);
	list_ui_broadcast_dir();
	reload_control_notify();
}

static void list_ui_item_html(char *filename)
{
	int fd;
	char *language;
	char *pdot, *pbuff;
	char temp_file[256];
	struct stat node_stat;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	
	sprintf(temp_file, "%s/%s", g_sign_path, filename);
	if (0 != stat(temp_file, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		system_log_info("[list_ui]: can not access %s", temp_file);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	fd = open(temp_file, O_RDONLY);
	if (-1 == fd) {
		system_log_info("[list_ui]: can not open %s for reading", temp_file);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pbuff = malloc(node_stat.st_size + 1);
	if (NULL == pbuff) {
		close(fd);
		system_log_info("[list_ui]: can not allocate memory for reading %s",
			temp_file);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		system_log_info("[list_ui]: read %s error!", temp_file);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pbuff[node_stat.st_size] = '\0';
	close(fd);
	
	strcpy(temp_file, filename);
	pdot = strrchr(temp_file, '.');
	if (NULL == pdot) {
		free(pbuff);
		system_log_info("[list_ui]: can not find file type information of %s",
			filename);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
			language));
		return;
	}
	*pdot = '\0';
	pdot ++;
	if (0 == strcasecmp("plain", pdot)) {
		printf("Content-Type:text/plain;charset=%s\n\n", temp_file);
		printf(pbuff);
	} else if (0 == strcasecmp("html", pdot)) {
		printf("Content-Type:text/html;charset=%s\n\n", temp_file);
		printf(pbuff);
	} else {
		system_log_info("[list_ui]: unkonwn file type %s for %s", pdot,
			filename);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
			language));
	}
	free(pbuff);
	return;

}

static void list_ui_main_html(const char *session)
{
	DIR *dirp;
	int type;
	int i, len;
	char *pdot;
	char *language;
	char url_buff[1024];
	char temp_buff[256];
	struct dirent *direntp;
	
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	dirp = opendir(g_sign_path);
	if (NULL == dirp) {
		system_log_info("[list_ui]: fail to open directory %s", g_sign_path);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
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
	printf(HTML_MAIN_5, url_buff, session, url_buff, session);
	printf(url_buff);
	printf(HTML_MAIN_6, session,
		lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_PLAIN", language),
		lang_resource_get(g_lang_resource,"MAIN_HTML", language),
		lang_resource_get(g_lang_resource,"MAIN_FILE", language),
		lang_resource_get(g_lang_resource,"UPLOAD_LABEL", language),
		lang_resource_get(g_lang_resource,"MAIN_CHARSET_CAUTION", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));

	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		strcpy(temp_buff, direntp->d_name);
		pdot = strrchr(temp_buff, '.');
		if (NULL == pdot) {
			continue;
		}
		*pdot = '\0';
		pdot ++;
		if (0 == strcasecmp(pdot, "plain")) {
			printf(HTML_TBITEM_NORMAL, temp_buff,
				lang_resource_get(g_lang_resource,"MAIN_PLAIN", language),
				direntp->d_name, lang_resource_get(g_lang_resource,"OPEN_LABEL", language),
				direntp->d_name, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		} else if (0 == strcasecmp(pdot, "html")) {
			printf(HTML_TBITEM_NORMAL, temp_buff,
				lang_resource_get(g_lang_resource,"MAIN_HTML", language),
				direntp->d_name, lang_resource_get(g_lang_resource,"OPEN_LABEL", language),
				direntp->d_name, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		}
	}
	closedir(dirp);
	printf(HTML_MAIN_8);
}

static void list_ui_broadcast_dir()
{
	char *pbuff;
	int fd, fd1, len;
	DIR *dirp, *dirp1;
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;
	struct dirent *direntp1;
	

	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[list_ui]: fail to open directory %s\n",
			g_mount_path);
		return;
	}
	/*
	 * enumerate the sub-directory of source director each
	 * sub-directory represents one MTA
	 */
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s/data/delivery/system_sign", g_mount_path,
			direntp->d_name);
		dirp1 = opendir(temp_path);
		if (NULL == dirp1) {
			continue;
		}
		while ((direntp1 = readdir(dirp1)) != NULL) {
			if (0 == strcmp(direntp1->d_name, ".") ||
				0 == strcmp(direntp1->d_name, "..")) {
				continue;
			}
			sprintf(temp_path, "%s/%s/data/delivery/system_sign/%s",
				g_mount_path, direntp->d_name, direntp1->d_name);
			remove(temp_path);
		}
		closedir(dirp1);
		
		dirp1 = opendir(g_sign_path);
		if (NULL == dirp1) {
			continue;
		}
		while ((direntp1 = readdir(dirp1)) != NULL) {
			if (0 == strcmp(direntp1->d_name, ".") ||
				0 == strcmp(direntp1->d_name, "..")) {
				continue;
			}
			sprintf(temp_path, "%s/%s", g_sign_path, direntp1->d_name);
			if (0 != stat(temp_path, &node_stat) ||
				0 == S_ISREG(node_stat.st_mode)) {
				continue;
			}
			pbuff = malloc(node_stat.st_size);
			if (NULL == pbuff) {
				continue;
			}
			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				free(pbuff);
				continue;
			}
			if (node_stat.st_size == read(fd, pbuff, node_stat.st_size)) {
				sprintf(temp_path, "%s/%s/data/delivery/system_sign/%s",
					g_mount_path, direntp->d_name, direntp1->d_name);
				fd1 = open(temp_path, O_CREAT|O_WRONLY|O_TRUNC, DEF_MODE);
				if (-1 != fd1) {
					write(fd1, pbuff, node_stat.st_size);
					close(fd1);
				}
			}
			close(fd);
			free(pbuff);
		}
		closedir(dirp1);
	}
	closedir(dirp);
}

static void list_ui_unencode(char *src, char *last, char *dest)
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

