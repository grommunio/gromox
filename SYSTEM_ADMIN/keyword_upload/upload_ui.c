#include "upload_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "reload_control.h"
#include "list_file.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
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

/* fill statistic result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM method=get action=%s><TABLE><TBODY>\n\
<TR><TD align=left>%s&nbsp;&nbsp;</TD><TD align=right><INPUT type=hidden \n\
name=\"session\" value=\"%s\" /><TEXTAREA name=charset_list cols=16 rows=6>"

#define HTML_MAIN_6	\
"</TEXTAREA></TD><TD align=center><INPUT type=submit \n\
value=\"  %s  \" /></TD></TR></TBODY></TABLE><BR>%s</FORM>"

#define HTML_MAIN_7	\
"<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"subject_keyword\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM>"

#define HTML_MAIN_8	\
"<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"from_keyword\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM>"

#define HTML_MAIN_9	\
"<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"to_keyword\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM>"

#define HTML_MAIN_10	\
"<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"cc_keyword\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM>"

#define HTML_MAIN_11	\
"<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"content_keyword\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM>"

#define HTML_MAIN_12	\
"<FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TABLE width=\"75%\"><TBODY><TR bgColor=#d9d9d9><TD width=\"30%\">%s</TD><TD>\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file name=\"attachment_keyword\" /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TABLE></FORM><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static void upload_ui_error_html(const char *error_string);

static void upload_ui_main_html(const char *session);

static void upload_ui_broadcast_charset();

static void upload_ui_broadcast_keyword(const char *list);

static BOOL upload_ui_get_self(char *url_buff, int length);

static void upload_ui_unencode(char *src, char *last, char *dest);

static void upload_ui_encode_line(const char *in, char *out);

static char g_charset_path[256];
static char g_subject_path[256];
static char g_from_path[256];
static char g_to_path[256];
static char g_cc_path[256];
static char g_content_path[256];
static char g_attachment_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static char g_resourc_path[256];
static LANG_RESOURCE *g_lang_resource;

void upload_ui_init(const char *charset_path, const char *subject_path,
	const char *from_path, const char *to_path, const char *cc_path,
	const char *content_path, const char *attachment_path,
	const char *mount_path, const char *url_link, const char *resource_path)
{
	strcpy(g_charset_path, charset_path);
	strcpy(g_subject_path, subject_path);
	strcpy(g_from_path, from_path);
	strcpy(g_to_path, to_path);
	strcpy(g_cc_path, cc_path);
	strcpy(g_content_path, content_path);
	strcpy(g_attachment_path, attachment_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resourc_path, resource_path);
}

int upload_ui_run()
{
	int len, fd, i;
	int bnd_len;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char boundary[1024];
	char temp_buff[1024];
	char session[256];
	char password[256];
	char post_buff[1024];
	char search_buff[4096];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		upload_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resourc_path);
	if (NULL == g_lang_resource) {
		system_log_info("[upload_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[upload_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[upload_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[upload_ui]: post buffer too long");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
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
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		upload_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2) {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "session")) {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
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

		switch (acl_control_check(session, remote_ip,
			ACL_PRIVILEGE_ANTI_SPAM)) {
		case ACL_SESSION_OK:
		    break;
		case ACL_SESSION_TIMEOUT:
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
				language));
			return 0;
		case ACL_SESSION_PRIVILEGE:
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
				language));
			return 0;
		default:
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
				language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		upload_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2) {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 == strcasecmp(temp_buff, "subject_keyword")) {
			fd = open(g_subject_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);	
		} else if (0 == strcasecmp(temp_buff, "from_keyword")) {
			fd = open(g_from_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		} else if (0 == strcasecmp(temp_buff, "to_keyword")) {
			fd = open(g_to_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		} else if (0 == strcasecmp(temp_buff, "cc_keyword")) {
			fd = open(g_cc_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		} else if (0 == strcasecmp(temp_buff, "content_keyword")) {
			fd = open(g_content_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		} else if (0 == strcasecmp(temp_buff, "attachment_keyword")) {
			fd = open(g_attachment_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		} else {
			system_log_info("[upload_ui]: query string of POST format error");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		if (-1 == fd) {
			system_log_info("[upload_ui]: fail to create list file for %s\n",
				temp_buff);
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strncmp(post_buff, boundary, bnd_len)) {
				break;
			}
			if ('\r' == post_buff[0] || '\n' == post_buff[0]) {
				continue;
			}
			upload_ui_encode_line(post_buff, search_buff);
			len = strlen(search_buff);
			write(fd, search_buff, len);
		}
		close(fd);
		upload_ui_broadcast_keyword(temp_buff);
		reload_control_notify_keyword(temp_buff);
		upload_ui_main_html(session);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[upload_ui]: fail to get QUERY_STRING "
				"environment!");
			upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 4096) {
				system_log_info("[upload_ui]: query string too long!");
				upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			upload_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[upload_ui]: query string of GET "
					"format error");
				upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = search_string(search_buff, "&charset_list=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1> 256) {
					system_log_info("[upload_ui]: query string of GET "
						"format error");
					upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_ANTI_SPAM)) {
				case ACL_SESSION_OK:
				    break;
				case ACL_SESSION_TIMEOUT:
					upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				upload_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[upload_ui]: query string of GET "
					"format error");
				upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_ANTI_SPAM)) {
			case ACL_SESSION_OK:
			    break;
			case ACL_SESSION_TIMEOUT:
				upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			default:
				upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}

			fd = open(g_charset_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
			if (-1 == fd) {
				system_log_info("[upload_ui]: fail to truncate %s",
					g_charset_path);
				upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			ptr2 += 14;
			for (ptr1=ptr2; ptr1<search_buff+len; ptr1++) {
				if ('\r' == *ptr1 || '\n' == *ptr1) {
					if (ptr1 - ptr2 != 1) {
						write(fd, ptr2, ptr1 - ptr2);
						write(fd, "\n", 1);
					}
					while ('\n' == *(ptr1+1) || '\r' == *(ptr1+1)) {
						ptr1 ++;
					}
					ptr2 = ptr1 + 1;
				}
			}
			close(fd);
			upload_ui_broadcast_charset();
			reload_control_notify_charset();
			upload_ui_main_html(session);
			return 0;
		}
	} else {
		system_log_info("[upload_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
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
		system_log_info("[upload_ui]: fail to get"
			" HTTP_HOST or SCRIPT_NAME environment!");
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


static void upload_ui_main_html(const char *session)
{
	int i, item_num;
	char *pitem;
	char *language;
	char url_buff[1024];
	char temp_buff[1024];
	const char *str_submit;
	LIST_FILE *plist;
	
	
	if (FALSE == upload_ui_get_self(url_buff, 1024)) {
		upload_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	plist = list_file_init(g_charset_path, "%s:32");
	if (NULL == plist) {
		system_log_info("[upload_ui]: fail to init list file %s",
			g_charset_path);
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
	printf(HTML_MAIN_5, url_buff, lang_resource_get(g_lang_resource,"MAIN_CHARSET_LIST",
		language), session);
	item_num = list_file_get_item_num(plist);
	pitem = list_file_get_list(plist);
	for (i=0; i<item_num; i++) {
		printf("%s\r\n", pitem + 32*i);
	}
	list_file_free(plist);
	printf(HTML_MAIN_6, str_submit, lang_resource_get(g_lang_resource,
		"MAIN_CHARSET_CAUTION", language));
	printf(HTML_MAIN_7, url_buff, lang_resource_get(g_lang_resource,"MAIN_SUBJECT_KEYWORD",
		language), session, str_submit);
	printf(HTML_MAIN_8, url_buff, lang_resource_get(g_lang_resource,"MAIN_FROM_KEYWORD",
		language), session, str_submit);
	printf(HTML_MAIN_9, url_buff, lang_resource_get(g_lang_resource,"MAIN_TO_KEYWORD",
		language), session, str_submit);
	printf(HTML_MAIN_10, url_buff, lang_resource_get(g_lang_resource,"MAIN_CC_KEYWORD",
		language), session, str_submit);
	printf(HTML_MAIN_11, url_buff, lang_resource_get(g_lang_resource,"MAIN_CONTENT_KEYWORD",
		language), session, str_submit);
	printf(HTML_MAIN_12, url_buff,
		lang_resource_get(g_lang_resource,"MAIN_ATTACHMENT_KEYWORD", language),
		session, str_submit);
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

static void upload_ui_broadcast_charset()
{
	DIR *dirp;
	int i, len;
	int item_num, fd;
	char *pitem;
	char temp_buff[64];
	char temp_path[256];
	struct dirent *direntp;
	LIST_FILE *pfile;

	pfile = list_file_init(g_charset_path, "%s:32");
	if (NULL == pfile) {
		system_log_info("[upload_ui]: fail to open charset list %s",
			g_charset_path);
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (char*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[upload_ui]: fail to open directory %s\n",
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
		sprintf(temp_path, "%s/%s/data/smtp/keyword_filter/charset.txt",
			g_mount_path, direntp->d_name);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[upload_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			len = sprintf(temp_buff, "%s\n", pitem + 32*i);
			write(fd, temp_buff, len);
		}
		close(fd);
		
	}
	closedir(dirp);
	list_file_free(pfile);
}

static void upload_ui_broadcast_keyword(const char *list)
{
	DIR *dirp;
	int i, len;
	int item_num, fd;
	char *pitem;
	char temp_buff[1024];
	char temp_path[256];
	struct dirent *direntp;
	LIST_FILE *pfile;

	if (0 == strcasecmp(list, "subject_keyword")) {
		pfile = list_file_init(g_subject_path, "%s:256");
	} else if (0 == strcasecmp(list, "from_keyword")) {
		pfile = list_file_init(g_from_path, "%s:256");
	} else if (0 == strcasecmp(list, "to_keyword")) {
		pfile = list_file_init(g_to_path, "%s:256");
	} else if (0 == strcasecmp(list, "cc_keyword")) {
		pfile = list_file_init(g_cc_path, "%s:256");
	} else if (0 == strcasecmp(list, "content_keyword")) {
		pfile = list_file_init(g_content_path, "%s:256");
	} else if (0 == strcasecmp(list, "attachment_keyword")) {
		pfile = list_file_init(g_attachment_path, "%s:256");
	}
	if (NULL == pfile) {
		system_log_info("[upload_ui]: fail to open %s list for broadcasting",
			list);
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (char*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[upload_ui]: fail to open directory %s\n",
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
		if (0 == strcasecmp(list, "subject_keyword")) {
			sprintf(temp_path, "%s/%s/data/smtp/keyword_filter/subject.txt",
				g_mount_path, direntp->d_name);
		} else if (0 == strcasecmp(list, "from_keyword")) {
			sprintf(temp_path, "%s/%s/data/smtp/keyword_filter/from.txt",
				g_mount_path, direntp->d_name);
		} else if (0 == strcasecmp(list, "to_keyword")) {
			sprintf(temp_path, "%s/%s/data/smtp/keyword_filter/to.txt",
				g_mount_path, direntp->d_name);
		} else if (0 == strcasecmp(list, "cc_keyword")) {
			sprintf(temp_path, "%s/%s/data/smtp/keyword_filter/cc.txt",
				g_mount_path, direntp->d_name);
		} else if (0 == strcasecmp(list, "content_keyword")) {
			sprintf(temp_path, "%s/%s/data/smtp/keyword_filter/content.txt",
				g_mount_path, direntp->d_name);
		} else if (0 == strcasecmp(list, "attachment_keyword")) {
			sprintf(temp_path, "%s/%s/data/smtp/keyword_filter/attachment.txt",
				g_mount_path, direntp->d_name);
		}
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[upload_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			upload_ui_encode_line(pitem + 256*i, temp_buff);
			len = strlen(temp_buff);
			temp_buff[len] = '\n';
			len ++;
			write(fd, temp_buff, len);
		}
		close(fd);
		
	}
	closedir(dirp);
	list_file_free(pfile);
}

static void upload_ui_encode_line(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if (' ' == in[i] || '\\' == in[i] || '\t' == in[i] || '#' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

