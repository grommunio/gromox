#include "password_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "list_file.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
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

/* fill HTML title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\""

/* fill retype link here */

#define HTML_RESULT_6	"\">"

/* fill retype label here */


#define HTML_RESULT_7	"</A></TD></TR><TR><TD noWrap align=center height=23>"

/* fill change result here */

#define HTML_RESULT_8	\
"</TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_CHANGE_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=searchpattern method=post action="

/* fill action here */

#define HTML_CHANGE_6	" >\n<INPUT type=hidden value="

#define HTML_CHANGE_7	\
" name=session><TABLE class=SearchTable cellSpacing=0 cellPadding=2 \n\
width=\"100%\" border=0><TBODY><TR><TD></TD><TD vAlign=center>\n"

/* fill old password label */

#define HTML_CHANGE_8 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"password\" name=old /></SPAN>\n\
</TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill new password here */

#define HTML_CHANGE_9 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"password\" name=new_password />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill retype new password here */

#define HTML_CHANGE_10 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"password\" name=retype_password />\n\
</SPAN></TD><TD><INPUT type=submit value=\"    "

/* fill button label here */

#define HTML_CHANGE_11	\
"    \" onclick=\"if (0 == new_password.value.length) {\n\
alert('%s');\nreturn false;}\n\
if (new_password.value != retype_password.value) {\n\
alert('%s');\nreturn false;}\"\n\
/></TD></TR></TBODY></TABLE></FORM></TBODY></TABLE>\n\
</TD></TR></TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;"

#define HTML_CHANGE_12	"</CENTER></BODY></HTML>"

#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static void password_ui_error_html(const char *error_string);

static void password_ui_change_html(const char *session);

static BOOL password_ui_modify_list(const char *username, const char *password);

static void password_ui_result_html(const char *session,
	const char *old_password, const char *new_password);

static BOOL password_ui_get_self(char *url_buff, int length);

static void password_ui_unencode(char *src, char *last, char *dest);

static char g_logo_link[1024];
static char g_list_path[256];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void password_ui_init(const char *list_path, const char *url_link,
	const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int password_ui_run()
{
	int len;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char *query, *request;
	char password[256];
	char session[256];
	char post_buff[1024];
	char search_buff[1024];
	char old_password[256];
	char new_password[256];
	char retype_password[256];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		password_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[password_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[password_ui]: fail to get REQUEST_METHOD environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[password_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[password_ui]: post buffer too long");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		password_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "session=", len);
		if (NULL == ptr1) {
			system_log_info("[password_ui]: query string of POST "
				"format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
			return 0;
		}
		ptr1 += 8;
		ptr2 = search_string(search_buff, "&old=", len);
		if (NULL == ptr2) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
		ptr1 = ptr2 + 5;
		ptr2 = search_string(search_buff, "&new_password=", len);
		if (NULL == ptr2) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(old_password, ptr1, ptr2 - ptr1);
		old_password[ptr2 - ptr1] = '\0';
		
		ptr1 = ptr2 + 14;
		ptr2 = search_string(search_buff, "&retype_password=", len);
		if (NULL == ptr2) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(new_password, ptr1, ptr2 - ptr1);
		new_password[ptr2 - ptr1] = '\0';
		
		ptr2 += 17;
		if (search_buff + len - ptr2 > 256) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(retype_password, ptr2, search_buff + len - ptr2 - 1);
		retype_password[search_buff + len - ptr2 - 1] = '\0';

		if (0 != strcmp(new_password, retype_password)) {
			system_log_info("[password_ui]: query string of POST format error");
			password_ui_error_html(lang_resource_get(g_lang_resource,"NEW_PASSWORD_ERROR",
				language));
			return 0;
		}

		switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_IGNORE)) {
		case ACL_SESSION_OK:
			break;
		case ACL_SESSION_TIMEOUT:
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
				language));
			return 0;
		default:
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
				language));
			return 0;
		}
		
		password_ui_result_html(session, old_password, new_password);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[password_ui]: fail to get QUERY_STRING "
					"environment!");
			password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 256) {
				system_log_info("[password_ui]: query string too long!");
				password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 = search_string(query, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[password_ui]: query string of GET format error");
				password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 += 8;
			if (query + len - ptr1 > 255) {
				system_log_info("[password_ui]: query string of GET format error");
				password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(session, ptr1, query + len - ptr1);
			session[query + len - ptr1] = '\0';
			
			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_IGNORE)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			default:
				password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			password_ui_change_html(session);
			return 0;
		}
	} else {
		system_log_info("[password_ui]: unrecognized REQUEST_METHOD \"%s\"!",
					request);
		password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int password_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void password_ui_free()
{
	/* do nothing */
}

static BOOL password_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[password_ui]: fail to get "
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

static void password_ui_error_html(const char *error_string)
{
	char *language;
	
	if (NULL ==error_string) {
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

static void password_ui_change_html(const char *session)
{
	char *language;
	char url_buff[1024];
	
	if (FALSE == password_ui_get_self(url_buff, 1024)) {
		password_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
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
	printf(HTML_CHANGE_5);
	printf(url_buff);
	printf(HTML_CHANGE_6);
	printf(session);
	printf(HTML_CHANGE_7);
	printf(lang_resource_get(g_lang_resource,"OLD_PASSWORD", language));
	printf(HTML_CHANGE_8);
	printf(lang_resource_get(g_lang_resource,"NEW_PASSWORD", language));
	printf(HTML_CHANGE_9);
	printf(lang_resource_get(g_lang_resource,"RETYPE_NEW_PASSWORD", language));
	printf(HTML_CHANGE_10);
	printf(lang_resource_get(g_lang_resource,"CHANGE_LABEL", language));
	printf(HTML_CHANGE_11, lang_resource_get(g_lang_resource,"NULL_PASSWORD_ERROR", language),
		lang_resource_get(g_lang_resource,"NEW_PASSWORD_ERROR", language));
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	printf(HTML_CHANGE_12);
}

static void password_ui_result_html(const char *session,
	const char *old_password, const char *new_password)
{
	char *language;
	char username[256];
	char url_buff[1024];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
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
	printf(HTML_RESULT_5);
	password_ui_get_self(url_buff, 1024);
	printf(url_buff);
	printf("?session=%s", session);
	printf(HTML_RESULT_6);
	printf(lang_resource_get(g_lang_resource,"CHANGE_AGAIN_LABEL", language));
	printf(HTML_RESULT_7);
	
	if (FALSE == acl_control_naming(session, username)) {
		printf(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
	} else {
		if (FALSE == acl_control_auth(username, old_password)) {
			printf(lang_resource_get(g_lang_resource,"OLD_PASSWORD_ERROR", language));
		} else {
			if (TRUE == password_ui_modify_list(username, new_password)) {
				printf(lang_resource_get(g_lang_resource,"PASSWORD_CHANGED_LABEL", language));
			} else {
				printf(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			}
		}
	}
	printf(HTML_RESULT_8);

}

static BOOL password_ui_modify_list(const char *username, const char *password)
{
	int fd, i;
	size_t len;
	int item_num;
	LIST_FILE *pfile;
	char *pitem;
	char temp_char;
	char temp_buff[256];
	char temp_path[256];
	char temp_line[1024];

	memset(temp_buff, 0, 256);
	encode64(password, strlen(password), temp_buff, 256, &len);
	for (i=0; i<len/2; i++) {
		temp_char = temp_buff[i];
		temp_buff[i] = temp_buff[len - 1 - i];
		temp_buff[len - 1 - i] = temp_char;
	}

	pfile = list_file_init(g_list_path, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		system_log_info("[password_ui]: fail to init account list file %s",
			g_list_path);
		return FALSE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	sprintf(temp_path, "%s.tmp", g_list_path);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[password_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return FALSE;
	}
	if (0 == item_num && 0 == strcasecmp(username, "administrator")) {
		len = sprintf(temp_line, "administrator\t%s\t1111\n", temp_buff);
		write(fd, temp_line, len);
	} else {
		for (i=0; i<item_num; i++) {
			if (0 == strcasecmp(username, pitem + 3*256*i)) {
				len = sprintf(temp_line, "%s\t%s\t%s\n", username,
						temp_buff, pitem + 3*256*i + 2*256);
			} else {
				len = sprintf(temp_line, "%s\t%s\t%s\n", pitem + 3*256*i,
						pitem + 3*256*i + 256, pitem + 3*256*i + 2*256);
			}
			write(fd, temp_line, len);
		}
	}
	close(fd);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	list_file_free(pfile);
	return TRUE;
}

static void password_ui_unencode(char *src, char *last, char *dest)
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

