#include "info_ui.h"
#include "lang_resource.h"
#include <gromox/system_log.h>
#include <gromox/session_client.h>
#include "data_source.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
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

/* fill status result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR><BR>\n\
<BR><BR><TABLE cellSpacing=1 cellPadding=1 width=\"75%\" border=0><TBODY>\n\
<TR class=ItemEven><TD>%s</TD><TD>%s</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%s</TD></TR>\n\
<TR class=%s><TD>%s</TD><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=%s><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%s</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%s</TD></TR>\n\
</TBODY></TABLE><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=group_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define CSS_ITEM_OVERQUOTA			"ItemOverquota"

#define CSS_ITEMODD				"ItemOdd"

static void info_ui_error_html(const char *error_string);

static void info_ui_main_html(const char *groupname, const char *session);

static BOOL info_ui_get_self(char *url_buff, int length);

static void info_ui_from_utf8(char *src, char *dst, size_t len);

static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void info_ui_init(const char *url_link, const char *resource_path)
{
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int info_ui_run()
{
	int len;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char groupname[128];
	char session[256];
	char *ptr1, *ptr2;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		info_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[info_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[info_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -1;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[info_ui]: fail to get REMOTE_ADDR environment!");
		return -2;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[info_ui]: fail to get QUERY_STRING "
				"environment!");
			info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 256) {
				system_log_info("[info_ui]: query string too long!");
				info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = search_string(query, "group=", len);
			if (NULL == ptr1) {
				system_log_info("[info_ui]: query string of GET "
					"format error");
				info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 6;
			ptr2 = search_string(query, "&session=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 128) {
				system_log_info("[info_ui]: query string of GET "
					"format error");
				info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(groupname, ptr1, ptr2 - ptr1);
			groupname[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 9;
			if (query + len - ptr1 > 256) {
				system_log_info("[info_ui]: query string of GET "
					"format error");
				info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, query + len - ptr1);
			session[query + len - ptr1] = '\0';

			if (FALSE == session_client_check(groupname, session)) {
				info_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_SESSION", language));
				return 0;
			}
				
			info_ui_main_html(groupname, session);
			return 0;
		}
	} else {
		system_log_info("[info_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int info_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void info_ui_free()
{
	/* do nothing */
}

static BOOL info_ui_get_self(char *url_buff, int length)
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

static void info_ui_error_html(const char *error_string)
{
	const char *language;
	
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

static void info_ui_main_html(const char *groupname, const char *session)
{
	char *language;
	char grouptitle[128];
	char temp_title[128];
	char url_buff[1024];
	char class_user[16];
	char class_size[16];
	char str_size[16];
	char str_actual[16];
	char str_create[64];
	char str_backup[16];
	char str_monitor[16];
	char str_log[16];
	char str_account[16];
	time_t create_day;
	time_t now_time;
	int max_size;
	int actual_size;
	int max_user;
	int actual_user;
	int alias_num;
	int privilege_bits;
	struct tm temp_tm;
	
	time(&now_time);

	language = getenv("HTTP_ACCEPT_LANGUAGE");

	if (FALSE == data_source_group_info(groupname, grouptitle, &create_day,
		&max_size, &actual_size, &max_user, &actual_user, &alias_num,
		&privilege_bits)) {
		info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	info_ui_from_utf8(grouptitle, temp_title, 128);
	if (FALSE == info_ui_get_self(url_buff, 1024)) {
		info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}

	localtime_r(&create_day, &temp_tm);
	strftime(str_create, 64, lang_resource_get(g_lang_resource,"DATE_FORMAT", language),
		&temp_tm);
	
	if (actual_size >= max_size) {
		strcpy(class_size, CSS_ITEM_OVERQUOTA);
	} else {
		strcpy(class_size, CSS_ITEMODD);
	}

	if (actual_user >= max_user) {
		strcpy(class_user, CSS_ITEM_OVERQUOTA);
	} else {
		strcpy(class_user, CSS_ITEMODD);
	}
	
	if (max_size >= 1024) {
		sprintf(str_size, "%.1fG", (float)max_size/1024);
	} else {
		sprintf(str_size, "%dM", max_size);
	}
	

	if (actual_size >= 1024) {
		sprintf(str_actual, "%.1fG", (float)actual_size/1024);
	} else {
		sprintf(str_actual, "%dM", actual_size);
	}

	if (privilege_bits & GROUP_PRIVILEGE_BACKUP) {
		strcpy(str_backup, lang_resource_get(g_lang_resource,"OPTION_YES", language));
	} else {
		strcpy(str_backup, lang_resource_get(g_lang_resource,"OPTION_NO", language));
	}

	if (privilege_bits & GROUP_PRIVILEGE_MONITOR) {
		strcpy(str_monitor, lang_resource_get(g_lang_resource,"OPTION_YES", language));
	} else {
		strcpy(str_monitor, lang_resource_get(g_lang_resource,"OPTION_NO", language));
	}

	if (privilege_bits & GROUP_PRIVILEGE_LOG) {
		strcpy(str_log, lang_resource_get(g_lang_resource,"OPTION_YES", language));
	} else {
		strcpy(str_log, lang_resource_get(g_lang_resource,"OPTION_NO", language));
	}
	
	if (privilege_bits & GROUP_PRIVILEGE_ACCOUNT) {
		strcpy(str_account, lang_resource_get(g_lang_resource,"OPTION_YES", language));
	} else {
		strcpy(str_account, lang_resource_get(g_lang_resource,"OPTION_NO", language));
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
	printf(HTML_MAIN_5, lang_resource_get(g_lang_resource,"GROUP_TITLE", language),
		temp_title, lang_resource_get(g_lang_resource,"CREATE_DAY", language),
		str_create, lang_resource_get(g_lang_resource,"MAX_SPACE", language), str_size,
		class_size, lang_resource_get(g_lang_resource,"ALLOCATED_SPACE", language),
		str_actual, lang_resource_get(g_lang_resource,"MAX_USERS", language),
		max_user, class_user, lang_resource_get(g_lang_resource,"ALLOCATED_USERS", language),
		actual_user, lang_resource_get(g_lang_resource,"ALIAS_NUM", language), alias_num,
		lang_resource_get(g_lang_resource,"MAIL_BACKUP", language), str_backup,
		lang_resource_get(g_lang_resource,"MAIL_MONITOR", language), str_monitor,
		lang_resource_get(g_lang_resource,"MAIL_LOG", language), str_log,
		lang_resource_get(g_lang_resource,"MAIL_ACCOUNT", language), str_account);
}

static void info_ui_from_utf8(char *src, char *dst, size_t len)
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


