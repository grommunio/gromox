#include "info_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "data_source.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemEven><TD>%s</TD><TD>%d</TD></TR>\n\
<TR class=ItemOdd><TD>%s</TD><TD>%d%c</TD></TR>\n\
</TBODY></TABLE><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

static void info_ui_error_html(const char *error_string);

static void info_ui_main_html(const char *session);

static BOOL info_ui_get_self(char *url_buff, int length);

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
	char *ptr;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char session[256];


	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		info_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[list_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[info_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[info_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
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
			ptr = search_string(query, "session=", len);
			if (NULL == ptr) {
				system_log_info("[info_ui]: query string of GET "
					"format error");
				info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr += 8;
			if (query + len - ptr > 256) {
				system_log_info("[info_ui]: query string of GET "
					"format error");
				info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr, query + len - ptr);
			session[query + len - ptr] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_STATUS)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				info_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_TIMEOUT", language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				info_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_PRIVILEGE", language));
				return 0;
			default:
				info_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_SESSION", language));
				return 0;
			}
				
			info_ui_main_html(session);
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
		system_log_info("[info_ui]: fail to get "
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

static void info_ui_error_html(const char *error_string)
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

static void info_ui_main_html(const char *session)
{
	char space_unit;
	char *language;
	char url_buff[1024];
	int real_domains;
	int backup_domains;
	int monitor_domains;
	int unchkusr_domains;
	int subsys_domains;
	int sms_domains;
	int extpasswd_domains;
	int alias_domains;
	int outofdate_domains;
	int deleted_domains;
	int suspend_domains;
	int total_groups;
	int alloc_addresses;
	int real_addresses;
	int alias_addresses;
	int total_mlists;
	long total_space;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");

	if (FALSE == data_source_system_info(&real_domains, &backup_domains,
		&monitor_domains, &unchkusr_domains, &subsys_domains, &sms_domains,
		&extpasswd_domains, &alias_domains, &outofdate_domains, &deleted_domains,
		&suspend_domains, &total_groups, &alloc_addresses, &real_addresses,
		&alias_addresses, &total_mlists, &total_space)) {
		info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	if (FALSE == info_ui_get_self(url_buff, 1024)) {
		info_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	if (total_space >= 1024*1024) {
		total_space /= 1024*1024;
		space_unit = 'T';
	} else if (total_space >= 1024) {
		total_space /= 1024;
		space_unit = 'G';
	} else {
		space_unit = 'M';
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
	printf(HTML_MAIN_5, lang_resource_get(g_lang_resource,"REAL_DOMAIN_NUM", language),
		real_domains, lang_resource_get(g_lang_resource,"BACKUP_DOMAIN_NUM", language),
		backup_domains, lang_resource_get(g_lang_resource,"MONITOR_DOMAIN_NUM", language),
		monitor_domains, lang_resource_get(g_lang_resource,"UNCHECK_USER_DOMAIN_NUM",
		language), unchkusr_domains, lang_resource_get(g_lang_resource,"SUBSYSTEM_DOMAIN_NUM",
		language), subsys_domains, lang_resource_get(g_lang_resource,"NETDISK_DOMAIN_NUM",
		language), sms_domains, lang_resource_get(g_lang_resource,"EXTPASSWD_DOMAIN_NUM",
		language), extpasswd_domains, lang_resource_get(g_lang_resource,"ALIAS_DOMAIN_NUM",
		language), alias_domains, lang_resource_get(g_lang_resource,"OUT_OF_DATE_DOMAIN_NUM",
		language), outofdate_domains, lang_resource_get(g_lang_resource,"DELETED_DOMAIN_NUM",
		language), deleted_domains, lang_resource_get(g_lang_resource,"SUSPEND_DOMAIN_NUM",
		language), suspend_domains, lang_resource_get(g_lang_resource,"TOTAL_GROUP_NUM",
		language), total_groups, lang_resource_get(g_lang_resource,"ALLOC_ADDRESS_NUM",
		language), alloc_addresses, lang_resource_get(g_lang_resource,"REAL_ADDRESS_NUM",
		language), real_addresses, lang_resource_get(g_lang_resource,"ALIAS_ADDRESS_NUM",
		language), alias_addresses, lang_resource_get(g_lang_resource,"MLIST_NUM", language),
		total_mlists, lang_resource_get(g_lang_resource,"TOTAL_SPACE", language),
		total_space, space_unit);
}

