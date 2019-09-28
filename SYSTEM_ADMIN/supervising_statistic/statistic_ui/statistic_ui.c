#include "statistic_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "list_file.h"
#include "acl_control.h"
#include "util.h"
#include <time.h>
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

/* fill statistic result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<TABLE><TBODY><TR><TD width=160 bgColor=#66f0ff>%s</TD>\n\
<TD width=160 bgColor=#ffb055>%s</TD>\n\
<TD width=320 bgColor=#4477dd>%s</TD></TR>\n"

/* fill data report here */

#define HTML_MAIN_6	\
"</TBODY></TABLE><BR></CENTER></TD></TR></TBODY></TABLE></TD></TR> \
</TBODY></TABLE></TD></TR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBCELL_BEGIN		"<TD>"
#define HTML_TBCELL_END			"</TD>\n"
#define HTML_TBLINE_BEGIN_EVEN	"<TR bgColor>"
#define HTML_TBLINE_BEGIN_ODD	"<TR bgColor=#d9d9d9>"
#define HTML_TBLINE_END			"</TR>\n"


#define	MESSAGE_SMTP_CANNOT_CONNECT		0
#define MESSAGE_SMTP_CONNECT_ERROR		1
#define MESSAGE_SMTP_TIME_OUT			2
#define MESSAGE_SMTP_TEMP_ERROR			3
#define MESSAGE_SMTP_UNKNOWN_RESPONSE	4
#define	MESSAGE_SMTP_PERMANENT_ERROR	5
#define MESSAGE_SMTP_AUTH_FAIL			6
#define MESSAGE_ALARM_QUEUE				7
#define MESSAGE_POP3_CANNOT_CONNECT		8
#define MESSAGE_POP3_CONNECT_ERROR		9
#define MESSAGE_POP3_TIME_OUT			10
#define MESSAGE_POP3_RESPONSE_ERROR		11
#define MESSAGE_POP3_UPDATE_FAIL		12
#define MESSAGE_POP3_AUTH_FAIL			13
#define MESSAGE_POP3_RETRIEVE_NONE		14

typedef struct _STATISTIC_ITEM {
	char date[32];
	char address[32];
	int type;
} STATISTIC_ITEM;

static void statistic_ui_error_html(const char *error_string);

static void statistic_ui_main_html(const char *session);

static BOOL statistic_ui_get_self(char *url_buff, int length);

static void statistic_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[1024];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void statistic_ui_init(const char *list_path, const char *url_link,
	const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int statistic_ui_run()
{
	int len;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char session[256];
	char post_buff[1024];
	char search_buff[1024];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		statistic_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[statistic_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[statistic_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[statistic_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[statistic_ui]: fail to get QUERY_STRING "
				"environment!");
			statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 256) {
				system_log_info("[statistic_ui]: query string too long!");
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = search_string(query, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[statistic_ui]: query string of GET "
					"format error");
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			if (query + len - ptr1 > 256) {
				system_log_info("[statistic_ui]: query string of GET "
					"format error");
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, query + len - ptr1);
			session[query + len - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_STATUS)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			default:
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			statistic_ui_main_html(session);
			return 0;
		}
	} else {
		system_log_info("[statistic_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int statistic_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void statistic_ui_free()
{
	/* do nothing */
}

static BOOL statistic_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[statistic_ui]: fail to get "
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

static void statistic_ui_error_html(const char *error_string)
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

static void statistic_ui_main_html(const char *session)
{
	int i, len;
	int item_num;
	time_t cur_time;
	char *language;
	LIST_FILE *pfile;
	char temp_buff[1024];
	STATISTIC_ITEM *pitem;
	struct tm temp_tm, *ptm;
	
	
	pfile = list_file_init(g_list_path, "%s:32%s:32%d");
	if (NULL == pfile) {
		system_log_info("[statistic_ui]: fail to open list file %s",
			g_list_path);
		statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pitem = (STATISTIC_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	
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
	printf(HTML_MAIN_5, lang_resource_get(g_lang_resource,"MAIN_TIME", language),
		lang_resource_get(g_lang_resource,"MAIN_IP_PORT", language),
		lang_resource_get(g_lang_resource,"MAIN_RESULT", language));
	
	for (i=0; i<item_num; i++) {
		memset(&temp_tm, 0, sizeof(temp_tm));
		strptime(pitem[i].date, "%Y-%m-%d-%H-%M", &temp_tm);
		strftime(temp_buff, 1024, lang_resource_get(g_lang_resource,"MAIN_TIME_FORMAT",
			language), &temp_tm);
		if (0 == i%2) {
			printf(HTML_TBLINE_BEGIN_EVEN);
		} else {
			printf(HTML_TBLINE_BEGIN_ODD);
		}
		printf(HTML_TBCELL_BEGIN);
		printf(temp_buff);
		printf(HTML_TBCELL_END);
		printf(HTML_TBCELL_BEGIN);
		printf(pitem[i].address);
		printf(HTML_TBCELL_END);
		printf(HTML_TBCELL_BEGIN);
		switch (pitem[i].type) {
		case MESSAGE_SMTP_CANNOT_CONNECT:
			printf(lang_resource_get(g_lang_resource,"MSG_SMTP_CANNOT_CONNECT", language));
			break;
		case MESSAGE_SMTP_CONNECT_ERROR:
			printf(lang_resource_get(g_lang_resource,"MSG_SMTP_CONNECT_ERROR", language));
			break;
		case MESSAGE_SMTP_TIME_OUT:
			printf(lang_resource_get(g_lang_resource,"MSG_SMTP_TIME_OUT", language));
			break;
		case MESSAGE_SMTP_TEMP_ERROR:
			printf(lang_resource_get(g_lang_resource,"MSG_SMTP_TEMP_ERROR", language));
			break;
		case MESSAGE_SMTP_UNKNOWN_RESPONSE:
			printf(lang_resource_get(g_lang_resource,"MSG_SMTP_UNKNOWN_RESPONSE", language));
			break;
		case MESSAGE_SMTP_PERMANENT_ERROR:
			printf(lang_resource_get(g_lang_resource,"MSG_SMTP_PERMANENT_ERROR", language));
			break;
		case MESSAGE_SMTP_AUTH_FAIL:
			printf(lang_resource_get(g_lang_resource,"MSG_SMTP_AUTH_FAIL", language));
			break;
		case MESSAGE_ALARM_QUEUE:
			printf(lang_resource_get(g_lang_resource,"MSG_ALARM_QUEUE", language));
			break;
		case MESSAGE_POP3_CANNOT_CONNECT:
			printf(lang_resource_get(g_lang_resource,"MSG_POP3_CANNOT_CONNECT", language));
			break;
		case MESSAGE_POP3_CONNECT_ERROR:
			printf(lang_resource_get(g_lang_resource,"MSG_POP3_CONNECT_ERROR", language));
			break;
		case MESSAGE_POP3_TIME_OUT:
			printf(lang_resource_get(g_lang_resource,"MSG_POP3_TIME_OUT", language));
			break;
		case MESSAGE_POP3_RESPONSE_ERROR:
			printf(lang_resource_get(g_lang_resource,"MSG_POP3_RESPONSE_ERROR", language));
			break;
		case MESSAGE_POP3_UPDATE_FAIL:
			printf(lang_resource_get(g_lang_resource,"MSG_POP3_UPDATE_FAIL", language));
			break;
		case MESSAGE_POP3_AUTH_FAIL:
			printf(lang_resource_get(g_lang_resource,"MSG_POP3_AUTH_FAIL", language));
			break;
		case MESSAGE_POP3_RETRIEVE_NONE:
			printf(lang_resource_get(g_lang_resource,"MSG_POP3_RETRIEVE_NONE", language));
			break;
		default:
			printf("ERROR");
			break;
		}
		printf(HTML_TBCELL_END);
		printf(HTML_TBLINE_END);
	}
	list_file_free(pfile);
	printf(HTML_MAIN_6);
}

static void statistic_ui_unencode(char *src, char *last, char *dest)
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

