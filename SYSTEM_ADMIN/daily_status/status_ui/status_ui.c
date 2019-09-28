#include "status_ui.h"
#include "system_log.h"
#include "acl_control.h"
#include "list_file.h"
#include "lang_resource.h"
#include "data_extractor.h"
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

/* fill status result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=searchpattern method=get action="

#define HTML_MAIN_6	\
" ><INPUT type=hidden value=%s name=session />\n\
<SPAN>%s: <SELECT name=console>"

/* fill console here */

#define HTML_MAIN_7	\
"</SELECT></SPAN><SPAN>&nbsp;&nbsp;&nbsp;&nbsp;<INPUT type=submit \n\
value=\"    %s    \" /></FORM>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\"\n\
border=0><TBODY><TR><TD noWrap align=left height=23></TD></TR>\n\
</TBODY></TABLE><BR><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" \n\
border=0><TBODY><TABLE class=ChartTable cellSpacing=0 cellPadding=2 \n\
width=\"100%\" border=0><TBODY><TR><TD align=middle><CENTER>\n\
<TABLE><TBODY><TR vAlign=bottom><TD>&nbsp;</TD>\n"

/* fill chart here */

#define HTML_MAIN_8	\
"<TD>&nbsp;</TD></TR><TR vAlign=center><TD>&nbsp;</TD>\n"

/* fill unit lable here */

#define HTML_MAIN_9	\
"<TD>&nbsp;</TD></TR></TBODY></TABLE><BR>\n\
<TABLE><TBODY><TR><TD width=80 bgColor=#ececec>%s</TD>\n\
<TD width=160 bgColor=#ffb055>%s</TD>\n\
<TD width=160 bgColor=#4477dd>%s</TD>\
<TD width=160 bgColor=#66f0ff>%s</TD></TR>\n"

/* fill data report here */

#define HTML_MAIN_10	\
"</TBODY></TABLE><BR></CENTER></TD></TR></TBODY></TABLE></TD></TR> \
</TBODY></TABLE><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_OPTION_NORMAL	"<OPTION value=%s>%s</OPTION>"

#define HTML_OPTION_SELECTED "<OPTION value=%s selected>%s</OPTION>"

#define HTML_TBCELL_BEGIN	"<TD>"
#define HTML_TBCELL_END		"</TD>\n"
#define HTML_TBLINE_BEGIN	"<TR>"
#define HTML_TBLINE_END		"</TR>\n"

#define HTML_CHART_CPU	\
"<IMG title=\"%s: %d%%\" src=\"../data/picture/vu.png\" height=%d width=12 \
align=bottom>"

#define HTML_CHART_NETWORK	\
"<IMG title=\"%s: %s\" src=\"../data/picture/vp.png\" height=%d width=12 \
align=bottom>"

#define HTML_CHART_CONNECTION \
"<IMG title=\"%s: %d\" src=\"../data/picture/vh.png\" height=%d width=12 \
align=bottom>"

typedef struct _CONSOLE_UNIT {
	char smtp_ip[16];
	int smtp_port;
	char delivery_ip[16];
	int delivery_port;
} CONSOLE_UNIT;

static void status_ui_error_html(const char *error_string);

static void status_ui_main_html(const char *session, const char *console);

static BOOL status_ui_get_self(char *url_buff, int length);

static void status_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[1024];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void status_ui_init(const char *list_path, const char *url_link,
	const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int status_ui_run()
{
	int len;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char session[256];
	char search_buff[1024];
	char temp_buff[16];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		status_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[status_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[status_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[status_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[status_ui]: fail to get QUERY_STRING "
				"environment!");
			status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 256) {
				system_log_info("[status_ui]: query string too long!");
				status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = search_string(query, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[status_ui]: query string of GET "
					"format error");
				status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = search_string(query, "&console=", len);
			if (NULL == ptr2) {
				if (query + len - ptr1 > 256) {
					system_log_info("[status_ui]: query string of GET "
						"format error");
					status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
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
					status_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_TIMEOUT", language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					status_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				default:
					status_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_SESSION", language));
					return 0;
				}
				
				status_ui_main_html(session, NULL);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[status_ui]: query string of GET "
					"format error");
				status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 9;
			if (query + len - ptr1 > 16) {
				system_log_info("[status_ui]: query string of GET "
					"format error");
				status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(temp_buff, ptr1, query + len - ptr1);
			temp_buff[query + len - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_STATUS)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				status_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_TIMEOUT", language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				status_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_PRIVILEGE", language));
				return 0;
			default:
				status_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_SESSION", language));
				return 0;
			}
			
			status_ui_main_html(session, temp_buff);
			return 0;
		}
	} else {
		system_log_info("[status_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int status_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void status_ui_free()
{
	/* do nothing */
}

static BOOL status_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[status_ui]: fail to get"
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

static void status_ui_error_html(const char *error_string)
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

static void status_ui_main_html(const char *session, const char *console)
{
	int i, len;
	int height;
	int item_num;
	int max_connection;
	double max_network;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char temp_size[32];
	CONSOLE_UNIT *items;
	STATUS_ITEM *pitem;
	STATUS_ITEM temp_array[24];
	
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	pitem = temp_array;
	if (FALSE == status_ui_get_self(url_buff, 1024)) {
		status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:16%d%s:16%d");
	if (NULL == pfile) {
		system_log_info("[status_ui]: fail to open list file %s",
			g_list_path);
		status_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	items = (CONSOLE_UNIT*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
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
	printf(HTML_MAIN_5);
	printf(url_buff);
	printf(HTML_MAIN_6, session, lang_resource_get(g_lang_resource,
		"MAIN_CONSOLE", language));
	if (NULL == console) {
		console = items[0].smtp_ip;
	}
	for (i=0; i<item_num; i++) {
		if (0 != strcmp(items[i].smtp_ip, console)) {
			printf(HTML_OPTION_NORMAL, items[i].smtp_ip, items[i].smtp_ip);
		} else {
			printf(HTML_OPTION_SELECTED, items[i].smtp_ip, items[i].smtp_ip);
		}
	}
	printf(HTML_MAIN_7, lang_resource_get(g_lang_resource,"DISPLAY_LABEL", language));
	item_num = data_extractor_retrieve(console, pitem);
	list_file_free(pfile);
	max_network = 0;
	max_connection = 0;
	for (i=0; i<item_num; i++) {
		if (pitem[i].network > max_network) {
			max_network = pitem[i].network;
		}
		if (pitem[i].connection > max_connection) {
			max_connection = pitem[i].connection;
		}
	}
	for (i=0; i<item_num; i++) {
		printf(HTML_TBCELL_BEGIN);
		if (0 == pitem[i].cpu) {
			height = 1;
		} else {
			height = pitem[i].cpu*2;
		}
		printf(HTML_CHART_CPU, lang_resource_get(g_lang_resource,"MAIN_CPU", language),
			pitem[i].cpu, height);
		if (0 == pitem[i].network || 0 == max_network) {
			height = 1;
		} else {
			height = (int)(pitem[i].network/max_network*200);
		}
		if (pitem[i].network > 0xFFFFFFFF) {
			sprintf(temp_size, "%dG", (int)(pitem[i].network/0x3FFFFFFF));
		} else {
			bytetoa((size_t)pitem[i].network, temp_size);
		}
		printf(HTML_CHART_NETWORK, lang_resource_get(g_lang_resource,"MAIN_NETWORK",
			language), temp_size, height);
		if (0 == pitem[i].connection || 0 == max_connection) {
			height = 1;
		} else {
			height = pitem[i].connection*200/max_connection;
		}
		printf(HTML_CHART_CONNECTION, lang_resource_get(g_lang_resource,"MAIN_CONNECTION",
			language), pitem[i].connection, height);
		printf(HTML_TBCELL_END);	
	}
	printf(HTML_MAIN_8);
	for (i=0; i<item_num; i++) {
		printf(HTML_TBCELL_BEGIN);
		if (i < 10) {
			printf("0%d:00", i);
		} else {
			printf("%d:00", i);
		}
		printf(HTML_TBCELL_END);
	}
	printf(HTML_MAIN_9, lang_resource_get(g_lang_resource,"MAIN_HOUR", language),
		lang_resource_get(g_lang_resource,"MAIN_CPU", language),
		lang_resource_get(g_lang_resource,"MAIN_NETWORK", language),
		lang_resource_get(g_lang_resource,"MAIN_CONNECTION", language));
	for (i=0; i<item_num; i++) {
		printf(HTML_TBLINE_BEGIN);
		printf(HTML_TBCELL_BEGIN);
		if (i < 10) {
			printf("0%d:00", i);
		} else {
			printf("%d:00", i);
		}
		printf(HTML_TBCELL_END);
		printf(HTML_TBCELL_BEGIN);
		printf("%d%%", pitem[i].cpu);
		printf(HTML_TBCELL_END);
		printf(HTML_TBCELL_BEGIN);
		if (pitem[i].network > 0xFFFFFFFF) {
			sprintf(temp_size, "%dG", (int)(pitem[i].network/0x3FFFFFFF));
		} else {
			bytetoa((size_t)pitem[i].network, temp_size);
		}
		printf("%s", temp_size);
		printf(HTML_TBCELL_END);
		printf(HTML_TBCELL_BEGIN);
		printf("%d", pitem[i].connection);
		printf(HTML_TBCELL_END);
		printf(HTML_TBLINE_END);
	}
	printf(HTML_MAIN_10);
}

static void status_ui_unencode(char *src, char *last, char *dest)
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

