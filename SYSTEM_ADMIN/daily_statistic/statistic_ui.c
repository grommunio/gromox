#include "statistic_ui.h"
#include "data_extractor.h"
#include "lang_resource.h"
#include "acl_control.h"
#include "translator.h"
#include "system_log.h"
#include "list_file.h"
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
<FORM class=SearchForm name=searchpattern method=get action="

#define HTML_MAIN_6	\
" ><INPUT type=hidden value=%s name=session />\n\
<SPAN>%s: <SELECT name=console>"

/* fill console here */

#define HTML_MAIN_7	\
"</SELECT></SPAN>&nbsp;&nbsp;&nbsp;&nbsp;<INPUT type=submit \n\
value=\"    %s    \" /></FORM><TABLE cellSpacing=0 cellPadding=0 \n\
width=\"90%\" border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill table title here */

#define HTML_MAIN_8 \
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_MAIN_9	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR>\n\
<TABLE width=\"90%\" border=0 cellpadding=1 cellspacing=1><TR>\n\
<TD height=\"23\" align=\"left\" nowrap>\n"

#define HTML_MAIN_10	"</TD></TR></TABLE><P></P><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_FIRST_ITEM	\
"<TR class=SolidRow><TD colSpan=3>&nbsp; %s (%s - %s)</TD></TR>\n"

#define HTML_TBITEM_ODD		\
"<TR class=OddRow><TD width=\"25%\">&nbsp;%s&nbsp;</TD><TD noWrap \
width=\"0%\">&nbsp;%d&nbsp;</TD><TD width=\"75%\">"

#define HTML_TBITEM_EVEN	\
"<TR class=EvenRow><TD width=\"25%\">&nbsp;%s&nbsp;</TD><TD noWrap \
width=\"0%\">&nbsp;%d&nbsp;</TD><TD width=\"75%\">"

#define HTML_TBITEM_END		"</TD></TR>\n"

#define HTML_CHART_32   "<IMG src=\"../data/picture/bar32.png\">"
#define HTML_CHART_16   "<IMG src=\"../data/picture/bar16.png\">"
#define HTML_CHART_8    "<IMG src=\"../data/picture/bar08.png\">"
#define HTML_CHART_4    "<IMG src=\"../data/picture/bar04.png\">"
#define HTML_CHART_2    "<IMG src=\"../data/picture/bar02.png\">"
#define HTML_CHART_1    "<IMG src=\"../data/picture/bar01.png\">"

#define HTML_OPTION_NORMAL	"<OPTION value=%s>%s</OPTION>"

#define HTML_OPTION_SELECTED "<OPTION value=%s selected>%s</OPTION>"

#define SPAM_TABLE_SIZE     1024

typedef struct _CONSOLE_UNIT {
	char smtp_ip[16];
	int smtp_port;
	char delivery_ip[16];
	int delivery_port;
} CONSOLE_UNIT;

static void statistic_ui_error_html(const char *error_string);

static void statistic_ui_main_html(const char *session, const char *console);

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
	char temp_buff[16];

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
			ptr2 = search_string(query, "&console=", len);
			if (NULL == ptr2) {
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
					statistic_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_TIMEOUT", language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					statistic_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				default:
					statistic_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_SESSION", language));
					return 0;
				}
				
				statistic_ui_main_html(session, NULL);
				return 0;
				
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[statistic_ui]: query string of GET "
					"format error");
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 9;
			if (query + len - ptr1 > 16) {
				system_log_info("[statistic_ui]: query string of GET "
					"format error");
				statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
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
				statistic_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_TIMEOUT", language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				statistic_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_PRIVILEGE", language));
				return 0;
			default:
				statistic_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_SESSION", language));
				return 0;
			}
			
			statistic_ui_main_html(session, temp_buff);
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
		system_log_info("[statistic_ui]: fail to get"
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

static void statistic_ui_main_html(const char *session, const char *console)
{
	int i;
	int max_num;
	int item_num;
	int spam_num;
	int base_val;
	int temp_num;
	int smtp_num;
	int total_num;
	int normal_num;
	int delivery_num;
	time_t cur_time;
	time_t smtp_time;
	time_t delivery_time;
	char *language;
	LIST_FILE *pfile;
	char tf_buff[128];
	char tt_buff[128];
	char url_buff[1024];
	CONSOLE_UNIT *items;
	STATISTIC_ITEM *pitem;
	STATISTIC_ITEM psmtp_item[SPAM_TABLE_SIZE];
	STATISTIC_ITEM pdelivery_item[SPAM_TABLE_SIZE];
	
	
	if (FALSE == statistic_ui_get_self(url_buff, 1024)) {
		statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:16%d%s:16%d");
	if (NULL == pfile) {
		system_log_info("[statistic_ui]: fail to open list file %s",
			g_list_path);
		statistic_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	items = (CONSOLE_UNIT*)list_file_get_list(pfile);
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
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	printf(HTML_MAIN_8);

	time(&cur_time);
	
	data_extractor_retrieve(console, psmtp_item, &smtp_num, &smtp_time,
		pdelivery_item, &delivery_num, &delivery_time);
	translator_do(psmtp_item, smtp_num, pdelivery_item, delivery_num, language);
	max_num = psmtp_item[0].number;
	total_num = psmtp_item[0].number;
	for (i=1; i<smtp_num; i++) {
		if (psmtp_item[i].number > max_num) {
			max_num = psmtp_item[i].number;
		}
		total_num += psmtp_item[i].number;
	}
	for (i=0; i<delivery_num; i++) {
		if (pdelivery_item[i].number > max_num) {
			max_num = pdelivery_item[i].number;
		}
	}
	base_val = max_num / 64;
	
	strftime(tf_buff, 128, lang_resource_get(g_lang_resource,"MAIN_TIME_FORMAT", language),
		localtime(&smtp_time));
	strftime(tt_buff, 128, lang_resource_get(g_lang_resource,"MAIN_TIME_FORMAT", language),
		localtime(&cur_time));
	printf(HTML_FIRST_ITEM, lang_resource_get(g_lang_resource,"MAIN_SMTP", language),
		tf_buff, tt_buff);	

	pitem = psmtp_item;
	for (i=0; i<smtp_num; i++,pitem++) {
		if (i % 2 != 0) {
			printf(HTML_TBITEM_ODD, pitem->tag, pitem->number);
		} else {
			printf(HTML_TBITEM_EVEN, pitem->tag, pitem->number);
		} 

		if (0 == base_val) {
			printf(HTML_TBITEM_END);
			continue;
		}
		temp_num = pitem->number;
		if (1 == temp_num / (base_val*64)) {
			printf(HTML_CHART_32);
			printf(HTML_CHART_32);
			temp_num = 0;
		} 
		if (1 == temp_num / (base_val*32)) {
			printf(HTML_CHART_32);
			temp_num = temp_num % (base_val*32);
		}
		if (1 == temp_num / (base_val*16)) {
			printf(HTML_CHART_16);
			temp_num = temp_num % (base_val*16);
		}
		if (1 == temp_num / (base_val*8)) {
			printf(HTML_CHART_8);
			temp_num = temp_num % (base_val*8);
		}
		if (1 == temp_num / (base_val*4)) {
			printf(HTML_CHART_4);
			temp_num = temp_num % (base_val*4);
		}
		if (1 == temp_num / (base_val*2)) {
			printf(HTML_CHART_2);
			temp_num = temp_num % (base_val*2);
		}
		if (1 == temp_num / base_val) {
			printf(HTML_CHART_1);
		}
		printf(HTML_TBITEM_END);
	}
	
	strftime(tf_buff, 128, lang_resource_get(g_lang_resource,"MAIN_TIME_FORMAT", language),
		localtime(&delivery_time));
	printf(HTML_FIRST_ITEM, lang_resource_get(g_lang_resource,"MAIN_DELIVERY", language),
		tf_buff, tt_buff);	

	pitem = pdelivery_item;
	for (i=0; i<delivery_num; i++,pitem++) {
		if (i % 2 != 0) {
			printf(HTML_TBITEM_ODD, pitem->tag, pitem->number);
		} else {
			printf(HTML_TBITEM_EVEN, pitem->tag, pitem->number);
		} 
	
		if (0 == base_val) {
			printf(HTML_TBITEM_END);
			continue;
		}

		temp_num = pitem->number;
		if (1 == temp_num / (base_val*64)) {
			printf(HTML_CHART_32);
			printf(HTML_CHART_32);
			temp_num = 0;
		} 
		if (1 == temp_num / (base_val*32)) {
			printf(HTML_CHART_32);
			temp_num = temp_num % (base_val*32);
		}
		if (1 == temp_num / (base_val*16)) {
			printf(HTML_CHART_16);
			temp_num = temp_num % (base_val*16);
		}
		if (1 == temp_num / (base_val*8)) {
			printf(HTML_CHART_8);
			temp_num = temp_num % (base_val*8);
		}
		if (1 == temp_num / (base_val*4)) {
			printf(HTML_CHART_4);
			temp_num = temp_num % (base_val*4);
		}
		if (1 == temp_num / (base_val*2)) {
			printf(HTML_CHART_2);
			temp_num = temp_num % (base_val*2);
		}
		if (1 == temp_num / base_val) {
			printf(HTML_CHART_1);
		}
		printf(HTML_TBITEM_END);
	}
	printf(HTML_MAIN_9);	
	if (0 != total_num) {
		normal_num = psmtp_item[0].number;
		spam_num = total_num - normal_num;
		printf("%s: %d, %s: %d, %s: %d, %s: %5.2f%%",
				lang_resource_get(g_lang_resource,"MAIN_TOTAL", language), total_num,
				lang_resource_get(g_lang_resource,"MAIN_NORMAL", language), normal_num,
				lang_resource_get(g_lang_resource,"MAIN_SPAM", language), spam_num,
				lang_resource_get(g_lang_resource,"MAIN_PERCENTAGE", language),
				(float)normal_num/total_num*100);
	}
	printf(HTML_MAIN_10);
	list_file_free(pfile);
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

