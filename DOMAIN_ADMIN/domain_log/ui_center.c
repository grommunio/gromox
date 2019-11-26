#include "ui_center.h"
#include "lang_resource.h"
#include <gromox/system_log.h>
#include "search_engine.h"
#include <gromox/session_client.h>
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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

/* fill search result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\""

/* fill search URL link here */

#define HTML_RESULT_6	"\">"

/* fill search again label here */


#define HTML_RESULT_7	"</A></TD></TR><TR><TD noWrap align=left height=23>"

/* fill search condition here */

#define HTML_RESULT_8	\
"</TD></TR></TBODY></TABLE><BR><BR>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill result table title here */

#define HTML_RESULT_9	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_RESULT_10	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_SEARCH_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=searchpattern method=post action="

/* fill form action here */

#define HTML_SEARCH_6	">\n<INPUT type=hidden value="

#define HTML_SEARCH_7	" name=domain>\n<INPUT type=hidden value="

#define HTML_SEARCH_8	\
" name=session>\n<TABLE class=SearchTable cellSpacing=0 cellPadding=2 \n\
width=\"100%\" border=0><TBODY><TR><TD colSpan=4 align=right>\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</TD></TR>\n\
<TR><TD></TD><TD vAlign=center>\n"

/* fill IP address tag here */

#define HTML_SEARCH_9 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=ip /></SPAN>\n\
</TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill sender tag here */

#define HTML_SEARCH_10 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=from />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill recipient tag here */
#define HTML_SEARCH_11	\
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=rcpt />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill begin time here */

#define HTML_SEARCH_12	"</TD><TD vAlign=center><SPAN><SELECT name=start>\n"

#define HTML_SEARCH_13	"</SELECT></TR><TR><TD></TD><TD vAlign=center>"

/* fill end time here */

#define HTML_SEARCH_14	\
"</TD><TD width=\"30%\" vAlign=center><SPAN><SELECT name=end>\n"


#define HTML_SEARCH_15	\
"</SELECT></TD><TD><INPUT type=submit onclick=\n\
\"var str_ip = searchpattern.ip.value;\n\
var iplength = str_ip.length;\n\
var letters = \'1234567890. \';\n\
for (i=0; i<searchpattern.ip.value.length; i++) {\n\
var check_char = searchpattern.ip.value.charAt(i);\n\
if (letters.indexOf(check_char) == -1) {\n alert (\'"


#define HTML_SEARCH_16	\
"\');\nsearchpattern.ip.value=\'\';\n\
searchpattern.ip.focus();\n\
return false;\n}\n}\
var start_time;\nvar end_time;\n\n\
start_time = parseInt(searchpattern.start.value);\n\
end_time = parseInt(searchpattern.end.value);\n\
if ((start_time != 0 && end_time != 0 && start_time < end_time)) {\n\
alert(\'"

#define HTML_SEARCH_17	\
"\');\nreturn false;\n} else {\n return true;\n}\" value=\"    "

/* fill button label here */

#define HTML_SEARCH_18	\
"    \"/></TD></TR></TBODY></TABLE></FORM>\n\
</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy; "

#define HTML_SEARCH_19	"</CENTER></BODY></HTML>"

#define HTML_OPTION_1	"<OPTION value="

#define HTML_OPTION_SELECTED	" selected>"

#define HTML_OPTION_2	">"

#define HTML_OPTION_3	"</OPTION>\n"


#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=domain_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"



#define HTML_TBITEM_FIRST   "<TR class=SolidRow><TD>&nbsp; "
#define HTML_TBITEM_1       "<TR class=ItemRow><TD>&nbsp; "
#define HTML_TBITEM_2       "&nbsp;</TD><TD>&nbsp; "
#define HTML_TBITEM_3       "&nbsp;</TD><TD>&nbsp; "
#define HTML_TBITEM_4       "&nbsp;</TD><TD>&nbsp; "
#define HTML_TBITEM_5       "&nbsp;</TD><TD>"
#define HTML_TBITEM_6       "</TD></TR>\n"

#define HTML_NORESULT_LABEL	"<TR class=ItemRow><TD colSpan=5>%s</TD></TR>"

static void ui_center_error_html(const char *error_string);

static void ui_center_search_html(const char *domain, const char *session);

static void ui_center_result_html(const char *domain, const char *session,
	const char *ip, const char *from, const char *rcpt, time_t start_point,
	time_t end_point);

static BOOL ui_center_get_self(char *url_buff, int length);

static void ui_center_unencode(char *src, char *last, char *dest);


static int g_valid_days;
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void ui_center_init(int valid_days, const char *url_link,
	const char *resource_path)
{
	g_valid_days = valid_days;
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int ui_center_run()
{
	struct tm *ptm;
	time_t start, end;
	time_t current_time;
	int len;
	char *language;
	char *ptr1, *ptr2;
	char *query, *request;
	char domain[256];
	char session[256];
	char post_buff[1024];
	char search_buff[1024];
	char tmp_ip[16], tmp_rcpt[256];
	char tmp_from[256], tmp_time[8];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		ui_center_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[ui_center]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[ui_center]: fail to get REQUEST_METHOD environment!");
		return -2;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[ui_center]: post buffer too long");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		ui_center_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "domain=", len);
		if (NULL == ptr1) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		ptr1 += 7;
		ptr2 = search_string(search_buff, "&session=", len);
		if (NULL == ptr2) {
			system_log_info("[ui_center]: query string of POST "
				"format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(domain, ptr1, ptr2 - ptr1);
		domain[ptr2 - ptr1] = '\0';
		ptr1 = ptr2 + 9;
		ptr2 = search_string(search_buff, "&ip=", len);
		if (NULL == ptr2) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
		ptr1 = ptr2 + 4;
		ptr2 = search_string(search_buff, "&from=", len);
		if (NULL == ptr2) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 15) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_ip, ptr1, ptr2 - ptr1);
		tmp_ip[ptr2 - ptr1] = '\0';
		ltrim_string(tmp_ip);
		rtrim_string(tmp_ip);

		ptr1 = ptr2 + 6;
		ptr2 = search_string(search_buff, "&rcpt=", len);
		if (NULL == ptr2) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_from, ptr1, ptr2 - ptr1);
		tmp_from[ptr2 - ptr1] = '\0';
		ltrim_string(tmp_from);
		rtrim_string(tmp_from);

		ptr1 = ptr2 + 6;
		ptr2 = search_string(search_buff, "&start=", len);
		if (NULL == ptr2) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_rcpt, ptr1, ptr2 - ptr1);
		tmp_rcpt[ptr2 - ptr1] = '\0';
		ptr1 = ptr2 + 7;
		ptr2 = search_string(search_buff, "&end=", len);
		if (ptr2 < ptr1 || ptr2 - ptr1 > 3) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_time, ptr1, ptr2 - ptr1);
		tmp_time[ptr2 - ptr1] = '\0';
		start = atoi(tmp_time);
		ptr2 += 5;
		if (search_buff + len - ptr2 > 3) {
			system_log_info("[ui_center]: query string of POST format error");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_time, ptr2, search_buff + len - ptr2);
		tmp_time[search_buff + len - ptr2] = '\0';
		end = atoi(tmp_time);
		
		if (FALSE == session_client_check(domain, session)) {
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",language));
			return 0;
		}
		
		time(&current_time);
		ptm = localtime(&current_time);
		current_time -= ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec;
		if (0 != start) {
			start = current_time - 24*60*60*start;
		}
		if (0 != end) {
			end = current_time - 24*60*60*(end - 1) - 1;
		}
		ui_center_result_html(domain, session, tmp_ip, tmp_from, tmp_rcpt,
			start, end);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[ui_center]: fail to get QUERY_STRING "
					"environment!");
			ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 512) {
				system_log_info("[ui_center]: query string too long!");
				ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 = search_string(query, "domain=", len);
			if (NULL == ptr1) {
				system_log_info("[ui_center]: query string of GET format error");
				ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 += 7;
			ptr2 = search_string(query, "&session=", len);
			if (NULL == ptr2) {
				system_log_info("[ui_center]: query string of GET format error");
				ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[ui_center]: query string of GET format error");
				ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(domain, ptr1, ptr2 - ptr1);
			domain[ptr2 - ptr1] = '\0';
			ptr2 += 9;
			if (query + len - ptr2 > 255) {
				system_log_info("[ui_center]: query string of GET format error");
				ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(session, ptr2, query + len - ptr2);
			session[query + len - ptr2] = '\0';
			
			if (FALSE == session_client_check(domain, session)) {
				ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
				return 0;
			}
			
			ui_center_search_html(domain, session);
			return 0;
		}
	} else {
		system_log_info("[ui_center]: unrecognized REQUEST_METHOD \"%s\"!",
					request);
		ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int ui_center_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void ui_center_free()
{
	/* do nothing */
}

static BOOL ui_center_get_self(char *url_buff, int length)
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

static void ui_center_error_html(const char *error_string)
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

static void ui_center_search_html(const char *domain, const char *session)
{
	int i;
	char *language;
	char time_buff[64];
	char url_buff[1024];
	time_t current_time;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == ui_center_get_self(url_buff, 1024)) {
		ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_SEARCH_5);
	printf(url_buff);
	printf(HTML_SEARCH_6);
	printf(domain);
	printf(HTML_SEARCH_7);
	printf(session);
	printf(HTML_SEARCH_8, lang_resource_get(g_lang_resource,"HELP_LINK", language),
		lang_resource_get(g_lang_resource,"HELP_LABEL", language));
	printf(lang_resource_get(g_lang_resource,"IP_ADDRESS", language));
	printf(HTML_SEARCH_9);
	printf(lang_resource_get(g_lang_resource,"FROM_ADDRESS", language));
	printf(HTML_SEARCH_10);
	printf(lang_resource_get(g_lang_resource,"RCPT_ADDRESS", language));
	printf(HTML_SEARCH_11);
	printf(lang_resource_get(g_lang_resource,"START_TIME", language));
	printf(HTML_SEARCH_12);
	time(&current_time);
	printf("%s0%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SELECTED", language), HTML_OPTION_3);
	for (i=1; i<g_valid_days; i++) {
		current_time -= 24*60*60;
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"RESULT_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
	}
	printf(HTML_SEARCH_13);
	printf(lang_resource_get(g_lang_resource,"END_TIME", language));
	printf(HTML_SEARCH_14);
	time(&current_time);
	printf("%s0%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SELECTED", language), HTML_OPTION_3);
	for (i=1; i<g_valid_days; i++) {
		current_time -= 24*60*60;
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"RESULT_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
	}
	printf(HTML_SEARCH_15);
	printf(lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language));
	printf(HTML_SEARCH_16);
	printf(lang_resource_get(g_lang_resource,"MSGERR_STARTTIME", language));
	printf(HTML_SEARCH_17);
	printf(lang_resource_get(g_lang_resource,"SEARCH_LABEL", language));
	printf(HTML_SEARCH_18);
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	printf(HTML_SEARCH_19);

}

static void ui_center_result_html(const char *domain, const char *session,
	const char *ip, const char *from, const char *rcpt, time_t start_point,
	time_t end_point)
{
	char *language;
	char temp_buff[64];
	char url_buff[1024];
	const char *ptype;
	struct in_addr addr;
	ITEM_DATA *pitem;
	SEARCH_COLLECT *pcollection;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	pcollection = search_engine_collect_init();
	if (FALSE == search_engine_search(domain, ip, from, rcpt, start_point,
		end_point, pcollection)) {
		ui_center_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_RESULT_5);
	ui_center_get_self(url_buff, 1024);
	printf(url_buff);
	printf("?domain=%s&session=%s", domain, session);
	printf(HTML_RESULT_6);
	printf(lang_resource_get(g_lang_resource,"SEARCH_AGAIN_LABEL", language));
	printf(HTML_RESULT_7);
	if ('\0' != ip[0]) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"IP_ADDRESS", language), ip);
	}
	if ('\0' != from[0]) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"FROM_ADDRESS", language), from);
	}
	if ('\0' != rcpt[0]) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"RCPT_ADDRESS", language), rcpt);
	}
	if (start_point > 0) {
		printf("%s: ", lang_resource_get(g_lang_resource,"START_TIME", language));
		strftime(temp_buff, 64, lang_resource_get(g_lang_resource,"RESULT_TIME_FORMAT",
			language), localtime(&start_point));
		printf("%s; ", temp_buff);
	}
	if (end_point > 0) {
		printf("%s: ", lang_resource_get(g_lang_resource,"END_TIME", language));
		strftime(temp_buff, 64, lang_resource_get(g_lang_resource,"RESULT_TIME_FORMAT",
			language), localtime(&end_point));
		printf("%s; ", temp_buff);
	}
	
	printf(HTML_RESULT_8);
	printf(lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	printf(HTML_RESULT_9);
	
	printf(HTML_TBITEM_FIRST);
	printf(lang_resource_get(g_lang_resource,"TIME_TAG", language));
	printf(HTML_TBITEM_2);
	printf(lang_resource_get(g_lang_resource,"IP_TAG", language));
	printf(HTML_TBITEM_3);
	printf(lang_resource_get(g_lang_resource,"FROM_TAG", language));
	printf(HTML_TBITEM_4);
	printf(lang_resource_get(g_lang_resource,"TO_TAG", language));
	printf(HTML_TBITEM_5);
	printf(lang_resource_get(g_lang_resource,"TYPE_TAG", language));
	printf(HTML_TBITEM_6);
	
	for (search_engine_collect_begin(pcollection);
		!search_engine_collect_done(pcollection);
		search_engine_collect_forward(pcollection)) {
		pitem = search_engine_collect_get_value(pcollection);
		strftime(temp_buff, 64, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&pitem->time));
		addr.s_addr = pitem->ip;
		switch (pitem->type) {
		case LOG_ITEM_OK:
			ptype = lang_resource_get(g_lang_resource,"TYPE_NORMAL", language);
			break;
		case LOG_ITEM_SPAM_MAIL:
			ptype = lang_resource_get(g_lang_resource,"TYPE_SPAM", language);
			break;
		case LOG_ITEM_SPAM_VIRUS:
			ptype = lang_resource_get(g_lang_resource,"TYPE_VIRUS", language);
			break;
		case LOG_ITEM_SPAM_INSULATION:
			ptype = lang_resource_get(g_lang_resource,"TYPE_INSULATION", language);
			break;
		case LOG_ITEM_NO_USER:
			ptype = lang_resource_get(g_lang_resource,"TYPE_NOUSER", language);
			break;
		case LOG_ITEM_TIMEOUT:
			ptype = lang_resource_get(g_lang_resource,"TYPE_TIMEOUT", language);
			break;
		case LOG_ITEM_RETRYING:
			ptype = lang_resource_get(g_lang_resource,"TYPE_RETRYING", language);
			break;
		case LOG_ITEM_OUTGOING_OK:
			ptype = lang_resource_get(g_lang_resource,"TYPE_OUTGOING", language);
			break;
		default:
			ptype = "error type";
			break;
		}
		printf("%s%s%s%s%s%s%s%s%s%s%s", 
			HTML_TBITEM_1,
			temp_buff,
			HTML_TBITEM_2,
			inet_ntoa(addr),
			HTML_TBITEM_3,
			pitem->from,
			HTML_TBITEM_4,
			pitem->to,
			HTML_TBITEM_5,
			ptype,
			HTML_TBITEM_6);
	}
	if (0 == search_engine_collect_total(pcollection)) {
		printf(HTML_NORESULT_LABEL, lang_resource_get(g_lang_resource,
			"NORESULT_LABEL", language));
	}
	search_engine_collect_free(pcollection);
	printf(HTML_RESULT_10);

}

static void ui_center_unencode(char *src, char *last, char *dest)
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

