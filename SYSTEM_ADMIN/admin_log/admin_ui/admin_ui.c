#include "admin_ui.h"
#include "system_log.h"
#include "acl_control.h"
#include "match_engine.h"
#include "lang_resource.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
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

#define HTML_SEARCH_6	" >\n<INPUT type=hidden value="

#define HTML_SEARCH_7	\
" name=session><TABLE class=SearchTable cellSpacing=0 cellPadding=2 \n\
width=\"100%\" border=0><TBODY><TR><TD></TD><TD vAlign=center>\n"

/* fill IP address tag here */

#define HTML_SEARCH_8 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=ip /></SPAN>\n\
</TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill sender tag here */

#define HTML_SEARCH_9 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=from />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill ricipient tag here */

#define HTML_SEARCH_10 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=to />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

#define HTML_OPTION_1	"<OPTION value="

#define HTML_OPTION_SELECTED	" selected>"

#define HTML_OPTION_2	">"

#define HTML_OPTION_3	"</OPTION>\n"

/* fill begin time here */

#define HTML_SEARCH_11	"</TD><TD vAlign=center><SPAN><SELECT name=start_day>\n"

#define HTML_SEARCH_12	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=start_hour>\n\
<OPTION value=0 selected>00:00</OPTION>\n\
<OPTION value=1>01:00</OPTION>\n\
<OPTION value=2>02:00</OPTION>\n\
<OPTION value=3>03:00</OPTION>\n\
<OPTION value=4>04:00</OPTION>\n\
<OPTION value=5>05:00</OPTION>\n\
<OPTION value=6>06:00</OPTION>\n\
<OPTION value=7>07:00</OPTION>\n\
<OPTION value=8>08:00</OPTION>\n\
<OPTION value=9>09:00</OPTION>\n\
<OPTION value=10>10:00</OPTION>\n\
<OPTION value=11>11:00</OPTION>\n\
<OPTION value=12>12:00</OPTION>\n\
<OPTION value=13>13:00</OPTION>\n\
<OPTION value=14>14:00</OPTION>\n\
<OPTION value=15>15:00</OPTION>\n\
<OPTION value=16>16:00</OPTION>\n\
<OPTION value=17>17:00</OPTION>\n\
<OPTION value=18>18:00</OPTION>\n\
<OPTION value=19>19:00</OPTION>\n\
<OPTION value=20>20:00</OPTION>\n\
<OPTION value=21>21:00</OPTION>\n\
<OPTION value=22>22:00</OPTION>\n\
<OPTION value=23>23:00</OPTION>\n</SELECT></TR><TR><TD></TD><TD vAlign=center>"

/* fill end time here */

#define HTML_SEARCH_13	\
"</TD><TD width=\"30%\" vAlign=center><SPAN><SELECT name=end_day>\n"

#define HTML_SEARCH_14	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=end_hour>\n\
<OPTION value=0>00:00</OPTION>\n\
<OPTION value=1>01:00</OPTION>\n\
<OPTION value=2>02:00</OPTION>\n\
<OPTION value=3>03:00</OPTION>\n\
<OPTION value=4>04:00</OPTION>\n\
<OPTION value=5>05:00</OPTION>\n\
<OPTION value=6>06:00</OPTION>\n\
<OPTION value=7>07:00</OPTION>\n\
<OPTION value=8>08:00</OPTION>\n\
<OPTION value=9>09:00</OPTION>\n\
<OPTION value=10>10:00</OPTION>\n\
<OPTION value=11>11:00</OPTION>\n\
<OPTION value=12>12:00</OPTION>\n\
<OPTION value=13>13:00</OPTION>\n\
<OPTION value=14>14:00</OPTION>\n\
<OPTION value=15>15:00</OPTION>\n\
<OPTION value=16>16:00</OPTION>\n\
<OPTION value=17>17:00</OPTION>\n\
<OPTION value=18>18:00</OPTION>\n\
<OPTION value=19>19:00</OPTION>\n\
<OPTION value=20>20:00</OPTION>\n\
<OPTION value=21>21:00</OPTION>\n\
<OPTION value=22>22:00</OPTION>\n\
<OPTION value=23 selected>23:00</OPTION>\n\
</SELECT></TD><TD><INPUT type=submit onclick=\n\
\"var str_ip = searchpattern.ip.value;\n\
var iplength = str_ip.length;\n\
var letters = \'1234567890. \';\n\
for (i=0; i<searchpattern.ip.value.length; i++) {\n\
var check_char = searchpattern.ip.value.charAt(i);\n\
if (letters.indexOf(check_char) == -1) {\n alert (\'"


#define HTML_SEARCH_15	\
"\');\nsearchpattern.ip.value=\'\';\n\
searchpattern.ip.focus();\n\
return false;\n}\n}\
var start_time;\nvar end_time;\n\n\
start_time = 3600 - 24*parseInt(searchpattern.start_day.value) + \
parseInt(searchpattern.start_hour.value);\n\
end_time = 3600 - 24*parseInt(searchpattern.end_day.value) + \
parseInt(searchpattern.end_hour.value);\n\
if (start_time > end_time) {\n\
alert(\'"

#define HTML_SEARCH_16	\
"\');\nreturn false;\n} else {\n return true;\n}\" value=\"    "

/* fill button label here */

#define HTML_SEARCH_17	\
"    \"/></TD></TR></TBODY></TABLE></FORM>\n\
</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy; "

#define HTML_SEARCH_18	"</CENTER></BODY></HTML>"

#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"


#define HTML_TBITEM_ODD     "<TR class=ItemOdd><TD>&nbsp; "
#define HTML_TBITEM_EVEN    "<TR class=ItemEven><TD>&nbsp; "
#define HTML_TBITEM_2       "</TD></TR>\n"

#define HTML_NORESULT_LABEL	"<TR class=ItemRow><TD colSpan=5>%s</TD></TR>"

static void admin_ui_error_html(const char *error_string);

static void admin_ui_search_html(const char *session);

static void admin_ui_result_html(const char *session, const char *ip,
	const char *from, const char *to, time_t start_point, time_t end_point);

static BOOL admin_ui_get_self(char *url_buff, int length);

static void admin_ui_unencode(char *src, char *last, char *dest);

static int g_valid_days;
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void admin_ui_init(int valid_days, const char *url_link,
	const char *resource_path)
{
	g_valid_days = valid_days;
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int admin_ui_run()
{
	struct tm *ptm;
	time_t current_time;
	time_t start, end;
	int start_day, end_day;
	int start_hour, end_hour;
	int scan_num, type, len;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char *pip, *pfrom, *pto;
	char *query, *request;
	char session[256];
	char post_buff[1024];
	char search_buff[1024];
	char tmp_ip[16], tmp_to[256];
	char tmp_from[256], tmp_time[8];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		admin_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[ui_main]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[admin_ui]: fail to get REQUEST_METHOD environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[admin_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[admin_ui]: post buffer too long");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		admin_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "session=", len);
		if (NULL == ptr1) {
			system_log_info("[admin_ui]: query string of POST "
				"format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
			return 0;
		}
		ptr1 += 8;
		ptr2 = search_string(search_buff, "&ip=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
		ptr1 = ptr2 + 4;
		ptr2 = search_string(search_buff, "&from=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 15) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 == ptr1) {
			pip = NULL;
		} else {
			memcpy(tmp_ip, ptr1, ptr2 - ptr1);
			tmp_ip[ptr2 - ptr1] = '\0';
			ltrim_string(tmp_ip);
			rtrim_string(tmp_ip);
			pip = tmp_ip;
		}
		ptr1 = ptr2 + 6;
		ptr2 = search_string(search_buff, "&to=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 == ptr1) {
			pfrom = NULL;
		} else {
			memcpy(tmp_from, ptr1, ptr2 - ptr1);
			tmp_from[ptr2 - ptr1] = '\0';
			ltrim_string(tmp_from);
			rtrim_string(tmp_from);
			pfrom = tmp_from;
		}
		ptr1 = ptr2 + 4;
		ptr2 = search_string(search_buff, "&start_day=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 == ptr1) {
			pto = NULL;
		} else {
			memcpy(tmp_to, ptr1, ptr2 - ptr1);
			tmp_to[ptr2 - ptr1] = '\0';
			ltrim_string(tmp_to);
			rtrim_string(tmp_to);
			pto = tmp_to;
		}
		ptr1 = ptr2 + 11;
		ptr2 = search_string(search_buff, "&start_hour=", len);
		if (ptr2 < ptr1 || ptr2 - ptr1 > 3) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_time, ptr1, ptr2 - ptr1);
		tmp_time[ptr2 - ptr1] = '\0';
		start_day = atoi(tmp_time);
		ptr1 = ptr2 + 12;
		ptr2 = search_string(search_buff, "&end_day=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 3) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_time, ptr1, ptr2 - ptr1);
		tmp_time[ptr2 - ptr1] = '\0';
		start_hour = atoi(tmp_time);
		ptr1 = ptr2 + 9;
		ptr2 = search_string(search_buff, "&end_hour=", len);
		if (ptr2 < ptr1 || ptr2 - ptr1 > 3) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_time, ptr1, ptr2 - ptr1);
		tmp_time[ptr2 - ptr1] = '\0';
		end_day = atoi(tmp_time);
		ptr2 += 10;
		if (search_buff + len - ptr2 > 3) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(tmp_time, ptr2, search_buff + len - ptr2);
		tmp_time[search_buff + len - ptr2] = '\0';
		end_hour = atoi(tmp_time);
		
		switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_IGNORE)) {
		case ACL_SESSION_OK:
			break;
		case ACL_SESSION_TIMEOUT:
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT", language));
			return 0;
		default:
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION", language));
			return 0;
		}
		
		time(&current_time);
		ptm = localtime(&current_time);
		current_time -= ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec;
		start = current_time - 24*60*60*start_day + 60*60*start_hour;
		end = current_time - 24*60*60*end_day  + 60*60*end_hour;
		admin_ui_result_html(session, pip, pfrom, pto, start, end);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[admin_ui]: fail to get QUERY_STRING "
					"environment!");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 256) {
				system_log_info("[admin_ui]: query string too long!");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 = search_string(query, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[admin_ui]: query string of GET format error");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 += 8;
			if (query + len - ptr1 > 255) {
				system_log_info("[admin_ui]: query string of GET format error");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
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
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			default:
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			admin_ui_search_html(session);
			return 0;
		}
	} else {
		system_log_info("[admin_ui]: unrecognized REQUEST_METHOD \"%s\"!",
					request);
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int admin_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void admin_ui_free()
{
	/* do nothing */
}

static BOOL admin_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[admin_ui]: fail to get "
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

static void admin_ui_error_html(const char *error_string)
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

static void admin_ui_search_html(const char *session)
{
	int i, len;
	char *language;
	char time_buff[64];
	char url_buff[1024];
	time_t current_time;
	
	if (FALSE == admin_ui_get_self(url_buff, 1024)) {
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
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
	printf(session);
	printf(HTML_SEARCH_7);
	printf(lang_resource_get(g_lang_resource,"IP_ADDRESS", language));
	printf(HTML_SEARCH_8);
	printf(lang_resource_get(g_lang_resource,"FROM_ADDRESS", language));
	printf(HTML_SEARCH_9);
	printf(lang_resource_get(g_lang_resource,"TO_ADDRESS", language));
	printf(HTML_SEARCH_10);
	printf(lang_resource_get(g_lang_resource,"START_TIME", language));
	printf(HTML_SEARCH_11);
	time(&current_time);
	strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT", language),
		localtime(&current_time));
	printf("%s0%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED, time_buff,
		HTML_OPTION_3);
	for (i=1; i<g_valid_days; i++) {
		current_time -= 24*60*60;
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
	}
	printf(HTML_SEARCH_12);
	printf(lang_resource_get(g_lang_resource,"END_TIME", language));
	printf(HTML_SEARCH_13);
	time(&current_time);
	strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT", language),
		localtime(&current_time));
	printf("%s0%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED, time_buff,
		HTML_OPTION_3);
	for (i=1; i<g_valid_days; i++) {
		current_time -= 24*60*60;
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
	}
	printf(HTML_SEARCH_14);
	printf(lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language));
	printf(HTML_SEARCH_15);
	printf(lang_resource_get(g_lang_resource,"MSGERR_STARTTIME", language));
	printf(HTML_SEARCH_16);
	printf(lang_resource_get(g_lang_resource,"SEARCH_LABEL", language));
	printf(HTML_SEARCH_17);
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	printf(HTML_SEARCH_18);
}

static void admin_ui_result_html(const char *session, const char *ip,
	const char *from, const char *to, time_t start_point, time_t end_point)
{
	int i;
	char *language;
	char temp_buff[64];
	char url_buff[1024];
	struct in_addr addr;
	MATCH_COLLECT *pcollection;

	pcollection = match_engine_collect_init();
	if (FALSE == match_engine_match(start_point, end_point, (char*)ip,
		(char*)from, (char*)to, pcollection)) {
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
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
	admin_ui_get_self(url_buff, 1024);
	printf(url_buff);
	printf("?session=%s", session);
	printf(HTML_RESULT_6);
	printf(lang_resource_get(g_lang_resource,"SEARCH_AGAIN_LABEL", language));
	printf(HTML_RESULT_7);
	if (NULL != ip) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"IP_ADDRESS", language), ip);
	}
	if (NULL != from) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"FROM_ADDRESS", language), from);
	}
	if (NULL != to) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"TO_ADDRESS", language), to);
	}
	printf("%s: ", lang_resource_get(g_lang_resource,"START_TIME", language));
	strftime(temp_buff, 64, lang_resource_get(g_lang_resource,"RESULT_TIME_FORMAT", language),
		localtime(&start_point));
	printf("%s; ", temp_buff);

	printf("%s: ", lang_resource_get(g_lang_resource,"END_TIME", language));
	strftime(temp_buff, 64, lang_resource_get(g_lang_resource,"RESULT_TIME_FORMAT", language),
		localtime(&end_point));
	printf("%s; ", temp_buff);
	
	printf(HTML_RESULT_8);
	printf(lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	printf(HTML_RESULT_9);
	i = 0;
	for (match_engine_collect_begin(pcollection);
		!match_engine_collect_done(pcollection);
		match_engine_collect_forward(pcollection)) {
		i ++;
		if (0 == i%2) {
			printf(HTML_TBITEM_EVEN);
		} else {
			printf(HTML_TBITEM_ODD);
		}
		printf(match_engine_collect_get_value(pcollection));
		printf(HTML_TBITEM_2);
	}
	if (0 == match_engine_collect_total(pcollection)) {
		printf(HTML_NORESULT_LABEL, lang_resource_get(g_lang_resource,
			"NORESULT_LABEL", language));
	}
	match_engine_collect_free(pcollection);
	printf(HTML_RESULT_10);

}

static void admin_ui_unencode(char *src, char *last, char *dest)
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

