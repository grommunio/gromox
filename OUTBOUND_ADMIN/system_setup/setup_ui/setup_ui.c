#include "setup_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "gateway_control.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
width=195 align=right border=0></A></TD></TR></TBODY></TABLE>\n\
<iframe src=\"\" style=\"display:none\" width=\"0\" height=\"0\" name=\"dummy_window\"></iframe>\n\
<BR><BR><TABLE width=\"75%\"><TBODY>\n"

#define HTML_MAIN_6	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=DefaultDM onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text size=36 value=\"%s\" %s name=default_domain />&nbsp;\n\
<INPUT type=submit value=\"  %s  \" %s onclick=\
\"with (DefaultDM.default_domain) {\n\
	dotpos=value.lastIndexOf('.');\n\
	if (dotpos<1) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
dummy_window.location.href='%s?session=%s&action=default-domain&value=' +\
DefaultDM.default_domain.value;\n\
return false;\"\
/></TD></TR>\n\
</TBODY></TABLE></FORM></TD></TR>\n"


#define HTML_MAIN_7	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=AdminMB onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text size=36 value=\"%s\" %s name=admin_mailbox />&nbsp;\n\
<INPUT type=submit value=\"  %s  \" %s onclick=\
\"with (AdminMB.admin_mailbox) {\n\
	apos=value.indexOf('@');\n\
	dotpos=value.lastIndexOf('.');\n\
	if (apos<1||dotpos-apos<2) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
dummy_window.location.href='%s?session=%s&action=admin-mailbox&value=' +\
AdminMB.admin_mailbox.value;\n\
return false;\"\
/></TD></TR>\n\
</TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_8	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=HugeDM onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<SELECT name=is_huge %s >"

#define HTML_MAIN_9	\
"</SELECT>&nbsp;<INPUT type=submit \n\
value=\"  %s  \" %s onclick=\
\"dummy_window.location.href='%s?session=%s&action=huge-domain&value=' +\
HugeDM.is_huge.value;\n\
return false;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_10	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=SessionNM onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=10 value=\"%s\" %s\n\
name=session_num />&nbsp;<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(SessionNM.session_num.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=session-num&value=' +\
SessionNM.session_num.value;\n\
return false;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_11	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=RcptNM onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=10 value=\"%s\" %s\n\
name=rcpt_num />&nbsp;<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(RcptNM.rcpt_num.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=rcpt-num&value=' +\
RcptNM.rcpt_num.value;\n\
return false;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_12	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=MaxLNG onSubmit=\"return false;\">\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=4 value=\"%s\" %s name=max_length />\
<SELECT name=unit %s>"

#define HTML_MAIN_13	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(MaxLNG.max_length.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=max-length&value=' +\
MaxLNG.max_length.value + '&unit=' + MaxLNG.unit.value;\n\
return false;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_14	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=TimeOUT onSubmit=\"return false;\">\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=4 value=\"%s\" %s name=time_out />\
<SELECT name=unit %s>\n"

#define HTML_MAIN_15	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(TimeOUT.time_out.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=time-out&value=' +\
TimeOUT.time_out.value + '&unit=' + TimeOUT.unit.value;\n\
return false;\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"

#define HTML_MAIN_16	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=ScanSZ onSubmit=\"return false;\">\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=4 value=\"%s\" %s name=scanning_size />\
<SELECT name=unit %s>"

#define HTML_MAIN_17	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(ScanSZ.scanning_size.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=scanning-size&value=' +\
ScanSZ.scanning_size.value + '&unit=' + ScanSZ.unit.value;\n\
return false;\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"


#define HTML_MAIN_18	\
"<TR class=ItemOdd><TD>%s</TD>\n\
</TR><TR class=ItemEven><TD><FORM name=ConnFRQ onSubmit=\"return false;\">\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=4 value=\"%s\" %s name=times_val /> /\
<INPUT type=text size=4 value=\"%s\" %s name=interval_val />\
<SELECT name=unit %s>"

#define HTML_MAIN_19	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(ConnFRQ.times_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
num=parseInt(ConnFRQ.interval_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=conn-freq&time=' +\
ConnFRQ.times_val.value + '&interval=' + ConnFRQ.interval_val.value + \
'&unit=' + ConnFRQ.unit.value;\n\
return false;\"\n\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"


#define HTML_MAIN_20	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=OutmailFRQ onSubmit=\"return false;\">\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=4 value=\"%s\" name=times_val /> /\
<INPUT type=text size=4 value=\"%s\" name=interval_val /><SELECT name=unit>"

#define HTML_MAIN_21	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" onclick=\
\"var num=parseInt(OutmailFRQ.times_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
num=parseInt(OutmailFRQ.interval_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=outmail-freq&time=' +\
OutmailFRQ.times_val.value + '&interval=' + OutmailFRQ.interval_val.value + \
'&unit=' + OutmailFRQ.unit.value;\n\
return false;\"\n\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"

#define HTML_MAIN_22	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=LimitationFRQ onSubmit=\"return false;\">\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=4 value=\"%s\" name=times_val /> /\
<INPUT type=text size=4 value=\"%s\" name=interval_val /><SELECT name=unit>"

#define HTML_MAIN_23	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" onclick=\
\"var num=parseInt(LimitationFRQ.times_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
num=parseInt(LimitationFRQ.interval_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=limitation-freq&time=' +\
LimitationFRQ.times_val.value + '&interval=' + \
LimitationFRQ.interval_val.value + '&unit=' + LimitationFRQ.unit.value;\n\
return false;\"\n\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"

#define HTML_MAIN_24	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=RetryFRQ onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
%s: <INPUT type=text class=RightInput size=4 value=\"%s\" %s name=times_val />\
 &nbsp;&nbsp;&nbsp;&nbsp;%s: <INPUT type=text class=RightInput size=4 \
value=\"%s\" %s name=interval_val /><SELECT name=unit %s>"

#define HTML_MAIN_25	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(RetryFRQ.times_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
num=parseInt(RetryFRQ.interval_val.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\
dummy_window.location.href='%s?session=%s&action=retrying-freq&time=' +\
RetryFRQ.times_val.value + '&interval=' + RetryFRQ.interval_val.value +\
'&unit=' + RetryFRQ.unit.value;\n\
return false;\"\n\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"

#define HTML_MAIN_26	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=DeliveryITVL onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
1:&nbsp;<INPUT type=text class=RightInput size=4 value=\"%s\" \n\
name=first_interval /><SELECT name=unit1>"

#define HTML_MAIN_27	\
"</SELECT>&nbsp;2:&nbsp;<INPUT type=text class=RightInput \n\
size=4 value=\"%s\" name=second_interval /><SELECT name=unit2>"

#define HTML_MAIN_28	\
"</SELECT>&nbsp;3:&nbsp;<INPUT type=text class=RightInput \n\
size=4 value=\"%s\" name=third_interval /><SELECT name=unit3>"

#define HTML_MAIN_29	\
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" onclick=\
\"var first_itvl=parseInt(DeliveryITVL.first_interval.value);\n\
if(isNaN(first_itvl) || first_itvl <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var second_itvl=parseInt(DeliveryITVL.second_interval.value);\n\
if(isNaN(second_itvl) || second_itvl <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var third_itvl=parseInt(DeliveryITVL.third_interval.value);\n\
if(isNaN(third_itvl) || third_itvl <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if(DeliveryITVL.unit1.value == '3') {\n\
	first_itvl = first_itvl*60;\n\
}\n\
if(DeliveryITVL.unit2.value == '3') {\n\
	second_itvl = second_itvl*60;\n\
}\n\
if(DeliveryITVL.unit3.value == '3') {\n\
	third_itvl = third_itvl*60;\n\
}\n\
if(first_itvl < 2) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if(second_itvl < first_itvl*2) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (third_itvl < second_itvl*2) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=delivery-interval&\
first-interval=' + DeliveryITVL.first_interval.value + '&unit1=' + \
DeliveryITVL.unit1.value + '&second-interval=' + \
DeliveryITVL.second_interval.value + '&unit2=' + DeliveryITVL.unit2.value +\
'&third-interval=' + DeliveryITVL.third_interval.value + '&unit3=' + \
DeliveryITVL.unit3.value;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"

#define HTML_MAIN_30	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=RetryTMS onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=10 value=\"%s\" name=retry_times />\
&nbsp;<INPUT type=submit value=\"  %s  \" onclick=\
\"var num=parseInt(RetryTMS.retry_times.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=retry-times&value=' +\
RetryTMS.retry_times.value;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"


#define HTML_MAIN_31    \
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=RelayAGNT onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<SELECT name=relay_switch>"


#define HTML_MAIN_32    \
"</SELECT>&nbsp;<INPUT type=submit value=\"  %s  \" onclick=\
\"dummy_window.location.href='%s?session=%s&action=relay-switch&value=' + \
RelayAGNT.relay_switch.value;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>"


#define HTML_MAIN_33	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=LogDY onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text class=RightInput size=10 value=\"%s\" %s name=log_days />&nbsp;\
<INPUT type=submit value=\"  %s  \" %s onclick=\
\"var num=parseInt(LogDY.log_days.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
dummy_window.location.href='%s?session=%s&action=log-days&value=' +\
LogDY.log_days.value;\n\"\
/></TD></TR></TBODY></TABLE>\
</FORM></TD></TR></TBODY></TABLE><BR></CENTER></TD></TR></TBODY>\n\
</TABLE></TD></TR></TBODY></TABLE></TD></TR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_ACTIVE_OK  \
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>message is actived</TITLE>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\"\n\
</HEAD><BODY onload=\"alert('%s');\"> messgae is actived! </BODY></HTML>"


#define OPTION_SELECT	"<OPTION value=%d selected>%s</OPTION>"
#define OPTION_NORMAL	"<OPTION value=%d>%s</OPTION>"
#define PARAM_DISABLED	"disabled=true"
#define PARAM_ENABLED	""


#define UNIT_BYTE		1
#define UNIT_KILO		2
#define UNIT_MEGA		3
#define UNIT_SECOND		1
#define UNIT_MINUTE		2
#define UNIT_HOUR		3

#define INDEX_DEFAULT_DOMAIN    1
#define INDEX_ADMIN_MAILBOX     2
#define INDEX_HUGE_DOMAIN       3
#define INDEX_SESSION_NUM       4
#define INDEX_RCPT_NUM          5
#define INDEX_MAIL_LENGTH       6
#define INDEX_TIME_OUT          7
#define INDEX_SCANNING_SIZE     8
#define INDEX_CONN_FREQ         9
#define INDEX_DISPARCH_FREQ     10
#define INDEX_LOG_DAYS          11
#define INDEX_BACKUP_DAYS       12

static const char* g_array_size[4] = {NULL, "B", "K", "M"};

static const char* g_array_time[4];

static void setup_ui_error_html(const char *error_string);

static void setup_ui_error_alert(const char *error_string);

static void setup_ui_main_html(const char *session);

static void setup_ui_set_domain(const char *domain);

static void setup_ui_set_mailbox(const char *mailbox);

static void setup_ui_set_hugedomain(BOOL is_huge);

static void setup_ui_set_rcpt(int num);

static void setup_ui_set_number(int num);

static void setup_ui_set_retry_times(int times);

static void setup_ui_set_log_days(int days);

static void setup_ui_set_relay_switch(BOOL b_switch);

static void setup_ui_set_length(int num, int unit);

static void setup_ui_set_timeout(int num, int unit);

static void setup_ui_set_scanning(int num, int unit);

static void setup_ui_set_conn_freq(int times, int num, int unit);

static void setup_ui_set_outmail_freq(int times, int num, int unit);

static void setup_ui_set_limitation_freq(int times, int num, int unit);

static void setup_ui_set_retrying_freq(int times, int num, int unit);

static void setup_ui_set_delivery_interval(int first_num, int first_unit,
	int second_num, int second_unit, int third_num, int third_unit);

static BOOL setup_ui_get_self(char *url_buff, int length);

static void setup_ui_unencode(char *src, char *last, char *dest);

static char g_logo_link[1024];
static char g_token_path[256];
static CONFIG_FILE *g_cfg_file;
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void setup_ui_init(CONFIG_FILE *pconfig, const char *token_path,
	const char *url_link, const char *resource_path)
{
	g_cfg_file = pconfig;
	strcpy(g_token_path, token_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int setup_ui_run()
{
	BOOL b_option;
	int num1, num2, num3;
	int unit1, unit2, unit3;
	int size1, size2, size3;
	int len, num, unit;
	int times, interval;
	unsigned int size;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char action[64];
	char value[256];
	char session[256];
	char search_buff[1024];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		setup_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[setup_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[setup_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[setup_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[setup_ui]: fail to get QUERY_STRING "
				"environment!");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 1024) {
				system_log_info("[setup_ui]: query string too long!");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = search_string(query, "session=", len);
			if (NULL == ptr1) {
				goto GET_ERROR;
			}
			ptr1 += 8;
			ptr2 = search_string(query, "&action=", len);
			if (NULL == ptr2) {
				if (query + len - ptr1 > 255) {
					goto GET_ERROR;
				}
				memcpy(session, ptr1, query + len - ptr1);
				session[query + len - ptr1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_SETUP)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				setup_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 && ptr2 - ptr1 > 255) {
				goto GET_ERROR;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_SETUP)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				setup_ui_error_alert(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				setup_ui_error_alert(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			default:
				setup_ui_error_alert(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			ptr1 = ptr2 + 8;
			ptr2 = strchr(ptr1, '&');
			if (NULL == ptr2 || ptr2 - ptr1 >= 64) {
				goto GET_ERROR;
			}
			
			memcpy(action, ptr1, ptr2 - ptr1);
			action[ptr2 - ptr1] = '\0';
			if (0 == strcasecmp(action, "default-domain")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 > 255 || 0 == query + len - ptr1) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, query + len - ptr1);
				value[query + len - ptr1] = '\0';
				ltrim_string(value);
				rtrim_string(value);
				setup_ui_set_domain(value);
				return 0;
			} else if (0 == strcasecmp(action, "admin-mailbox")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 > 255 || 0 == query + len - ptr1) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, query + len - ptr1);
				value[query + len - ptr1] = '\0';
				ltrim_string(value);
				rtrim_string(value);
				setup_ui_set_mailbox(value);
				return 0;
			} else if (0 == strcasecmp(action, "huge-domain") ||
				0 == strcasecmp(action, "relay-switch")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 != 1) {
					goto GET_ERROR;
				}
				if ('0' == *ptr1) {
					b_option = FALSE;
				} else if ('1' == *ptr1) {
					b_option = TRUE;
				} else {
					goto GET_ERROR;
				}
				if (0 == strcasecmp(action, "huge-domain")) {
					setup_ui_set_hugedomain(TRUE);
				} else if (0 == strcasecmp(action, "relay-switch")) {
					setup_ui_set_relay_switch(b_option);
				}
				return 0;
			} else if (0 == strcasecmp(action, "session-num") ||
				0 == strcasecmp(action, "rcpt-num") ||
				0 == strcasecmp(action, "retry-times") ||
				0 == strcasecmp(action, "log-days")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, query + len - ptr1);
				value[query + len - ptr1] = '\0';
				num = atoi(value);
				if (num <= 0) {
					goto GET_ERROR;
				}
				if (0 == strcasecmp(action, "session-num")) {
					setup_ui_set_number(num);
				} else if (0 == strcasecmp(action, "rcpt-num")) {
					setup_ui_set_rcpt(num);
				} else if (0 == strcasecmp(action, "retry-times")) {
					setup_ui_set_retry_times(num);
				} else if (0 == strcasecmp(action, "log-days")) {
					setup_ui_set_log_days(num);
				}
				return 0;
			} else if (0 == strcasecmp(action, "max-length")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				ptr2 = search_string(query, "&unit=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				num = atoi(value);
				if (num <= 0) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 6;
				if (1 != query + len - ptr1) {
					goto GET_ERROR;
				}
				switch (*ptr1) {
				case '2':
					unit = UNIT_KILO;
					size = num * 1024;
					break;
				case '3':
					unit = UNIT_MEGA;
					size = num * 1024 * 1024;
					break;
				default:
					goto GET_ERROR;
				}
				if (size > 0x7FFFFFFF) {
					goto GET_ERROR;
				}
				setup_ui_set_length(num, unit);
				return 0;	
			} else if (0 == strcasecmp(action, "time-out")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				ptr2 = search_string(query, "&unit=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				num = atoi(value);
				if (num <= 0) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 6;
				if (1 != query + len - ptr1) {
					goto GET_ERROR;
				}
				switch (*ptr1) {
				case '1':
					unit = UNIT_SECOND;
					interval = num;
					break;
				case '2':
					unit = UNIT_MINUTE;
					interval = num * 60;
					break;
				default:
					goto GET_ERROR;
				}
				if (interval > 3600) {
					goto GET_ERROR;
				}
				setup_ui_set_timeout(num, unit);
				return 0;
			} else if (0 == strcasecmp(action, "scanning-size")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;	
				}
				ptr1 = ptr2 + 7;
				ptr2 = search_string(query, "&unit=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				num = atoi(value);
				if (num <= 0) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 6;
				if (1 != query + len - ptr1) {
					goto GET_ERROR;
				}
				switch (*ptr1) {
				case '1':
					unit = UNIT_BYTE;
					size = num;
					break;
				case '2':
					unit = UNIT_KILO;
					size = num * 1024;
					break;
				case '3':
					unit = UNIT_MEGA;
					size = num * 1024 * 1024;
					break;
				default:
					goto GET_ERROR;
				}
				if (size > 0x7FFFFFFF) {
					goto GET_ERROR;
				}
				setup_ui_set_scanning(num, unit);
				return 0;
			} else if (0 == strcasecmp(action, "conn-freq") ||
				0 == strcasecmp(action, "outmail-freq") ||
				0 == strcasecmp(action, "limitation-freq") ||
				0 == strcasecmp(action, "retrying-freq")) {
				if (0 != strncasecmp(ptr2, "&time=", 6)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 6;
				ptr2 = search_string(query, "&interval=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				times = atoi(value);
				if (times <= 0) {
					goto GET_ERROR;
				}
				
				ptr1 = ptr2 + 10;
				ptr2 = search_string(query, "&unit=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				num = atoi(value);
				if (num <= 0) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 6;
				if (1 != query + len - ptr1) {
					goto GET_ERROR;
				}
				switch (*ptr1) {
				case '1':
					unit = UNIT_SECOND;
					interval = num;
					break;
				case '2':
					unit = UNIT_MINUTE;
					interval = num * 60;
					break;
				case '3':
					unit = UNIT_HOUR;
					interval = num * 3600;
					break;
				default:
					goto GET_ERROR;
				}
				
				if (0 == strcasecmp(action, "conn-freq")) {
					setup_ui_set_conn_freq(times, num, unit);
				} else if (0 == strcasecmp(action, "outmail-freq")) {
					setup_ui_set_outmail_freq(times, num, unit);
				} else if (0 == strcasecmp(action, "limitation-freq")) {
					setup_ui_set_limitation_freq(times, num, unit);
				} else if (0 == strcasecmp(action, "retrying-freq")) {
					setup_ui_set_retrying_freq(times, num, unit);
				}
				return 0;
			} else if (0 == strcasecmp(action, "delivery-interval")) {
				if (0 != strncasecmp(ptr2, "&first-interval=", 16)) {
					goto GET_ERROR;	
				}
				ptr1 = ptr2 + 16;
				ptr2 = search_string(query, "&unit1=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				num1 = atoi(value);
				if (num1 <= 0) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				ptr2 = search_string(query, "&second-interval=", len);
				if (NULL == ptr2 || 1 != ptr2 - ptr1) {
					goto GET_ERROR;
				}
				switch (*ptr1) {
				case '2':
					unit1 = UNIT_MINUTE;
					size1 = num1*60;
					break;
				case '3':
					unit1 = UNIT_HOUR;
					size1 = num1 * 3600;
					break;
				default:
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 17;
				ptr2 = search_string(query, "&unit2=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				num2 = atoi(value);
				if (num2 <= 0) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				ptr2 = search_string(query, "&third-interval=", len);
				if (NULL == ptr2 || 1 != ptr2 - ptr1) {
					goto GET_ERROR;
				}
				switch (*ptr1) {
				case '2':
					unit2 = UNIT_MINUTE;
					size2 = num2 * 60;
					break;
				case '3':
					unit2 = UNIT_HOUR;
					size2 = num2 * 3600;
					break;
				default:
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 16;
				ptr2 = search_string(query, "&unit3=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 16) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, ptr2 - ptr1);
				value[ptr2 - ptr1] = '\0';
				num3 = atoi(value);
				if (num3 <= 0) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 != 1) {
					goto GET_ERROR;
				}
				switch (*ptr1) {
				case '2':
					unit3 = UNIT_MINUTE;
					size3 = num3 * 60;
					break;
				case '3':
					unit3 = UNIT_HOUR;
					size3 = num3 * 3600;
					break;
				default:
					goto GET_ERROR;
				}
				if (size2 < 2*size1 || size3 < 2*size2 ) {
					goto GET_ERROR;
				}
				setup_ui_set_delivery_interval(num1, unit1,
					num2, unit2, num3, unit3);
				return 0;
			} else {
				goto GET_ERROR;
			}
		}
	} else {
		system_log_info("[setup_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
GET_ERROR:
	system_log_info("[setup_ui]: query string of GET format error");
	setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
	return 0;		
}

int setup_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void setup_ui_free()
{
	/* do nothing */
}

static BOOL setup_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *script;
	
	host = getenv("SERVER_NAME");
	script = getenv("SCRIPT_NAME");
	if (NULL == host || NULL == script) {
		system_log_info("[setup_ui]: fail to get SERVER_NAME or "
			"SCRIPT_NAME environment!");
		return FALSE;
	}
	snprintf(url_buff, length, "http://%s%s", host, script);
	return TRUE;
}

static void setup_ui_error_html(const char *error_string)
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

static void setup_ui_error_alert(const char *error_string)
{
	char *language;
	const char *charset;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset, error_string);
}

static void setup_ui_main_html(const char *session)
{
	BOOL b_sync;
	int i, option;
	char *language;
	char *str_value;
	char *str_times;
	char *str_intvl;
	char master_ip[16];
	char url_buff[1024];
	char str_submit[64];
	char dummy_string[32];
	char mask_string[20];
	
	if (FALSE == setup_ui_get_self(url_buff, 1024)) {
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
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
	printf(HTML_MAIN_5);

	strcpy(str_submit, lang_resource_get(g_lang_resource,"LABEL_SUBMIT", language));
	memset(mask_string, '0', sizeof(mask_string));
	str_value = config_file_get_value(g_cfg_file, "SYNC_MASK_STRING");
	if (NULL != str_value) {
		strcpy(mask_string, str_value);
	}
	str_value = config_file_get_value(g_cfg_file, "SYNC_SWITCH");
	if (NULL == str_value) {
		b_sync = FALSE;
	} else {
		if (0 == strcasecmp(str_value, "TRUE")) {
			b_sync = TRUE;
		} else {
			b_sync = FALSE;
		}
	}
	str_value = config_file_get_value(g_cfg_file, "MASTER_ADDRESS");
	if (NULL == str_value) {
		b_sync = FALSE;
	} else if (NULL == extract_ip(str_value, master_ip)) {
		b_sync = FALSE;
	}
	g_array_time[0] = NULL;
	g_array_time[1] = lang_resource_get(g_lang_resource,"UNIT_SECOND", language);
	g_array_time[2] = lang_resource_get(g_lang_resource,"UNIT_MINUTE", language);
	g_array_time[3] = lang_resource_get(g_lang_resource,"UNIT_HOUR", language);
	
	if (TRUE == b_sync) {
		printf("<I>%s</I>",
			lang_resource_get(g_lang_resource,"TIP_SYNCHRONIZATION", language));
	}
	str_value = config_file_get_value(g_cfg_file, "DEFAULT_DOMAIN");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_DEFAULT_DOMAIN]) {
		printf(HTML_MAIN_6, lang_resource_get(g_lang_resource,"TIP_DEFAULT_DOMAIN", language),
			lang_resource_get(g_lang_resource,"MAIN_DEFAULT_DOMAIN", language),
			str_value, PARAM_DISABLED, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_DOMAINFORMATERR", language),
			url_buff, session);
	} else {
		printf(HTML_MAIN_6, lang_resource_get(g_lang_resource,"TIP_DEFAULT_DOMAIN", language),
			lang_resource_get(g_lang_resource,"MAIN_DEFAULT_DOMAIN", language),
			str_value, PARAM_ENABLED, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_DOMAINFORMATERR", language),
			url_buff, session);
	}

	str_value = config_file_get_value(g_cfg_file, "ADMIN_MAILBOX");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_ADMIN_MAILBOX]) {
		printf(HTML_MAIN_7, lang_resource_get(g_lang_resource,"TIP_ADMIN_MAILBOX", language),
			lang_resource_get(g_lang_resource,"MAIN_ADMIN_MAILBOX", language),
			str_value, PARAM_DISABLED, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_MAILBOXFORMATERR", language),
			url_buff, session);
	} else {
		printf(HTML_MAIN_7, lang_resource_get(g_lang_resource,"TIP_ADMIN_MAILBOX", language),
			lang_resource_get(g_lang_resource,"MAIN_ADMIN_MAILBOX", language),
			str_value, PARAM_ENABLED, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_MAILBOXFORMATERR", language),
			url_buff, session);
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_HUGE_DOMAIN]) {
		printf(HTML_MAIN_8, lang_resource_get(g_lang_resource,"TIP_HUGE_DOMAIN", language),
			lang_resource_get(g_lang_resource,"MAIN_HUGE_DOMAIN", language), PARAM_DISABLED);
	} else {
		printf(HTML_MAIN_8, lang_resource_get(g_lang_resource,"TIP_HUGE_DOMAIN", language),
			lang_resource_get(g_lang_resource,"MAIN_HUGE_DOMAIN", language), PARAM_ENABLED);
	}
	str_value = config_file_get_value(g_cfg_file, "HASH_HUGE");
	if (NULL == str_value) {
		str_value = "TRUE";
	}
	if (0 == strcasecmp(str_value, "TRUE")) {
		printf(OPTION_SELECT, 1, lang_resource_get(g_lang_resource,"OPTION_YES", language));
		printf(OPTION_NORMAL, 0, lang_resource_get(g_lang_resource,"OPTION_NO", language));
	} else {
		printf(OPTION_NORMAL, 1, lang_resource_get(g_lang_resource,"OPTION_YES", language));
		printf(OPTION_SELECT, 0, lang_resource_get(g_lang_resource,"OPTION_NO", language));
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_HUGE_DOMAIN]) {
		printf(HTML_MAIN_9, str_submit, PARAM_DISABLED, url_buff, session);
	} else {
		printf(HTML_MAIN_9, str_submit, PARAM_ENABLED, url_buff, session);
	}
	str_value = config_file_get_value(g_cfg_file, "SMTP_SESSION_MAIL_NUM");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_SESSION_NUM]) {
		printf(HTML_MAIN_10, lang_resource_get(g_lang_resource,"TIP_SESSION_NUM", language),
			lang_resource_get(g_lang_resource,"MAIN_SESSION_NUM", language),
			str_value, PARAM_DISABLED, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_SESSIONNUMERR", language),
			url_buff, session);
	} else {
		printf(HTML_MAIN_10, lang_resource_get(g_lang_resource,"TIP_SESSION_NUM", language),
			lang_resource_get(g_lang_resource,"MAIN_SESSION_NUM", language),
			str_value, PARAM_ENABLED, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_SESSIONNUMERR", language),
			url_buff, session);
	}
	str_value = config_file_get_value(g_cfg_file, "SMTP_MAX_RCPT_NUM");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_RCPT_NUM]) {
		printf(HTML_MAIN_11, lang_resource_get(g_lang_resource,"TIP_RCPT_NUM", language),
			lang_resource_get(g_lang_resource,"MAIN_RCPT_NUM", language),
			str_value, PARAM_DISABLED, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_RCPTNUMERROR", language),
			url_buff, session);
	} else {
		printf(HTML_MAIN_11, lang_resource_get(g_lang_resource,"TIP_RCPT_NUM", language),
			lang_resource_get(g_lang_resource,"MAIN_RCPT_NUM", language),
			str_value, PARAM_ENABLED, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_RCPTNUMERROR", language),
			url_buff, session);
	}
		
	str_value = config_file_get_value(g_cfg_file, "SMTP_MAIL_LEN_NUM");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_MAIL_LENGTH]) {	
		printf(HTML_MAIN_12, lang_resource_get(g_lang_resource,"TIP_MAIL_LENGTH", language),
			lang_resource_get(g_lang_resource,"MAIN_MAIL_LENGTH", language), str_value,
			PARAM_DISABLED, PARAM_DISABLED);
	} else {
		printf(HTML_MAIN_12, lang_resource_get(g_lang_resource,"TIP_MAIL_LENGTH", language),
			lang_resource_get(g_lang_resource,"MAIN_MAIL_LENGTH", language), str_value,
			PARAM_ENABLED, PARAM_ENABLED);
	}
	
	str_value = config_file_get_value(g_cfg_file, "SMTP_MAIL_LEN_UNIT");
	if (NULL == str_value) {
		option = UNIT_MEGA;
	} else {
		option = atoi(str_value);
		if (option > UNIT_MEGA || option < UNIT_KILO) {
			option = UNIT_MEGA;
		}
	}
	for (i=UNIT_KILO; i<=UNIT_MEGA; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_size[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_size[i]);
		}
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_MAIL_LENGTH]) {	
		printf(HTML_MAIN_13, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_MAXLENGTHERR", language),
			url_buff, session);
	} else {
		printf(HTML_MAIN_13, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_MAXLENGTHERR", language),
			url_buff, session);
	}

	str_value = config_file_get_value(g_cfg_file, "SMTP_TIMEOUT_NUM");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_TIME_OUT]) {
		printf(HTML_MAIN_14, lang_resource_get(g_lang_resource,"TIP_SMTP_TIMEOUT", language),
			lang_resource_get(g_lang_resource,"MAIN_SMTP_TIMEOUT", language), str_value,
			PARAM_DISABLED, PARAM_DISABLED);
	} else {
		printf(HTML_MAIN_14, lang_resource_get(g_lang_resource,"TIP_SMTP_TIMEOUT", language),
			lang_resource_get(g_lang_resource,"MAIN_SMTP_TIMEOUT", language), str_value,
			PARAM_ENABLED, PARAM_ENABLED);
	}

	str_value = config_file_get_value(g_cfg_file, "SMTP_TIMEOUT_UNIT");
	if (NULL == str_value) {
		option = UNIT_MINUTE;
	} else {
		option = atoi(str_value);
		if (option > UNIT_MINUTE || option < UNIT_SECOND) {
			option = UNIT_MINUTE;
		}
	}
	for (i=UNIT_SECOND; i<=UNIT_MINUTE; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_TIME_OUT]) {
		printf(HTML_MAIN_15, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_TIMEOUTERR", language), url_buff,
			session);
	} else {
		printf(HTML_MAIN_15, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_TIMEOUTERR", language), url_buff,
			session);
	}
	
	str_value = config_file_get_value(g_cfg_file, "VIRUS_SCANNING_NUM");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_SCANNING_SIZE]) {
		printf(HTML_MAIN_16, lang_resource_get(g_lang_resource,"TIP_VIRUS_SCANNING", language),
			lang_resource_get(g_lang_resource,"MAIN_VIRUS_SCANNING", language), str_value,
			PARAM_DISABLED, PARAM_DISABLED);
	} else {
		printf(HTML_MAIN_16, lang_resource_get(g_lang_resource,"TIP_VIRUS_SCANNING", language),
			lang_resource_get(g_lang_resource,"MAIN_VIRUS_SCANNING", language), str_value,
			PARAM_ENABLED, PARAM_ENABLED);
	}

	str_value = config_file_get_value(g_cfg_file, "VIRUS_SCANNING_UNIT");
	if (NULL == str_value) {
		option = UNIT_KILO;
	} else {
		option = atoi(str_value);
		if (option > UNIT_MEGA || option < UNIT_BYTE) {
			option = UNIT_KILO;
		}
	}
	for (i=UNIT_BYTE; i<=UNIT_MEGA; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_size[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_size[i]);
		}
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_SCANNING_SIZE]) {
		printf(HTML_MAIN_17, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_SCANSIZEERR", language), url_buff,
			session);
	} else {
		printf(HTML_MAIN_17, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_SCANSIZEERR", language), url_buff,
			session);
	}

	str_times = config_file_get_value(g_cfg_file, "CONNECTION_TIMES");
	if (NULL == str_times) {
		str_times = "N/A";
	}
	str_intvl = config_file_get_value(g_cfg_file, "CONNECTION_INTERVAL_NUM");
	if (NULL == str_intvl) {
		str_intvl = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_CONN_FREQ]) {
		printf(HTML_MAIN_18, 
			lang_resource_get(g_lang_resource,"TIP_CONNECTION_FREQUENCE", language),
			lang_resource_get(g_lang_resource,"MAIN_CONNECTION_FREQUENCE", language),
			str_times, PARAM_DISABLED, str_intvl, PARAM_DISABLED,
			PARAM_DISABLED);
	} else {
		printf(HTML_MAIN_18, 
			lang_resource_get(g_lang_resource,"TIP_CONNECTION_FREQUENCE", language),
			lang_resource_get(g_lang_resource,"MAIN_CONNECTION_FREQUENCE", language),
			str_times, PARAM_ENABLED, str_intvl, PARAM_ENABLED,
			PARAM_ENABLED);
	}

	str_value = config_file_get_value(g_cfg_file, "CONNECTION_INTERVAL_UNIT");
	if (NULL == str_value) {
		option = UNIT_SECOND;
	} else {
		option = atoi(str_value);
		if (option > UNIT_MINUTE || option < UNIT_SECOND) {
			option = UNIT_SECOND;
		}
	}
	for (i=UNIT_SECOND; i<=UNIT_MINUTE; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_CONN_FREQ]) {
		printf(HTML_MAIN_19, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_TIMESERR", language),
			lang_resource_get(g_lang_resource,"MSGERR_INTVLERR", language),
			url_buff, session);
	} else {
		printf(HTML_MAIN_19, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_TIMESERR", language),
			lang_resource_get(g_lang_resource,"MSGERR_INTVLERR", language),
			url_buff, session);
	}

	str_times = config_file_get_value(g_cfg_file, "OUTMAIL_TIMES");
	if (NULL == str_times) {
		str_times = "N/A";
	}
	str_intvl = config_file_get_value(g_cfg_file, "OUTMAIL_INTERVAL_NUM");
	if (NULL == str_intvl) {
		str_intvl = "N/A";
	}
	printf(HTML_MAIN_20,
		lang_resource_get(g_lang_resource,"TIP_OUTMAIL_FREQUENCE", language),
		lang_resource_get(g_lang_resource,"MAIN_OUTMAIL_FREQUENCE", language),
		str_times, str_intvl);

	str_value = config_file_get_value(g_cfg_file, "OUTMAIL_INTERVAL_UNIT");
	if (NULL == str_value) {
		option = UNIT_MINUTE;
	} else {
		option = atoi(str_value);
		if (option > UNIT_HOUR || option < UNIT_SECOND) {
			option = UNIT_MINUTE;
		}
	}
	for (i=UNIT_SECOND; i<=UNIT_HOUR; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	printf(HTML_MAIN_21, str_submit,
		lang_resource_get(g_lang_resource,"MSGERR_TIMESERR", language),
		lang_resource_get(g_lang_resource,"MSGERR_INTVLERR", language),
		url_buff, session);

	str_times = config_file_get_value(g_cfg_file, "LIMITATION_TIMES");
	if (NULL == str_times) {
		str_times = "N/A";
	}
	str_intvl = config_file_get_value(g_cfg_file, "LIMITATION_INTERVAL_NUM");
	if (NULL == str_intvl) {
		str_intvl = "N/A";
	}
	printf(HTML_MAIN_22,
		lang_resource_get(g_lang_resource,"TIP_LIMITATION_FREQUENCE", language),
		lang_resource_get(g_lang_resource,"MAIN_LIMITATION_FREQUENCE", language),
		str_times, str_intvl);

	str_value = config_file_get_value(g_cfg_file, "LIMITATION_INTERVAL_UNIT");
	if (NULL == str_value) {
		option = UNIT_MINUTE;
	} else {
		option = atoi(str_value);
		if (option > UNIT_HOUR || option < UNIT_SECOND) {
			option = UNIT_MINUTE;
		}
	}
	for (i=UNIT_SECOND; i<=UNIT_HOUR; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	printf(HTML_MAIN_23, str_submit,
		lang_resource_get(g_lang_resource,"MSGERR_TIMESERR", language),
		lang_resource_get(g_lang_resource,"MSGERR_INTVLERR", language),
		url_buff, session);

	str_times = config_file_get_value(g_cfg_file, "DISPATCH_RETRING_TIMES");
	if (NULL == str_times) {
		str_times = "N/A";
	}
	str_intvl = config_file_get_value(g_cfg_file,
					"DISPATCH_RETRING_INTERVAL_NUM");
	if (NULL == str_intvl) {
		str_intvl = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_DISPARCH_FREQ]) {
		printf(HTML_MAIN_24,
			lang_resource_get(g_lang_resource,"TIP_RETRYING_FREQUENCE", language),
			lang_resource_get(g_lang_resource,"MAIN_RETRYING_FREQUENCE", language),
			lang_resource_get(g_lang_resource,"MAIN_RETRYING_TIMES", language),
			str_times, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MAIN_RETRYING_INTERVAL", language),
			str_intvl, PARAM_DISABLED, PARAM_DISABLED);
	} else {
		printf(HTML_MAIN_24,
			lang_resource_get(g_lang_resource,"TIP_RETRYING_FREQUENCE", language),
			lang_resource_get(g_lang_resource,"MAIN_RETRYING_FREQUENCE", language),
			lang_resource_get(g_lang_resource,"MAIN_RETRYING_TIMES", language),
			str_times, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MAIN_RETRYING_INTERVAL", language),
			str_intvl, PARAM_ENABLED, PARAM_ENABLED);
	}

	str_value = config_file_get_value(g_cfg_file,
					"DISPATCH_RETRING_INTERVAL_UNIT");
	if (NULL == str_value) {
		option = UNIT_MINUTE;
	} else {
		option = atoi(str_value);
		if (option > UNIT_HOUR || option < UNIT_SECOND) {
			option = UNIT_MINUTE;
		}
	}
	for (i=UNIT_SECOND; i<=UNIT_HOUR; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	printf(HTML_MAIN_25, str_submit,
		lang_resource_get(g_lang_resource,"MSGERR_TIMESERR", language),
		lang_resource_get(g_lang_resource,"MSGERR_INTVLERR", language),
		url_buff, session);
	
	 
	str_intvl = config_file_get_value(g_cfg_file, "DELIVERY_FIRST_INTERVAL_NUM");
	if (NULL == str_intvl) {
		str_intvl = "N/A";
	}
	printf(HTML_MAIN_26,
		lang_resource_get(g_lang_resource,"TIP_DELIVERY_INTERVAL", language),
		lang_resource_get(g_lang_resource,"MAIN_DELIVERY_INTERVAL", language), str_intvl);
	str_value = config_file_get_value(g_cfg_file,
					"DELIVERY_FIRST_INTERVAL_UNIT");
	if (NULL == str_value) {
		option = UNIT_MINUTE;
	} else {
		option = atoi(str_value);
		if (option > UNIT_HOUR || option < UNIT_MINUTE) {
			option = UNIT_MINUTE;
		}
	}
	for (i=UNIT_MINUTE; i<UNIT_HOUR; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	str_intvl = config_file_get_value(g_cfg_file,
					"DELIVERY_SECOND_INTERVAL_NUM");
	if (NULL == str_intvl) {
		str_intvl = "N/A";
	}
	printf(HTML_MAIN_27, str_intvl);
	str_value = config_file_get_value(g_cfg_file,
					"DELIVERY_SECOND_INTERVAL_UNIT");
	if (NULL == str_value) {
		option = UNIT_HOUR;
	} else {
		option = atoi(str_value);
		if (option > UNIT_HOUR || option < UNIT_MINUTE) {
			option = UNIT_HOUR;
		}
	}
	for (i=UNIT_MINUTE; i<=UNIT_HOUR; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	str_intvl = config_file_get_value(g_cfg_file,
					"DELIVERY_THIRD_INTERVAL_NUM");
	if (NULL == str_intvl) {
		str_intvl = "N/A";
	}
	printf(HTML_MAIN_28, str_intvl);
	str_value = config_file_get_value(g_cfg_file,
					"DELIVERY_THIRD_INTERVAL_UNIT");
	if (NULL == str_value) {
		option = UNIT_HOUR;
	} else {
		option = atoi(str_value);
		if (option > UNIT_HOUR || option < UNIT_MINUTE) {
			option = UNIT_HOUR;
		}
	}
	for (i=UNIT_MINUTE; i<=UNIT_HOUR; i++) {
		if (option == i) {
			printf(OPTION_SELECT, i, g_array_time[i]);
		} else {
			printf(OPTION_NORMAL, i, g_array_time[i]);
		}
	}
	
	printf(HTML_MAIN_29, str_submit,
		lang_resource_get(g_lang_resource,"MSGERR_FIRST_INTERVAL", language),
		lang_resource_get(g_lang_resource,"MSGERR_SECOND_INTERVAL", language),
		lang_resource_get(g_lang_resource,"MSGERR_THIRD_INTERVAL", language),
		lang_resource_get(g_lang_resource,"MSGERR_FIRST_INTERVAL", language),
		lang_resource_get(g_lang_resource,"MSGERR_SECOND_INTERVAL", language),
		lang_resource_get(g_lang_resource,"MSGERR_THIRD_INTERVAL", language),
		url_buff, session);

	str_value = config_file_get_value(g_cfg_file, "DELIVERY_RETRYING_TIMES");
	if (NULL == str_value) {
		str_value = "N/A";
	}		
	printf(HTML_MAIN_30, lang_resource_get(g_lang_resource,"TIP_DELIVERY_RETRYING_TIMES",
		language), lang_resource_get(g_lang_resource,"MAIN_DELIVERY_RETRYING_TIMES",
		language), str_value, str_submit,
		lang_resource_get(g_lang_resource,"MSGERR_RETRYTIMESERR", language),
		url_buff, session);


	printf(HTML_MAIN_31, lang_resource_get(g_lang_resource,"TIP_OVERSEA_RELAY", language),
		lang_resource_get(g_lang_resource,"MAIN_OVERSEA_RELAY", language));

	str_value = config_file_get_value(g_cfg_file, "OVERSEA_RELAY_SWITCH");
	if (NULL == str_value) {
		str_value = "FALSE";
	}
	if (0 == strcasecmp(str_value, "FALSE")) {
		printf(OPTION_SELECT, 0, lang_resource_get(g_lang_resource,"OPTION_NO", language));
		printf(OPTION_NORMAL, 1, lang_resource_get(g_lang_resource,"OPTION_YES", language));
	} else {
		printf(OPTION_NORMAL, 0, lang_resource_get(g_lang_resource,"OPTION_NO", language));
		printf(OPTION_SELECT, 1, lang_resource_get(g_lang_resource,"OPTION_YES", language));
	}

	printf(HTML_MAIN_32, str_submit, url_buff, session);
	
	str_value = config_file_get_value(g_cfg_file, "LOG_VALID_DAYS");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	if (TRUE == b_sync && '1' == mask_string[INDEX_LOG_DAYS]) {
		printf(HTML_MAIN_33, lang_resource_get(g_lang_resource,"TIP_LOG_VALID_DAYS", language),
			lang_resource_get(g_lang_resource,"MAIN_LOG_VALID_DAYS", language),
			str_value, PARAM_DISABLED, str_submit, PARAM_DISABLED,
			lang_resource_get(g_lang_resource,"MSGERR_LOGDAYSERR", language), url_buff,
			session);
	} else {
		printf(HTML_MAIN_33, lang_resource_get(g_lang_resource,"TIP_LOG_VALID_DAYS", language),
			lang_resource_get(g_lang_resource,"MAIN_LOG_VALID_DAYS", language),
			str_value, PARAM_ENABLED, str_submit, PARAM_ENABLED,
			lang_resource_get(g_lang_resource,"MSGERR_LOGDAYSERR", language), url_buff,
			session);
	}
	
}

static void setup_ui_unencode(char *src, char *last, char *dest)
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

static void setup_ui_set_domain(const char *domain)
{
	char *language;
	const char *charset;
	char command_string[1024];

	sprintf(command_string, "system set default-domain %s", domain);
	gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
	config_file_set_value(g_cfg_file, "DEFAULT_DOMAIN", (char*)domain);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);	
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_mailbox(const char *mailbox)
{
	char *language;
	const char *charset;
	char command_string[1024];

	sprintf(command_string, "system set admin-mailbox %s", mailbox);
	gateway_control_notify(command_string, NOTIFY_DELIVERY);
	config_file_set_value(g_cfg_file, "ADMIN_MAILBOX", (char*)mailbox);
	config_file_save(g_cfg_file);
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_hugedomain(BOOL is_huge)
{
	char *language;
	const char *charset;
	char command_string[1024];

	if (TRUE == is_huge) {
		strcpy(command_string, "mail_backup.hook set hash-huge TRUE");
		config_file_set_value(g_cfg_file, "HASH_HUGE", "TRUE");
	} else {
		strcpy(command_string, "mail_backup.hook set hash-huge FALSE");
		config_file_set_value(g_cfg_file, "HASH_HUGE", "FALSE");
	}
	gateway_control_notify(command_string, NOTIFY_DELIVERY);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_number(int num)
{
	char *language;
	const char *charset;
	char command_string[1024];

	sprintf(command_string, "smtp set max-mails %d", num);
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "SMTP_SESSION_MAIL_NUM", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_rcpt(int num)
{
	char *language;
	const char *charset;
	char command_string[1024];

	sprintf(command_string, "rcpt_limit.pas set max-rcpt %d", num);
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "SMTP_MAX_RCPT_NUM", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_retry_times(int times)
{
	char *language;
	const char *charset;
	char command_string[1024];

	sprintf(command_string,
		"remote_postman.hook set trying-times %d", times);
	gateway_control_notify(command_string, NOTIFY_DELIVERY);
	sprintf(command_string, "%d", times);
	config_file_set_value(g_cfg_file, "DELIVERY_RETRYING_TIMES",
		command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
	
}

static void setup_ui_set_relay_switch(BOOL b_switch)
{
	char *language;
	const char *charset;

	if (FALSE == b_switch) {
		gateway_control_notify("relay_agent.hook switch OFF", NOTIFY_DELIVERY);
		config_file_set_value(g_cfg_file, "OVERSEA_RELAY_SWITCH", "FALSE");
	} else {
		gateway_control_notify("relay_agent.hook switch ON", NOTIFY_DELIVERY);
		config_file_set_value(g_cfg_file, "OVERSEA_RELAY_SWITCH", "TRUE");
	}
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_log_days(int days)
{
	char *language;
	const char *charset;
	char command_string[1024];
	
	sprintf(command_string, "log_plugin.svc set valid-days %d", days);
	gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
	sprintf(command_string, "%d", days);
	config_file_set_value(g_cfg_file, "LOG_VALID_DAYS", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_length(int num, int unit)
{
	char *language;
	const char *charset;
	char command_string[1024];

	switch (unit) {
	case UNIT_KILO:
		sprintf(command_string, "smtp set mail-length %dK", num);
		break;
	case UNIT_MEGA:
		sprintf(command_string, "smtp set mail-length %dM", num);
		break;
	}
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "SMTP_MAIL_LEN_NUM", command_string);
	sprintf(command_string, "%d", unit);
	config_file_set_value(g_cfg_file, "SMTP_MAIL_LEN_UNIT", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_timeout(int num, int unit)
{
	char *language;
	const char *charset;
	char command_string[1024];

	switch (unit) {
	case UNIT_SECOND:
		sprintf(command_string, "smtp set time-out %dseconds", num);
		break;
	case UNIT_MINUTE:
		sprintf(command_string, "smtp set time-out %dminutes", num);
		break;
	}
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "SMTP_TIMEOUT_NUM", command_string);
	sprintf(command_string, "%d", unit);
	config_file_set_value(g_cfg_file, "SMTP_TIMEOUT_UNIT", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_scanning(int num, int unit)
{
	char *language;
	const char *charset;
	char command_string[1024];

	switch (unit) {
	case UNIT_BYTE:
		sprintf(command_string, "flusher set scanning-size %d", num);
		break;
	case UNIT_KILO:
		sprintf(command_string, "flusher set scanning-size %dK", num);
		break;
	case UNIT_MEGA:
		sprintf(command_string, "flusher set scanning-size %dM", num);
		break;
	}
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "VIRUS_SCANNING_NUM", command_string);
	sprintf(command_string, "%d", unit);
	config_file_set_value(g_cfg_file, "VIRUS_SCANNING_UNIT", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_conn_freq(int times, int num, int unit)
{
	char *language;
	const char *charset;
	char command_string[1024];

	switch (unit) {
	case UNIT_SECOND:
		sprintf(command_string, "ip_filter.svc audit set %d/%d", times, num);
		break;
	case UNIT_MINUTE:
		sprintf(command_string, "ip_filter.svc audit set %d/%dminutes",
			times, num);
		break;
	}
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", times);
	config_file_set_value(g_cfg_file, "CONNECTION_TIMES", command_string);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "CONNECTION_INTERVAL_NUM", command_string);
	sprintf(command_string, "%d", unit);
	config_file_set_value(g_cfg_file, "CONNECTION_INTERVAL_UNIT", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_outmail_freq(int times, int num, int unit)
{
	char *language;
	const char *charset;
	char command_string[1024];

	switch (unit) {
	case UNIT_SECOND:
		sprintf(command_string, "outmail_frequency_audit.svc audit set %d/%d",
			times, num);
		break;
	case UNIT_MINUTE:
		sprintf(command_string, "outmail_frequency_audit.svc audit set "
			"%d/%dminutes", times, num);
		break;
	case UNIT_HOUR:
		sprintf(command_string, "outmail_frequency_audit.svc audit set "
			"%d/%dhours", times, num);
		break;
	}
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", times);
	config_file_set_value(g_cfg_file, "OUTMAIL_TIMES", command_string);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "OUTMAIL_INTERVAL_NUM", command_string);
	sprintf(command_string, "%d", unit);
	config_file_set_value(g_cfg_file, "OUTMAIL_INTERVAL_UNIT", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_limitation_freq(int times, int num, int unit)
{
	char *language;
	const char *charset;
	char command_string[1024];

	switch (unit) {
	case UNIT_SECOND:
		sprintf(command_string, "outmail_limitation_audit.svc audit set %d/%d",
			times, num);
		break;
	case UNIT_MINUTE:
		sprintf(command_string, "outmail_limitation_audit.svc audit set "
			"%d/%dminutes", times, num);
		break;
	case UNIT_HOUR:
		sprintf(command_string, "outmail_limitation_audit.svc audit set "
			"%d/%dhours", times, num);
		break;
	}
	gateway_control_notify(command_string, NOTIFY_SMTP);
	sprintf(command_string, "%d", times);
	config_file_set_value(g_cfg_file, "LIMITATION_TIMES", command_string);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "LIMITATION_INTERVAL_NUM", command_string);
	sprintf(command_string, "%d", unit);
	config_file_set_value(g_cfg_file, "LIMITATION_INTERVAL_UNIT", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_retrying_freq(int times, int num, int unit)
{
	char *language;
	const char *charset;
	char command_string[1024];

	sprintf(command_string, "gateway_dispatch.hook set retrying-times %d", times);
	gateway_control_notify(command_string, NOTIFY_DELIVERY);
	switch (unit) {
	case UNIT_SECOND:
		sprintf(command_string, "gateway_dispatch.hook set cache-scan %d", num);
		break;
	case UNIT_MINUTE:
		sprintf(command_string, "gateway_dispatch.hook set cache-scan %dminutes", num);
		break;
	case UNIT_HOUR:
		sprintf(command_string, "gateway_dispatch.hook set cache-scan %dhours", num);
		break;
	}
	gateway_control_notify(command_string, NOTIFY_DELIVERY);
	sprintf(command_string, "%d", times);
	config_file_set_value(g_cfg_file, "DISPATCH_RETRING_TIMES", command_string);
	sprintf(command_string, "%d", num);
	config_file_set_value(g_cfg_file, "DISPATCH_RETRING_INTERVAL_NUM", command_string);
	sprintf(command_string, "%d", unit);
	config_file_set_value(g_cfg_file, "DISPATCH_RETRING_INTERVAL_UNIT", command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_delivery_interval(int first_num, int first_unit,
	int second_num, int second_unit, int third_num, int third_unit)
{
	char *language;
	const char *charset;
	char first_interval[256];
	char second_interval[256];
	char third_interval[256];
	char command_string[1024];

	switch (first_unit) {
	case UNIT_MINUTE:
		sprintf(first_interval, "%dminutes", first_num);
		break;
	case UNIT_HOUR:
		sprintf(first_interval, "%dhours", first_num);
		break;
	}
	
	switch (second_unit) {
	case UNIT_MINUTE:
		sprintf(second_interval, "%dminutes", second_num);
		break;
	case UNIT_HOUR:
		sprintf(second_interval, "%dhours", second_num);
		break;
	}
	
	switch (third_unit) {
	case UNIT_MINUTE:
		sprintf(third_interval, "%dminutes", third_num);
		break;
	case UNIT_HOUR:
		sprintf(third_interval, "%dhours", third_num);
		break;
	}
	sprintf(command_string, "remote_postman.hook set timer-intervals 1minute "
		"%s %s %s", first_interval, second_interval, third_interval);
	gateway_control_notify(command_string, NOTIFY_DELIVERY);
	sprintf(command_string, "%d", first_num);
	config_file_set_value(g_cfg_file, "DELIVERY_FIRST_INTERVAL_NUM",
		command_string);
	sprintf(command_string, "%d", first_unit);
	config_file_set_value(g_cfg_file, "DELIVERY_FIRST_INTERVAL_UNIT",
		command_string);
	sprintf(command_string, "%d", second_num);
	config_file_set_value(g_cfg_file, "DELIVERY_SECOND_INTERVAL_NUM",
		command_string);
	sprintf(command_string, "%d", second_unit);
	config_file_set_value(g_cfg_file, "DELIVERY_SECOND_INTERVAL_UNIT",
		command_string);
	sprintf(command_string, "%d", third_num);
	config_file_set_value(g_cfg_file, "DELIVERY_THIRD_INTERVAL_NUM",
		command_string);
	sprintf(command_string, "%d", third_unit);
	config_file_set_value(g_cfg_file, "DELIVERY_THIRD_INTERVAL_UNIT",
		command_string);
	config_file_save(g_cfg_file);
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

