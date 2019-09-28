#include "admin_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "midb_client.h"
#include "message_lookup.h"
#include "request_parser.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <iconv.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
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

/* fill search result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function all_to() {\n\
var mailbox=prompt(\"%s\",\"\");\n\
if (null != mailbox && '' != mailbox) {\n\
dummy_window.location.href='%s?session=%s&type=mailto&mailbox=' + mailbox + '&ids=all';}}\n\
function ids_to() {\n\
var mail_ids='';\n\
var inputs;\n\
inputs = document.getElementsByTagName('input');\n\
for(var i=0;i<inputs.length;i++){\n\
	if (true == inputs[i].checked) {\n\
		mail_ids += inputs[i].value + ';';\n\
	}\n\
}\n\
var mailbox=prompt(\"%s\",\"\");\n\
if (null != mailbox && '' != mailbox) {\n\
dummy_window.location.href='%s?session=%s&type=mailto&mailbox=' + mailbox + '&ids=' + mail_ids;}}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp\n\
<A href=\"javascript:ids_to()\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp\n\
<A href=\"javascript:all_to()\">%s</A></TD></TR><TR><TD noWrap align=left height=23>"

/* fill rows num here */

#define HTML_RESULT_6	\
"</TD></TR><TR><TD noWrap align=right>%s:%d&nbsp;&nbsp&nbsp;&nbsp;\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;<A href=\"%s\" %s>%s</A>&nbsp;&nbsp;\n\
<A href=\"%s\" %s>%s</A>&nbsp;&nbsp;<A href=\"%s\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR>\n\
<iframe src=\"\" style=\"display:none\" width=\"0\" height=\"0\" name=\"dummy_window\"></iframe>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill result table title here */

#define HTML_RESULT_7	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE class=\"table-layout:fixed;\
overflow:hidden;text-overflow:ellipsis;word-break:break-all;\"\
cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_RESULT_8	\
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

/* fill envelop user or domain tag here */

#define HTML_SEARCH_8 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=unit /></SPAN>\n\
</TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill sender tag here */

#define HTML_SEARCH_9 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=sender />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill rcpt tag here */

#define HTML_SEARCH_10 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=rcpt />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill from tag here */

#define HTML_SEARCH_11 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=from />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill to tag here */

#define HTML_SEARCH_12 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=to />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill cc tag here */

#define HTML_SEARCH_13 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=cc />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill subject tag here */

#define HTML_SEARCH_14 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=subject />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill content tag here */

#define HTML_SEARCH_15 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=content />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill attachment tag here */

#define HTML_SEARCH_16 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=attachment />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill priority tag here */

#define HTML_SEARCH_17 \
"</TD><TD vAlign=center><SPAN><SELECT name=priority>\n\
<OPTION value=0 selected>%s</OPTION>\n\
<OPTION value=5>%s</OPTION>\n\
<OPTION value=3>%s</OPTION>\n\
<OPTION value=1>%s</OPTION>\n\
</SELECT></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"


#define HTML_OPTION_1	"<OPTION value="

#define HTML_OPTION_SELECTED	" selected>"

#define HTML_OPTION_2	">"

#define HTML_OPTION_3	"</OPTION>\n"

/* fill archive time here */

#define HTML_SEARCH_18	"</TD><TD vAlign=center><SPAN><SELECT name=aday_start>\n"

#define HTML_SEARCH_19	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=ahour_start>\n\
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
<OPTION value=23>23:00</OPTION>\n</SELECT>\n\
&nbsp;-&nbsp;<SELECT name=aday_end>\n"

#define HTML_SEARCH_20	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=ahour_end>\n\
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
</SELECT></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill received time here */

#define HTML_SEARCH_21	"</TD><TD vAlign=center><SPAN><SELECT name=rday_start>\n"

#define HTML_SEARCH_22	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=rhour_start>\n\
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
<OPTION value=23>23:00</OPTION>\n</SELECT>\n\
&nbsp;-&nbsp;<SELECT name=rday_end>\n"

#define HTML_SEARCH_23	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=rhour_end>\n\
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
</SELECT></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill composed time here */

#define HTML_SEARCH_24	"</TD><TD vAlign=center><SPAN><SELECT name=cday_start>\n"

#define HTML_SEARCH_25	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=chour_start>\n\
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
<OPTION value=23>23:00</OPTION>\n</SELECT>\n\
&nbsp;-&nbsp;<SELECT name=cday_end>\n"

#define HTML_SEARCH_26	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=chour_end>\n\
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
</SELECT></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill size tag here */

#define HTML_SEARCH_27 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=size_from />&nbsp;-&nbsp;\n\
<INPUT type=\"text\" name=size_end /></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"


/* fill reference tag here */

#define HTML_SEARCH_28 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=reference />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill ID tag here */

#define HTML_SEARCH_29 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=id_from />&nbsp;-&nbsp;\n\
<INPUT type=\"text\" name=id_end /></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill header tag here */

#define HTML_SEARCH_30 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=header_tag />&nbsp;-&nbsp;\n\
<INPUT type=\"text\" name=header_value /></SPAN></TD><TD>%s:\n\
<SELECT name=server_id><OPTION value=-1 selected>%s</OPTION>\n"

#define HTML_SEARCH_31 \
"</SELECT>&nbsp;&nbsp;<INPUT type=submit onclick=\"\
if ('' == searchpattern.unit.value && '' == searchpattern.sender.value && \
	'' == searchpattern.rcpt.value && '' == searchpattern.from.value && \
	'' == searchpattern.to.value && '' == searchpattern.cc.value && \
	'' == searchpattern.subject.value && '' == searchpattern.content.value && \
	'' == searchpattern.attachment.value && 0 == searchpattern.priority.value && \
	'NULL' == searchpattern.aday_start.value && 'NULL' == searchpattern.rday_start.value && \
	'NULL' == searchpattern.cday_start.value && '' == searchpattern.size_from.value && \
	'' == searchpattern.size_end.value && '' == searchpattern.reference.value && \
	'' == searchpattern.id_from.value && '' == searchpattern.id_end.value && \
	'' == searchpattern.header_tag.value && '' == searchpattern.header_value.value) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (searchpattern.size_from.value != '' && true == isNaN(searchpattern.size_from.value)) {\n\
	alert('%s');\n\
	searchpattern.size_from.focus();\n\
	return false;\n\
}\n\
if (searchpattern.size_end.value != '' && true == isNaN(searchpattern.size_end.value)) {\n\
	alert('%s');\n\
	searchpattern.size_end.focus();\n\
	return false;\n\
}\n\
if ((searchpattern.header_tag.value != '' && searchpattern.header_value.value == '') ||\
	(searchpattern.header_tag.value == '' && searchpattern.header_value.value  != '')) {\n\
	alert('%s');\n\
	searchpattern.header_tag.focus();\n\
	return false;\n\
}\n\
return true;\" value=\"   "

/* fill button label here */

#define HTML_SEARCH_32	\
"   \"/></TD></TR></TBODY></TABLE></FORM>\n\
</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy; "

#define HTML_SEARCH_33	"</CENTER></BODY></HTML>"


#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_ODD  \
"<TR class=ItemOdd><TD nowrap>&nbsp;%d:%lld&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;<input name=\"mail_chk[]\" type=\"checkbox\" value=\"%d:%lld\"/>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_EVEN  \
"<TR class=ItemEven><TD nowrap>&nbsp;%d:%lld&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;%s&nbsp;</TD>\n\
<TD nowrap>&nbsp;<input name=\"mail_chk[]\" type=\"checkbox\" value=\"%d:%lld\"/>&nbsp;</TD></TR>\n"

#define HTML_ACTIVE_OK	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>message is actived</TITLE>\n\
<META http-equiv=Content-Type content=\"text/html; charset=UTF-8\"\n\
</HEAD><BODY onload=\"alert('%s');\"> messgae is actived! </BODY></HTML>"

#define OPTION_ENABLED	""

#define OPTION_DISABLED "disabled"


typedef struct _CACHE_ITEM {
	uint64_t mail_id;
	int server_id;
} CACHE_ITEM;

static void admin_ui_error_html(const char *error_string);

static void admin_ui_search_html(const char *session);

static void admin_ui_result_html(const char *session, int page_index);

static BOOL admin_ui_cache_result(const char *session, const char *charset,
	const char *unit, const char *sender, const char *rcpt, const char *from,
	const char *to, const char *cc, const char *subject,
	const char *content, const char *filename, BOOL *attached,
	int *priority, VAL_SCOPE *atime, VAL_SCOPE *rtime,
	VAL_SCOPE *ctime, VAL_SCOPE *size, uint64_t *reference,
	VAL_SCOPE *id, HEADER_VAL *header, int server_id);


static void admin_ui_activate_message(BOOL b_activated);

static BOOL admin_ui_get_self(char *url_buff, int length);

static BOOL admin_ui_delivery_mails(const char *username, const char *ids_string);

static BOOL admin_ui_delivery_all(const char *username, const char *session);

static BOOL admin_ui_insert_mail(int seq_id, int server_id, uint64_t mail_id,
	const char *dst_path);

static int g_valid_days;
static char g_logo_link[1024];
static char g_cidb_path[256];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void admin_ui_init(int valid_days, const char *url_link,
	const char *cidb_path, const char *resource_path)
{
	g_valid_days = valid_days;
	strcpy(g_logo_link, url_link);
	strcpy(g_cidb_path, cidb_path);
	strcpy(g_resource_path, resource_path);

}

int admin_ui_run()
{
	struct tm *ptm;
	time_t current_time;
	time_t tmp_time;
	int scan_num, type;
	int start_day, end_day;
	int start_hour, end_hour;
	char *language;
	char *remote_ip;
	char *query, *request;
	const char *session;
	char post_buff[4096];
	const char *subject;
	const char *unit;
	const char *rcpt;
	const char *sender;
	const char *from;
	const char *to, *cc;
	const char *content;
	const char *attachment;
	const char *pvalue;
	int *priority;
	int tmp_priority;
	int server_id;
	REQUEST_PARSER *pparser;
	VAL_SCOPE *patime, tmp_atime;
	VAL_SCOPE *prtime, tmp_rtime;
	VAL_SCOPE *pctime, tmp_ctime;
	VAL_SCOPE *psscope, tmp_sscope;
	VAL_SCOPE *pidscope, tmp_idscope;
	uint64_t *preference, tmp_ref;
	HEADER_VAL *pheader, tmp_header;


	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		admin_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[admin_ui]: fail to init language resource");
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
		if (NULL == fgets(post_buff, 4096, stdin)) {
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		pparser = request_parser_init(post_buff);
		if (NULL == pparser) {
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			return 0;
		}
		
		time(&current_time);
		ptm = localtime(&current_time);
		
		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			system_log_info("[admin_ui]: query string of POST "
				"format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
			return 0;
		}
		
		unit = request_parser_get(pparser, "unit");
		if (NULL != unit && '\0' == unit[0]) {
			unit = NULL;
		}
		sender = request_parser_get(pparser, "sender");
		if (NULL != sender && '\0' == sender[0]) {
			sender = NULL;
		}
		rcpt = request_parser_get(pparser, "rcpt");
		if (NULL != rcpt && '\0' == rcpt[0]) {
			rcpt = NULL;
		}
		from = request_parser_get(pparser, "from");
		if (NULL != from && '\0' == from[0]) {
			from = NULL;
		}
		to = request_parser_get(pparser, "to");
		if (NULL != to && '\0' == to[0]) {
			to = NULL;
		}
		cc = request_parser_get(pparser, "cc");
		if (NULL != cc && '\0' == cc[0]) {
			cc = NULL;
		}
		subject = request_parser_get(pparser, "subject");
		if (NULL != subject && '\0' == subject[0]) {
			subject = NULL;
		}
		content = request_parser_get(pparser, "content");
		if (NULL != content && '\0' == content[0]) {
			content = NULL;
		}
		attachment = request_parser_get(pparser, "attachment");
		if (NULL != attachment && '\0' == attachment[0]) {
			attachment = NULL;
		}
		pvalue = request_parser_get(pparser, "priority");
		if (NULL != pvalue) {
			tmp_priority = *pvalue - '0';
			if (0 == tmp_priority) {
				priority = NULL;
			} else if (1 == tmp_priority || 3 == tmp_priority || 5 == tmp_priority) {
				priority = &tmp_priority;
			} else {
				system_log_info("[admin_ui]: query string of POST format error");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
				return 0;
			}

		} else {
			priority = NULL;
		}

		pvalue = request_parser_get(pparser, "aday_start");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}	
		if (0 == strcasecmp(pvalue, "NULL")) {
			start_day = -1;
		} else {
			start_day = atoi(pvalue);
		}

		pvalue = request_parser_get(pparser, "ahour_start");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		start_hour = atoi(pvalue);

		pvalue = request_parser_get(pparser, "aday_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (0 == strcasecmp(pvalue, "NULL")) {
			end_day = -1;
		} else {
			end_day = atoi(pvalue);
		}

		pvalue = request_parser_get(pparser, "ahour_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		end_hour = atoi(pvalue);

		if (-1 == start_day && -1 == end_day) {
			patime = NULL;
		} else {
			if (-1 == start_day) {
				tmp_atime.begin = 0;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_atime.begin = tmp_time - 24*60*60*start_day + 
							60*60*start_hour;
			}
			
			if (-1 == end_day) {
				tmp_atime.end = -1;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_atime.end = tmp_time - 24*60*60*end_day  + 60*60*end_hour;
			}
			
			patime = &tmp_atime;
		}

		pvalue = request_parser_get(pparser, "rday_start");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}	
		if (0 == strcasecmp(pvalue, "NULL")) {
			start_day = -1;
		} else {
			start_day = atoi(pvalue);
		}

		pvalue = request_parser_get(pparser, "rhour_start");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		start_hour = atoi(pvalue);

		pvalue = request_parser_get(pparser, "rday_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}	
		if (0 == strcasecmp(pvalue, "NULL")) {
			end_day = -1;
		} else {
			end_day = atoi(pvalue);
		}

		pvalue = request_parser_get(pparser, "rhour_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		end_hour = atoi(pvalue);

		if (-1 == start_day && -1 == end_day) {
			prtime = NULL;
		} else {
			if (-1 == start_day) {
				tmp_rtime.begin = 0;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_rtime.begin = tmp_time - 24*60*60*start_day + 
							60*60*start_hour;
			}
			
			if (-1 == end_day) {
				tmp_rtime.end = -1;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_rtime.end = tmp_time - 24*60*60*end_day  + 60*60*end_hour;
			}
			
			prtime = &tmp_rtime;
		}

		pvalue = request_parser_get(pparser, "cday_start");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}	
		if (0 == strcasecmp(pvalue, "NULL")) {
			start_day = -1;
		}

		pvalue = request_parser_get(pparser, "chour_start");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		start_hour = atoi(pvalue);
		
		pvalue = request_parser_get(pparser, "cday_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (0 == strcasecmp(pvalue, "NULL")) {
			end_day = -1;
		} else {
			end_day = atoi(pvalue);
		}
		
		pvalue = request_parser_get(pparser, "chour_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;	
		}
		end_hour = atoi(pvalue);

		if (-1 == start_day && -1 == end_day) {
			pctime = NULL;
		} else {
			if (-1 == start_day) {
				tmp_ctime.begin = 0;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_ctime.begin = tmp_time - 24*60*60*start_day + 
							60*60*start_hour;
			}
			
			if (-1 == end_day) {
				tmp_ctime.end = -1;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_ctime.end = tmp_time - 24*60*60*end_day  + 60*60*end_hour;
			}
			
			pctime = &tmp_ctime;
		}

		pvalue = request_parser_get(pparser, "size_from");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;	
		}
			
		if ('\0' == pvalue[0]) {
			tmp_sscope.begin = 0;
		} else {
			tmp_sscope.begin = atoll(pvalue);
		}

		pvalue = request_parser_get(pparser, "size_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;	
		}
			
		if ('\0' == pvalue[0]) {
			tmp_sscope.end = -1;
		} else {
			tmp_sscope.end = atoll(pvalue);
		}

		if (0 == tmp_sscope.begin && -1 == tmp_sscope.end) {
			psscope = NULL;
		} else {
			psscope = &tmp_sscope;
		}

		pvalue = request_parser_get(pparser, "reference");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;	
		}

		if ('\0' == pvalue[0]) {
			preference = NULL;
		} else {
			tmp_ref = atoll(pvalue);
			preference = &tmp_ref;
		}

		pvalue = request_parser_get(pparser, "id_from");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}

		if ('\0' == pvalue[0]) {
			tmp_idscope.begin = 0;
		} else {
			tmp_idscope.begin = atoll(pvalue);
		}

		pvalue = request_parser_get(pparser, "id_end");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}

		if ('\0' == pvalue[0]) {
			tmp_idscope.end = -1;
		} else {
			tmp_idscope.end = atoll(pvalue);
		}

		if (0 == tmp_idscope.begin && -1 == tmp_idscope.end) {
			pidscope = NULL;
		} else {
			pidscope = &tmp_idscope;
		}

		pvalue = request_parser_get(pparser, "header_tag");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if ('\0' == pvalue[0]) {
			tmp_header.field = NULL;
		} else {
			tmp_header.field = (char*)pvalue;
		}

		pvalue = request_parser_get(pparser, "header_value");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if ('\0' == pvalue[0]) {
			tmp_header.value = NULL;
		} else {
			tmp_header.value = (char*)pvalue;
		}

		if (NULL == tmp_header.field && NULL == tmp_header.value) {
			pheader = NULL;
		} else {
			if (NULL == tmp_header.field || NULL == tmp_header.value) {
				system_log_info("[admin_ui]: query string of POST format error");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
				return 0;
			}
			pheader = &tmp_header;
		}

		pvalue = request_parser_get(pparser, "server_id");
		if (NULL == pvalue) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		
		server_id = atoi(pvalue);
		
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
				
		if (FALSE == admin_ui_cache_result(session, lang_resource_get(g_lang_resource,
			"CHARSET", language), unit, sender, rcpt, from, to, cc, subject,
			content, attachment, NULL, priority, patime, prtime,
			pctime, psscope, preference, pidscope, pheader, server_id)) {
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			return 0;
		}

		admin_ui_result_html(session, 1);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[admin_ui]: fail to get QUERY_STRING "
					"environment!");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}

		pparser = request_parser_init(query);
		if (NULL == pparser) {
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			return 0;
		}

		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			system_log_info("[admin_ui]: query string of GET format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		
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
		
		pvalue = request_parser_get(pparser, "type");
		if (NULL == pvalue) {
			admin_ui_search_html(session);
			return 0;
		}
		
		if (0 == strcasecmp(pvalue, "paging")) {
			pvalue = request_parser_get(pparser, "index");
			if (NULL == pvalue) {
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			} else {
				admin_ui_result_html(session, atoi(pvalue));
			}
		} else if (0 == strcasecmp(pvalue, "mailto")) {
			rcpt = request_parser_get(pparser, "mailbox");
			if (NULL == rcpt) {
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
				return 0;
			}
			pvalue = request_parser_get(pparser, "ids");
			if (NULL == pvalue) {
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			} else {
				if (0 == strcasecmp(pvalue, "all")) {
					admin_ui_activate_message(admin_ui_delivery_all(rcpt, session));
				} else {
					admin_ui_activate_message(admin_ui_delivery_mails(rcpt, pvalue));
				}
			}
		} else {
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		}
		return 0;
		
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
	printf("Content-Type:text/html;charset=UTF-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf("UTF-8");
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ERROR_5, lang_resource_get(g_lang_resource,"BACK_LABEL", language),
		error_string);
}

static void admin_ui_search_html(const char *session)
{
	int i, len, num;
	char *language;
	char time_buff[64];
	char url_buff[1024];
	time_t current_time;
	LIST_FILE *plist;
	
	if (FALSE == admin_ui_get_self(url_buff, 1024)) {
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=UTF-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf("UTF-8");
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_SEARCH_5);
	printf(url_buff);
	printf(HTML_SEARCH_6);
	printf(session);
	printf(HTML_SEARCH_7);
	printf(lang_resource_get(g_lang_resource,"ENVELOP_UNIT", language));
	printf(HTML_SEARCH_8);
	printf(lang_resource_get(g_lang_resource,"ENVELOP_SENDER", language));
	printf(HTML_SEARCH_9);
	printf(lang_resource_get(g_lang_resource,"ENVELOP_RCPT", language));
	printf(HTML_SEARCH_10);
	printf(lang_resource_get(g_lang_resource,"HEADER_FROM", language));
	printf(HTML_SEARCH_11);
	printf(lang_resource_get(g_lang_resource,"HEADER_TO", language));
	printf(HTML_SEARCH_12);
	printf(lang_resource_get(g_lang_resource,"HEADER_CC", language));
	printf(HTML_SEARCH_13);
	printf(lang_resource_get(g_lang_resource,"MAIL_SUBJECT", language));
	printf(HTML_SEARCH_14);
	printf(lang_resource_get(g_lang_resource,"MAIL_CONTENT", language));
	printf(HTML_SEARCH_15);
	printf(lang_resource_get(g_lang_resource,"MAIL_ATTACHMENT", language));
	printf(HTML_SEARCH_16);
	printf(lang_resource_get(g_lang_resource,"MAIL_PRIORITY", language));
	printf(HTML_SEARCH_17, lang_resource_get(g_lang_resource,"NOT_SPECIFIED", language),
		lang_resource_get(g_lang_resource,"PRIORITY_LOW", language),
		lang_resource_get(g_lang_resource,"PRIORITY_NORMAL", language),
		lang_resource_get(g_lang_resource,"PRIORITY_HIGH", language));
	printf(lang_resource_get(g_lang_resource,"ARCHIVED_TIME", language));
	printf(HTML_SEARCH_18);
	
	printf("%sNULL%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SPECIFIED", language), HTML_OPTION_3);
	time(&current_time);
	for (i=0; i<g_valid_days; i++) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
		current_time -= 24*60*60;
	}
	
	
	printf(HTML_SEARCH_19);
	
	time(&current_time);
	printf("%sNULL%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SPECIFIED", language), HTML_OPTION_3);
	for (i=0; i<g_valid_days; i++) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
		current_time -= 24*60*60;
	}
	
	printf(HTML_SEARCH_20);
	
	printf(lang_resource_get(g_lang_resource,"RECEIVED_TIME", language));
	printf(HTML_SEARCH_21);
	
	printf("%sNULL%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SPECIFIED", language), HTML_OPTION_3);
	time(&current_time);
	for (i=0; i<g_valid_days; i++) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
		current_time -= 24*60*60;
	}
	
	printf(HTML_SEARCH_22);
	
	time(&current_time);
	printf("%sNULL%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SPECIFIED", language), HTML_OPTION_3);
	for (i=0; i<g_valid_days; i++) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
		current_time -= 24*60*60;
	}
	
	printf(HTML_SEARCH_23);
	
	printf(lang_resource_get(g_lang_resource,"COMPOSED_TIME", language));
	printf(HTML_SEARCH_24);
	
	printf("%sNULL%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SPECIFIED", language), HTML_OPTION_3);
	time(&current_time);
	for (i=0; i<g_valid_days; i++) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
		current_time -= 24*60*60;
	}
	
	printf(HTML_SEARCH_25);
	
	time(&current_time);
	printf("%sNULL%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED,
		lang_resource_get(g_lang_resource,"NOT_SPECIFIED", language), HTML_OPTION_3);
	for (i=0; i<g_valid_days; i++) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT",
			language), localtime(&current_time));
		printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2, time_buff,
			HTML_OPTION_3);
		current_time -= 24*60*60;
	}
	
	printf(HTML_SEARCH_26);
	
	printf(lang_resource_get(g_lang_resource,"MAIL_SIZE", language));
	
	printf(HTML_SEARCH_27);
	
	printf(lang_resource_get(g_lang_resource,"REFERENCE_ID", language));
	
	printf(HTML_SEARCH_28);
	
	printf(lang_resource_get(g_lang_resource,"ARCHIVED_ID", language));
	
	printf(HTML_SEARCH_29);
	
	printf(lang_resource_get(g_lang_resource,"MAIL_HEADER", language));
	
	printf(HTML_SEARCH_30,
		lang_resource_get(g_lang_resource,"ARCHIVE_SERVER", language),
		lang_resource_get(g_lang_resource,"ALL_SERVER", language));
	
	plist = list_file_init(g_cidb_path, "%s:128%s:16%d");
	if (NULL != plist) {
		num = list_file_get_item_num(plist);
		for (i=0; i<num; i++) {
			printf("<OPTION value=%d>%d</OPTION>\n", i, i);
		}
		list_file_free(plist);
	}
	
	printf(HTML_SEARCH_31,
		lang_resource_get(g_lang_resource,"MSGERR_CONDITION", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_HEADER", language));
	
	printf(lang_resource_get(g_lang_resource,"SEARCH_LABEL", language));
	
	printf(HTML_SEARCH_32);
	
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	
	printf(HTML_SEARCH_33);
}

static BOOL admin_ui_cache_result(const char *session, const char *charset,
	const char *unit, const char *sender, const char *rcpt, const char *from,
	const char *to, const char *cc, const char *subject,
	const char *content, const char *filename, BOOL *attached,
	int *priority, VAL_SCOPE *atime, VAL_SCOPE *rtime,
	VAL_SCOPE *ctime, VAL_SCOPE *size, uint64_t *reference,
	VAL_SCOPE *id, HEADER_VAL *header, int server_id)
{
	int i, fd;
	DIR *dirp;
	time_t cur_time;
	char temp_path[256];
	MESSAGE_ITEM *pitem;
	char temp_buff[1200];
	CACHE_ITEM tmp_item;
	struct stat node_stat;
	struct dirent *direntp;
	DOUBLE_LIST_NODE *pnode;
	LOOKUP_COLLECT *pcollection;
	
	
	time(&cur_time);
	dirp = opendir("/tmp");
	if (NULL != dirp) {
		while (direntp = readdir(dirp)) {
			if (0 == strcmp(direntp->d_name, ".") ||
				0 == strcmp(direntp->d_name, "..")) {
				continue;
			}
			if (0 != strncmp(direntp->d_name, "archive_list.", 13)) {
				continue;
			}
			sprintf(temp_path, "/tmp/%s", direntp->d_name);
			if (0 == stat(temp_path, &node_stat) &&
				cur_time - node_stat.st_mtime > 6*60*60) {
				remove(temp_path);
			}
		}
	}
	closedir(dirp);
	
	pcollection = message_lookup_collect_init();
	if (FALSE == message_lookup_search(server_id, charset, unit, sender, rcpt,
		from, to, cc, subject, content, filename, attached, priority, atime,
		rtime, ctime, size, reference, id, header, pcollection)) {
		return FALSE;
	}
	
	snprintf(temp_path, 256, "/tmp/archive_list.%s", session);
	fd = open(temp_path, O_CREAT|O_WRONLY|O_TRUNC, 0666);
	if (-1 == fd) {
		return FALSE;
	}
	
	i = 0;
	for (message_lookup_collect_begin(pcollection);
		!message_lookup_collect_done(pcollection);
		message_lookup_collect_forward(pcollection)) {
		pitem = message_lookup_collect_get_value(pcollection);
		tmp_item.mail_id = pitem->mail_id;
		tmp_item.server_id = pitem->server_id;
		memcpy(temp_buff + 12*i, &tmp_item, 12);
		if (i == 99) {
			write(fd, temp_buff, 1200);
			i = 0;
		} else {
			i ++;
		}
	}
	
	if (i > 0) {
		write(fd, temp_buff, 12*i);
	}
	
	close(fd);
	message_lookup_collect_free(pcollection);
	return TRUE;
	
}

static char* admin_ui_to_utf8(const char *charset, const char *string)
{
	int length;
	iconv_t conv_id;
	char *ret_string;
	char *pin, *pout;
	size_t in_len, out_len;

	
	if (0 == strcasecmp(charset, "UTF-8") ||
		0 == strcasecmp(charset, "US-ASCII")) {
		return strdup(string);
	}
	
	length = strlen(string) + 1;
	ret_string = malloc(2*length);
	if (NULL == ret_string) {
		return NULL;
	}
	conv_id = iconv_open("UTF-8", charset);
	if ((iconv_t)-1 == conv_id) {
		free(ret_string);
		return NULL;
	}
	pin = (char*)string;
	pout = ret_string;
	in_len = length;
	out_len = 2*length;
	if (-1 == iconv(conv_id, &pin, &in_len, &pout, &out_len)) {
		iconv_close(conv_id);
		free(ret_string);
		return NULL;
	}
	iconv_close(conv_id);
	return ret_string;
}

static char* admin_ui_decode_mime(const char *charset, const char *mime_string)
{
	BOOL b_decoded;
	int i, buff_len;
	int offset;
	size_t tmp_len, decode_len;
	int last_pos, begin_pos, end_pos;
	ENCODE_STRING encode_string;
	char *in_buff, *out_buff;
	char *ret_string, *tmp_string;
	char temp_buff[1024];

	buff_len = strlen(mime_string);
	ret_string = malloc(2*(buff_len + 1));
	if (NULL == ret_string) {
		return NULL;
	}
	
	in_buff = (char*)mime_string;
	out_buff = ret_string;
	offset = 0;
	begin_pos = -1;
	end_pos = -1;
	last_pos = 0;
	for (i=0; i<buff_len-1&&offset<2*buff_len+1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				memcpy(temp_buff, in_buff + last_pos, begin_pos - last_pos);
				temp_buff[begin_pos - last_pos] = '\0';
				ltrim_string(temp_buff);
				tmp_string = admin_ui_to_utf8(charset, temp_buff);
				if (NULL == tmp_string) {
					free(ret_string);
					return NULL;
				}
				tmp_len = strlen(tmp_string);
				memcpy(out_buff + offset, tmp_string, tmp_len);
				free(tmp_string);
				offset += tmp_len;
				last_pos = i;
			}
		}
		if (-1 == end_pos && -1 != begin_pos && '?' == in_buff[i] &&
			'=' == in_buff[i + 1] && ('q' != in_buff[i - 1] &&
			'Q' != in_buff[i - 1] || '?' != in_buff[i - 2])) {
			end_pos = i + 1;
		}
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			tmp_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, tmp_len, temp_buff, &decode_len);
				temp_buff[decode_len] = '\0';
				tmp_string = admin_ui_to_utf8(encode_string.charset, temp_buff);
			} else if (0 == strcmp(encode_string.encoding, "quoted-printable")){
				decode_len = qp_decode(temp_buff, encode_string.title, tmp_len);
				temp_buff[decode_len] = '\0';
				tmp_string = admin_ui_to_utf8(encode_string.charset, temp_buff);
			} else {
				tmp_string = admin_ui_to_utf8(charset, encode_string.title);
			}
			if (NULL == tmp_string) {
				free(ret_string);
				return NULL;
			}
			tmp_len = strlen(tmp_string);
			memcpy(out_buff + offset, tmp_string, tmp_len);
			free(tmp_string);
			offset += tmp_len;
			
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos) {
		tmp_string = admin_ui_to_utf8(charset, in_buff + last_pos);
		if (NULL == tmp_string) {
			free(ret_string);
			return NULL;
		}
		tmp_len = strlen(tmp_string);
		memcpy(out_buff + offset, tmp_string, tmp_len);
		free(tmp_string);
		offset += tmp_len;
	} 
	out_buff[offset] = '\0';
	return ret_string;

}

static void admin_ui_parse_digest(char *charset, char *digest,
	time_t *ptime, char *from, char *to, char *subject)
{
	size_t temp_len;
	struct tm tmp_tm;
	char *ret_string;
	char temp_buff[4096];
	char temp_buff1[4096];
	
	*ptime = 0;
	if (TRUE == get_digest(digest, "received", temp_buff, sizeof(temp_buff)) &&
		0 == decode64(temp_buff, strlen(temp_buff), temp_buff1, &temp_len)) {
		ltrim_string(temp_buff1);
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		parse_rfc822_timestamp(temp_buff1, ptime);
	}
	
	*from = '\0';	
	if (TRUE == get_digest(digest, "from", temp_buff, sizeof(temp_buff)) &&
		0 == decode64(temp_buff, strlen(temp_buff), temp_buff1, &temp_len)) {
		temp_buff1[temp_len] = '\0';
		ret_string = admin_ui_decode_mime(charset, temp_buff1);
		if (NULL != ret_string) {
			strncpy(from, ret_string, 256);
			free(ret_string);
		}
	}

	*to = '\0';
	if (TRUE == get_digest(digest, "to", temp_buff, sizeof(temp_buff)) &&
		0 == decode64(temp_buff, strlen(temp_buff), temp_buff1, &temp_len)) {
		temp_buff1[temp_len] = '\0';
		ret_string = admin_ui_decode_mime(charset, temp_buff1);
		if (NULL != ret_string) {
			strncpy(to, ret_string, 1024);
			free(ret_string);
		}
	}
	
	*subject = '\0';
	if (TRUE == get_digest(digest, "subject", temp_buff, sizeof(temp_buff)) &&
		0 == decode64(temp_buff, strlen(temp_buff), temp_buff1, &temp_len)) {
		temp_buff1[temp_len] = '\0';
		ret_string = admin_ui_decode_mime(charset, temp_buff1);
		if (NULL != ret_string) {
			strncpy(subject, ret_string, 1024);
			free(ret_string);
		}
	}
}

static void admin_ui_result_html(const char *session, int page_index)
{
	int i, fd;
	int pages;
	time_t rtime;
	char *charset;
	char *language;
	char from[256];
	char to[1024];
	char time_buff[64];
	char subject[1024];
	char temp_path[128];
	char url_buff[1024];
	CACHE_ITEM tmp_item;
	char digest[256*1024];
	struct stat node_stat;
	char option_prev[32];
	char option_next[32];
	char url_search[1024];
	char url_paging_first[1024];
	char url_paging_last[1024];
	char url_paging_prev[1024];
	char url_paging_next[1024];
	
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = (char*)lang_resource_get(g_lang_resource, "CHARSET", language);
	snprintf(temp_path, 256, "/tmp/archive_list.%s", session);
	if (0 != stat(temp_path, &node_stat)) {
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	pages = (node_stat.st_size - 1) / 1200 + 1;
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	lseek(fd, 1200*(page_index-1), SEEK_SET);

	printf("Content-Type:text/html;charset=UTF-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf("UTF-8");
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	admin_ui_get_self(url_buff, 1024);
	
	sprintf(url_search, "%s?session=%s", url_buff, session);
	
	sprintf(url_paging_first, "%s?session=%s&type=paging&index=1",
		url_buff, session);
	sprintf(url_paging_last, "%s?session=%s&type=paging&index=%d",
		url_buff, session, pages);
	
	printf(HTML_RESULT_5,
		lang_resource_get(g_lang_resource, "PROMPT_MAILTO", language),
		url_buff, session,
		lang_resource_get(g_lang_resource, "PROMPT_MAILTO", language),
		url_buff, session,
		url_search,
		lang_resource_get(g_lang_resource, "SEARCH_AGAIN_LABEL", language),
		lang_resource_get(g_lang_resource, "IDS_TO_LABEL", language),
		lang_resource_get(g_lang_resource, "ALL_TO_LABEL", language));
	
	printf(lang_resource_get(g_lang_resource,"RESULT_SUMMARY", language), node_stat.st_size/12, pages);

	if (page_index < pages) {
		sprintf(url_paging_next, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index + 1);
		strcpy(option_next, OPTION_ENABLED);
	} else {
		sprintf(url_paging_next, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index);
		strcpy(option_next, OPTION_DISABLED);
	}

	if (page_index > 1) {
		sprintf(url_paging_prev, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index - 1);
		strcpy(option_prev, OPTION_ENABLED);
	} else {
		sprintf(url_paging_prev, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index);
		strcpy(option_prev, OPTION_DISABLED);
	}
	
	printf(HTML_RESULT_6, lang_resource_get(g_lang_resource,"CURRENT_PAGE", language),
		page_index, url_paging_first, lang_resource_get(g_lang_resource,"FIRST_PAGE",
		language), url_paging_prev, option_prev, lang_resource_get(g_lang_resource,
		"PREV_PAGE", language), url_paging_next, option_next,
		lang_resource_get(g_lang_resource,"NEXT_PAGE", language), url_paging_last,
		lang_resource_get(g_lang_resource,"LAST_PAGE", language));
	
	printf(lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	printf(HTML_RESULT_7);

	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"ID_TAG", language),
		lang_resource_get(g_lang_resource,"TIME_TAG", language),
		lang_resource_get(g_lang_resource,"FROM_TAG", language),
		lang_resource_get(g_lang_resource,"TO_TAG", language),
		lang_resource_get(g_lang_resource,"SUBJECT_TAG", language),
		lang_resource_get(g_lang_resource,"MAIL_OPERATION", language));
	
	i = 0;
	
	while (TRUE) {
		if (12 != read(fd, &tmp_item, 12)) {
			break;
		}
		
		if (TRUE == message_lookup_match(tmp_item.server_id, tmp_item.mail_id,
			temp_path, digest)) {
			admin_ui_parse_digest(charset, digest, &rtime, from, to, subject);
			strftime(time_buff, 64, lang_resource_get(g_lang_resource,
				"ITEM_TIME_FORMAT", language), localtime(&rtime));
			if (0 == i%2) {
				printf(HTML_TBITEM_ODD, tmp_item.server_id, tmp_item.mail_id,
					time_buff, from, to, subject, tmp_item.server_id,
					tmp_item.mail_id);
			} else {
				printf(HTML_TBITEM_EVEN, tmp_item.server_id, tmp_item.mail_id,
					time_buff, from, to, subject, tmp_item.server_id,
					tmp_item.mail_id);
			}
		}
		
		i ++;
		if (100 == i) {
			break;
		}
	}
	
	printf(HTML_RESULT_8);
	close(fd);

}

static void admin_ui_activate_message(BOOL b_activated)
{
	char *language;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=UTF-8\n\n");
	if (TRUE == b_activated) {
		printf(HTML_ACTIVE_OK, lang_resource_get(g_lang_resource,"MSGERR_ACTIVE", language));
	} else {
		printf(HTML_ACTIVE_OK, lang_resource_get(g_lang_resource,"MSGERR_INACTIVE",language));
	}
	
}

static BOOL admin_ui_delivery_all(const char *username, const char *session)
{
	int fd;
	pid_t pid;
	int seq_id;
	char maildir[256];
	char temp_path[256];
	CACHE_ITEM tmp_item;
	

	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		return FALSE;
	} else if (pid > 0) {
		return TRUE;
	}
	setsid();
	fclose (stdout);
	if (FALSE == data_source_get_maildir(username, maildir)) {
		exit(0);
	}
	
	snprintf(temp_path, 256, "/tmp/archive_list.%s", session);
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		exit(0);
	}
	
	seq_id = 1;
	while (12 == read(fd, &tmp_item, 12)) {
		if (FALSE == admin_ui_insert_mail(seq_id, tmp_item.server_id,
			tmp_item.mail_id, maildir)) {
			close(fd);
			exit(0);
		}
		seq_id ++;
	}
	
	close(fd);
	exit(0);
}

static BOOL admin_ui_delivery_mails(const char *username, const char *ids_string)
{
	int i;
	int seq_id;
	int ids_len;
	int last_pos;
	char *ptoken;
	int server_id;
	uint64_t mail_id;
	char temp_id[32];
	char maildir[256];
	
	
	if (FALSE == data_source_get_maildir(username, maildir)) {
		return FALSE;
	}
	
	ids_len = strlen(ids_string);
	
	
	seq_id = 1;
	last_pos = 0;
	for (i=0; i<ids_len; i++) {
		if (';' == ids_string[i]) {
			memcpy(temp_id, ids_string + last_pos, i - last_pos);
			temp_id[i - last_pos] = '\0';
			ptoken = strchr(temp_id, ':');
			if (NULL != ptoken) {
				*ptoken = '\0';
				server_id = atoi(temp_id);
				mail_id = atoll(ptoken + 1);
				if (FALSE == admin_ui_insert_mail(seq_id, server_id,
					mail_id, maildir)) {
					return FALSE;	
				}
				seq_id ++;
			}
			last_pos = i + 1;
		}
	}
	return TRUE;
}

static BOOL admin_ui_insert_mail(int seq_id, int server_id,
	uint64_t mail_id, const char *dst_path)
{
	int fd;
	char *pbuff;
	time_t rcv_time;
	time_t now_time;
	size_t decode_len;
	char msg_path[128];
	char file_name[128];
	char temp_path[256];
	char temp_rcv[1024];
	char temp_rcv1[1024];
	char digest[256*1024];
	struct stat node_stat;

	if (FALSE == message_lookup_match(server_id, mail_id, msg_path, digest)) {
		return FALSE;
	}
	
	if (FALSE == get_digest(digest, "received", temp_rcv, 1024)) {
		return 1;
	}
	decode_len = 1024;
	decode64(temp_rcv, strlen(temp_rcv), temp_rcv1, &decode_len);
	temp_rcv1[decode_len] = '\0';
	ltrim_string(temp_rcv1);
	if (FALSE == parse_rfc822_timestamp(temp_rcv1, &rcv_time)) {
		rcv_time = 0;
	}
	
	time(&now_time);
	sprintf(file_name, "%ld.%d.archive", now_time, seq_id);
	snprintf(temp_path, 255, "%s/%lld", msg_path, mail_id);
	if (0 != stat(temp_path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}

	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		return FALSE;
	}

	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		close(fd);
		return FALSE;
	}

	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		return FALSE;
	}
	close(fd);
	
	sprintf(temp_path, "%s/eml/%s", dst_path, file_name);
	fd = open(temp_path, O_CREAT|O_WRONLY, 0666);
	if (-1 == fd) {
		free(pbuff);
		return FALSE;
	}
	write(fd, pbuff, node_stat.st_size);
	close(fd);
	free(pbuff);
	
	if (FALSE == midb_client_insert(dst_path,
		"inbox", file_name, "()", rcv_time)) {
		remove(temp_path);
		return FALSE;
	}
	return TRUE;
}
