#include "setup_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "gateway_control.h"
#include "session_client.h"
#include "data_source.h"
#include "list_file.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
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
<TR class=ItemEven><TD><FORM name=AdminMB onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text size=36 value=\"%s\" name=admin_mailbox /></TD>\n\
<TD></TD></TR><TR><TD><B>%s</B></TD><TD><SELECT name=language>"


#define HTML_MAIN_7	\
"</SELECT></TD><TD></TD></TR><TR><TD><B>%s</B></TD><TD><SELECT name=report_type>"

#define HTML_MAIN_8	\
"</SELECT></TD><TD><INPUT type=submit value=\"  %s  \" onclick=\
\"if (0 != AdminMB.report_type.value) {\n\
	with (AdminMB.admin_mailbox) {\n\
		apos=value.indexOf('@');\n\
		dotpos=value.lastIndexOf('.');\n\
		if (apos<1||dotpos-apos<2) {\n\
			alert('%s');\n\
			return false;\n\
		}\n\
	}\n\
}\n\
dummy_window.location.href='%s?domain=%s&session=%s&action=admin-mailbox&value=' +\
AdminMB.admin_mailbox.value + '&language=' + AdminMB.language.value + '&type=' + AdminMB.report_type.value;\n\
return false;\"/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_9	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=LimitTYPE onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<SELECT name=limit_type>"


#define HTML_MAIN_10	\
"</SELECT></TD><TD><INPUT type=submit value=\"  %s  \" onclick=\
\"dummy_window.location.href='%s?domain=%s&session=%s&action=limit-type&value=' + \
LimitTYPE.limit_type.value;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_11	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=CollectMB onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text size=36 value=\"%s\" name=collector_mailbox /></TD>\n\
<TD><INPUT type=submit value=\"  %s  \" %s onclick=\
\"if (CollectMB.collector_mailbox.value.length > 0) {\n\
	with (CollectMB.collector_mailbox) {\n\
		apos=value.indexOf('@');\n\
		dotpos=value.lastIndexOf('.');\n\
		if (apos<1||dotpos-apos<2) {\n\
			alert('%s');\n\
			return false;\n\
		}\n\
	}\n\
}\n\
dummy_window.location.href='%s?domain=%s&session=%s&action=collector-mailbox&value=' +\
CollectMB.collector_mailbox.value;\n\
return false\" /></TD></TR></TBODY></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_12	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=SubSTM onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text size=16 value=\"%s\" name=subsys_ip />&nbsp;:&nbsp;\
<INPUT type=text size=4 value=\"%d\" name=subsys_port /></TD>\n\
<TD><INPUT type=submit value=\"  %s  \" %s onclick=\"\n\
var scount = 0;\n\
var str_ip = SubSTM.subsys_ip.value;\n\
var iplength = str_ip.length;\n\
if (iplength > 0) {\n\
	var letters = '1234567890. ';\n\
	for (i=0; i<iplength; i++) {\n\
		var check_char = str_ip.charAt(i);\n\
		if (letters.indexOf(check_char) == -1) {\n\
			alert ('%s');\n\
			SubSTM.subsys_ip.value='';\n\
			SubSTM.subsys_ip.focus();\n\
			return false;\n\
		}\n\
	}\n\
	for (var i=0;i<iplength;i++)\n\
		(str_ip.substr(i,1)=='.')?scount++:scount;\n\
	if(scount!=3) {\n\
		alert ('%s');\n\
		SubSTM.subsys_ip='';\n\
		SubSTM.subsys_ip.focus();\n\
		return false;\n\
	}\n\
	var port_num = parseInt(SubSTM.subsys_port.value);\n\
	if (isNaN(port_num)) {\n\
		alert('%s');\n\
		SubSTM.subsys_port.value='25';\n\
		SubSTM.subsys_port.focus();\n\
		return false;\n\
	}\n\
	dummy_window.location.href='%s?domain=%s&session=%s&action=sub-system&value=' +\
	SubSTM.subsys_ip.value + ':' + SubSTM.subsys_port.value;\n\
} else {\n\
	dummy_window.location.href='%s?domain=%s&session=%s&action=sub-system&value=';\n\
}\n\
return false\" /></TD></TR></TBODY></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_13	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=ExtpassTYPE onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<SELECT name=extpass_type %s>"

#define HTML_MAIN_14	\
"</SELECT></TD><TD><INPUT type=submit value=\"  %s  \" %s onclick=\
\"dummy_window.location.href='%s?domain=%s&session=%s&action=extpass-type&value=' + \
ExtpassTYPE.extpass_type.value;\n\"\
/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_15	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=DomainKW onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD><B>%s</B></TD><TD><SELECT name=keyword_type>"

#define HTML_MAIN_16	\
"</SELECT></TD><TD></TD></TR><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=text size=36 value=\"%s\" name=approving_mailbox /></TD>\n\
<TD></TD></TR><TR><TD><B>%s</B></TD><TD><SELECT name=language>"

#define HTML_MAIN_17	\
"</SELECT></TD><TD><INPUT type=submit value=\"  %s  \" onclick=\
\"if (DomainKW.keyword_type.value == '1') with (DomainKW.approving_mailbox) {\n\
	apos=value.indexOf('@');\n\
	dotpos=value.lastIndexOf('.');\n\
	if (apos<1||dotpos-apos<2) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
dummy_window.location.href='%s?domain=%s&session=%s&action=keyword-type&type=' +\
DomainKW.keyword_type.value + '&mailbox=' + DomainKW.approving_mailbox.value + \
'&language=' + DomainKW.language.value;\n\
return false;\"/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_18	\
"<TR class=ItemOdd><TD>%s&nbsp;&nbsp;<A href=../data/script/theme.zip>%s</A></TD></TR>\n\
<TR class=ItemEven><TD><FORM name=PostURL method=post action=%s\n\
enctype=\"multipart/form-data\" target=dummy_window>\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>\n\
<INPUT type=hidden name=\"domain\" value=\"%s\" />\n\
<INPUT type=hidden name=\"session\" value=\"%s\" />\n\
<INPUT type=file size=36 name=\"theme\" /></TD>\n\
<TD><INPUT type=submit value=\"  %s  \" /></TD></TR>\n\
</TBODY></TBODY></TABLE></FORM></TD></TR>\n"

#define HTML_MAIN_19	\
"<TR class=ItemOdd><TD>%s</TD></TR>\n\
<TR class=ItemEven><TD><FORM name=PasswordSET onSubmit=\"return false;\">\n\
<TABLE><TBODY><TR><TD width=180><B>%s</B></TD><TD>%s:</TD><TD>\n\
<INPUT type=password name=old_pass /></TD><TD></TD></TR>\n\
<TD></TD><TD>%s:</TD><TD><INPUT type=password name=new1_pass />\n\
</TD><TD></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<INPUT type=password name=new2_pass /></TD><TD>\n\
<INPUT type=submit value=\"  %s  \" onclick=\
\"if (new1_pass.value.length == 0) {\n\
	alert('%s');\n\
	return false;}\n\
if (new1_pass.value != new2_pass.value) {\n\
	alert('%s');\n\
	return false;}\n\
dummy_window.location.href='%s?domain=%s&session=%s&action=set-password&value=' +\
escape(PasswordSET.old_pass.value) + '&new=' + escape(PasswordSET.new1_pass.value);\n\
return false;\"/></TD></TR></TBODY></TABLE></FORM></TD></TR>\n\
</TBODY></TABLE><BR></CENTER></TD></TR></TBODY>\n\
</TABLE></TD></TR></TBODY></TABLE></TD></TR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=domain_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_ACTIVE_OK  \
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>message is actived</TITLE>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\"\n\
</HEAD><BODY onload=\"alert('%s');\"> messgae is actived! </BODY></HTML>"

#define HTML_ACTIVE_FAIL    \
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>message cannot be actived</TITLE>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\"\n\
</HEAD><BODY onload=\"alert('%s');\"> messgae cannot be actived! </BODY></HTML>"

#define OPTION_SELECT	"<OPTION value=%s selected>%s</OPTION>"
#define OPTION_NORMAL	"<OPTION value=%s>%s</OPTION>"

#define OPTION_SELECT_NUMBER	"<OPTION value=%d selected>%d</OPTION>"
#define OPTION_NORMAL_NUMBER	"<OPTION value=%d>%d</OPTION>"

#define OPTION_ENABLED				""
#define OPTION_DISABLED				"disabled"

#define DOMAIN_PRIVILEGE_UNCHECKUSR         0x4

#define DOMAIN_PRIVILEGE_SUBSYSTEM			0x8

#define DOMAIN_PRIVILEGE_EXTPASSWD			0x20

#define DEF_MODE        S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static void setup_ui_error_html(const char *error_string);

static void setup_ui_main_html(const char *domain, const char *session);

static void setup_ui_set_mailbox(const char *domain, const char *session,
	const char *mailbox, const char *lang, int type);

static void setup_ui_set_keyword(const char *domain, int type,
	const char *mailbox, const char *lang);

static void setup_ui_set_collector(const char *domain, const char *mailbox);

static void setup_ui_set_subsystem(const char *domain, const char *address);

static void setup_ui_set_limit_type(const char *domain, int type);

static void setup_ui_set_extpass_type(const char *domain, int type);

static void setup_ui_set_password(const char *domain, const char *old_password,
	const char *new_password);
	
static void setup_ui_broadcast_limit(const char *list_path, const char *domain,
	int limit_type);

static void setup_ui_broadcast_keyword(const char *list_path, const char *domain,
	int keyword_type);

static void setup_ui_set_theme(const char *domain);

static BOOL setup_ui_get_self(char *url_buff, int length);

static void setup_ui_decode_url(char *src, char *dest);

static void setup_ui_encode_line(const char *in, char *out);

static char g_app_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

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

void setup_ui_init(const char *mount_path, const char *app_path,
	const char *url_link, const char *resource_path)
{
	strcpy(g_mount_path, mount_path);
	strcpy(g_app_path, app_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int setup_ui_run()
{
	int type;
	int i, fd;
	int offset;
	int len, num;
	int interval;
	char *query;
	int bnd_len;
	char *request;
	char *language;
	char *ptr1, *ptr2;
	char action[64];
	char value[1024];
	char domain[256];
	char session[256];
	char boundary[128];
	char temp_path[256];
	char temp_buff[1024];
	char post_buff[1024];
	char old_passwd[256];
	char new_passwd[256];
	struct stat node_stat;
	char search_buff[4096];

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
			ptr1 = search_string(query, "domain=", len);
			if (NULL == ptr1) {
				goto GET_ERROR;
			}
			ptr1 += 7;
			ptr2 = search_string(ptr1, "&session=", len);
			if (NULL == ptr2) {
				goto GET_ERROR;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				goto GET_ERROR;	
			}
			memcpy(domain, ptr1, ptr2 - ptr1);
			domain[ptr2 - ptr1] = '\0';
			lower_string(domain);
			
			ptr1 = ptr2 + 9;
			ptr2 = search_string(ptr1, "&action=", len);
			if (NULL == ptr2) {
				if (query + len - ptr1 > 255) {
					goto GET_ERROR;
				}
				memcpy(session, ptr1, query + len - ptr1);
				session[query + len - ptr1] = '\0';
				if (FALSE == session_client_check(domain, session)) {
					setup_ui_error_html(lang_resource_get(
						g_lang_resource, "ERROR_SESSION", language));
					return 0;
				}
				setup_ui_main_html(domain, session);
				return 0;
			}
			if (ptr2 <= ptr1 && ptr2 - ptr1 > 255) {
				goto GET_ERROR;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			if (FALSE == session_client_check(domain, session)) {
				setup_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_SESSION", language));
				return 0;
			}
			ptr1 = ptr2 + 8;
			ptr2 = strchr(ptr1, '&');
			if (NULL == ptr2 || ptr2 - ptr1 >= 64) {
				goto GET_ERROR;
			}
			
			memcpy(action, ptr1, ptr2 - ptr1);
			action[ptr2 - ptr1] = '\0';
			if (0 == strcasecmp(action, "admin-mailbox")) {
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
				if (NULL == (ptr1 = strstr(value, "&language="))) {
					goto GET_ERROR;
				}
				*ptr1 = '\0';
				if (NULL == (ptr2 = strstr(ptr1 + 10, "&type="))) {
					goto GET_ERROR;
				}
				*ptr2 = '\0';
				setup_ui_set_mailbox(domain, session,
					value, ptr1 + 10, atoi(ptr2 + 6));
				return 0;
			} else if (0 == strcasecmp(action, "keyword-type")) {
				if (0 != strncasecmp(ptr2, "&type=", 6)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 6;
				if (query + len - ptr1 > 255 || 0 == query + len - ptr1) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, query + len - ptr1);
				value[query + len - ptr1] = '\0';
				ltrim_string(value);
				rtrim_string(value);
				if ('0' == value[0]) {
					num = 0;
				} else if ('1' == value[0]) { 
					num = 1;
				} else {
					goto GET_ERROR;
				}
				if (NULL == (ptr1 = strstr(value, "&mailbox="))) {
					goto GET_ERROR;
				}
				*ptr1 = '\0';
				if (NULL == (ptr2 = strstr(ptr1 + 9, "&language="))) {
					goto GET_ERROR;
				}
				*ptr2 ='\0';
				setup_ui_set_keyword(domain, num, ptr1 + 9, ptr2 + 10);
				return 0;
			} else if (0 == strcasecmp(action, "limit-type")) {
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
				setup_ui_set_limit_type(domain, num);
				return 0;
			} else if (0 == strcasecmp(action, "extpass-type")) {
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
				setup_ui_set_extpass_type(domain, num);
				return 0;
			} else if (0 == strcasecmp(action, "collector-mailbox")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 > 255) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, query + len - ptr1);
				value[query + len - ptr1] = '\0';
				setup_ui_set_collector(domain, value);
				return 0;
			} else if (0 == strcasecmp(action, "sub-system")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 > 32) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, query + len - ptr1);
				value[query + len - ptr1] = '\0';
				setup_ui_set_subsystem(domain, value);
			} else if (0 == strcasecmp(action, "set-password")) {
				if (0 != strncasecmp(ptr2, "&value=", 7)) {
					goto GET_ERROR;	
				}
				ptr1 = ptr2 + 7;
				if (query + len - ptr1 > 128 || 0 == query + len - ptr1) {
					goto GET_ERROR;
				}
				memcpy(value, ptr1, query + len - ptr1);
				value[query + len - ptr1] = '\0';
				if (NULL == (ptr1 = strstr(value, "&new="))) {
					goto GET_ERROR;
				}
				if (0 == strlen(ptr1 + 5) || strlen(ptr1 + 5) > 128) {
					goto GET_ERROR;
				}
				*ptr1 = '\0';
				setup_ui_decode_url(value, old_passwd);
				setup_ui_decode_url(ptr1 + 5, new_passwd);
				setup_ui_set_password(domain, old_passwd, new_passwd);
				return 0;
			} else {
				goto GET_ERROR;
			}
		}
	} else if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		if (len > 127) {
			goto POST_ERROR;
		}
		strcpy(boundary, post_buff);
		bnd_len = strlen(boundary);
		if ('\n' == boundary[bnd_len - 1]) {
			bnd_len --;
		}
		if ('\r' == boundary[bnd_len - 1]) {
			bnd_len --;
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		setup_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			goto POST_ERROR;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2 || ptr2 - ptr1 > 32) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "domain")) {
			goto POST_ERROR;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		if (len >= 128) {
			goto POST_ERROR;
		}
		memset(domain, 0, 128);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				domain[i] = '\0';
				break;
			} else {
				domain[i] = post_buff[i];
			}
		}
		lower_string(domain);

		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
			
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		setup_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			goto POST_ERROR;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2 || ptr2 - ptr1 > 32) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "session")) {
			goto POST_ERROR;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		len = strlen(post_buff);
		if (len >= 128) {
			goto POST_ERROR;
		}
		memset(session, 0, 128);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				session[i] = '\0';
				break;
			} else {
				session[i] = post_buff[i];
			}
		}

		if (FALSE == session_client_check(domain, session)) {
			setup_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_SESSION", language));
			return 0;
		}
		
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			goto POST_ERROR;
		}
		snprintf(temp_path, 255, "%s/%s", g_app_path, domain);
		if (0 != stat(temp_path, &node_stat)) {
			mkdir(temp_path, 0777);
		}
		snprintf(temp_path, 255, "%s/%s/steep-webapp", g_app_path, domain);
		if (0 != stat(temp_path, &node_stat)) {
			mkdir(temp_path, 0777);
		}
		snprintf(temp_path, 255, "%s/%s/steep-webapp/tmp_theme.zip", g_app_path, domain);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);	
		if (-1 == fd) {
			system_log_info("[upload_ui]: fail to "
				"create zip file for %s\n", temp_path);
			setup_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_INTERNAL", language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		offset = 0;
		while (len = fread(post_buff + offset, 1, 1024 - offset, stdin)) {
			offset += len;
			if ('\r' == post_buff[0] && '\n' == post_buff[1] &&
				0 == strncmp(post_buff + 2, boundary, bnd_len)) {
				break;
			}
			if (offset >= bnd_len + 2) {
				write(fd, post_buff, offset - bnd_len - 2);
				memmove(post_buff, post_buff + offset - bnd_len - 2, bnd_len + 2);
				offset = bnd_len + 2;
			} else {
				continue;
			}
		}
		close(fd);
		setup_ui_set_theme(domain);
		return 0;
	} else {
		system_log_info("[setup_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		setup_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return 0;
	}
GET_ERROR:
	system_log_info("[setup_ui]: query string of GET format error");
	setup_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_REQUEST", language));
	return 0;
POST_ERROR:
	system_log_info("[upload_ui]: query string of POST format error");
	setup_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_REQUEST", language));
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


static void setup_ui_main_html(const char *domain, const char *session)
{
	int i, fd;
	int option;
	int subsys_port;
	int privilege_bits;
	BOOL b_privilege;
	char *pcolon;
	char *language;
	char *str_value;
	char *str_times;
	char *str_intvl;
	char subsys_ip[16];
	char url_buff[1024];
	char str_submit[64];
	char str_option[16];
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;
	struct stat node_stat;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == setup_ui_get_self(url_buff, 1024)) {
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (FALSE == data_source_get_homedir(domain, domain_path) ||
		'\0' == domain_path[0]) {
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	snprintf(temp_path, 256, "%s/domain.cfg", domain_path);
	if (0 != stat(temp_path, &node_stat)) {
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
				language));
			return;
		}
		close(fd);
	}
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
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
	printf(HTML_MAIN_5);

	strcpy(str_submit, lang_resource_get(g_lang_resource,"LABEL_SUBMIT", language));
	
	str_value = config_file_get_value(pconfig, "ADMIN_MAILBOX");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	printf(HTML_MAIN_6, lang_resource_get(g_lang_resource,"TIP_ADMIN_MAILBOX", language),
		lang_resource_get(g_lang_resource,"MAIN_ADMIN_MAILBOX", language), str_value,
		lang_resource_get(g_lang_resource,"MAIN_REPORT_LANGUAGE", language));
	str_value = config_file_get_value(pconfig, "REPORT_LANGUAGE");
	if (NULL == str_value || '\0' == str_value[0]) {
		printf(OPTION_SELECT, "auto", "auto");
		printf(OPTION_NORMAL, "en", lang_resource_get(
			g_lang_resource, "LANGUAGE_ENGLISH", language));
		printf(OPTION_NORMAL, "zh-cn", lang_resource_get(
			g_lang_resource, "LANGUAGE_CHINESE", language));
	} else {
		if (0 == strcmp(str_value, "en")) {
			printf(OPTION_SELECT, "en", lang_resource_get(
				g_lang_resource, "LANGUAGE_ENGLISH", language));
			printf(OPTION_NORMAL, "zh-cn", lang_resource_get(
				g_lang_resource, "LANGUAGE_CHINESE", language));
		} else {
			printf(OPTION_NORMAL, "en", lang_resource_get(
				g_lang_resource, "LANGUAGE_ENGLISH", language));
			printf(OPTION_SELECT, "zh-cn", lang_resource_get(
				g_lang_resource, "LANGUAGE_CHINESE", language));
		}
	}

	printf(HTML_MAIN_7, lang_resource_get(g_lang_resource,"MAIN_REPORT_TYPE", language));
	str_value = config_file_get_value(pconfig, "REPORT_TYPE");
	if (NULL == str_value) {
		option = 0;
	} else {
		option = atoi(str_value);
		if (option < 1 || option > 3) {
			option = 0;
		}
	}
	if (0 == option) {
		printf(OPTION_SELECT, "0", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_NONE", language));
	} else {
		printf(OPTION_NORMAL, "0", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_NONE", language));
	}
	if (1 == option) {
		printf(OPTION_SELECT, "1", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_BRIEF", language));
	} else {
		printf(OPTION_NORMAL, "1", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_BRIEF", language));
	}
	if (2 == option) {
		printf(OPTION_SELECT, "2", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_DETAIL", language));
	} else {
		printf(OPTION_NORMAL, "2", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_DETAIL", language));
	}
	if (3 == option) {
		printf(OPTION_SELECT, "3", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_SIMPLE", language));
	} else {
		printf(OPTION_NORMAL, "3", lang_resource_get(
			g_lang_resource, "REPORT_TYPE_SIMPLE", language));
	}
	
	printf(HTML_MAIN_8, str_submit,
		lang_resource_get(g_lang_resource,"MSGERR_MAILBOXFORMATERR", language),
		url_buff, domain, session);

	printf(HTML_MAIN_9, lang_resource_get(g_lang_resource,"TIP_LIMIT_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_LIMIT_TYPE", language));

	str_value = config_file_get_value(pconfig, "LIMIT_TYPE");
	if (NULL == str_value || 2 != atoi(str_value)) {
		printf(OPTION_SELECT, "1", lang_resource_get(
			g_lang_resource, "LIMIT_TYPE_DENY", language));
		printf(OPTION_NORMAL, "2", lang_resource_get(
			g_lang_resource, "LIMIT_TYPE_ALLOW", language));
	} else {
		printf(OPTION_NORMAL, "1", lang_resource_get(
			g_lang_resource, "LIMIT_TYPE_DENY", language));
		printf(OPTION_SELECT, "2", lang_resource_get(
			g_lang_resource, "LIMIT_TYPE_ALLOW", language));
	}
	printf(HTML_MAIN_10, str_submit, url_buff, domain, session); 

	b_privilege = data_source_info_domain(domain, &privilege_bits);
	
	if (TRUE == b_privilege && (privilege_bits&DOMAIN_PRIVILEGE_UNCHECKUSR)) { 
		str_value = config_file_get_value(pconfig, "COLLECTOR_MAILBOX");
		if (NULL == str_value) {
			str_value = "N/A";
		}
		strcpy(str_option, OPTION_ENABLED);
	} else {
		str_value = "N/A";
		strcpy(str_option, OPTION_DISABLED);
	}

	printf(HTML_MAIN_11, lang_resource_get(g_lang_resource,"TIP_COLLECTOR", language),
		lang_resource_get(g_lang_resource,"MAIN_COLLECTOR", language), str_value, str_submit,
		str_option, lang_resource_get(g_lang_resource,"MSGERR_MAILBOXFORMATERR", language),
		url_buff, domain, session);
	
	
	if (TRUE == b_privilege && (privilege_bits&DOMAIN_PRIVILEGE_SUBSYSTEM)) {
		str_value = config_file_get_value(pconfig, "SUBSYSTEM_ADDRESS");
		if (NULL == str_value) {
			strcpy(subsys_ip, "N/A");
			subsys_port = 25;
		} else {
			pcolon = strchr(str_value, ':');
			if (NULL != pcolon) {
				*pcolon = '\0';
				strcpy(subsys_ip, str_value);
				subsys_port = atoi(pcolon + 1);
			} else {
				strcpy(subsys_ip, str_value);
				subsys_port = 25;
			}
		}
		strcpy(str_option, OPTION_ENABLED);
	} else {
		strcpy(subsys_ip, "N/A");
		subsys_port = 25;
		strcpy(str_option, OPTION_DISABLED);
	}
	
	printf(HTML_MAIN_12, lang_resource_get(g_lang_resource,"TIP_SUBSYSTEM", language),
		lang_resource_get(g_lang_resource,"MAIN_SUBSYSTEM", language), subsys_ip,
		subsys_port, str_submit, str_option,
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_PORT", language),
		url_buff, domain, session, url_buff, domain, session);
	
	if (TRUE == b_privilege && (privilege_bits&DOMAIN_PRIVILEGE_EXTPASSWD)) { 
		strcpy(str_option, OPTION_ENABLED);
	} else {
		strcpy(str_option, OPTION_DISABLED);
	}
	
	printf(HTML_MAIN_13, lang_resource_get(g_lang_resource,"TIP_EXTPASS_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_EXTPASS_TYPE", language), str_option);
	
	if (TRUE == b_privilege && (privilege_bits&DOMAIN_PRIVILEGE_EXTPASSWD)) { 
		str_value = config_file_get_value(pconfig, "EXTPASSWD_TYPE");
		if (NULL == str_value) {
			option = 2;
		} else {
			option = atoi(str_value);
			if (option < 2 || option > 5) {
				option = 2;
			}
		}
		if (2 == option) {
			printf(OPTION_SELECT, "2", lang_resource_get(g_lang_resource,"PASSWORD_AGING_1YEAR", language));
		} else {
			printf(OPTION_NORMAL, "2", lang_resource_get(g_lang_resource,"PASSWORD_AGING_1YEAR", language));
		}
		if (3 == option) {
			printf(OPTION_SELECT, "3", lang_resource_get(g_lang_resource,"PASSWORD_AGING_6MONTH", language));
		} else {
			printf(OPTION_NORMAL, "3", lang_resource_get(g_lang_resource,"PASSWORD_AGING_6MONTH", language));
		}
		if (4 == option) {
			printf(OPTION_SELECT, "4", lang_resource_get(g_lang_resource,"PASSWORD_AGING_3MONTH", language));
		} else {
			printf(OPTION_NORMAL, "4", lang_resource_get(g_lang_resource,"PASSWORD_AGING_3MONTH", language));
		}
		if (5 == option) {
			printf(OPTION_SELECT, "5", lang_resource_get(g_lang_resource,"PASSWORD_AGING_1MONTH", language));
		} else {
			printf(OPTION_NORMAL, "5", lang_resource_get(g_lang_resource,"PASSWORD_AGING_1MONTH", language));
		}
	} else {
		printf(OPTION_SELECT, "0", lang_resource_get(g_lang_resource,"PASSWORD_AGING_NEVER", language));
	}
	printf(HTML_MAIN_14, str_submit, str_option, url_buff, domain, session); 
	

	printf(HTML_MAIN_15, lang_resource_get(g_lang_resource,"TIP_KEYWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_KEYWORD_TYPE", language));

	str_value = config_file_get_value(pconfig, "KEYWORD_TYPE");
	if (NULL == str_value) {
		option = 0;
	} else {
		option = atoi(str_value);
		if (0 != option && 1 != option) {
			option = 0;
		}
	}

	if (0 == option) {
		printf(OPTION_SELECT, "0", lang_resource_get(g_lang_resource,"KEYWORD_TYPE_REJECT",
			language));
		printf(OPTION_NORMAL, "1", lang_resource_get(g_lang_resource,"KEYWORD_TYPE_APPROVING",
			language));
	} else {
		printf(OPTION_NORMAL, "0", lang_resource_get(g_lang_resource,"KEYWORD_TYPE_REJECT",
			language));
		printf(OPTION_SELECT, "1", lang_resource_get(g_lang_resource,"KEYWORD_TYPE_APPROVING",
			language));
	}

	str_value = config_file_get_value(pconfig, "KBOUNCE_MAILBOX");
	if (NULL == str_value) {
		str_value = "";
	}

	printf(HTML_MAIN_16, lang_resource_get(g_lang_resource,"MAIN_APPROVING_MAILBOX", language),
		str_value, lang_resource_get(g_lang_resource,"MAIN_APPROVING_LANGUAGE", language));


	str_value = config_file_get_value(pconfig, "KBOUNCE_LANGUAGE");
	if (NULL == str_value) {
		str_value = "en";
	}

	if (0 != strcmp(str_value, "en") &&
		0 != strcmp(str_value, "zh-cn")) {
		str_value = "en";
	}

	if (0 == strcmp(str_value, "en")) {
		printf(OPTION_SELECT, "en", lang_resource_get(g_lang_resource,"LANGUAGE_ENGLISH", language));
		printf(OPTION_NORMAL, "zh-cn", lang_resource_get(g_lang_resource,"LANGUAGE_CHINESE", language));
	} else {
		printf(OPTION_NORMAL, "en", lang_resource_get(g_lang_resource,"LANGUAGE_ENGLISH", language));
		printf(OPTION_SELECT, "zh-cn", lang_resource_get(g_lang_resource,"LANGUAGE_CHINESE", language));
	}

	printf(HTML_MAIN_17, str_submit, lang_resource_get(g_lang_resource,"MSGERR_MAILBOXFORMATERR", language),
		url_buff, domain, session);
	
	printf(HTML_MAIN_18, lang_resource_get(g_lang_resource,"TIP_UPLOADTHEME", language),
		lang_resource_get(g_lang_resource,"TIP_DOWNLOADTHEME", language), url_buff,
		lang_resource_get(g_lang_resource,"MAIN_UPLOADTHEME", language),
		domain, session, str_submit);

	printf(HTML_MAIN_19, lang_resource_get(g_lang_resource,"TIP_SET_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_SET_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_OLD_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_NEW_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_RETYPE_PASSWORD", language),
		str_submit, lang_resource_get(g_lang_resource,"MSGERR_PASSEMPTY", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSDIFF", language),
		url_buff, domain, session);

	config_file_free(pconfig);	
}

static void setup_ui_set_keyword(const char *domain, int type,
	const char *mailbox, const char *lang)
{
	int old_type;
	char *language;
	const char *charset;
	char temp_num[16];
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);

	if (FALSE == data_source_get_homedir(domain, domain_path) ||
		'\0' == domain_path[0]) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	snprintf(temp_num, 16, "%d", type);
	snprintf(temp_path, 256, "%s/domain.cfg", domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	if ('\0' != mailbox[0]) {
		config_file_set_value(pconfig, "KBOUNCE_MAILBOX", (char*)mailbox);
	}
	if (0 == strcmp(lang, "en") || 0 == strcmp(lang, "zh-cn")) {
		config_file_set_value(pconfig, "KBOUNCE_LANGUAGE", (char*)lang);
	}

	snprintf(temp_path, 256, "%s/keyword.txt", domain_path);
	setup_ui_broadcast_keyword(temp_path, domain, type);

	config_file_set_value(pconfig, "KEYWORD_TYPE", temp_num);
	if (FALSE == config_file_save(pconfig)) {
		config_file_free(pconfig);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	config_file_free(pconfig);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));

}

static void setup_ui_set_mailbox(const char *domain, const char *session,
	const char *mailbox, const char *lang, int type)
{
	char *language;
	char temp_num[16];
	const char *charset;
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;
	
	if (0 == strcasecmp(lang, "auto")) {
		lang = "";
	}
	if (0 == type && 0 == strcasecmp(mailbox, "N/A")) {
		mailbox = "";
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);

	if (FALSE == data_source_get_homedir(domain, domain_path) ||
		'\0' == domain_path[0]) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	snprintf(temp_num, 16, "%d", type);
	snprintf(temp_path, 256, "%s/domain.cfg", domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	config_file_set_value(pconfig, "ADMIN_MAILBOX", (char*)mailbox);
	config_file_set_value(pconfig, "REPORT_LANGUAGE", (char*)lang);
	config_file_set_value(pconfig, "REPORT_TYPE", temp_num);
	if (FALSE == config_file_save(pconfig)) {
		config_file_free(pconfig);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	config_file_free(pconfig);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_limit_type(const char *domain, int type)
{
	int fd;
	char *language;
	const char *charset;
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;
	struct stat node_stat;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);

	if (FALSE == data_source_get_homedir(domain, domain_path) ||
		'\0' == domain_path[0]) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	snprintf(temp_path, 256, "%s/domain.cfg", domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	
	snprintf(temp_path, 256, "%s/limit.txt", domain_path);
	if (0 != stat(temp_path, &node_stat)) {
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			config_file_free(pconfig);
			printf("Content-Type:text/html;charset=%s\n\n", charset);
			printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
			return;
		}
		close(fd);
	}
	
	if (2 == type) {
		config_file_set_value(pconfig, "LIMIT_TYPE", "2");
	} else {
		config_file_set_value(pconfig, "LIMIT_TYPE", "1");
	}
	if (FALSE == config_file_save(pconfig)) {
		config_file_free(pconfig);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	sprintf(temp_path, "%s/limit.txt", domain_path);
	setup_ui_broadcast_limit(temp_path, domain, type);

	config_file_free(pconfig);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
	
}


static void setup_ui_set_extpass_type(const char *domain, int type)
{
	int fd;
	char *language;
	char num_buff[16];
	const char *charset;
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;
	int privilege_bits;
	
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);

	if (FALSE == data_source_info_domain(domain, &privilege_bits) ||
		(privilege_bits & DOMAIN_PRIVILEGE_EXTPASSWD) == 0 ||
		type < 2 || type > 5) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	if (FALSE == data_source_get_homedir(domain, domain_path) ||
		'\0' == domain_path[0]) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	snprintf(temp_path, 256, "%s/domain.cfg", domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	
	sprintf(num_buff, "%d", type);
	config_file_set_value(pconfig, "EXTPASSWD_TYPE", num_buff);
	
	if (FALSE == config_file_save(pconfig)) {
		config_file_free(pconfig);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	
	config_file_free(pconfig);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
	
}

static void setup_ui_set_collector(const char *domain, const char *mailbox)
{
	int privilege_bits;
	char *language;
	const char *charset;
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);

	if (FALSE == data_source_info_domain(domain, &privilege_bits) ||
		(privilege_bits & DOMAIN_PRIVILEGE_UNCHECKUSR) == 0 ||
		FALSE == data_source_get_homedir(domain, domain_path) ||
		'\0' == domain_path[0]) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	snprintf(temp_path, 256, "%s/domain.cfg", domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	config_file_set_value(pconfig, "COLLECTOR_MAILBOX", (char*)mailbox);
	if (FALSE == config_file_save(pconfig)) {
		config_file_free(pconfig);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	config_file_free(pconfig);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_subsystem(const char *domain, const char *address)
{
	int privilege_bits;
	char *language;
	const char *charset;
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);

	if (FALSE == data_source_info_domain(domain, &privilege_bits) ||
		(privilege_bits & DOMAIN_PRIVILEGE_SUBSYSTEM) == 0 ||
		FALSE == data_source_get_homedir(domain, domain_path) ||
		'\0' == domain_path[0]) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	snprintf(temp_path, 256, "%s/domain.cfg", domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	config_file_set_value(pconfig, "SUBSYSTEM_ADDRESS", (char*)address);
	if (FALSE == config_file_save(pconfig)) {
		config_file_free(pconfig);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	config_file_free(pconfig);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_set_password(const char *domain, const char *old_password,
	const char *new_password)
{
	BOOL b_result;
	char *language;
	char *str_value;
	const char *charset;
	char old_pw[40];
	char new_pw[40];

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	
	if (FALSE == data_source_get_password(domain, old_pw, &b_result)) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	if (FALSE == b_result) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	
	if ('\0' == old_password[0] && '\0' == old_pw[0]) {
		strcpy(new_pw, md5_crypt_wrapper(new_password));
		if (TRUE == data_source_set_password(domain, new_pw)) {
			printf("Content-Type:text/html;charset=%s\n\n", charset);
			printf(HTML_ACTIVE_OK, charset,
			lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
		} else {
			printf("Content-Type:text/html;charset=%s\n\n", charset);
			printf(HTML_ACTIVE_FAIL, charset,
				lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		}
		return;
	}

	if (0 != strcmp(crypt(old_password, old_pw), old_pw)) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_PASSERR", language));
		return;
	}
	
	strcpy(new_pw, md5_crypt_wrapper(new_password));
	if (TRUE == data_source_set_password(domain, new_pw)) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
	} else {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
	}
	return;
}

static void setup_ui_broadcast_keyword(const char *list_path, const char *domain,
	int keyword_type)
{
	DIR *dirp;
	int item_num;
	int i, fd, len;
	char *pitem;
	char *str_value;
	char temp_path[256];
	char temp_keyword[512];
	char command_line[1024];
	struct dirent *direntp;
	LIST_FILE *pfile;	
	CONFIG_FILE *pconfig;
	

	pfile = list_file_init((char*)list_path, "%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (char*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[setup_ui]: fail to open directory %s\n",
			g_mount_path);
		return;
	}
	/*
	 * enumerate the sub-directory of source director each
	 * sub-directory represents one MTA
	 */
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		if (0 == keyword_type) {
			sprintf(temp_path, "%s/%s/data/smtp/domain_keyword/%s.txt",
				g_mount_path, direntp->d_name, domain);
		} else {
			sprintf(temp_path, "%s/%s/data/delivery/domain_keyword/%s.txt",
				g_mount_path, direntp->d_name, domain);
		}
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[setup_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			setup_ui_encode_line(pitem + (256 + 256) * i, temp_keyword);
			len = strlen(temp_keyword);
			temp_keyword[len] = '\n';
			write(fd, temp_keyword, len + 1);
		}
		close(fd);
	}
	closedir(dirp);
	list_file_free(pfile);
	if (0 == keyword_type) {
		snprintf(command_line, 1024, "domain_keyword.hook remove %s", domain);
		gateway_control_notify(command_line, NOTIFY_DELIVERY);
		snprintf(command_line, 1024, "domain_keyword.pas add %s", domain);
		gateway_control_notify(command_line, NOTIFY_SMTP);
	} else {
		snprintf(command_line, 1024, "domain_keyword.pas remove %s", domain);
		gateway_control_notify(command_line, NOTIFY_SMTP);
		snprintf(command_line, 1024, "domain_keyword.hook add %s", domain);
		gateway_control_notify(command_line, NOTIFY_DELIVERY);
	}
}

static void setup_ui_broadcast_limit(const char *list_path, const char *domain,
	int limit_type)
{
	DIR *dirp;
	int item_num;
	int i, fd, len;
	char *pitem;
	char *str_value;
	char temp_object[257];
	char temp_path[256];
	char command_line[1024];
	struct dirent *direntp;
	LIST_FILE *pfile;	
	CONFIG_FILE *pconfig;
	

	pfile = list_file_init((char*)list_path, "%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (char*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[setup_ui]: fail to open directory %s\n",
			g_mount_path);
		return;
	}
	/*
	 * enumerate the sub-directory of source director each
	 * sub-directory represents one MTA
	 */
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		if (2 == limit_type) {
			sprintf(temp_path, "%s/%s/data/smtp/domain_limit/allow/%s.txt",
				g_mount_path, direntp->d_name, domain);
		} else {
			sprintf(temp_path, "%s/%s/data/smtp/domain_limit/deny/%s.txt",
				g_mount_path, direntp->d_name, domain);
		}
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[setup_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			len = sprintf(temp_object, "%s\n", pitem + (256 + 256) * i);
			write(fd, temp_object, len);
		}
		close(fd);
	}
	closedir(dirp);
	list_file_free(pfile);
	if (2 == limit_type) {
		snprintf(command_line, 1024, "domain_limit.pas remove deny %s", domain);
		gateway_control_notify(command_line, NOTIFY_SMTP);
		snprintf(command_line, 1024, "domain_limit.pas add allow %s", domain);
		gateway_control_notify(command_line, NOTIFY_SMTP);
	} else {
		snprintf(command_line, 1024, "domain_limit.pas remove allow %s", domain);
		gateway_control_notify(command_line, NOTIFY_SMTP);
		snprintf(command_line, 1024, "domain_limit.pas add deny %s", domain);
		gateway_control_notify(command_line, NOTIFY_SMTP);
	}
}

static void setup_ui_remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

	if (0 != lstat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 256, "%s/%s", path, direntp->d_name);
		setup_ui_remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}

static BOOL setup_ui_unzip(const char *domain)
{
	pid_t pid;
	int status;
	char tmp_path[256];
	char tmp_path1[256];
	char *args[] = {"unzip", NULL, NULL, NULL, NULL};
	
	snprintf(tmp_path, 255, "%s/%s/steep-webapp/tmp", g_app_path, domain);
	snprintf(tmp_path1, 255, "%s/%s/steep-webapp/tmp_theme.zip", g_app_path, domain);
	pid = fork();
	if (0 == pid) {
		args[1] = tmp_path1;
		args[2] = "-d";
		args[3] = tmp_path;
		if (-1 == execvp("unzip", args)) {
			exit(EXIT_FAILURE);
		}
	} else if (pid > 0) {
		waitpid(pid, &status, 0);
		remove(tmp_path1);
		if (0 == WEXITSTATUS(status)) {
			return TRUE;
		} else {
			return FALSE;
		}
	} else {
		return FALSE;
	}
}

static void setup_ui_set_theme(const char *domain)
{
	char *language;
	const char *charset;
	char temp_path[256];
	char temp_path1[256];
	struct stat node_stat;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	sprintf(temp_path, "%s/%s/steep-webapp/theme", g_app_path, domain);
	setup_ui_remove_inode(temp_path);
	snprintf(temp_path, 255, "%s/%s/steep-webapp/tmp_theme.zip", g_app_path, domain);
	if (0 != stat(temp_path, &node_stat)) {
		system_log_info("[upload_ui]: fail to stat "
				"uploaded zip file %s\n", temp_path);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (0 == node_stat.st_size) {
		remove(temp_path);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource, "MSGERR_DELETED", language));
		return;
	}
	if (FALSE == setup_ui_unzip(domain)) {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
		return;
	}
	sprintf(temp_path1, "%s/%s/steep-webapp/tmp/theme", g_app_path, domain);
	if (0 != stat(temp_path1, &node_stat) || 0 == S_ISDIR(node_stat.st_mode)) {
		sprintf(temp_path, "%s/%s/steep-webapp/tmp", g_app_path, domain);
		setup_ui_remove_inode(temp_path);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_THEMEERR", language));
	}
	sprintf(temp_path1, "%s/%s/steep-webapp/tmp/theme/css/theme.css", g_app_path, domain);
	if (0 != stat(temp_path1, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		sprintf(temp_path, "%s/%s/steep-webapp/tmp", g_app_path, domain);
		setup_ui_remove_inode(temp_path);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_CSSERR", language));
	}
	sprintf(temp_path1, "%s/%s/steep-webapp/tmp/theme", g_app_path, domain);
	sprintf(temp_path, "%s/%s/steep-webapp/theme", g_app_path, domain);
	if (0 == rename(temp_path1, temp_path)) {
		sprintf(temp_path, "%s/%s/steep-webapp/tmp", g_app_path, domain);
		setup_ui_remove_inode(temp_path);
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
	} else {
		printf("Content-Type:text/html;charset=%s\n\n", charset);
		printf(HTML_ACTIVE_FAIL, charset,
			lang_resource_get(g_lang_resource,"MSGERR_UNSAVED", language));
	}
	return;
}

static void setup_ui_decode_url(char *src, char *dest)
{
	int code;
	char *last;

	last = src + strlen(src);

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
	*dest = '\0';
}

static void setup_ui_encode_line(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if (' ' == in[i] || '\\' == in[i] || '\t' == in[i] || '#' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

