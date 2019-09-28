#include "list_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
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

/* fill list title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(ip, type) {location.href='%s?session=%s&ip=' + ip + \n\
'&type=' + type;}\n\
function ModifyItem(ip, port, type, mailbox, username, password) {\n\
opeform.ip.value=ip; opeform.port.value=port;\n\
opeform.type.value=type; opeform.mailbox.value=mailbox;\n\
opeform.username.value=username; opeform.password.value=password;\n\
opeform.mailbox.focus();}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" size=16 tabindex=1 \n\
name=ip />&nbsp;:&nbsp;<INPUT type=text value=\"\" size=2 tabindex=2 \n\
name=port /></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<SELECT tabindex=3 name=type><OPTION value=0 selected>%s</OPTION>\n\
<OPTION value=1>%s</OPTION><OPTION value=2>%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" \
size=24 tabindex=4 name=mailbox /></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" \
size=24 tabindex=5 name=username /></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" \
size=24 tabindex=6 name=password /></TD></TR>\n\
<TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=7 value=\"%s\" \
onclick=\"\
var scount = 0;\n\
var str_ip = opeform.ip.value;\n\
var iplength = str_ip.length;\n\
var letters = \'1234567890. \';\n\
if (iplength == 0) return false;\n\
for (i=0; i<opeform.ip.value.length; i++) {\n\
var check_char = opeform.ip.value.charAt(i);\n\
if (letters.indexOf(check_char) == -1) {\n\
alert (\'%s\');\n\
opeform.ip.value=\'\';\n\
opeform.ip.focus();\n\
return false;\n}\n}\n\
for (var i=0;i<iplength;i++)\n\
(str_ip.substr(i,1)==\'.\')?scount++:scount;\n\
if(scount!=3) {\n\
alert (\'%s\');\n\
opeform.ip.value=\'\';\n\
opeform.ip.focus();\n\
return false;}\n\
var port_num;\n\
port_num = parseInt(opeform.port.value);\n\
if (isNaN(port_num)) {\n\
alert(\'%s\');\n\
opeform.port.value=\'\';\n\
opeform.port.focus();\n\
return false;}\n\
var apos;\n\
var dotpos;\n\
apos=opeform.mailbox.value.indexOf('@');\n\
dotpos=opeform.mailbox.value.lastIndexOf('.');\n\
if (apos<1||dotpos-apos<2) {\n\
alert(\'%s\');\n\
opeform.mailbox.value=\'\';\n\
opeform.mailbox.focus();\n\
return false;}\n\
if (opeform.username.value.length==0) {\n\
alert(\'%s\');\n\
opeform.username.value=\'\';\n\
opeform.username.focus();\n\
return false;}\n\
if (opeform.password.value.length==0) {\n\
alert(\'%s\');\n\
opeform.password.value=\'\';\n\
opeform.password.focus();\n\
return false;}\n\
return true;\" />\n\
</TD></TR><TR><TD colspan=3>%s</TD></TR></TABLE></FORM>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill list table title here */

#define HTML_MAIN_7	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_MAIN_8	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s\
&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;\
</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>\
&nbsp;%d&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;%s&nbsp</TD><TD>&nbsp;<A href=\"javascript:DeleteItem('%s', %d)\"\
>%s</A> | <A href=\"javascript:ModifyItem('%s', %d, %d, '%s', '%s', '%s')\">%s\
</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define TYPE_SMTP_IN		0
#define TYPE_SMTP_OUT		1
#define TYPE_POP3			2

#define TOKEN_CONTROL				100
#define CTRL_RESTART_SUPERVISOR		2


typedef struct _LIST_ITEM {
	char type[16];
	char mailbox[256];
	char username[256];
	char password[256];
	char ip[16];
	int port;
} LIST_ITEM;

static void	list_ui_modify_list(const char *ip, int port, int type, 
	const char *mailbox, const char *username, const char *password);

static void list_ui_remove_item(const char *ip, int type);
			
static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *session);

static void list_ui_restart_service();

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[256];
static char g_token_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void list_ui_init(const char *list_path, const char *token_path,
	const char *url_link, const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_token_path, token_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int list_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char mailbox[256];
	char username[256];
	char password[256];
	char ip_addr[16];
	char temp_ip[16];
	char session[256];
	char temp_buff[16];
	char post_buff[1024];
	char search_buff[1024];
	int type, len, port;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		list_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[list_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[list_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[list_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[list_ui]: fail to get QUERY_STRING "
				"environment!");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 1024) {
				system_log_info("[list_ui]: query string too long!");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			list_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = search_string(search_buff, "&ip=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1> 255) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_MISC)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_TIMEOUT", language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				default:
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_SESSION", language));
					return 0;
				}
				
				list_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 4;
			ptr2 = search_string(search_buff, "&port=", len);
			if (NULL == ptr2) {
				ptr2 = search_string(search_buff, "&type=", len);
				if (NULL == ptr2) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_ip, ptr1, ptr2 - ptr1);
				temp_ip[ptr2 - ptr1] = '\0';
				ltrim_string(temp_ip);
				rtrim_string(temp_ip);
				if (NULL == extract_ip(temp_ip, ip_addr)) {
					system_log_info("[list_ui]: ip address in GET query "
						"string error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				ptr1 = ptr2 + 6;
				if (search_buff + len - ptr1 - 1 != 1) {
					system_log_info("[list_ui]: cannot find memo in GET query "
						"string");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				if ('0' == *ptr1) {
					type = TYPE_SMTP_IN;
				} else if ('1' == *ptr1) {
					type = TYPE_SMTP_OUT;
				} else if ('2' == *ptr1) {
					type = TYPE_POP3;
				} else {
					system_log_info("[list_ui]: type in GET query "
						"string error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_MISC)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_TIMEOUT", language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				default:
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_SESSION", language));
					return 0;
				}

				list_ui_remove_item(ip_addr, type);
				list_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 16) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_ip, ptr1, ptr2 - ptr1);
			temp_ip[ptr2 - ptr1] = '\0';
			ltrim_string(temp_ip);
			rtrim_string(temp_ip);
			if (NULL == extract_ip(temp_ip, ip_addr)) {
				system_log_info("[list_ui]: ip address in GET query "
					"string error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			
			ptr1 = ptr2 + 6;
			ptr2 = search_string(search_buff, "&type=", len);
			if (NULL == ptr2) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 16) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			port = atoi(temp_buff);
			
			ptr1 = ptr2 + 6;
			ptr2 = search_string(search_buff, "&mailbox=", len);
			if (NULL == ptr2) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 - ptr1 != 1) {
				system_log_info("[list_ui]: type in GET query "
					"string error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			
			if ('0' == *ptr1) {
				type = TYPE_SMTP_IN;
			} else if ('1' == *ptr1) {
				type = TYPE_SMTP_OUT;
			} else if ('2' == *ptr1) {
				type = TYPE_POP3;
			} else {
				system_log_info("[list_ui]: type in GET query "
					"string error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			
			ptr1 = ptr2 + 9;
			ptr2 = search_string(search_buff, "&username=", len);
			if (NULL == ptr2) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(mailbox, ptr1, ptr2 - ptr1);
			mailbox[ptr2 - ptr1] = '\0';
			ltrim_string(mailbox);
			rtrim_string(mailbox);

			ptr1 = ptr2 + 10;
			ptr2 = search_string(search_buff, "&password=", len);
			if (NULL == ptr2) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(username, ptr1, ptr2 - ptr1);
			username[ptr2 - ptr1] = '\0';
			ltrim_string(username);
			rtrim_string(username);
			
			ptr1 = ptr2 + 10;
			if (search_buff + len - ptr1 - 1 > 256) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(password, ptr1, search_buff + len - ptr1 - 1);
			password[search_buff + len - ptr1 - 1] = '\0';

			switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_MISC)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			default:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			list_ui_modify_list(ip_addr, port, type, mailbox,
				username, password);
			list_ui_main_html(session);
			return 0;
		}
	} else {
		system_log_info("[list_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int list_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void list_ui_free()
{
	/* do nothing */
}

static BOOL list_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[list_ui]: fail to get "
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

static void list_ui_error_html(const char *error_string)
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

static void list_ui_main_html(const char *session)
{
	int type;
	int i, len;
	int item_num;
	time_t cur_time;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char item_type[256];
	LIST_ITEM *pitem;
	struct tm temp_tm, *ptm;
	
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:16:%s:256%s:256%s:256%s:16%d");
	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to open list file %s",
			g_list_path);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pitem = (LIST_ITEM*)list_file_get_list(pfile);
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
	printf(HTML_MAIN_5, url_buff, session);
	printf(url_buff);
	printf(HTML_MAIN_6, session,
		lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_SMTP_IN", language),
		lang_resource_get(g_lang_resource,"MAIN_SMTP_OUT", language),
		lang_resource_get(g_lang_resource,"MAIN_POP3", language),
		lang_resource_get(g_lang_resource,"MAIN_MAILBOX", language),
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_PASSWORD", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_PORT", language),
		lang_resource_get(g_lang_resource,"MSGERR_MAILBOX", language),
		lang_resource_get(g_lang_resource,"MSGERR_USERNAME", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD", language),
		lang_resource_get(g_lang_resource,"CAUTION_LABEL", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_PORT", language),
		lang_resource_get(g_lang_resource,"MAIN_MAILBOX", language),
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		if (0 == strcmp("SMTP_IN", pitem[i].type)) {
			type = TYPE_SMTP_IN;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_SMTP_IN", language));
		} else if (0 == strcmp("SMTP_OUT", pitem[i].type)) {
			type = TYPE_SMTP_OUT;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_SMTP_OUT", language));
		} else {
			type = TYPE_POP3;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_POP3", language));
		}
	
		printf(HTML_TBITEM_NORMAL, item_type, pitem[i].ip, pitem[i].port,
			pitem[i].mailbox, pitem[i].username, pitem[i].password,
			pitem[i].ip, type, lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
			pitem[i].ip, pitem[i].port, type, pitem[i].mailbox,
			pitem[i].username, pitem[i].password,
			lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
	}
	list_file_free(pfile);
	printf(HTML_MAIN_8);
}

static void list_ui_unencode(char *src, char *last, char *dest)
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

static void	list_ui_modify_list(const char *ip, int port, int type, 
	const char *mailbox, const char *username, const char *password)
{
	int len, fd;
	int i, j, item_num;
	time_t cur_time;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_type[32];
	char temp_line[1024];
	LIST_ITEM *pitem;


	if (TYPE_SMTP_IN == type) {
		strcpy(temp_type, "SMTP_IN");
	} else if (TYPE_SMTP_OUT == type) {
		strcpy(temp_type, "SMTP_OUT");
	} else {
		strcpy(temp_type, "POP3");
	}
	
	pfile = list_file_init(g_list_path, "%s:16:%s:256%s:256%s:256%s:16%d");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip) &&
			0 == strcasecmp(temp_type, pitem[i].type)) {
			break;
		}
	}
	time(&cur_time);
	sprintf(temp_path, "%s.tmp", g_list_path);
	if (i < item_num) {
		fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[list_ui]: fail to create %s", temp_path);
			list_file_free(pfile);
			return;
		}
		for (j=0; j<item_num; j++) {
			if (j == i) {
				continue;
			}
			len = sprintf(temp_line, "%s\t%s\t%s\t%s\t%s\t%d\n",
				pitem[j].type, pitem[j].mailbox, pitem[j].username,
				pitem[j].password, pitem[j].ip, pitem[j].port);
			write(fd, temp_line, len);
		}
		if (TYPE_SMTP_IN == type) {
			len = sprintf(temp_line, "SMTP_IN\t%s\t%s\t%s\t%s\t%d\n",
					mailbox, username, password, ip, port);
		} else if (TYPE_SMTP_OUT == type) {
			len = sprintf(temp_line, "SMTP_OUT\t%s\t%s\t%s\t%s\t%d\n",
					mailbox, username, password, ip, port);
		} else {
			len = sprintf(temp_line, "POP3\t%s\t%s\t%s\t%s\t%d\n",
					mailbox, username, password, ip, port);
		}
		write(fd, temp_line, len);
		close(fd);
		list_file_free(pfile);
		remove(g_list_path);
		link(temp_path, g_list_path);
		remove(temp_path);
		list_ui_restart_service();
	} else {
		list_file_free(pfile);
		fd = open(g_list_path, O_APPEND|O_WRONLY);
		if (-1 == fd) {
			system_log_info("[list_ui]: fail to open %s in append mode",
				g_list_path);
			return;
		}
		if (TYPE_SMTP_IN == type) {
			len = sprintf(temp_line, "SMTP_IN\t%s\t%s\t%s\t%s\t%d\n",
					mailbox, username, password, ip, port);
		} else if (TYPE_SMTP_OUT == type) {
			len = sprintf(temp_line, "SMTP_OUT\t%s\t%s\t%s\t%s\t%d\n",
					mailbox, username, password, ip, port);
		} else {
			len = sprintf(temp_line, "POP3\t%s\t%s\t%s\t%s\t%d\n",
					mailbox, username, password, ip, port);
		}
		write(fd, temp_line, len);
		close(fd);
		list_ui_restart_service();
	}
}

static void list_ui_remove_item(const char *ip, int type)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_type[32];
	char temp_line[1024];
	LIST_ITEM *pitem;

	if (TYPE_SMTP_IN == type) {
		strcpy(temp_type, "SMTP_IN");
	} else if (TYPE_SMTP_OUT == type) {
		strcpy(temp_type, "SMTP_OUT");
	} else {
		strcpy(temp_type, "POP3");
	}

	pfile = list_file_init(g_list_path, "%s:16:%s:256%s:256%s:256%s:16%d");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", g_list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip) &&
			0 == strcasecmp(temp_type, pitem[i].type)) {
			break;
		}
	}
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[list_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	for (j=0; j<item_num; j++) {
		if (j == i) {
			continue;
		}
		len = sprintf(temp_line, "%s\t%s\t%s\t%s\t%s\t%d\n",
			pitem[j].type, pitem[j].mailbox, pitem[j].username,
			pitem[j].password, pitem[j].ip, pitem[j].port);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	list_ui_restart_service();
}


static void list_ui_restart_service()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;

	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[list_ui]: cannot open key for control\n");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_SUPERVISOR;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

