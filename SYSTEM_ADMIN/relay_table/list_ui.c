#include "list_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "reload_control.h"
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

/* fill blacklist title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(ip, port) {location.href='%s?session=%s&ip=' + ip + \n\
'&port=' + port;}\n\
function ModifyItem(ip, port, bit64, memo) {\n\
opeform.ip.value=ip; opeform.port.value=port; opeform.bit64.value=bit64, opeform.memo.value=memo;}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" size=16 tabindex=1 \n\
name=ip />&nbsp;:&nbsp;<INPUT type=text value=\"8000\" size=4 tabindex=2 \n\
name=port />&nbsp;&nbsp<SELECT name=bit64><OPTION value=1 selected>64bit</OPTION> \n\
<OPTION value=0>32bit</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" \n\
size=34 tabindex=3 name=memo /></TD></TR><TR><TD></TD><TD></TD><TD>\n\
<INPUT type=submit tabindex=4 value=\"%s\" onclick=\"\
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
alert('%s');\n\
opeform.port.value='';\n\
opeform.port.focus();\n\
return false;}\n\
return true;\" />\n\
</TD></TR></TABLE></FORM><TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill list table title here */

#define HTML_MAIN_7	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=4><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_MAIN_8	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;32bit|64bit&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%d&nbsp;</TD>\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;<A href=\"javascript:DeleteItem('%s', %d)\">%s</A> | \n\
<A href=\"javascript:ModifyItem('%s', %d, %d, '%s')\">%s</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct LIST_ITEM {
	char ip[16];
	char memo[256];
	int port;
	int bit64;
} LIST_ITEM;

static void list_ui_encode_line(const char *in, char *out);
	
static void	list_ui_modify_list(const char *ip, int port,
	int bit64, const char *memo);

static void list_ui_remove_item(const char *ip, int port);
			
static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *session);

static void list_ui_broadcast_list();

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static BOOL g_switch_on;
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;


void list_ui_init(const char *list_path, const char *mount_path,
	BOOL switch_on, const char *url_link, const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	g_switch_on = switch_on;
	strcpy(g_resource_path, resource_path);
}

int list_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char memo[256];
	char ip_addr[16];
	char temp_ip[16];
	char temp_port[16];
	char session[256];
	char search_buff[1024];
	int len, port, bit64;

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
				if (search_buff + len - ptr1 - 1 > 256) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_SETUP)) {
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
				
				list_ui_main_html(session);
				return 0;
			}
			if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
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
			ptr2 = search_string(search_buff, "&bit64=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 16 ||
					search_buff + len - ptr1 - 1 == 0) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_port, ptr1, search_buff + len - ptr1 - 1);
				temp_port[search_buff + len - ptr1 - 1] = '\0';
				port = atoi(temp_port);
				if (port <= 0) {
					system_log_info("[list_ui]: ip address in GET query "
						"string error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				
				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_SETUP)) {
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
				
				list_ui_remove_item(ip_addr, port);
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
			memcpy(temp_port, ptr1, ptr2 - ptr1);
			temp_port[ptr2 - ptr1] = '\0';
			port = atoi(temp_port);
			if (port <= 0) {
				system_log_info("[list_ui]: ip address in GET query "
					"string error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = ptr2 + 7;
			ptr2 = search_string(search_buff, "&memo=", len);
			if (NULL == ptr2 || 1 != ptr2 - ptr1 ||
				(*ptr1 != '0' && *ptr1 != '1')) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}

			if ('1' == *ptr1) {
				bit64 = 1;
			} else {
				bit64 = 0;
			}

			ptr1 = ptr2 + 6;
			if (search_buff + len - ptr1 - 1 > 256) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(memo, ptr1, search_buff + len - ptr1 - 1);
			memo[search_buff + len - ptr1 - 1] = '\0';
			ltrim_string(memo);
			rtrim_string(memo);
			if ('\0' == memo[0]) {
				strcpy(memo, "none");
			}
			
			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_SETUP)) {
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
			
			list_ui_modify_list(ip_addr, port, bit64, memo);
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
	int i, len;
	int item_num;
	time_t cur_time;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char temp_buff[128];
	LIST_ITEM *pitem;
	char* str_table[] = {"32bit", "64bit"}; 
	
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:16%s:256%d%d");
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
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_PORT", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	if (TRUE == g_switch_on) {
		printf("(%s)", lang_resource_get(g_lang_resource,"SWITCH_ON", language));
	} else {
		printf("(%s)", lang_resource_get(g_lang_resource,"SWITCH_OFF", language));
	}
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST,lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_PORT", language),
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(pitem[i].memo, "none")) {
			printf(HTML_TBITEM_NORMAL, pitem[i].ip, pitem[i].port,
				str_table[pitem[i].bit64],
				lang_resource_get(g_lang_resource,"MAIN_NONE", language),
				pitem[i].ip, pitem[i].port,  
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				pitem[i].ip, pitem[i].port, pitem[i].bit64, pitem[i].memo,
				lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
		} else {
			printf(HTML_TBITEM_NORMAL, pitem[i].ip, pitem[i].port,
				str_table[pitem[i].bit64],
				pitem[i].memo, pitem[i].ip, pitem[i].port, 
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				pitem[i].ip, pitem[i].port, pitem[i].bit64, pitem[i].memo,
				lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
		}
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

static void	list_ui_modify_list(const char *ip, int port,
	int bit64, const char *memo)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_memo[512];
	char temp_line[1024];
	LIST_ITEM *pitem;

	pfile = list_file_init(g_list_path, "%s:16%s:256%d%d");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip) && port == pitem[i].port) {
			break;
		}
	}
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
			list_ui_encode_line(pitem[j].memo, temp_memo);
			len = sprintf(temp_line, "%s\t%s\t%d\t%d\n", pitem[j].ip, temp_memo,
					pitem[j].port, pitem[j].bit64);
			write(fd, temp_line, len);

		}
		list_ui_encode_line(memo, temp_memo);
		len = sprintf(temp_line, "%s\t%s\t%d\t%d\n", ip, temp_memo, port, bit64);
		write(fd, temp_line, len);
		close(fd);
		list_file_free(pfile);
		remove(g_list_path);
		link(temp_path, g_list_path);
		remove(temp_path);
	} else {
		list_file_free(pfile);
		fd = open(g_list_path, O_APPEND|O_WRONLY);
		if (-1 == fd) {
			system_log_info("[list_ui]: fail to open %s in append mode",
				g_list_path);
			return;
		}
		list_ui_encode_line(memo, temp_memo);
		len = sprintf(temp_line, "%s\t%s\t%d\t%d\n", ip, temp_memo, port, bit64);
		write(fd, temp_line, len);
		close(fd);
	}
	list_ui_broadcast_list();
	reload_control_notify();
}

static void list_ui_remove_item(const char *ip, int port)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_memo[512];
	char temp_line[1024];
	LIST_ITEM *pitem;

	pfile = list_file_init(g_list_path, "%s:16%s:256%d%d");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", g_list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip) && port == pitem[i].port) {
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
		list_ui_encode_line(pitem[j].memo, temp_memo);
		len = sprintf(temp_line, "%s\t%s\t%d\t%d\n", pitem[j].ip, temp_memo,
				pitem[j].port, pitem[j].bit64);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	list_ui_broadcast_list();
	reload_control_notify();
}

static void list_ui_encode_line(const char *in, char *out)
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

static void list_ui_broadcast_list()
{
	DIR *dirp;
	int item_num;
	int i, len, fd;
	char temp_ip[32];
	char temp_path[256];
	struct dirent *direntp;
	LIST_FILE *pfile;
	LIST_ITEM *pitem;
	
	
	pfile = list_file_init(g_list_path, "%s:16%s:256%d%d");
	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to open blacklist %s",
			g_list_path);
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (LIST_ITEM*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[list_ui]: fail to open directory %s\n",
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
		sprintf(temp_path, "%s/%s/data/delivery/relay_agent.txt",
			g_mount_path, direntp->d_name);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[list_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			len = sprintf(temp_ip, "%s:%d\t%d\n", pitem[i].ip, pitem[i].port, pitem[i].bit64);
			write(fd, temp_ip, len);
		}
		close(fd);
	}
	closedir(dirp);
	list_file_free(pfile);
}

