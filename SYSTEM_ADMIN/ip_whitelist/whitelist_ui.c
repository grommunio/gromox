#include "whitelist_ui.h"
#include "system_log.h"
#include "acl_control.h"
#include "lang_resource.h"
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

/* fill whitelist title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(ip) {location.href='%s?session=%s&ip=' + ip;}\n\
function ModifyItem(ip, type, memo) {\
opeform.ip.value=ip; opeform.type.value=type; opeform.memo.value=memo; \
opeform.memo.focus();}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=ip /></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\
<SELECT name=type><OPTION value=0 selected>%s</OPTION><OPTION value=1>%s\
</OPTION><OPTION value=2>%s</OPTION></SELECT></TD></TR><TR><TD></TD>\n\
<TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=2 name=memo /></TD></TR>\
<TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=3 value=\"%s\" \
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
return true;\n\" />\n\
</TD></TR></TABLE></FORM><TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill whitelist table title here */

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
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s\
&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>\
&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\
<A href=\"javascript:DeleteItem('%s')\">%s</A> | \
<A href=\"javascript:ModifyItem('%s', '%d', '%s')\">%s</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define TYPE_NORMAL			0
#define TYPE_EXTEND			1
#define TYPE_ABSOLUTE		2


typedef struct _WHITELIST_ITEM {
	char ip[16];
	time_t time;
	char type[8];
	char memo[256];
} WHITELIST_ITEM;

typedef struct _BLACKLIST_ITEM {
	char ip[16];
	time_t time;
	char memo[256];
} BLACKLIST_ITEM;

static void whitelist_ui_encode_line(const char *in, char *out);
	
static void	whitelist_ui_modify_list(const char *ip, int type,const char *memo);

static void whitelist_ui_remove_item(const char *ip);
			
static void whitelist_ui_error_html(const char *error_string);

static void whitelist_ui_main_html(const char *session);

static void whitelist_ui_broadcast_list();

static BOOL whitelist_ui_get_self(char *url_buff, int length);

static void whitelist_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[256];
static char g_black_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void whitelist_ui_init(const char *list_path, const char *black_path,
	const char *mount_path, const char *url_link, const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_black_path, black_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int whitelist_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char memo[256];
	char ip_addr[16];
	char temp_ip[16];
	char session[256];
	char post_buff[1024];
	char search_buff[1024];
	char temp_buff[8];
	int type, len;
	int year, month;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		whitelist_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[whitelist_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[whitelist_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -1;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[whitelist_ui]: fail to get REMOTE_ADDR environment!");
		return -2;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[whitelist_ui]: fail to get QUERY_STRING "
				"environment!");
			whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 1024) {
				system_log_info("[whitelist_ui]: query string too long!");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			whitelist_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[whitelist_ui]: query string of GET "
					"format error");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = search_string(search_buff, "&ip=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 256) {
					system_log_info("[whitelist_ui]: query string of GET "
						"format error");
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_ANTI_SPAM)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_TIMEOUT", language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				default:
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_SESSION", language));
					return 0;
				}
				
				whitelist_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[whitelist_ui]: query string of GET "
					"format error");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 4;
			ptr2 = search_string(search_buff, "&type=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 16 ||
					search_buff + len - ptr1 - 1 == 0) {
					system_log_info("[whitelist_ui]: query string of GET "
						"format error");
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_ip, ptr1, search_buff + len - ptr1 - 1);
				temp_ip[search_buff + len - ptr1 - 1] = '\0';
				ltrim_string(temp_ip);
				rtrim_string(temp_ip);
				if (NULL == extract_ip(temp_ip, ip_addr)) {
					system_log_info("[whitelist_ui]: ip address in GET query "
						"string error");
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_ANTI_SPAM)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_TIMEOUT", language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				default:
					whitelist_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_SESSION", language));
					return 0;
				}
				
				whitelist_ui_remove_item(ip_addr);
				whitelist_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 16) {
				system_log_info("[whitelist_ui]: query string of GET "
					"format error");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_ip, ptr1, ptr2 - ptr1);
			temp_ip[ptr2 - ptr1] = '\0';
			ltrim_string(temp_ip);
			rtrim_string(temp_ip);
			if (NULL == extract_ip(temp_ip, ip_addr)) {
				system_log_info("[whitelist_ui]: ip address in GET query "
					"string error");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = ptr2 + 6;
			ptr2 = search_string(search_buff, "&memo=", len);
			if (NULL == ptr2) {
				system_log_info("[whitelist_ui]: cannot find memo in GET query "
					"string");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 < ptr1 || ptr2 - ptr1 != 1) {
				system_log_info("[whitelist_ui]: type in GET query "
					"string error");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if ('0' == *ptr1) {
				type = TYPE_NORMAL;
			} else if ('1' == *ptr1) {
				type = TYPE_EXTEND;
			} else if ('2' == *ptr1) {
				type = TYPE_ABSOLUTE;
			} else {
				system_log_info("[whitelist_ui]: type in GET query "
					"string error");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = ptr2 + 6;
			if (search_buff + len - ptr1 - 1 > 256) {
				system_log_info("[whitelist_ui]: query string of GET "
					"format error");
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
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
				ACL_PRIVILEGE_ANTI_SPAM)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_TIMEOUT", language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_PRIVILEGE", language));
				return 0;
			default:
				whitelist_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_SESSION", language));
				return 0;
			}
			
			whitelist_ui_modify_list(ip_addr, type, memo);
			whitelist_ui_main_html(session);
			return 0;
		}
	} else {
		system_log_info("[whitelist_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int whitelist_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void whitelist_ui_free()
{
	/* do nothing */
}

static BOOL whitelist_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[whitelist_ui]: fail to get "
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

static void whitelist_ui_error_html(const char *error_string)
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

static void whitelist_ui_main_html(const char *session)
{
	int type;
	int i, len;
	int item_num;
	time_t cur_time;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char item_type[256];
	char temp_buff[128];
	WHITELIST_ITEM *pitem;
	struct tm temp_tm, *ptm;
	
	
	if (FALSE == whitelist_ui_get_self(url_buff, 1024)) {
		whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:16%l%s:8%s:256");
	if (NULL == pfile) {
		system_log_info("[whitelist_ui]: fail to open list file %s",
			g_list_path);
		whitelist_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pitem = (WHITELIST_ITEM*)list_file_get_list(pfile);
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
		lang_resource_get(g_lang_resource,"MAIN_NORMAL", language),
		lang_resource_get(g_lang_resource,"MAIN_EXTEND", language),
		lang_resource_get(g_lang_resource,"MAIN_ABSOLUTE", language),
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_TIME", language),
		lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		strftime(temp_buff, 128, lang_resource_get(g_lang_resource,"MAIN_TIME_FORMAT",
			language), localtime(&pitem[i].time));
		if (0 == strcmp("EXT", pitem[i].type)) {
			type = TYPE_EXTEND;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_EXTEND", language));
		} else if (0 == strcmp("ABS", pitem[i].type)) {
			type = TYPE_ABSOLUTE;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_ABSOLUTE", language));
		} else {
			type = TYPE_NORMAL;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_NORMAL", language));
		}
		if (0 == strcmp(pitem[i].memo, "none")) {
			printf(HTML_TBITEM_NORMAL, temp_buff, pitem[i].ip, item_type,
				lang_resource_get(g_lang_resource,"MAIN_NONE", language),
				pitem[i].ip, lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				pitem[i].ip, type, pitem[i].memo,
				lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
		} else {
			printf(HTML_TBITEM_NORMAL, temp_buff, pitem[i].ip, item_type,
				pitem[i].memo, pitem[i].ip, 
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				pitem[i].ip, type, pitem[i].memo,
				lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
		}
	}
	list_file_free(pfile);
	printf(HTML_MAIN_8);
}

static void whitelist_ui_unencode(char *src, char *last, char *dest)
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

static void	whitelist_ui_modify_list(const char *ip, int type, const char *memo)
{
	int len, fd;
	int i, j, item_num;
	time_t cur_time;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_memo[512];
	char temp_line[1024];
	WHITELIST_ITEM *pitem;

	pfile = list_file_init(g_list_path, "%s:16%l%s:8%s:256");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip)) {
			break;
		}
	}
	time(&cur_time);
	sprintf(temp_path, "%s.tmp", g_list_path);
	if (i < item_num) {
		fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[whitelist_ui]: fail to create %s", temp_path);
			list_file_free(pfile);
			return;
		}
		for (j=0; j<item_num; j++) {
			if (j == i) {
				continue;
			}
			whitelist_ui_encode_line(pitem[j].memo, temp_memo);
			len = sprintf(temp_line, "%s\t%ld\t%s\t%s\n", pitem[j].ip,
					pitem[j].time, pitem[j].type, temp_memo);
			write(fd, temp_line, len);

		}
		whitelist_ui_encode_line(memo, temp_memo);
		if (TYPE_NORMAL == type) {
			len = sprintf(temp_line, "%s\t%ld\tNOR\t%s\n", ip, cur_time,
					temp_memo);
		} else if (TYPE_ABSOLUTE == type) {
			len = sprintf(temp_line, "%s\t%ld\tABS\t%s\n", ip, cur_time,
					temp_memo);
		} else {
			len = sprintf(temp_line, "%s\t%ld\tEXT\t%s\n", ip, cur_time,
					temp_memo);
		}
		write(fd, temp_line, len);
		close(fd);
		list_file_free(pfile);
		remove(g_list_path);
		link(temp_path, g_list_path);
		remove(temp_path);
		whitelist_ui_broadcast_list();
		reload_control_notify();
	} else {
		list_file_free(pfile);
		fd = open(g_list_path, O_APPEND|O_WRONLY);
		if (-1 == fd) {
			system_log_info("[whitelist_ui]: fail to open %s in append mode",
				g_list_path);
			return;
		}
		whitelist_ui_encode_line(memo, temp_memo);
		if (TYPE_NORMAL == type) {
			len = sprintf(temp_line, "%s\t%ld\tNOR\t%s\n", ip, cur_time, 
					temp_memo);
		} else if (TYPE_ABSOLUTE == type) {
			len = sprintf(temp_line, "%s\t%ld\tABS\t%s\n", ip, cur_time, 
					temp_memo);
		} else {
			len = sprintf(temp_line, "%s\t%ld\tEXT\t%s\n", ip, cur_time, 
					temp_memo);
		}
		write(fd, temp_line, len);
		close(fd);
		whitelist_ui_broadcast_list();
		reload_control_notify();
	}
}

static void whitelist_ui_remove_item(const char *ip)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_memo[512];
	char temp_line[1024];
	WHITELIST_ITEM *pitem;

	pfile = list_file_init(g_list_path, "%s:16%l%s:8%s:256");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", g_list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip)) {
			break;
		}
	}
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[whitelist_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	for (j=0; j<item_num; j++) {
		if (j == i) {
			continue;
		}
		whitelist_ui_encode_line(pitem[j].memo, temp_memo);
		len = sprintf(temp_line, "%s\t%ld\t%s\t%s\n", pitem[j].ip,
				pitem[j].time, pitem[j].type, temp_memo);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	whitelist_ui_broadcast_list();
	reload_control_notify();
}

static void whitelist_ui_encode_line(const char *in, char *out)
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

static void whitelist_ui_broadcast_list()
{
	DIR *dirp;
	int i, len;
	int fd1, fd2, fd3;
	int item_num;
	int black_num;
	char temp_ip[32];
	char temp_path[256];
	struct dirent *direntp;
	LIST_FILE *pfile;
	LIST_FILE *pfile_black;
	WHITELIST_ITEM *pitem;
	BLACKLIST_ITEM *pblack;
	
	
	pfile = list_file_init(g_list_path, "%s:16%l%s:8%s:256");
	pfile_black = list_file_init(g_black_path, "%s:16%l%s:256");
	if (NULL == pfile) {
		system_log_info("[whitelist_ui]: fail to open whitelist %s",
			g_list_path);
		return;
	}
	if (NULL == pfile_black) {
		system_log_info("[whitelist_ui]: fail to open blacklist %s",
			g_list_path);
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (WHITELIST_ITEM*)list_file_get_list(pfile);
	black_num = list_file_get_item_num(pfile_black);
	pblack = (BLACKLIST_ITEM*)list_file_get_list(pfile_black);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[whitelist_ui]: fail to open directory %s\n",
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
		sprintf(temp_path, "%s/%s/data/smtp/ip_whitelist.txt", g_mount_path,
			direntp->d_name);
		fd1 = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd1) {
			system_log_info("[whitelist_ui]: fail to truncate %s", temp_path);
			continue;
		}
		sprintf(temp_path, "%s/%s/data/smtp/ip_filter.txt", g_mount_path,
			direntp->d_name);
		fd2 = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd2) {
			system_log_info("[whitelist_ui]: fail to truncate %s", temp_path);
			continue;
		}
		sprintf(temp_path, "%s/%s/data/smtp/relay_list.txt", g_mount_path,
			direntp->d_name);
		fd3 = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd3) {
			system_log_info("[whitelist_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<black_num; i++) {
			len = sprintf(temp_ip, "%s\t0\t0second\n", pblack[i].ip);
			write(fd2, temp_ip, len);
		}
		for (i=0; i<item_num; i++) {
			if (0 == strcmp(pitem[i].type, "ABS")) {
				len = sprintf(temp_ip, "%s\n", pitem[i].ip);
				write(fd3, temp_ip, len);
			} else {
				if (0 == strcmp(pitem[i].type, "EXT")) {
					len = sprintf(temp_ip, "%s\t1\t0second\n", pitem[i].ip);
					write(fd2, temp_ip, len);
				}
				len = sprintf(temp_ip, "%s\n", pitem[i].ip);
				write(fd1, temp_ip, len);
			}
		}
		close(fd1);
		close(fd2);
		close(fd3);
	}
	closedir(dirp);
	list_file_free(pfile);
	list_file_free(pfile_black);
}

