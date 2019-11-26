#include "list_ui.h"
#include "acl_control.h"
#include "system_log.h"
#include "list_file.h"
#include "lang_resource.h"
#include "reload_control.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ipc.h>
#include <sys/msg.h>
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

/* fill table title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function RemoveItem(ip, port) {location.href='%s?session=%s&ip=' + ip + '&port=' + port;}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="


#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=prefix /></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<INPUT type=text value=\"\" tabindex=2 name=ip /></TD></TR>\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text class=RightInput size=5 \n\
value=\"5556\" tabindex=3 name=port /></TD></TR><TR><TD></TD><TD></TD> \n\
<TD><INPUT type=submit tabindex=6 \n\
value=\"    %s    \" onclick=\"if (opeform.prefix.value.length == 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (opeform.ip.value.length == 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var num = parseInt(opeform.port.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
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
return true;\" /></TD></TR>\n\
</TABLE></FORM><TABLE cellSpacing=0 cellPadding=0 \n\
width=\"90%\" border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill table title here */

#define HTML_MAIN_7 \
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_MAIN_8	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR>\n\
<TABLE width=\"90%\" border=0 cellpadding=1 cellspacing=1><TR>\n\
<TD height=\"23\" align=\"left\" nowrap>\n"

#define HTML_MAIN_9	"</TD></TR></TABLE><P></P><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST	\
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%d&nbsp;</TD><TD>&nbsp;<A href=\"javascript:RemoveItem('%s', %d)\">%s</A>&nbsp;</TD></TR>\n"


#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


typedef struct _ARCHIVE_ITEM {
	char prefix[128];
	char ip[16];
	int port;
} ARCHIVE_ITEM;


static void	list_ui_add_item(const char *prefix, const char *ip, int port);

static void list_ui_remove_item(const char *ip, int port);
			
static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *session);

static void list_ui_broadcast_list();

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;


void list_ui_init(const char *list_path, const char *mount_path,
	const char *url_link, const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path); 
}

int list_ui_run()
{
	int len;
	char *query;
	int host_port;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char prefix[128];
	char host_ip[256];
	char session[256];
	char search_buff[1024];
	char temp_buff[16];
	

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
			ptr2 = search_string(search_buff, "&prefix=", len);
			if (NULL == ptr2) {
				ptr2 = search_string(search_buff, "&ip=", len);
				if (NULL == ptr2) {
					if (search_buff + len - ptr1 - 1 > 256 ||
						search_buff + len - ptr1 - 1 == 0) {
						system_log_info("[list_ui]: query string of GET "
							"format error");
						list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
								language));
						return 0;
					}
					memcpy(session, ptr1, search_buff + len - ptr1 - 1);
					session[search_buff + len  - ptr1 - 1] = '\0';

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
				
				
				if (ptr2 <= ptr1 || ptr2 - ptr1 > 256) {
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
				if (NULL == ptr2 || ptr2 - ptr1 >= 16) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
							language));
					return 0;
				}
				memcpy(host_ip, ptr1, ptr2 - ptr1);
				host_ip[ptr2 - ptr1] = '\0';
				
				ptr1 = ptr2 + 6;
				if (search_buff + len - ptr1 - 1 > 16 ||
					search_buff + len - 1 - ptr1 == 0) {
					system_log_info("[list_ui]: query string of GET "
						"format error");
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_buff, ptr1, search_buff + len - ptr1 - 1);
				temp_buff[search_buff + len - ptr1 - 1] = '\0';
				host_port = atoi(temp_buff);

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
				
				list_ui_remove_item(host_ip, host_port);
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
				
			ptr1 = ptr2 + 8;
			ptr2 = search_string(search_buff, "&ip=", len);
			if (NULL == ptr2 || ptr2 - ptr1 > 128) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			
			memcpy(prefix, ptr1, ptr2 - ptr1);
			prefix[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 4;
			ptr2 = search_string(search_buff, "&port=", len);
			if (NULL == ptr2 || ptr2 - ptr1 > 16) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(host_ip, ptr1, ptr2 - ptr1);
			host_ip[ptr2 - ptr1] = '\0';
			

			ptr1 = ptr2 + 6;
			if (search_buff + len - 1 - ptr1 > 16 ||
				search_buff + len - 1 - ptr1 == 0) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_buff, ptr1, search_buff + len - 1 - ptr1);
			temp_buff[search_buff + len - 1 - ptr1] = '\0';
			host_port = atoi(temp_buff);
			
			list_ui_add_item(prefix, host_ip, host_port);
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
	int offset;
	int item_num;
	int i, len, fd;
	char *ptoken;
	char *language;
	char temp_buff[1024];
	char url_buff[1024];
	LIST_FILE *pfile;
	ARCHIVE_ITEM *pitem;
	
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:128%s:16%d");
	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to open list file %s",
			g_list_path);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pitem = (ARCHIVE_ITEM*)list_file_get_list(pfile);
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
		lang_resource_get(g_lang_resource,"MAIN_STORAGE", language),
		lang_resource_get(g_lang_resource,"MAIN_HOST", language),
		lang_resource_get(g_lang_resource,"MAIN_PORT", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_STORAGE", language),
		lang_resource_get(g_lang_resource,"MSGERR_HOST", language),
		lang_resource_get(g_lang_resource,"MSGERR_PORT", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language));
	
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	
	printf(HTML_MAIN_7);
	
	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_STORAGE", language),
		lang_resource_get(g_lang_resource,"MAIN_HOST", language),
		lang_resource_get(g_lang_resource,"MAIN_PORT", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		printf(HTML_TBITEM_NORMAL, pitem[i].prefix, pitem[i].ip,
			pitem[i].port, pitem[i].ip, pitem[i].port,
			lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
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

static void	list_ui_add_item(const char *prefix, const char *ip, int port)
{
	int len, fd;
	int i, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_line[1024];
	ARCHIVE_ITEM *pitem;
	
	
	pfile = list_file_init(g_list_path, "%s:128%s:16%d");
	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to init %s", g_list_path);
		return;
	}
	snprintf(temp_path, 256, "%s.tmp", g_list_path);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[list_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip) && port == pitem[i].port) {
			continue;
		} else {
			len = sprintf(temp_line, "%s\t%s\t%d\n", pitem[i].prefix,
					pitem[i].ip, pitem[i].port);
		}
		write(fd, temp_line, len);
	}
	len = sprintf(temp_line, "%s\t%s\t%d\n", prefix, ip, port);
	write(fd, temp_line, len);
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	rename(temp_path, g_list_path);
	list_ui_broadcast_list();
	reload_control_notify();
}

static void list_ui_remove_item(const char *ip, int port)
{
	int len, fd;
	int i, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_line[1024];
	ARCHIVE_ITEM *pitem;
	
	
	pfile = list_file_init(g_list_path, "%s:128%s:16%d");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", g_list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[list_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(ip, pitem[i].ip) && port == pitem[i].port) {
			continue;
		}
		len = sprintf(temp_line, "%s\t%s\t%d\n", pitem[i].prefix,
				pitem[i].ip, pitem[i].port);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	rename(temp_path, g_list_path);
	list_ui_broadcast_list();
	reload_control_notify();
}

static void list_ui_broadcast_list()
{
	int fd;
	DIR *dirp;
	char *pbuff;
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;
	
	
	if (0 != stat(g_list_path, &node_stat)) {
		return;
	}
	
	if (0 ==  S_ISREG(node_stat.st_mode)) {
		return;
	}
	
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return;
	}
	
	fd = open(g_list_path, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		return;
	}
	
	close(fd);
	
	
	dirp = opendir(g_mount_path);
	if (NULL == dirp) {
		free(pbuff);
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
		sprintf(temp_path, "%s/%s/data/delivery/cidb_list.txt",
			g_mount_path, direntp->d_name);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[list_ui]: fail to truncate %s", temp_path);
			continue;
		}
		write(fd, pbuff, node_stat.st_size);
		close(fd);
	}
	closedir(dirp);
	free(pbuff);
}
