#include "table_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include <gromox/gateway_control.h>
#include "session_client.h"
#include "data_source.h"
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
function DeleteItem(passive, dest) {location.href='%s?domain=%s&session=%s&passive=' + passive + '&dest=' + dest;}\n\
function ModifyItem(passive, type, dest) {\
opeform.passive.value=passive; opeform.type.value=type; \
opeform.dest.value=dest; opeform.dest.focus();}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=passive /></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<SELECT name=type><OPTION value=0>%s</OPTION><OPTION value=1>%s</OPTION>\n\
<OPTION value=2 selected>%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD>\n\
<INPUT type=text value=\"\" tabindex=2 name=dest /></TD></TR>\n\
<TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=3 value=\"%s\" onclick=\n\
\"with (opeform.dest) {\n\
	apos=value.indexOf('@');\n\
	dotpos=value.lastIndexOf('.');\n\
	if (apos<1||dotpos-apos<2) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if(opeform.passive.value == 0) {return false;} else {return true;}\" />\n\
</TD></TR><TR><TD colSpan=3>%s</TD></TR></TABLE></FORM>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
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
<P align=right><A href=domain_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s\
&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>\
&nbsp;%s&nbsp;</TD><TD>&nbsp;\
<A href=\"javascript:DeleteItem('%s', '%s')\">%s</A> | \
<A href=\"javascript:ModifyItem('%s', '%d', '%s')\">%s</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define DOMAIN_PRIVILEGE_MONITOR                      0x2

#define TYPE_IN			0
#define TYPE_OUT		1
#define	TYPE_ALL		2

typedef struct _BLACKLIST_ITEM {
	char passive[256];
	char type[12];
	char dest[256];
} BLACKLIST_ITEM;

static void table_ui_encode_line(const char *in, char *out);

static void table_ui_encode_squote(const char *in, char *out);

static void	table_ui_modify_list(const char *doman, const char *passive,
	int type,const char *dest);

static void table_ui_remove_item(const char *domain, const char *passive,
	const char *dest);
			
static void table_ui_error_html(const char *error_string);

static void table_ui_main_html(const char *domain, const char *session);

static void table_ui_broadcast_list(const char *domain);

static BOOL table_ui_get_self(char *url_buff, int length);

static void table_ui_unencode(char *src, char *last, char *dest);

static char g_mount_path[256];
static char g_logo_link[1024];
static char g_domain_path[256];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void table_ui_init(const char *mount_path, const char *url_link,
	const char *resource_path)
{
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int table_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *ptr1, *ptr2;
	char dest[256];
	char temp_passive[256];
	char domain[256];
	char session[256];
	char search_buff[1024];
	int type, len;
	int privilege_bits;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		table_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[table_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[table_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	if (0 == strcmp(request, "POST")) {
		table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[table_ui]: fail to get QUERY_STRING "
				"environment!");
			table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 ==len || len > 1024) {
				system_log_info("[table_ui]: query string too long!");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			table_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "domain=", len);
			if (NULL == ptr1) {
				system_log_info("[table_ui]: query string of GET "
					"format error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 7;
			ptr2 = search_string(ptr1, "&session=", len);
			if (NULL == ptr2) {
				system_log_info("[table_ui]: query string of GET "
					"format error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[table_ui]: query string of GET format error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(domain, ptr1, ptr2 - ptr1);
			domain[ptr2 - ptr1] = '\0';
			lower_string(domain);
			ptr1 = ptr2 + 9;
			ptr2 = search_string(search_buff, "&passive=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 256) {
					system_log_info("[table_ui]: query string of GET "
						"format error");
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';
				if (FALSE == session_client_check(domain, session)) {
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				if (FALSE == data_source_info_domain(domain, &privilege_bits,
					g_domain_path) || '\0' == g_domain_path[0]) {
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				if ((privilege_bits&DOMAIN_PRIVILEGE_MONITOR) == 0) {
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				}
				
				table_ui_main_html(domain, session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[table_ui]: query string of GET "
					"format error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 9;
			ptr2 = search_string(search_buff, "&type=", len);
			if (NULL == ptr2) {
				ptr2 = search_string(search_buff, "&dest=", len);
				if (ptr2 <= ptr1 || ptr2 - ptr1 > 256) {
					system_log_info("[table_ui]: GET query string error, cannot"
						"find dest string ");
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_passive, ptr1, ptr2 - ptr1);
				temp_passive[ptr2 - ptr1] = '\0';
				ltrim_string(temp_passive);
				rtrim_string(temp_passive);
				ptr1 = ptr2 + 6;
				
				if (search_buff + len - ptr1 - 1 > 256 ||
					search_buff + len - ptr1 - 1 == 0) {
					system_log_info("[table_ui]: query string of GET "
						"format error");
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(dest, ptr1, search_buff + len - ptr1 - 1);
				dest[search_buff + len - ptr1 - 1] = '\0';
				ltrim_string(dest);
				rtrim_string(dest);
				if (FALSE == session_client_check(domain, session)) {
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				if (FALSE == data_source_info_domain(domain, &privilege_bits,
					g_domain_path) || '\0' == g_domain_path[0]) {
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				
				if ((privilege_bits&DOMAIN_PRIVILEGE_MONITOR) == 0) {
					table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				}
				
				table_ui_remove_item(domain, temp_passive, dest);
				table_ui_main_html(domain, session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 256) {
				system_log_info("[table_ui]: query string of GET "
					"format error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_passive, ptr1, ptr2 - ptr1);
			temp_passive[ptr2 - ptr1] = '\0';
			ltrim_string(temp_passive);
			rtrim_string(temp_passive);
			ptr1 = ptr2 + 6;
			ptr2 = search_string(search_buff, "&dest=", len);
			if (NULL == ptr2) {
				system_log_info("[table_ui]: GET query string error, cannot"
					"find dest string ");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 - ptr1 != 1) {
				system_log_info("[table_ui]: query string of GET "
					"format error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if ('0' == *ptr1) {
				type = TYPE_IN;
			} else if ('1' == *ptr1) {
				type = TYPE_OUT;
			} else if ('2' == *ptr1) {
				type = TYPE_ALL;
			} else {
				system_log_info("[table_ui]: type in GET query "
					"string error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = ptr2 + 6;
			if (search_buff + len - ptr1 - 1 > 256 ||
				search_buff + len - ptr1 - 1 == 0) {
				system_log_info("[table_ui]: query string of GET "
					"format error");
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(dest, ptr1, search_buff + len - ptr1 - 1);
			dest[search_buff + len - ptr1 - 1] = '\0';
			ltrim_string(dest);
			rtrim_string(dest);
			if ('\0' == dest[0]) {
				strcpy(dest, "none");
			}
			if (FALSE == session_client_check(domain, session)) {
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			if (FALSE == data_source_info_domain(domain, &privilege_bits,
				g_domain_path) || '\0' == g_domain_path[0]) {
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			
			if ((privilege_bits&DOMAIN_PRIVILEGE_MONITOR) == 0) {
				table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			}
				
			table_ui_modify_list(domain, temp_passive, type, dest);
			table_ui_main_html(domain, session);
			return 0;
		}
	} else {
		system_log_info("[table_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int table_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void table_ui_free()
{
	/* do nothing */
}

static BOOL table_ui_get_self(char *url_buff, int length)
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

static void table_ui_error_html(const char *error_string)
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

static void table_ui_main_html(const char *domain, const char *session)
{
	int type;
	int i;
	int item_num;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char item_type[256];
	char list_path[256];
	char temp_dest[512];
	char temp_passive[512];
	BLACKLIST_ITEM *pitem;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");

	if (FALSE == table_ui_get_self(url_buff, 1024)) {
		table_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	snprintf(list_path, 256, "%s/monitor.txt", g_domain_path);
	pfile = list_file_init(list_path, "%s:256%s:12%s:256");
	if (NULL != pfile) {
		pitem = (BLACKLIST_ITEM*)list_file_get_list(pfile);
		item_num = list_file_get_item_num(pfile);
	} else {
		pitem = NULL;
		item_num = 0;
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
	printf(HTML_MAIN_5, url_buff, domain, session);
	printf(url_buff);
	printf(HTML_MAIN_6, domain, session,
		lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_IN", language),
		lang_resource_get(g_lang_resource,"MAIN_OUT", language),
		lang_resource_get(g_lang_resource,"MAIN_ALL", language),
		lang_resource_get(g_lang_resource,"MAIN_DEST", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"TIP_SINGLE_OBJECT", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_DEST", language),
		lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		if (0 == strcmp("IN", pitem[i].type)) {
			type = TYPE_IN;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_IN", language));
		} else if (0 == strcmp("OUT", pitem[i].type)) {
			type = TYPE_OUT;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_OUT", language));
		} else if (0 == strcmp("ALL", pitem[i].type)) {
			type = TYPE_ALL;
			strcpy(item_type, lang_resource_get(g_lang_resource,"MAIN_ALL", language));
		} else {
			continue;
		}
		table_ui_encode_squote(pitem[i].passive, temp_passive);
		table_ui_encode_squote(pitem[i].dest, temp_dest);
		printf(HTML_TBITEM_NORMAL, pitem[i].passive,
				pitem[i].dest, item_type, temp_passive, temp_dest, 
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				temp_passive, type, temp_dest,
				lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
	}
	if (NULL != pfile) {
		list_file_free(pfile);
	}
	printf(HTML_MAIN_8);
}

static void table_ui_unencode(char *src, char *last, char *dest)
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

static void	table_ui_modify_list(const char *domain, const char *passive,
	int type, const char *dest)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char list_path[256];
	char temp_path[256];
	char temp_dest[512];
	char temp_line[1024];
	char command_line[1024];
	char temp_passive[128];
	BLACKLIST_ITEM *pitem;

	snprintf(list_path, 256, "%s/monitor.txt", g_domain_path);
	pfile = list_file_init(list_path, "%s:256%s:12%s:256");
	if (NULL == pfile) {
		fd = open(list_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[table_ui]: fail to create %s", list_path);
			return;
		}
		table_ui_encode_line(passive, temp_passive);
		table_ui_encode_line(dest, temp_dest);
		if (TYPE_IN == type) {
			len = sprintf(temp_line, "%s\tIN\t%s\n", temp_passive, temp_dest);
		} else if (TYPE_OUT == type) {
			len = sprintf(temp_line, "%s\tOUT\t%s\n", temp_passive, temp_dest);
		} else if (TYPE_ALL == type) {
			len = sprintf(temp_line, "%s\tALL\t%s\n", temp_passive, temp_dest);
		} else {
			len = 0;
		}
		write(fd, temp_line, len);
		close(fd);
		table_ui_broadcast_list(domain);
		snprintf(command_line, 1024, "domain_monitor.hook add %s", domain);
		gateway_control_notify(command_line, NOTIFY_DELIVERY);
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(passive, pitem[i].passive) &&
			0 == strcasecmp(dest, pitem[i].dest)) {
			break;
		}
	}
	sprintf(temp_path, "%s.tmp", list_path);
	if (i < item_num) {
		fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[table_ui]: fail to create %s", temp_path);
			list_file_free(pfile);
			return;
		}
		for (j=0; j<item_num; j++) {
			if (j == i) {
				continue;
			}
			table_ui_encode_line(pitem[j].passive, temp_passive);
			table_ui_encode_line(pitem[j].dest, temp_dest);
			len = sprintf(temp_line, "%s\t%s\t%s\n", temp_passive,
					pitem[j].type, temp_dest);
			write(fd, temp_line, len);

		}
		table_ui_encode_line(passive, temp_passive);
		table_ui_encode_line(dest, temp_dest);
		if (TYPE_IN == type) {
			len = sprintf(temp_line, "%s\tIN\t%s\n", temp_passive, temp_dest);
		} else if (TYPE_OUT == type) {
			len = sprintf(temp_line, "%s\tOUT\t%s\n", temp_passive, temp_dest);
		} else if (TYPE_ALL == type) {
			len = sprintf(temp_line, "%s\tALL\t%s\n", temp_passive, temp_dest);
		} else {
			len = 0;
		}
		write(fd, temp_line, len);
		close(fd);
		list_file_free(pfile);
		remove(list_path);
		link(temp_path, list_path);
		remove(temp_path);
		table_ui_broadcast_list(domain);
		snprintf(command_line, 1024, "domain_monitor.hook add %s", domain);
		gateway_control_notify(command_line, NOTIFY_DELIVERY);
	} else {
		list_file_free(pfile);
		fd = open(list_path, O_APPEND|O_WRONLY);
		if (-1 == fd) {
			system_log_info("[table_ui]: fail to open %s in append mode",
				list_path);
			return;
		}
		table_ui_encode_line(passive, temp_passive);
		table_ui_encode_line(dest, temp_dest);
		if (TYPE_IN == type) {
			len = sprintf(temp_line, "%s\tIN\t%s\n", temp_passive, temp_dest);
		} else if (TYPE_OUT == type) {
			len = sprintf(temp_line, "%s\tOUT\t%s\n", temp_passive, temp_dest);
		} else if (TYPE_ALL == type) {
			len = sprintf(temp_line, "%s\tALL\t%s\n", temp_passive, temp_dest);
		} else {
			len = 0;
		}
		write(fd, temp_line, len);
		close(fd);
		table_ui_broadcast_list(domain);
		snprintf(command_line, 1024, "domain_monitor.hook add %s", domain);
		gateway_control_notify(command_line, NOTIFY_DELIVERY);
	}
}

static void table_ui_remove_item(const char *domain, const char *passive,
	const char *dest)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char list_path[256];
	char temp_path[256];
	char temp_dest[512];
	char temp_line[1024];
	char command_line[1024];
	char temp_passive[128];
	BLACKLIST_ITEM *pitem;
	struct stat node_stat;

	snprintf(list_path, 256, "%s/monitor.txt", g_domain_path);
	pfile = list_file_init(list_path, "%s:256%s:12%s:256");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(passive, pitem[i].passive) &&
			0 == strcasecmp(dest, pitem[i].dest)) {
			break;
		}
	}
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[table_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	for (j=0; j<item_num; j++) {
		if (j == i) {
			continue;
		}
		table_ui_encode_line(pitem[j].passive, temp_passive);
		table_ui_encode_line(pitem[j].dest, temp_dest);
		len = sprintf(temp_line, "%s\t%s\t%s\n", temp_passive,
				pitem[j].type, temp_dest);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(list_path);
	if (0 == stat(temp_path, &node_stat) && 0 == node_stat.st_size) {
		remove(temp_path);
		snprintf(command_line, 1024, "domain_monitor.hook remove %s", domain);
	} else {
		link(temp_path, list_path);
		remove(temp_path);
		table_ui_broadcast_list(domain);
		snprintf(command_line, 1024, "domain_monitor.hook add %s", domain);
	}
	gateway_control_notify(command_line, NOTIFY_DELIVERY);
}

static void table_ui_encode_line(const char *in, char *out)
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

static void table_ui_broadcast_list(const char *domain)
{
	DIR *dirp;
	int i, len, fd;
	int item_num;
	char list_path[256];
	char temp_line[1024];
	char temp_path[256];
	struct dirent *direntp;
	LIST_FILE *pfile;
	BLACKLIST_ITEM *pitem;
	
	
	snprintf(list_path, 256, "%s/monitor.txt", g_domain_path);
	pfile = list_file_init(list_path, "%s:256%s:12%s:256");
	if (NULL == pfile) {
		system_log_info("[table_ui]: fail to open whitelist %s",
			list_path);
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (BLACKLIST_ITEM*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[table_ui]: fail to open directory %s\n",
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
		sprintf(temp_path, "%s/%s/data/delivery/domain_monitor/%s.txt",
			g_mount_path, direntp->d_name, domain);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[table_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			if (0 == strcmp(pitem[i].type, "IN")) {
				len = sprintf(temp_line, "F_IN\t%s\t%s\n", pitem[i].passive,
						pitem[i].dest);
			} else if (0 == strcmp(pitem[i].type, "OUT")) {
				len = sprintf(temp_line, "F_OUT\t%s\t%s\n", pitem[i].passive,
						pitem[i].dest);
			} else if (0 == strcmp(pitem[i].type, "ALL")) {
				len = sprintf(temp_line, "F_ALL\t%s\t%s\n", pitem[i].passive,
						pitem[i].dest);
			} else {
				len = 0;
			}
			write(fd, temp_line, len);
		}
		close(fd);
	}
	closedir(dirp);
	list_file_free(pfile);
}

static void table_ui_encode_squote(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if ('\'' == in[i] || '\\' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

