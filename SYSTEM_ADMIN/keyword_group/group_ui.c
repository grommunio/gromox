#include "group_ui.h"
#include "system_log.h"
#include "acl_control.h"
#include "lang_resource.h"
#include "data_extractor.h"
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
function DeleteGroup(index) {location.href='%s?session=%s\
&action=remove-group&group=' + index;}\n\
function DeleteKeyword(kwd_index, grp_index) {location.href='%s?session=%s\
&action=remove-keyword&keyword=' + kwd_index + '&group=' + grp_index;}\n\
</SCRIPT><FORM class=SearchForm name=grpform method=get action=%s >\n\
<TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"add-group\" name=action />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=group /></TD></TR><TR><TD></TD><TD></TD><TD><INPUT type=submit \n\
tabindex=2 value=\"    %s    \" onclick=\"\
if (grpform.group.value.length == 0) {\n\
grpform.group.focus();\n\
return false;}\n\
return true;\" />\n\
</TD></TR></TABLE></FORM><HR><FORM class=SearchForm name=kwdform method=get \n\
action=%s ><TABLE border=0><INPUT type=hidden value=%s \n\
name=session /><INPUT type=hidden value=\"add-keyword\" name=action />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=3 \n\
name=keyword /></TD></TR><TR><TD></TD><TD>%s:</TD><TD><SELECT name=group>\n"

#define HTML_MAIN_6	\
"</SELECT></TD></TR><TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=4 \n\
value=\"    %s    \" onclick=\"\
if (kwdform.keyword.value.length == 0) {\n\
kwdform.keyword.focus();\n\
return false;}\n\
return true;\n\" />\n\
</TD></TR></TABLE></FORM><TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill table title here */

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
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD colSpan=2>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_GROUP_1	\
"<TR class=SolidRow><TD>&nbsp;%s:%s&nbsp;</TD><TD>&nbsp;%s:%d&nbsp;</TD><TD>"

#define HTML_TBITEM_GROUP_2	\
"</TD><TD>&nbsp;<A href=\"javascript:DeleteGroup('%d')\">%s</A></TD></TR>\n"

#define HTML_TBITEM_KEYWORD	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD colSpan=2>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;<A href=\"javascript:DeleteKeyword('%d', %d)\">%s</A></TD></TR>\n"

#define HTML_OPTION_NORMAL       "<OPTION value=%d>%s</OPTION>"

#define HTML_OPTION_SELECTED "<OPTION value=%d selected>%s</OPTION>"

#define HTML_CHART_32   "<IMG src=\"../data/picture/bar32.png\">"
#define HTML_CHART_16   "<IMG src=\"../data/picture/bar16.png\">"
#define HTML_CHART_8    "<IMG src=\"../data/picture/bar08.png\">"
#define HTML_CHART_4    "<IMG src=\"../data/picture/bar04.png\">"
#define HTML_CHART_2    "<IMG src=\"../data/picture/bar02.png\">"
#define HTML_CHART_1    "<IMG src=\"../data/picture/bar01.png\">"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


typedef struct _KEYWORD_ITEM {
	char keyword[256];
	time_t time;
} KEYWORD_ITEM;

static void group_ui_encode_line(const char *in, char *out);
	
static void	group_ui_add_keyword(const char *keyword, int group_index);

static void group_ui_remove_keyword(int keyword_index, int group_index);

static void group_ui_add_group(const char *group);

static void group_ui_remove_group(int group_index);
			
static void group_ui_error_html(const char *error_string);

static void group_ui_main_html(const char *session);

static void group_ui_broadcast_list();

static BOOL group_ui_get_self(char *url_buff, int length);

static void group_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void group_ui_init(const char *list_path, const char *mount_path,
	const char *url_link, const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int group_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char group[32];
	char action[64];
	char keyword[256];
	char session[256];
	char password[256];
	char post_buff[1024];
	char search_buff[1024];
	char temp_buff[8];
	int kwd_index, grp_index, len;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		group_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[group_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[group_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[group_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			goto GET_ERROR;
		} else {
			len = strlen(query);
			if (0 == len || len > 1024) {
				goto GET_ERROR;
			}
			group_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				goto GET_ERROR;
			}
			ptr1 += 8;
			ptr2 = search_string(search_buff, "&action=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 255) {
					goto GET_ERROR;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_ANTI_SPAM)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					group_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_TIMEOUT", language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					group_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				default:
					group_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_SESSION", language));
					return 0;
				}
				
				group_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				goto GET_ERROR;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_ANTI_SPAM)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				group_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_TIMEOUT", language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				group_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_PRIVILEGE", language));
				return 0;
			default:
				group_ui_error_html(lang_resource_get(g_lang_resource,
					"ERROR_SESSION", language));
				return 0;
			}
			
			ptr1 = ptr2 + 8;
			ptr2 = strchr(ptr1, '&');
			if (NULL == ptr2 || ptr2 - ptr1 >= 64) {
				goto GET_ERROR;
			}
			memcpy(action, ptr1, ptr2 - ptr1);
			action[ptr2 - ptr1] = '\0';
			if (0 == strcasecmp(action, "add-group")) {
				if (0 != strncasecmp(ptr2, "&group=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (search_buff + len - ptr1 - 1 > 32 ||
					0 == search_buff + len - ptr1) {
					goto GET_ERROR;
				}
				memcpy(group, ptr1, search_buff + len - ptr1 - 1);
				group[search_buff + len - ptr1 - 1] = '\0';
				ltrim_string(group);
				rtrim_string(group);
				group_ui_add_group(group);
			} else if (0 == strcasecmp(action, "remove-group")) {
				if (0 != strncasecmp(ptr2, "&group=", 7)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 7;
				if (search_buff + len - ptr1 - 1 > 8 ||
					0 == search_buff + len - ptr1) {
					goto GET_ERROR;
				}
				memcpy(temp_buff, ptr1, search_buff + len - ptr1 - 1);
				temp_buff[search_buff + len - ptr1 - 1] = '\0';
				grp_index = atoi(temp_buff);
				group_ui_remove_group(grp_index);
			} else if (0 == strcasecmp(action, "add-keyword")) {
				if (0 != strncasecmp(ptr2, "&keyword=", 9)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 9;
				ptr2 = search_string(search_buff, "&group=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 255) {
					goto GET_ERROR;
				}
				memcpy(keyword, ptr1, ptr2 - ptr1);
				keyword[ptr2 - ptr1] = '\0';
				ptr1 = ptr2 + 7;
				if (search_buff + len - ptr1 - 1 > 8 ||
					0 == search_buff + len - ptr1 - 1) {
					goto GET_ERROR;
				}
				memcpy(temp_buff, ptr1, search_buff + len - ptr1 - 1);
				temp_buff[search_buff + len - ptr1 - 1] = '\0';
				grp_index = atoi(temp_buff);
				group_ui_add_keyword(keyword, grp_index);
			} else if (0 == strcasecmp(action, "remove-keyword")) {
				if (0 != strncasecmp(ptr2, "&keyword=", 9)) {
					goto GET_ERROR;
				}
				ptr1 = ptr2 + 9;
				ptr2 = search_string(search_buff, "&group=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 8) {
					goto GET_ERROR;
				}
				memcpy(temp_buff, ptr1, ptr2 - ptr1);
				temp_buff[ptr2 - ptr1] = '\0';
				kwd_index = atoi(temp_buff);
				ptr1 = ptr2 + 7;
				if (search_buff + len - ptr1 - 1 > 8 ||
					0 == search_buff + len - ptr1 - 1) {
					goto GET_ERROR;
				}
				memcpy(temp_buff, ptr1, search_buff + len - ptr1 - 1);
				temp_buff[search_buff + len - ptr1 - 1] = '\0';
				grp_index = atoi(temp_buff);
				group_ui_remove_keyword(kwd_index, grp_index);
			} else {
				goto GET_ERROR;
			}
			group_ui_main_html(session);
			return 0;
		}
	} else {
		system_log_info("[group_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		group_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
GET_ERROR:
	system_log_info("[group_ui]: query string of GET format error");
	group_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
	return 0;
}

int group_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void group_ui_free()
{
	/* do nothing */
}

static BOOL group_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[group_ui]: fail to get "
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

static void group_ui_error_html(const char *error_string)
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

static void group_ui_main_html(const char *session)
{
	int i, len;
	int max_num;
	int item_num;
	int temp_num;
	int base_val;
	int keyword_index;
	int group_index;
	struct tm *ptm;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char temp_buff[128];
	int *statistic_array;
	KEYWORD_ITEM *pitem;
	
	
	if (FALSE == group_ui_get_self(url_buff, 1024)) {
		group_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:256%l");
	if (NULL == pfile) {
		system_log_info("[group_ui]: fail to open list file %s",
			g_list_path);
		group_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pitem = (KEYWORD_ITEM*)list_file_get_list(pfile);
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
	printf(HTML_MAIN_5, url_buff, session, url_buff, session, url_buff,
		session, lang_resource_get(g_lang_resource,"MAIN_GROUP", language),
		lang_resource_get(g_lang_resource,"ADDGROUP_LABEL", language), url_buff, session,
		lang_resource_get(g_lang_resource,"MAIN_KEYWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_GROUP", language));
	for (i=0, group_index=-1; i<item_num; i++) {
		if (0 == strncmp(pitem[i].keyword, "--------", 8)) {
			group_index ++;
			if (0 == group_index) {
				printf(HTML_OPTION_SELECTED, group_index, pitem[i].keyword + 8);
			} else {
				printf(HTML_OPTION_NORMAL, group_index, pitem[i].keyword + 8);
			}
		}
	}
	
	printf(HTML_MAIN_6, lang_resource_get(g_lang_resource,"ADDKEYWORD_LABEL", language));
	
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	
	printf(HTML_MAIN_7);
	statistic_array = (int*)malloc((group_index + 1)*sizeof(int));
	data_extractor_retrieve(statistic_array, group_index + 1);
	
	max_num = 0;
	for (i=0; i<=group_index; i++) {
		if (statistic_array[i] > max_num) {
			max_num = statistic_array[i];
		}
	}
	base_val = max_num / 64;
	
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_KEYWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_TIME", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	
	for (i=0, group_index=-1; i<item_num; i++) {
		if (0 == strncmp(pitem[i].keyword, "--------", 8)) {
			group_index ++;
			keyword_index = 0;
			printf(HTML_TBITEM_GROUP_1,
				lang_resource_get(g_lang_resource,"MAIN_GROUP", language),
				pitem[i].keyword + 8,
				lang_resource_get(g_lang_resource,"MAIN_STATISTIC", language),
				statistic_array[group_index]);

			if (0 == base_val) {
				printf(HTML_TBITEM_GROUP_2, group_index,
					lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
				continue;
			}
			temp_num = statistic_array[group_index];
			if (1 == temp_num / (base_val*64)) {
				printf(HTML_CHART_32);
				printf(HTML_CHART_32);
				temp_num = 0;
			}
			if (1 == temp_num / (base_val*32)) {
				printf(HTML_CHART_32);
				temp_num = temp_num % (base_val*32);
			}
			if (1 == temp_num / (base_val*16)) {
				printf(HTML_CHART_16);
				temp_num = temp_num % (base_val*16);
			}
			if (1 == temp_num / (base_val*8)) {
				printf(HTML_CHART_8);
				temp_num = temp_num % (base_val*8);
			}
			if (1 == temp_num / (base_val*4)) {
				printf(HTML_CHART_4);
				temp_num = temp_num % (base_val*4);
			}
			if (1 == temp_num / (base_val*2)) {
				printf(HTML_CHART_2);
				temp_num = temp_num % (base_val*2);
			}
			if (1 == temp_num / base_val) {
				printf(HTML_CHART_1);
			}
			printf(HTML_TBITEM_GROUP_2, pitem[i].keyword + 8,
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		} else {
			ptm = localtime(&pitem[i].time);
			strftime(temp_buff, 128, lang_resource_get(g_lang_resource,"MAIN_TIME_FORMAT",
				language), ptm);
			printf(HTML_TBITEM_KEYWORD, pitem[i].keyword, temp_buff,
				keyword_index, group_index,
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
			keyword_index ++;
		}
	}
	free(statistic_array);
	list_file_free(pfile);
	printf(HTML_MAIN_8);
}

static void group_ui_unencode(char *src, char *last, char *dest)
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

static void	group_ui_add_keyword(const char *keyword, int group_index)
{
	int len, fd;
	int i, item_num;
	int temp_index;
	time_t cur_time;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_line[1024];
	char temp_keyword[512];
	KEYWORD_ITEM *pitem;

	time(&cur_time);
	sprintf(temp_path, "%s.tmp", g_list_path);
	pfile = list_file_init(g_list_path, "%s:256%l");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(pitem[i].keyword, keyword)) {
			list_file_free(pfile);
			return;
		}
	}
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[group_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	
	for (i=0, temp_index=-1; i<item_num; i++) {
		group_ui_encode_line(pitem[i].keyword, temp_keyword);
		len = sprintf(temp_line, "%s\t%ld\n", temp_keyword, pitem[i].time);
		write(fd, temp_line, len);
		if (0 == strncmp(pitem[i].keyword, "--------", 8)) {
			temp_index ++;
			if (temp_index == group_index) {
				group_ui_encode_line(keyword, temp_keyword);
				len = sprintf(temp_line, "%s\t%ld\n", temp_keyword, cur_time);
				write(fd, temp_line, len);
			}
		}
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	group_ui_broadcast_list();
	reload_control_notify();
}

static void group_ui_remove_keyword(int keyword_index, int group_index)
{
	int len, fd;
	int i, item_num;
	int temp_index;
	int temp_index_ex;
	time_t cur_time;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_line[1024];
	char temp_keyword[512];
	KEYWORD_ITEM *pitem;

	time(&cur_time);
	sprintf(temp_path, "%s.tmp", g_list_path);
	pfile = list_file_init(g_list_path, "%s:256%l");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[group_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	temp_index = -1;
	temp_index_ex = -1;
	for (i=0; i<item_num; i++) {
		if (0 == strncmp(pitem[i].keyword, "--------", 8)) {
			temp_index ++;
		}
		if (temp_index != group_index || keyword_index != temp_index_ex) {
			group_ui_encode_line(pitem[i].keyword, temp_keyword);
			len = sprintf(temp_line, "%s\t%ld\n", temp_keyword, pitem[i].time);
			write(fd, temp_line, len);
		}
		if (temp_index == group_index) {
			temp_index_ex ++;
		}
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	group_ui_broadcast_list();
	reload_control_notify();
}
	
static void group_ui_add_group(const char *group)
{
	int fd, i, len;
	int item_num;
	LIST_FILE *pfile;
	char temp_buff[256];
	char temp_line[1024];
	KEYWORD_ITEM *pitem;
	
	pfile = list_file_init(g_list_path, "%s:256%l");
	if (NULL != pfile) {
		pitem = list_file_get_list(pfile);
		item_num = list_file_get_item_num(pfile);
		for (i=0; i<item_num; i++) {
			if (0 == strncmp(pitem[i].keyword, "--------", 8) &&
				0 == strcasecmp(pitem[i].keyword + 8, group)) {
				list_file_free(pfile);
				return;
			}
		}
	}
	fd = open(g_list_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		system_log_info("[group_ui]: fail to open %s in append mode",
			g_list_path);
		return;
	}
	group_ui_encode_line(group, temp_buff);
	len = sprintf(temp_line, "--------%s\t0\n", temp_buff);
	write(fd, temp_line, len);
	close(fd);
	group_ui_broadcast_list();
	reload_control_notify();
}

static void group_ui_remove_group(int group_index)
{
	int len, fd;
	int temp_index;
	int i, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_line[1024];
	char temp_keyword[512];
	KEYWORD_ITEM *pitem;

	sprintf(temp_path, "%s.tmp", g_list_path);
	pfile = list_file_init(g_list_path, "%s:256%l");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[group_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	temp_index = -1;
	for (i=0; i<item_num; i++) {
		if (0 == strncmp(pitem[i].keyword, "--------", 8)) {
			temp_index ++;
		}
		if (group_index != temp_index) {
			group_ui_encode_line(pitem[i].keyword, temp_keyword);
			len = sprintf(temp_line, "%s\t%ld\n", temp_keyword, pitem[i].time);
			write(fd, temp_line, len);
		}
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	group_ui_broadcast_list();
	reload_control_notify();
}

static void group_ui_encode_line(const char *in, char *out)
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

static void group_ui_broadcast_list()
{
	DIR *dirp;
	int fd, i, len;
	int item_num;
	char temp_path[256];
	char temp_line[1024];
	struct dirent *direntp;
	LIST_FILE *pfile;
	KEYWORD_ITEM *pitem;
	
	
	pfile = list_file_init(g_list_path, "%s:256%l");
	if (NULL == pfile) {
		system_log_info("[group_ui]: fail to open list file %s", g_list_path);
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (KEYWORD_ITEM*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[group_ui]: fail to open directory %s\n",
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
		sprintf(temp_path, "%s/%s/data/delivery/anonymous_keyword/keyword.txt",
			g_mount_path, direntp->d_name);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[group_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			group_ui_encode_line(pitem[i].keyword, temp_line);
			len = strlen(temp_line);
			temp_line[len] = '\n';
			len ++;
			write(fd, temp_line, len);
		}
		close(fd);
	}
	closedir(dirp);
	list_file_free(pfile);
}

