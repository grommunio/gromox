#include <errno.h>
#include "limit_ui.h"
#include "lang_resource.h"
#include <gromox/system_log.h>
#include "gateway_control.h"
#include "data_source.h"
#include <gromox/session_client.h>
#include "list_file.h"
#include "config_file.h"
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

/* fill list title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(object) {location.href='%s?domain=%s&session=%s&object=' + object;}\n\
function ModifyItem(object, memo) {\
opeform.object.value=object; opeform.memo.value=memo; opeform.memo.focus();}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=object /></TD></TR><TR><TD></TD><TD>%s:</TD><TD><INPUT type=text \
value=\"\" tabindex=2 name=memo /></TD></TR><TR><TD></TD><TD></TD><TD>\n\
<INPUT type=submit tabindex=3 value=\"%s\" onclick=\"\n\
if (0 == opeform.object.value.length) {return false;} return true;\" \n\
/></TD></TR><TR><TD colSpan=3>%s</TD></TR></TABLE></FORM>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
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
<P align=right><A href=domain_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;<A href=\"javascript:DeleteItem('%s')\">%s</A> | \
<A href=\"javascript:ModifyItem('%s', '%s')\">%s</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _BLACKLIST_ITEM {
	char object[256];
	char memo[256];
} BLACKLIST_ITEM;

static void limit_ui_encode_line(const char *in, char *out);

static void list_ui_encode_squote(const char *in, char *out);
	
static void	limit_ui_modify_list(const char *domain, const char *object,
	const char *memo);

static void limit_ui_remove_item(const char *domain, const char *object);
			
static void limit_ui_error_html(const char *error_string);

static void limit_ui_main_html(const char *domain, const char *session);

static void limit_ui_broadcast_list(const char *domain);

static BOOL limit_ui_get_self(char *url_buff, int length);

static void limit_ui_unencode(char *src, char *last, char *dest);


static char g_domain_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void limit_ui_init(const char *mount_path, const char *url_link,
	const char *resource_path)
{
	strcpy(g_mount_path, mount_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int limit_ui_run()
{
	int len;
	char *query;
	char *request;
	char *language;
	char *ptr1, *ptr2;
	char memo[256];
	char domain[256];
	char session[256];
	char temp_object[256];
	char search_buff[1024];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		limit_ui_error_html(NULL);
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
	if (0 == strcmp(request, "POST")) {
		limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[limit_ui]: fail to get QUERY_STRING "
				"environment!");
			limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			len = strlen(query);
			if (0 == len || len > 1024) {
				system_log_info("[limit_ui]: query string too long!");
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			limit_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);

			ptr1 = search_string(search_buff, "domain=", len);
			if (NULL == ptr1) {
				system_log_info("[limit_ui]: query string of GET format error");
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 7;
			ptr2 = search_string(search_buff, "&session=", len);
			if (NULL == ptr2) {
				system_log_info("[limit_ui]: query string of GET "
					"format error");
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[limit_ui]: query string of GET format error");
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(domain, ptr1, ptr2 - ptr1);
			domain[ptr2 - ptr1] = '\0';
			lower_string(domain);
			ptr1 = ptr2 + 9;
			ptr2 = search_string(search_buff, "&object=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 256) {
					system_log_info("[limit_ui]: query string of GET "
						"format error");
					limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';
				if (FALSE == session_client_check(domain, session)) {
					limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				if (FALSE == data_source_get_homedir(domain, g_domain_path) ||
					'\0' == g_domain_path[0]) {
					limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				limit_ui_main_html(domain, session);
				return 0;
			}
			if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[limit_ui]: query string of GET "
					"format error");
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 8;
			ptr2 = search_string(search_buff, "&memo=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 256 ||
					search_buff + len - ptr1 - 1 == 0) {
					system_log_info("[limit_ui]: query string of GET "
						"format error");
					limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_object, ptr1, search_buff + len - ptr1 - 1);
				temp_object[search_buff + len - ptr1 - 1] = '\0';
				ltrim_string(temp_object);
				rtrim_string(temp_object);
				if (FALSE == session_client_check(domain, session)) {
					limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				if (FALSE == data_source_get_homedir(domain, g_domain_path) ||
					'\0' == g_domain_path[0]) {
					limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				limit_ui_remove_item(domain, temp_object);
				limit_ui_main_html(domain, session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 256) {
				system_log_info("[limit_ui]: query string of GET "
					"format error");
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_object, ptr1, ptr2 - ptr1);
			temp_object[ptr2 - ptr1] = '\0';
			ltrim_string(temp_object);
			rtrim_string(temp_object);
			ptr1 = ptr2 + 6;
			if (search_buff + len - ptr1 - 1 > 256) {
				system_log_info("[limit_ui]: query string of GET "
					"format error");
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
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
			if (FALSE == session_client_check(domain, session)) {
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			if (FALSE == data_source_get_homedir(domain, g_domain_path) ||
				'\0' == g_domain_path[0]) {
				limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			limit_ui_modify_list(domain, temp_object, memo);
			limit_ui_main_html(domain, session);
			return 0;
		}
	} else {
		system_log_info("[limit_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int limit_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void limit_ui_free()
{
	/* do nothing */
}

static BOOL limit_ui_get_self(char *url_buff, int length)
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

static void limit_ui_error_html(const char *error_string)
{
	const char *language;
	
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

static void limit_ui_main_html(const char *domain, const char *session)
{
	int fd;
	int i;
	int item_num;
	char *language;
	LIST_FILE *pfile;
	CONFIG_FILE *pconfig;
	char *str_value;
	char url_buff[1024];
	char list_path[256];
	char temp_name[512];
	char config_path[256];
	BLACKLIST_ITEM *pitem;
	struct stat node_stat;
	
	
	if (FALSE == limit_ui_get_self(url_buff, 1024)) {
		limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	snprintf(list_path, 256, "%s/limit.txt", g_domain_path);
	if (0 != stat(list_path, &node_stat)) {
		fd = open(list_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		close(fd);
	}
	snprintf(config_path, 256, "%s/domain.cfg", g_domain_path);
	if (0 != stat(config_path, &node_stat)) {
		fd = open(config_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		close(fd);
	}
	pfile = list_file_init(list_path, "%s:256%s:256");
	if (NULL == pfile) {
		system_log_info("[limit_ui]: fail to open list file %s", list_path);
		limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pconfig = config_file_init(config_path);
	if (NULL == pconfig) {
		system_log_info("[limit_ui]: open %s: %s", config_path, strerror(errno));
		limit_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		list_file_free(pfile);
		return;
	}
	pitem = (BLACKLIST_ITEM*)list_file_get_list(pfile);
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
	printf(HTML_MAIN_5, url_buff, domain, session);
	printf(url_buff);
	printf(HTML_MAIN_6, domain, session,
		lang_resource_get(g_lang_resource,"MAIN_OBJECT", language),
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"TIP_TYPE_CONFIG", language));
	str_value = config_file_get_value(pconfig, "LIMIT_TYPE");
	if (NULL == str_value) {
		printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE_DENY", language));	
		config_file_set_value(pconfig, "LIMIT_TYPE", "1");
		config_file_save(pconfig);
	} else {
		switch (atoi(str_value)) {
		case 1:
			printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE_DENY", language));	
			break;
		case 2:
			printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE_ALLOW", language));
			break;
		default:
			config_file_set_value(pconfig, "LIMIT_TYPE", "1");
			config_file_save(pconfig);
			printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE_DENY", language));	
			break;
		}
	}
	config_file_free(pconfig);
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_OBJECT", language),
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		list_ui_encode_squote(pitem[i].object, temp_name);
		if (0 == strcmp(pitem[i].memo, "none")) {
			printf(HTML_TBITEM_NORMAL, pitem[i].object,
				lang_resource_get(g_lang_resource,"MAIN_NONE", language),
				temp_name, lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				temp_name, pitem[i].memo,
				lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
		} else {
			printf(HTML_TBITEM_NORMAL, pitem[i].object,
				pitem[i].memo, temp_name,
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				temp_name, pitem[i].memo,
				lang_resource_get(g_lang_resource,"MODIFY_LABEL", language));
		}
	}
	list_file_free(pfile);
	printf(HTML_MAIN_8);
}

static void limit_ui_unencode(char *src, char *last, char *dest)
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

static void	limit_ui_modify_list(const char *domain, const char *object,
	const char *memo)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char list_path[256];
	char temp_path[256];
	char temp_memo[512];
	char temp_object[512];
	char temp_line[1024];
	BLACKLIST_ITEM *pitem;

	snprintf(list_path, 256, "%s/limit.txt", g_domain_path);
	pfile = list_file_init(list_path, "%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(object, pitem[i].object)) {
			break;
		}
	}
	sprintf(temp_path, "%s.tmp", list_path);
	if (i < item_num) {
		fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[limit_ui]: fail to create %s", temp_path);
			list_file_free(pfile);
			return;
		}
		for (j=0; j<item_num; j++) {
			if (j == i) {
				continue;
			}
			limit_ui_encode_line(pitem[j].object, temp_object);
			limit_ui_encode_line(pitem[j].memo, temp_memo);
			len = sprintf(temp_line, "%s\t%s\n", temp_object, temp_memo);
			write(fd, temp_line, len);

		}
		limit_ui_encode_line(object, temp_object);
		limit_ui_encode_line(memo, temp_memo);
		len = sprintf(temp_line, "%s\t%s\n", temp_object, temp_memo);
		write(fd, temp_line, len);
		close(fd);
		list_file_free(pfile);
		remove(list_path);
		link(temp_path, list_path);
		remove(temp_path);
	} else {
		list_file_free(pfile);
		fd = open(list_path, O_APPEND|O_WRONLY);
		if (-1 == fd) {
			system_log_info("[limit_ui]: fail to open %s in append mode",
				list_path);
			return;
		}
		limit_ui_encode_line(object, temp_object);
		limit_ui_encode_line(memo, temp_memo);
		len = sprintf(temp_line, "%s\t%s\n", temp_object, temp_memo);
		write(fd, temp_line, len);
		close(fd);
		limit_ui_broadcast_list(domain);
	}
}

static void limit_ui_remove_item(const char *domain, const char *object)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char list_path[256];
	char temp_path[256];
	char temp_memo[512];
	char temp_object[512];
	char temp_line[1024];
	BLACKLIST_ITEM *pitem;

	snprintf(list_path, 256, "%s/limit.txt", g_domain_path);
	pfile = list_file_init(list_path, "%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(object, pitem[i].object)) {
			break;
		}
	}
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[limit_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	for (j=0; j<item_num; j++) {
		if (j == i) {
			continue;
		}
		limit_ui_encode_line(pitem[j].object, temp_object);
		limit_ui_encode_line(pitem[j].memo, temp_memo);
		len = sprintf(temp_line, "%s\t%s\n", temp_object, temp_memo);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(list_path);
	link(temp_path, list_path);
	remove(temp_path);
	limit_ui_broadcast_list(domain);
}

static void limit_ui_encode_line(const char *in, char *out)
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

static void limit_ui_broadcast_list(const char *domain)
{
	DIR *dirp;
	int item_num;
	int limit_type;
	int i, fd, len;
	char *str_value;
	char temp_object[257];
	char temp_path[256];
	char list_path[256];
	char command_line[1024];
	struct dirent *direntp;
	LIST_FILE *pfile;	
	BLACKLIST_ITEM *pitem;
	CONFIG_FILE *pconfig;
	

	snprintf(temp_path, 256, "%s/domain.cfg", g_domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		return;
	}
	str_value = config_file_get_value(pconfig, "LIMIT_TYPE");
	if (NULL == str_value) {
		limit_type = 1;
	} else {
		limit_type = atoi(str_value);
	}
	config_file_free(pconfig);

	snprintf(list_path, 256, "%s/limit.txt", g_domain_path);
	pfile = list_file_init(list_path, "%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = (BLACKLIST_ITEM*)list_file_get_list(pfile);
	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[limit_ui]: fail to open directory %s\n",
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
			system_log_info("[limit_ui]: fail to truncate %s", temp_path);
			continue;
		}
		for (i=0; i<item_num; i++) {
			len = sprintf(temp_object, "%s\n", pitem[i].object);
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

static void list_ui_encode_squote(const char *in, char *out)
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


