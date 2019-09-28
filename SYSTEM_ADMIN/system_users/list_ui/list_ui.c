#include "list_ui.h"
#include "lang_resource.h"
#include "acl_control.h"
#include "system_log.h"
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

/* fill list title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(username) {location.href='%s?session=%s&username=' + username;}\n\
function ModifyItem(username, privilege) {\
opeform.username.value=username; opeform.password.value='none-change-password'; \n\
if (privilege.charAt(0) == '1') {\n\
opeform.system_setup.checked = true;} else {\n\
opeform.system_setup.checked = false;}\n\
if (privilege.charAt(1) == '1') {\n\
opeform.anti_spam.checked = true;} else {\n\
opeform.anti_spam.checked = false;}\n\
if (privilege.charAt(2) == '1') {\n\
opeform.misc_setup.checked = true;} else {\n\
opeform.misc_setup.checked = false;}\n\
if (privilege.charAt(3) == '1') {\n\
opeform.status_view.checked = true;} else {\n\
opeform.status_view.checked = false;}}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=post action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT class=FormInput type=text value=\"\" \n\
tabindex=1 name=username /></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<INPUT class=FormInput type=password value=\"\" tabindex=2 name=password />\n\
</TD></TR><TR><TD colSpan=3><INPUT type=checkbox name=system_setup \n\
value=\"on\" checked/>%s&nbsp;&nbsp;&nbsp;&nbsp;\n\
<INPUT type=checkbox name=anti_spam value=\"on\" checked/>\n\
%s&nbsp;&nbsp;&nbsp;&nbsp;<INPUT type=checkbox name=misc_setup \n\
value=\"on\" checked/>%s&nbsp;&nbsp;&nbsp;<INPUT type=checkbox \n\
name=status_view value=\"on\" checked/>%s&nbsp;&nbsp;&nbsp;&nbsp;</TD>\n\
</TR><TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=3 value=\"%s\" \
onclick=\"if (username.value.length == 0) return false;\n\
if(password.value.length == 0) {\n\
alert (\'%s\');\n\
return false;}\n\
return true;\n\" />\n\
</TD></TR></TABLE></FORM><TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
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
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_CAUTION_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_ADMIN   \
"<TR class=ItemRow><TD>&nbsp;administrator&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD></TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\
<A href=\"javascript:DeleteItem('%s')\">%s</A> | \
<A href=\"javascript:ModifyItem('%s', '%s')\">%s</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static void list_ui_encode_line(const char *in, char *out);

static void list_ui_encode_password(const char *password, char *buff);
	
static void	list_ui_modify_list(const char *username, const char *password,
	const char *mask_string);

static void list_ui_remove_item(const char *username);
			
static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *session);

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void list_ui_init(const char *list_path, const char *url_link,
	const char *resource_path)
{
	strcpy(g_list_path, list_path);
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
	char mask_string[5];
	char username[256];
	char password[256];
	char temp_name[256];
	char session[256];
	char post_buff[1024];
	char search_buff[1024];
	int len;

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
		return -1;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[list_ui]: fail to get REMOTE_ADDR environment!");
		return -2;
	}
	if (0 == strcmp(request, "POST")) {
	   if (NULL == fgets(post_buff, 1024, stdin)) {
		    list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
			    language));
	        return 0;
		}
	    len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[list_ui]: post buffer too long");
	        list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
		        language));
			return 0;
		}
	    list_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "session=", len);
		if (NULL == ptr1) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		ptr1 += 8;
		ptr2 = search_string(search_buff, "&username=", len);
		if (NULL == ptr2) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
		        language));
			return 0;
		}
		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
		
		ptr1 = ptr2 + 10;
		ptr2 = search_string(search_buff, "&password=", len);
		if (NULL == ptr1) {
			system_log_info("[list_ui]: query string of POST format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		memcpy(username, ptr1, ptr2 - ptr1);
		username[ptr2 - ptr1] = '\0';
		
		ptr1 = ptr2 + 10;
		ptr2 = strchr(ptr1, '&');
		if (NULL == ptr2) {
			ptr2 = search_buff + len - 1;
		}

		memcpy(password, ptr1, ptr2 - ptr1);
		password[ptr2 - ptr1] = '\0';
		
		if (NULL != search_string(search_buff, "&system_setup=", len)) {
			mask_string[ACL_PRIVILEGE_SETUP] = '1';
		} else {
			mask_string[ACL_PRIVILEGE_SETUP] = '0';
		}
		if (NULL != search_string(search_buff, "&anti_spam=", len)) {
			mask_string[ACL_PRIVILEGE_ANTI_SPAM] = '1';
		} else {
			mask_string[ACL_PRIVILEGE_ANTI_SPAM] = '0';
		}
		if (NULL != search_string(search_buff, "&misc_setup=", len)) {
			mask_string[ACL_PRIVILEGE_MISC] = '1';
		} else {
			mask_string[ACL_PRIVILEGE_MISC] = '0';
		}
		if (NULL != search_string(search_buff, "&status_view=", len)) {
			mask_string[ACL_PRIVILEGE_STATUS] = '1';
		} else {
			mask_string[ACL_PRIVILEGE_STATUS] = '0';
		}
		mask_string[4] = '\0';
		list_ui_modify_list(username, password, mask_string);
		list_ui_main_html(session);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
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
			ptr2 = search_string(search_buff, "&username=", len);
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
					ACL_PRIVILEGE_IGNORE)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				default:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				if (FALSE == acl_control_naming(session, temp_name) ||
					0 != strcasecmp(temp_name, "administrator")) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
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
			
			ptr1 = ptr2 + 10;
			if (search_buff + len - ptr1 - 1 > 256) {
				system_log_info("[list_ui]: query string of GET "
					"format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			memcpy(username, ptr1, search_buff + len - ptr1 - 1);
			username[search_buff + len - ptr1 - 1] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_IGNORE)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			default:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			if (FALSE == acl_control_naming(session, temp_name) ||
				0 != strcasecmp(temp_name, "administrator")) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			}

			list_ui_remove_item(username);
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
	BOOL b_added;
	char *pitem;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char temp_buff[1024];
	struct tm temp_tm, *ptm;
	
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to open list file %s",
			g_list_path);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pitem = (char*)list_file_get_list(pfile);
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
	if (0 == item_num) {
		printf(HTML_CAUTION_5, lang_resource_get(g_lang_resource,"MAIN_FILL_CAUTION",
			language));
		list_file_free(pfile);
		return;
	}
	printf(HTML_MAIN_5, url_buff, session);
	printf(url_buff);
	printf(HTML_MAIN_6, session,
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_SYSTEM_SETUP", language),
		lang_resource_get(g_lang_resource,"MAIN_ANTI_SPAM", language),
		lang_resource_get(g_lang_resource,"MAIN_MISC_SETUP", language),
		lang_resource_get(g_lang_resource,"MAIN_STATUS_VIEW", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_NONEPASSWORD", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		temp_buff[0] = '\0';
		if (0 == strcasecmp(pitem + 3*256*i, "administrator")) {
			sprintf(temp_buff, "%s | %s | %s | %s",
				lang_resource_get(g_lang_resource,"MAIN_SYSTEM_SETUP", language),
				lang_resource_get(g_lang_resource,"MAIN_ANTI_SPAM", language),
				lang_resource_get(g_lang_resource,"MAIN_MISC_SETUP", language),
				lang_resource_get(g_lang_resource,"MAIN_STATUS_VIEW", language));
			printf(HTML_TBITEM_ADMIN, temp_buff);
			continue;
		}
		b_added = FALSE;
		if ('1' == *(pitem + 3*256*i + 2*256 + ACL_PRIVILEGE_SETUP)) {
			strcpy(temp_buff, lang_resource_get(g_lang_resource,"MAIN_SYSTEM_SETUP", language));
			b_added = TRUE;
		}
		if ('1' == *(pitem + 3*256*i + 2*256 + ACL_PRIVILEGE_ANTI_SPAM)) {
			if (TRUE == b_added) {
				strcat(temp_buff, " | ");
				strcat(temp_buff, lang_resource_get(g_lang_resource,"MAIN_ANTI_SPAM", language));
			} else {
				strcpy(temp_buff, lang_resource_get(g_lang_resource,"MAIN_ANTI_SPAM", language));
				b_added = TRUE;
			}
		}
		if ('1' == *(pitem + 3*256*i + 2*256 + ACL_PRIVILEGE_MISC)) {
			if (TRUE == b_added) {
				strcat(temp_buff, " | ");
				strcat(temp_buff, lang_resource_get(g_lang_resource,"MAIN_MISC_SETUP", language));
			} else {
				strcpy(temp_buff, lang_resource_get(g_lang_resource,"MAIN_MISC_SETUP", language));
				b_added = TRUE;
			}
		}
		if ('1' == *(pitem + 3*256*i + 2*256 + ACL_PRIVILEGE_STATUS)) {
			if (TRUE == b_added) {
				strcat(temp_buff, " | ");
				strcat(temp_buff, lang_resource_get(g_lang_resource,"MAIN_STATUS_VIEW", language));
			} else {
				strcpy(temp_buff, lang_resource_get(g_lang_resource,"MAIN_STATUS_VIEW", language));
				b_added = TRUE;
			}
		}
		printf(HTML_TBITEM_NORMAL, pitem + 3*256*i, temp_buff, pitem + 3*256*i, 
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language),
				pitem + 3*256*i, pitem + 3*256*i + 2*256,
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

static void	list_ui_modify_list(const char *username, const char *password,
	const char *mask_string)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char *pitem;
	char temp_path[256];
	char temp_buff[256];
	char temp_line[1024];
	char temp_password[256];

	pfile = list_file_init(g_list_path, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(username, pitem + 3*256*i)) {
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
			list_ui_encode_line(pitem + 3*256*j, temp_buff);
			len = sprintf(temp_line, "%s\t%s\t%s\n", temp_buff,
					pitem + 3*256*j + 256, pitem + 3*256*j + 2*256);
			write(fd, temp_line, len);
		}
		list_ui_encode_line(pitem + 3*256*i, temp_buff);
		if (0 != strcmp("none-change-password", password)) {
			list_ui_encode_password(password, temp_password);
		} else {
			strcpy(temp_password, pitem + 3*256*i + 256);
		}
		len = sprintf(temp_line, "%s\t%s\t%s\n", temp_buff,
				temp_password, mask_string);
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
		list_ui_encode_password(password, temp_password);
		len = sprintf(temp_line, "%s\t%s\t%s\n", username, temp_password,
				mask_string);
		write(fd, temp_line, len);
		close(fd);
	}
}

static void list_ui_remove_item(const char *username)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char *pitem;
	char temp_path[256];
	char temp_buff[256];
	char temp_line[1024];

	pfile = list_file_init(g_list_path, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", g_list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(username, pitem + 3*256*i)) {
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
		list_ui_encode_line(pitem + 3*256*j, temp_buff);
		len = sprintf(temp_line, "%s\t%s\t%s\n", temp_buff,
				pitem + 3*256*j + 256, pitem + 3*256*j + 2*256);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	acl_control_clear(username);
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

static void list_ui_encode_password(const char *password, char *buff)
{
	int i;
	size_t len;
	char temp_char;
	char temp_buff[256];
	
	memset(temp_buff, 0, 256);
	encode64(password, strlen(password), temp_buff, 256, &len);
	for (i=0; i<len/2; i++) {
	    temp_char = temp_buff[i];
		temp_buff[i] = temp_buff[len - 1 - i];
		temp_buff[len - 1 - i] = temp_char;
	}
	strcpy(buff, temp_buff);
}

