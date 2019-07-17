#include "setup_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "gateway_control.h"
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


#define HTML_MAIN_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(domain) {location.href='%s?session=%s&remove_domain=' + domain;}\n\
</SCRIPT><BR><BR><TABLE width=\"75%\"><TBODY>\n\
<TR class=ItemOdd><TD>%s:&nbsp;</TD><TD colSpan=2><B>%s</B></TD></TR>\n\
<TR class=ItemEven><TD colSpan=3>%s&nbsp;&nbsp;(%s)</TD></TR>\n\
<TR class=ItemOdd><FORM name=AutoDNS method=get action=%s>\n\
<TD><INPUT type=hidden name=\"session\" value=\"%s\"/></TD>\n\
<TD><TEXTAREA name=local_ips cols=16 rows=6>"


#define HTML_MAIN_6	\
"</TEXTAREA></TD><TD><INPUT type=submit value=\"  %s  \"/></TD></FORM></TR>\n\
<TR class=ItemEven><TD colSpan=3>%s&nbsp;&nbsp;(%s)</TD></TR>\n\
<TR class=ItemOdd><FORM name=WebLST method=get action=%s>\n\
<TD><INPUT type=hidden name=\"session\" value=\"%s\"/></TD>\n\
<TD><INPUT type=text size=60 name=\"url_path\" value=\"%s\"/></TD>\n\
<TD><INPUT type=submit value=\"  %s  \"/></TD></FORM></TR>\n\
<TR class=ItemEven><TD colSpan=3>%s&nbsp;&nbsp;(%s)</TD></TR>\n\
<TR class=ItemOdd><FORM method=post action=%s enctype=\"multipart/form-data\">\n\
<TD><INPUT type=hidden name=\"session\" value=\"%s\" /></TD>\n\
<TD><INPUT type=file name=\"upload_list\" /></TD>\n\
<TD><INPUT type=submit value=\"  %s  \" /></TD></FORM></TR>\n\
<TR class=ItemOdd><TD></TD><TD colSpan=2><HR></TD></TR>\n\
<TR class=ItemOdd><FORM name=EditLST method=get action=%s>\n\
<TD><INPUT type=hidden name=\"session\" value=\"%s\" /></TD>\n\
<TD><INPUT type=text name=\"add_domain\" value=\"\" /></TD>\n\
<TD><INPUT type=submit value=\"  %s  \"  onclick=\
\"if(EditLST.add_domain.value == 0) {return false;} else {return true;}\"\
/></TD></FORM></TR>\n\
</TBODY></TABLE><TABLE cellSpacing=0 cellPadding=0 width=\"75%\"\n\
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

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_FAKE   \
"<TR class=SolidRow><TD>--------</TD><TD>--------</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\
<A href=\"javascript:DeleteItem('%s')\">%s&nbsp;</TD></TR>\n"

#define DEF_MODE				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define TOKEN_CONTROL				100
#define CTRL_RESTART_WEBADAPTOR		3

static void setup_ui_encode_line(const char *in, char *out);
	
static void	setup_ui_add_item(const char *domain);

static void setup_ui_remove_item(const char *domain);

static void setup_ui_clear_item();

static void setup_ui_restart_web_adaptor();
			
static void setup_ui_error_html(const char *error_string);

static void setup_ui_main_html(const char *session);

static void setup_ui_broadcast_ips();

static void setup_ui_broadcast_domains();

static BOOL setup_ui_get_self(char *url_buff, int length);

static void setup_ui_unencode(char *src, char *last, char *dest);

static char g_list_path[256];
static char g_domains_path[256];
static char g_token_path[256];
static char g_mount_path[256];
static char g_logo_link[1024];
static CONFIG_FILE *g_cfg_file;
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void setup_ui_init(CONFIG_FILE *pfile, const char *list_path,
	const char *domain_path, const char *mount_path, const char *token_path,
	const char *url_link, const char *resource_path)
{
	g_cfg_file = pfile;
	strcpy(g_list_path, list_path);
	strcpy(g_domains_path, domain_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_token_path, token_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int setup_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *str_value;
	char *ptr1, *ptr2;
	char session[256];
	char temp_buff[1024];
	char post_buff[1024];
	char temp_domain[256];
	char search_buff[1024];
	char boundary[1024];
	int i, fd, len, bnd_len, temp_type;

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
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[setup_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[setup_ui]: post buffer too long");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
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
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		setup_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2) {
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "session")) {
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		memset(session, 0, 256);
		for (i=0; i<len; i++) {
			if ('\r' == post_buff[i] || '\n' == post_buff[i]) {
				session[i] = '\0';
				break;
			} else {
				session[i] = post_buff[i];
			}
		}

		switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_SETUP)) {
		case ACL_SESSION_OK:
			break;
		case ACL_SESSION_TIMEOUT:
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
				language));
			return 0;
		case ACL_SESSION_PRIVILEGE:
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
				language));
			return 0;
		default:
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
				language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strcmp(post_buff, boundary)) {
				break;
			}
		}
		if (NULL == fgets(post_buff, 1024, stdin)) {
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		len = strlen(post_buff);
		setup_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "name=\"", len);
		if (NULL == ptr1) {
			system_log_info("setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		ptr1 += 6;
		ptr2 = strchr(ptr1, '"');
		if (NULL == ptr2) {
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		if (0 != strcasecmp(temp_buff, "upload_list")) {
			system_log_info("[setup_ui]: query string of POST format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		fd = open(g_domains_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			system_log_info("[setup_ui]: fail to create list file for %s\n",
				temp_buff);
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if ('\n' == post_buff[0] || '\r' == post_buff[0]) {
				break;
			}
		}
		
		while (NULL != fgets(post_buff, 1024, stdin)) {
			if (0 == strncmp(post_buff, boundary, bnd_len)) {
				break;
			}
			if ('\r' == post_buff[0] || '\n' == post_buff[0]) {
				continue;
			}
			setup_ui_encode_line(post_buff, search_buff);
			len = strlen(search_buff);
			write(fd, search_buff, len);
		}
		close(fd);
		str_value = config_file_get_value(g_cfg_file, "LOCAL_SETUP_TYPE");
		if (NULL == str_value || 2 != atoi(str_value)) {
			config_file_set_value(g_cfg_file, "LOCAL_SETUP_TYPE", "2");
			config_file_save(g_cfg_file);
			setup_ui_restart_web_adaptor();
			gateway_control_enable_domains(TRUE);
		}
		setup_ui_broadcast_domains();
		gateway_control_reload_domains();
		setup_ui_main_html(session);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
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
			setup_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[setup_ui]: query string of GET "
					"format error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = strchr(ptr1, '&');
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 255) {
					system_log_info("[setup_ui]: query string of GET "
						"format error");
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
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
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				setup_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[setup_ui]: query string of GET "
					"format error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_SETUP)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			default:
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			ptr2 ++;
			if (0 == strncasecmp(ptr2, "local_ips=", 10)) {
				fd = open(g_list_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
				if (-1 == fd) {
					system_log_info("[setup_ui]: fail to truncate %s",
						g_list_path);
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				str_value = config_file_get_value(g_cfg_file,
							"LOCAL_SETUP_TYPE");
				if (NULL == str_value || 0 != atoi(str_value)) {
					setup_ui_clear_item();
					config_file_set_value(g_cfg_file, "LOCAL_SETUP_TYPE", "0");
					config_file_save(g_cfg_file);
					setup_ui_restart_web_adaptor();
					gateway_control_enable_domains(FALSE);
				}
				ptr2 += 10;
				for (ptr1=ptr2; ptr1<search_buff+len; ptr1++) {
					if ('\r' == *ptr1 || '\n' == *ptr1) {
						if (ptr1 - ptr2 != 1) {
							write(fd, ptr2, ptr1 - ptr2);
							write(fd, "\n", 1);
						}
						while ('\n' == *(ptr1+1) || '\r' == *(ptr1+1)) {
							ptr1 ++;
						}
						ptr2 = ptr1 + 1;
					}
				}
				close(fd);
				setup_ui_broadcast_ips();
				gateway_control_reload_ips();
				setup_ui_main_html(session);
				return 0;
			} else if (0 == strncasecmp(ptr2, "url_path=", 9)) {
				str_value = config_file_get_value(g_cfg_file,
							"LOCAL_SETUP_TYPE");
				if (NULL == str_value || 1 != atoi(str_value)) {
					setup_ui_clear_item();
					config_file_set_value(g_cfg_file, "LOCAL_SETUP_TYPE", "1");
					gateway_control_enable_domains(TRUE);
				}
				ptr2 += 9;
				memcpy(temp_buff, ptr2, search_buff + len - ptr2 - 1);
				temp_buff[search_buff + len - ptr2 - 1] = '\0';
				config_file_set_value(g_cfg_file, "DOMAINLIST_URL_PATH",
						temp_buff);
				config_file_save(g_cfg_file);
				setup_ui_restart_web_adaptor();
				setup_ui_main_html(session);
				return 0;
			} else if (0 == strncasecmp(ptr2, "remove_domain=", 14)) {
				str_value = config_file_get_value(g_cfg_file,
							"LOCAL_SETUP_TYPE");
				if (NULL == str_value || 2 != atoi(str_value)) {
					system_log_info("[setup_ui]: cannot remove domain when "
						"local setup type mismatches");
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				ptr2 += 14;
				memcpy(temp_domain, ptr2, search_buff + len - ptr2 - 1);
				temp_domain[search_buff + len - ptr2 - 1] = '\0';
				ltrim_string(temp_domain);
				rtrim_string(temp_domain);
				setup_ui_remove_item(temp_domain);
				setup_ui_broadcast_domains();
				gateway_control_reload_domains();
				setup_ui_main_html(session);
				return 0;
			} else if (0 == strncasecmp(ptr2, "add_domain=", 11)) {
				str_value = config_file_get_value(g_cfg_file,
							"LOCAL_SETUP_TYPE");
				if (NULL == str_value || 2 != atoi(str_value)) {
					setup_ui_clear_item();
					config_file_set_value(g_cfg_file, "LOCAL_SETUP_TYPE", "2");
					config_file_save(g_cfg_file);			
					setup_ui_restart_web_adaptor();
					gateway_control_enable_domains(TRUE);
				}
				ptr2 += 11;
				memcpy(temp_domain, ptr2, search_buff + len - ptr2 - 1);
				temp_domain[search_buff + len - ptr2 - 1] = '\0';
				ltrim_string(temp_domain);
				rtrim_string(temp_domain);
				setup_ui_add_item(temp_domain);
				setup_ui_broadcast_domains();
				gateway_control_reload_domains();
				setup_ui_main_html(session);
				return 0;
			}
			system_log_info("[setup_ui]: query string of GET format error");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
	} else {
		system_log_info("[setup_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
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
	char *script;
	
	host = getenv("SERVER_NAME");
	script = getenv("SCRIPT_NAME");
	if (NULL == host || NULL == script) {
		system_log_info("[setup_ui]: fail to get SERVER_NAME or "
			"SCRIPT_NAME environment!");
		return FALSE;
	}
	snprintf(url_buff, length, "http://%s%s", host, script);
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

static void setup_ui_main_html(const char *session)
{
	int i, len;
	int item_num, item_num1;
	int temp_type;
	char *language;
	LIST_FILE *pfile, *pfile1;
	char url_buff[1024];
	char *str_value, *pitem, *pitem1;
	
	
	if (FALSE == setup_ui_get_self(url_buff, 1024)) {
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_domains_path, "%s:256");
	if (NULL == pfile) {
		system_log_info("[setup_ui]: fail to open list file %s",
			g_domains_path);
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pfile1 = list_file_init(g_list_path, "%s:16");
	if (NULL == pfile1) {
		system_log_info("[setup_ui]: fail to open list file %s",
			g_list_path);
		list_file_free(pfile);
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pitem = (char*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	pitem1 = (char*)list_file_get_list(pfile1);
	item_num1 = list_file_get_item_num(pfile1);
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
	str_value = config_file_get_value(g_cfg_file, "LOCAL_SETUP_TYPE");
	if (NULL == str_value) {
		temp_type = -1;
	} else {
		temp_type = atoi(str_value);
	}
	switch (temp_type) {
	case 0:
		printf(HTML_MAIN_5, url_buff, session,
			lang_resource_get(g_lang_resource,"MAIN_CURRENT_TYPE", language),
			lang_resource_get(g_lang_resource,"MAIN_AUTODNS", language),
			lang_resource_get(g_lang_resource,"MAIN_AUTODNS", language), 
			lang_resource_get(g_lang_resource,"TIP_AUTODNS", language), url_buff, session);
		break;
	case 1:
		printf(HTML_MAIN_5, url_buff, session,
			lang_resource_get(g_lang_resource,"MAIN_CURRENT_TYPE", language),
			lang_resource_get(g_lang_resource,"MAIN_WEBLIST", language),
			lang_resource_get(g_lang_resource,"MAIN_AUTODNS", language),
			lang_resource_get(g_lang_resource,"TIP_AUTODNS", language), url_buff, session);
		break;
	case 2:
		printf(HTML_MAIN_5, url_buff, session,
			lang_resource_get(g_lang_resource,"MAIN_CURRENT_TYPE", language),
			lang_resource_get(g_lang_resource,"MAIN_MANUALEDIT", language),
			lang_resource_get(g_lang_resource,"MAIN_AUTODNS", language),
			lang_resource_get(g_lang_resource,"TIP_AUTODNS", language), url_buff, session);
		break;
	default:
		printf(HTML_MAIN_5, url_buff, session,
			lang_resource_get(g_lang_resource,"MAIN_CURRENT_TYPE", language),
			lang_resource_get(g_lang_resource,"MAIN_NOTSELECTED", language),
			lang_resource_get(g_lang_resource,"MAIN_AUTODNS", language),
			lang_resource_get(g_lang_resource,"TIP_AUTODNS", language), url_buff, session);
		break;
	}

	for (i=0; i<item_num1; i++) {
		printf("%s\n", pitem1 + 16*i);
	}
	
	str_value = config_file_get_value(g_cfg_file, "DOMAINLIST_URL_PATH");
	if (NULL == str_value) {
		str_value = "";
	}
	printf(HTML_MAIN_6, lang_resource_get(g_lang_resource,"SUBMIT_LABEL", language),
		lang_resource_get(g_lang_resource,"MAIN_WEBLIST", language),
		lang_resource_get(g_lang_resource,"TIP_WEBLIST", language), url_buff, session,
		str_value, lang_resource_get(g_lang_resource,"SUBMIT_LABEL", language),
		lang_resource_get(g_lang_resource,"MAIN_MANUALEDIT", language),
		lang_resource_get(g_lang_resource,"TIP_MANUALEDIT", language), url_buff, session,
		lang_resource_get(g_lang_resource,"UPLOAD_LABEL", language), url_buff, session,
		lang_resource_get(g_lang_resource,"ADD_LABEL", language));
	
	printf(HTML_MAIN_7);

	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	if (2 == temp_type) {
		for (i=0; i<item_num; i++) {
			printf(HTML_TBITEM_NORMAL, pitem + 256*i, pitem + 256*i,
				lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		}
	} else {
		printf(HTML_TBITEM_FAKE);
	}
	list_file_free(pfile);
	list_file_free(pfile1);
	printf(HTML_MAIN_8);
}

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

static void	setup_ui_add_item(const char *domain)
{
	int len, fd;
	int i, j, item_num;
	LIST_FILE *pfile;
	char temp_line[512];
	char *pitem;

	pfile = list_file_init(g_domains_path, "%s:256");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(domain, pitem + 256*i)) {
			list_file_free(pfile);
			return;
		}
	}
	list_file_free(pfile);
	fd = open(g_domains_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		system_log_info("[setup_ui]: fail to open %s in append mode",
			g_domains_path);
		return;
	}
	len = sprintf(temp_line, "%s\n", domain);
	write(fd, temp_line, len);
	close(fd);
}

static void setup_ui_remove_item(const char *domain)
{
	int len, fd;
	int i, item_num;
	LIST_FILE *pfile;
	char temp_path[256];
	char temp_line[512];
	char *pitem;

	pfile = list_file_init(g_domains_path, "%s:256");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", g_domains_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[setup_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	for (i=0; i<item_num; i++) {
		if (0 != strcasecmp(domain, pitem + 256*i)) {
			len = sprintf(temp_line, "%s\n", pitem + 256*i);
			write(fd, temp_line, len);
		}
	}
	close(fd);
	list_file_free(pfile);
	remove(g_domains_path);
	link(temp_path, g_domains_path);
	remove(temp_path);
}

static void setup_ui_clear_item()
{
	int fd;
	
	fd = open(g_domains_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	close(fd);
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

static void setup_ui_broadcast_domains()
{
	int fd;
	DIR *dirp;
	char *pbuff;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;
	
	if (0 != stat(g_domains_path, &node_stat)) {
		return;
	}
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		system_log_info("[setup_ui]: fail to allocate memory\n");
		return;
	}
	fd = open(g_domains_path, O_RDONLY);
	if (-1 == fd) {
		system_log_info("[setup_ui]: fail to open %s\n", g_domains_path);
		free(pbuff);
		return;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		system_log_info("[setup_ui]: fail to read %s\n", g_domains_path);
		free(pbuff);
		close(fd);
		return;
	}
	close(fd);
	
	dirp = opendir(g_mount_path);
	if (NULL == dirp) {
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
		sprintf(temp_path, "%s/%s/data/smtp/domain_list.txt",
			g_mount_path, direntp->d_name);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 != fd) {
			write(fd, pbuff, node_stat.st_size);
			close(fd);
		}
		sprintf(temp_path, "%s/%s/data/delivery/domain_list.txt",
			g_mount_path, direntp->d_name);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 != fd) {
			write(fd, pbuff, node_stat.st_size);
			close(fd);
		}
	}
	closedir(dirp);
	free(pbuff);
}

static void setup_ui_broadcast_ips()
{
	int fd;
	DIR *dirp;
	char *pbuff;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;
	
	if (0 != stat(g_list_path, &node_stat)) {
		return;
	}
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		system_log_info("[setup_ui]: fail to allocate memory\n");
		return;
	}
	fd = open(g_list_path, O_RDONLY);
	if (-1 == fd) {
		system_log_info("[setup_ui]: fail to open %s\n", g_list_path);
		free(pbuff);
		return;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		system_log_info("[setup_ui]: fail to read %s\n", g_list_path);
		free(pbuff);
		close(fd);
		return;
	}
	close(fd);
	
	dirp = opendir(g_mount_path);
	if (NULL == dirp) {
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
		sprintf(temp_path, "%s/%s/data/delivery/inbound_ips.txt",
			g_mount_path, direntp->d_name);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 != fd) {
			write(fd, pbuff, node_stat.st_size);
			close(fd);
		}
	}
	closedir(dirp);
	free(pbuff);
}

static void setup_ui_restart_web_adaptor()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;

	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[setup_ui]: cannot open key for control");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_WEBADAPTOR;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

