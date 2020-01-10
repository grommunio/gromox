#include "ui_main.h"
#include "list_file.h"
#include <gromox/system_log.h>
#include "config_file.h"
#include "data_source.h"
#include "lang_resource.h"
#include "cookie_parser.h"
#include <gromox/session_client.h>
#include "request_parser.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <fcntl.h>
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

/* fill search result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_LOGIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=LoginForm name=logindata method=post action="

/* fill form action here */ 

#define HTML_LOGIN_6	\
" target=_parent name=session>\n<BR><BR><BR><BR><BR><BR>\n\
<TABLE class=LoginTable cellSpacing=0 cellPadding=2 align=left \n\
width=\"60%\" border=0><TBODY><TR><TD align=right>\n"

/* fill domain label here */

#define HTML_LOGIN_7	\
": <INPUT class=FormInput type=text name=domain tabindex=1 />\n\
</TD></TR><TR><TD align=right>\n"

/* fill password lable here */

#define HTML_LOGIN_8	\
": <INPUT class=FormInput type=password name=password  tabindex=2/></TD></TR><TR>\n\
<TD align=right><INPUT type=submit value=\"  "

/* fill login button label here */

#define HTML_LOGIN_9	\
"  \"  tabindex=3 /></TBODY></TABLE><P></P><BR><P></P><BR><P></P>\n\
<BR><P></P><BR><P></P><BR><P></P><BR><P></P><BR><P></P><BR>&copy; "

#define HTML_LOGIN_10	"</CENTER></BODY></HTML>"

#define HTML_EXIT_1		\
"<HTML><HEAD><TITLE></TITLE>\n\
<meta http-equiv=\"Refresh\" content=\"0; url=%s\">\n\
</HEAD><BODY></BODY></HTML>"  

#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=%s>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_MAIN_HTML	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Frameset//EN\">\n\
<HTML><HEAD><TITLE>%s</TITLE><META http-equiv=Content-Type \n\
content=\"text/html; charset=%s\">\n\
<META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
<FRAMESET borderColor=#e5e6e6 rows=* cols=175,*>\n\
<FRAME name=leftfrm src=\"%s?domain=%s&session=%s\" scrolling=yes>\n\
<FRAME name=basefrm src=\"domain_info?domain=%s&session=%s\" scrolling=yes>\n\
</FRAMESET></HTML>"

#define HTML_LEFT_BEGIN	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"><HTML><HEAD>\n\
<LINK href=\"../data/css/result.css\" type=text/css rel=stylesheet>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\">\n\
<META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0 \n\
marginheight=\"0\" marginwidth=\"0\"><CENTER>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0>\n\
<TBODY><TR><TD noWrap align=middle background=\"../data/picture/di1.gif\"\n\
height=55><IMG src=\"../data/picture/contents.gif\">\n\
</TD></TR></TBODY></TABLE>\n\
<TABLE cellSpacing=5 cellPadding=2 width=\"100%\" border=0><TBODY>"

#define HTML_LEFT_ITEM_INFO	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_info?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_info.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_info?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_CONFIG	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_setup?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_config.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_setup?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_GROUPS	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_groups?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_groups.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_groups?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_USERS	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_users?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_users.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_users?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_BINPUT   \
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_binput?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_batch.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_binput?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_FOLDERS	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_folders?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_folders.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_folders?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_CLASSES	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_classes?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_classes.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_classes?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_MLISTS	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_mlists?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_mlists.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_mlists?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_LOG	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_log?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_log.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_log?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_ARCHIVE	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_archive?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_archive.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_archive?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_MONITOR	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_monitor?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_monitor.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_monitor?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_APPROVE	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_approve?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_approve.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_approve?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_SIGN	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_sign?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_sign.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_sign?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_LIMIT	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_limit?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_limit.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_limit?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_KEYWORD	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_keyword?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_keyword.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_keyword?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_STATISTIC	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_statistic?domain=%s&session=%s\" target=basefrm>\n\
<IMG src=\"../data/picture/icon_statistic.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_statistic?domain=%s&session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_EXIT	\
"<TR><TD align=left width=48><A title=\"%s\" \n\
href=\"domain_main?domain=%s&exit=%s\" target=_parent>\n\
<IMG src=\"../data/picture/icon_exit.jpg\" border=0></A></TD>\n\
<TD noWrap align=left><A title=\"%s\" \n\
href=\"domain_main?domain=%s&exit=%s\" target=_parent>%s</A></TD></TR>\n"

#define HTML_LEFT_END	"</TBODY></TABLE></BODY></HTML>"

#define DEF_MODE        S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static void ui_main_error_html(const char *error_string);
static void ui_main_login_html(void);
static void ui_main_exit_html(const char *domain, const char *session);

static void ui_main_main_html(const char *domain, const char *session);

static void ui_main_left_html(const char *domain, const char *session);

static BOOL ui_main_get_self(char *url_buff, int length);


static char g_exit_url[1024];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void ui_main_init(const char *exit_url, const char *url_link,
	const char *resource_path)
{
	strcpy(g_exit_url, exit_url);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int ui_main_run()
{
	char *cookie;
	BOOL b_result;
	char *language;
	int domain_type;
	char *str_value;
	char saved_pw[40];
	char homedir[256];
	int domain_status;
	const char *domain;
	const char *session;
	char temp_path[256];
	const char *password;
	CONFIG_FILE *pconfig;
	char post_buff[1024];
	char session_buff[64];
	char *query, *request;
	char cookie_buff[512];
	REQUEST_PARSER *pparser;
	COOKIE_PARSER *pcookie_parser;
	
	g_lang_resource = lang_resource_init(g_resource_path);
	if (g_lang_resource == nullptr) {
		system_log_info("[ui_main]: failed to init language resource");
		return -1;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		ui_main_error_html(NULL);
		return 0;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[ui_main]: $REQUEST_METHOD is unset");
		return -2;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST",language));
			return 0;
		}
		pparser = request_parser_init(post_buff);
		domain = request_parser_get(pparser, "domain");
		if (NULL == domain) {
			system_log_info("[ui_main]: query string of POST format error");
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST",language));
			return 0;
		}
		if (strlen(domain) < 4) {
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_DOMAIN", language));
			return 0;
		}
		password = request_parser_get(pparser, "password");
		if (NULL == password) {
			system_log_info("[ui_main]: query string of POST format error");
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		if (FALSE == data_source_info_domain(domain, &domain_status,
			&domain_type, saved_pw, homedir, &b_result)) {
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_INTERNAL", language));
			return 0;
		}
		if (FALSE == b_result) {
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_AUTH", language));
			return 0;
		}
		if (0 != domain_status) {
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_STATUS", language));
			return 0;
		}
		if (0 != domain_type) {
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_ALIAS", language));
			return 0;
		}
		cookie_buff[0] = '\0';
		sprintf(temp_path, "%s/domain.cfg", homedir);
		pconfig = config_file_init2(NULL, temp_path);
		if (NULL != pconfig) {
			str_value = config_file_get_value(pconfig, "REPORT_LANGUAGE");
			if (NULL != str_value && '\0' != str_value[0]) {
				sprintf(cookie_buff, "HTTP_ACCEPT_LANGUAGE=%s", str_value);
			}
			config_file_free(pconfig);
		}
		session_buff[0] = '\0';
		if ('\0' == saved_pw[0]) {
			if ('\0' != password[0]) {
				ui_main_error_html(lang_resource_get(
					g_lang_resource, "ERROR_AUTH", language));
			} else {
				if (FALSE == session_client_update(
					domain, cookie_buff, session_buff)) {
					system_log_info("[ui_main]: fail to produce"
							" session for domain %s", domain);
					ui_main_error_html(lang_resource_get(
						g_lang_resource,"ERROR_SERVICE", language));
				} else {
					ui_main_main_html(domain, session_buff);
				}
			}
		} else {
			if (0 == strcmp(saved_pw, crypt(password, saved_pw))) {
				if (FALSE == session_client_update(
					domain, cookie_buff, session_buff)) {
					system_log_info("[ui_main]: fail to produce"
							" session for domain %s", domain);
					ui_main_error_html(lang_resource_get(
						g_lang_resource, "ERROR_SERVICE", language));
				} else {
					ui_main_main_html(domain, session_buff);
				}
			} else {
				ui_main_error_html(lang_resource_get(
					g_lang_resource, "ERROR_AUTH", language));
			}
		}
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[ui_main]: $QUERY_STRING is unset");
			ui_main_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST",language));
			return 0;
		} else {
			if ('\0' == query[0]) {
				cookie = getenv("HTTP_COOKIE");
				if (NULL == cookie) {
					ui_main_login_html();
					return 0;
				}
				pcookie_parser = cookie_parser_init(cookie);
				domain = cookie_parser_get(pcookie_parser, "domain");
				if (NULL == domain) {
					ui_main_login_html();
					return 0;
				}
				session = cookie_parser_get(pcookie_parser, "session");
				if (NULL == session) {
					ui_main_login_html();
					return 0;
				}
				if (TRUE == session_client_check(domain, session)) {
					ui_main_main_html(domain, session);
				} else {
					ui_main_login_html();
				}
				return 0;
			}
			pparser = request_parser_init(query);
			domain = request_parser_get(pparser, "domain");
			if (NULL == domain) {
				system_log_info("[ui_main]: query string of GET format error");
				ui_main_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			session = request_parser_get(pparser, "session");
			if (NULL == session) {
				session = request_parser_get(pparser, "exit");
				if (NULL == session) {
					system_log_info("[ui_main]: query string of GET format error");
					ui_main_error_html(lang_resource_get(
						g_lang_resource, "ERROR_REQUEST", language));
					return 0;
				}
				session_client_remove(domain, session);
				ui_main_exit_html(domain, session);
				return 0;
			}
			session_client_check(domain, session);
			ui_main_left_html(domain, session);
			return 0;
		}
	} else {
		system_log_info("[ui_main]: unrecognized"
			" REQUEST_METHOD \"%s\"!", request);
		ui_main_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return 0;
	}
}

int ui_main_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void ui_main_free()
{
	/* do nothing */
}

static BOOL ui_main_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[ui_main]: $HTTP_HOST or $SCRIPT_NAME is unset");
		return FALSE;
	}
	if (NULL == https || 0 != strcasecmp(https, "ON")) {
		snprintf(url_buff, length, "http://%s%s", host, script);
	} else {
		snprintf(url_buff, length, "https://%s%s", host, script);
	}
	return TRUE;
}

static void ui_main_main_html(const char *domain, const char *session)
{
	struct tm *ptm;
	time_t cur_time;
	char *language;
	char url_buff[1024];
	char date_buff[256];
	
	if (FALSE == ui_main_get_self(url_buff, 1024)) {
		ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	time(&cur_time);
	cur_time += 30*24*60*60;
	ptm = localtime(&cur_time);
	strftime(date_buff, 256, "%a, %d %b %Y %H:%M:%S %Z", ptm);

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf("Set-Cookie:domain=%s;expires=%s\n", domain, date_buff);
	printf("Set-Cookie:session=%s;expires=%s\n", session, date_buff);
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_MAIN_HTML, lang_resource_get(g_lang_resource,"MAIN_HTML_TITLE", language),
		lang_resource_get(g_lang_resource,"CHARSET", language), url_buff, domain, session,
		domain, session);
}

static void ui_main_left_html(const char *domain, const char *session)
{
	char *language;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_LEFT_BEGIN, lang_resource_get(g_lang_resource,"CHARSET", language));

	printf(HTML_LEFT_ITEM_INFO, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_INFO",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_INFO",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_INFO",
		language));

	printf(HTML_LEFT_ITEM_CONFIG, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_CONFIG",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_CONFIG",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_CONFIG",
		language));

	printf(HTML_LEFT_ITEM_GROUPS, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_GROUPS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_GROUPS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_GROUPS",
		language));
	
	printf(HTML_LEFT_ITEM_USERS, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_USERS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_USERS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_USERS",
		language));

	printf(HTML_LEFT_ITEM_BINPUT, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_BINPUT",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_BINPUT",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_BINPUT",
		language));
		
	printf(HTML_LEFT_ITEM_FOLDERS, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_FOLDERS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_FOLDERS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_FOLDERS",
		language));
	
	printf(HTML_LEFT_ITEM_CLASSES, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_CLASSES",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_CLASSES",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_CLASSES",
		language));

	printf(HTML_LEFT_ITEM_MLISTS, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_MLISTS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_MLISTS",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_MLISTS",
		language));

	printf(HTML_LEFT_ITEM_LOG, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_LOG", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_LOG", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_LOG", language));

	printf(HTML_LEFT_ITEM_ARCHIVE,
		lang_resource_get(g_lang_resource,"ITEM_DOMAIN_ARCHIVE", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_ARCHIVE", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_ARCHIVE", language));
	
	printf(HTML_LEFT_ITEM_MONITOR,
		lang_resource_get(g_lang_resource,"ITEM_DOMAIN_MONITOR", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_MONITOR", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_MONITOR", language));
	
	printf(HTML_LEFT_ITEM_APPROVE,
		lang_resource_get(g_lang_resource,"ITEM_DOMAIN_APPROVE", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_APPROVE", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_APPROVE", language));
	
	printf(HTML_LEFT_ITEM_SIGN,
		lang_resource_get(g_lang_resource,"ITEM_DOMAIN_SIGN", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_SIGN", language),
		domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_SIGN", language));
	
	printf(HTML_LEFT_ITEM_LIMIT, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_LIMIT",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_LIMIT",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_LIMIT",
		language));
	
	printf(HTML_LEFT_ITEM_KEYWORD, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_KEYWORD",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_KEYWORD",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_KEYWORD",
		language));
	
	printf(HTML_LEFT_ITEM_STATISTIC, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_STATISTIC",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_STATISTIC",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_STATISTIC",
		language));

	printf(HTML_LEFT_ITEM_EXIT, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_EXIT",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_EXIT",
		language), domain, session, lang_resource_get(g_lang_resource,"ITEM_DOMAIN_EXIT",
		language));

	printf(HTML_LEFT_END);

}

static void ui_main_error_html(const char *error_string)
{
	const char *language;
	char url_buff[1024];
	
	if (NULL ==error_string) {
		error_string = "fatal error!";
	}
	if (FALSE == ui_main_get_self(url_buff, 1024)) {
		url_buff[0] = '\0';
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
	printf(HTML_ERROR_5, url_buff, lang_resource_get(g_lang_resource,"BACK_LABEL",
		language), error_string);
}

static void ui_main_login_html()
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == ui_main_get_self(url_buff, 1024)) {
		ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"LOGIN_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"LOGIN_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_LOGIN_5);
	printf(url_buff);
	printf(HTML_LOGIN_6);
	printf(lang_resource_get(g_lang_resource,"DOMAIN", language));
	printf(HTML_LOGIN_7);
	printf(lang_resource_get(g_lang_resource,"PASSWORD", language));
	printf(HTML_LOGIN_8);
	printf(lang_resource_get(g_lang_resource,"LOGIN_LABEL", language));
	printf(HTML_LOGIN_9);
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	printf(HTML_LOGIN_10);
}

static void ui_main_exit_html(const char *domain, const char *session)
{
	char *language;
	char *str_value;
	char exit_url[1024];
	char temp_path[256];
	char domain_path[256];
	CONFIG_FILE *pconfig;
	
	strcpy(exit_url, g_exit_url);
	if (TRUE == data_source_get_homedir(domain, domain_path)) {
		sprintf(temp_path, "%s/tmp/domain_users.%s", domain_path, session);
		remove(temp_path);
		sprintf(temp_path, "%s/domain.cfg", domain_path);
		pconfig = config_file_init2(NULL, temp_path);
		if (NULL != pconfig) {
			str_value = config_file_get_value(pconfig, "EXIT_URL");
			if (NULL != str_value) {
				strcpy(exit_url, str_value);
			}
			config_file_free(pconfig);
		}
	}
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));

	printf(HTML_EXIT_1, exit_url);
}
