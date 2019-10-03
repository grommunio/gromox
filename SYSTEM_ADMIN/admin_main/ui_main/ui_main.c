#include "ui_main.h"
#include "lang_resource.h"
#include "cookie_parser.h"
#include "request_parser.h"
#include "acl_control.h"
#include "system_log.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
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

/* fill title here */

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

/* fill username label here */

#define HTML_LOGIN_7    \
": <INPUT class=FormInput type=text name=username tabindex=1 />\n\
</TD></TR><TR><TD align=right>\n"

/* fill password label here */

#define HTML_LOGIN_8	\
": <INPUT class=FormInput type=password name=password  tabindex=2/></TD></TR>\n\
<TR><TD align=right><INPUT type=checkbox checked=\"checked\" name=extmenu \n\
value=\"ext\" tabindex=3 />"

/* fill extended menu here */

#define HTML_LOGIN_9	\
"</TD></TR><TR><TD align=right><INPUT type=submit value=\"  "

/* fill login button label here */

#define HTML_LOGIN_10	\
"  \"  tabindex=4 /></TBODY></TABLE><P></P><BR><P></P><BR><P></P>\n\
<BR><P></P><BR><P></P><BR><P></P><BR><P></P><BR><P></P><BR>&copy; "

#define HTML_LOGIN_11	"</CENTER></BODY></HTML>"

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
<FRAME name=leftfrm src=\"%s?session=%s\" scrolling=yes>\n\
<FRAME name=basefrm src=\"admin_log?session=%s\" scrolling=yes>\n\
</FRAMESET></HTML>"

#define HTML_MAIN_HTML_EXT	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Frameset//EN\">\n\
<HTML><HEAD><TITLE>%s</TITLE><META http-equiv=Content-Type \n\
content=\"text/html; charset=%s\">\n\
<META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
<FRAMESET borderColor=#e5e6e6 rows=* cols=175,*>\n\
<FRAME name=leftfrm src=\"%s?session=%s&extmenu=ext\" scrolling=no>\n\
<FRAME name=basefrm src=\"admin_log?session=%s\" scrolling=yes>\n\
</FRAMESET></HTML>"


#define HTML_LEFT_BEGIN_EXT	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"><HTML><HEAD>\n\
<LINK href=\"../data/css/panelbar.css\" type=text/css rel=stylesheet>\n\
<SCRIPT src=\"../data/script/panelbar.js\"></SCRIPT>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\">\n\
<META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0 \n\
marginheight=\"0\" marginwidth=\"0\"><CENTER>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0>\n\
<TBODY><TR><TD noWrap align=middle background=\"../data/picture/di1.gif\"\n\
height=55><IMG src=\"../data/picture/contents.gif\">\n\
</TD></TR></TBODY></TABLE><BR><TABLE width=\"221\" border=\"0\" \n\
cellspacing=\"0\" cellpadding=\"0\"><TR><TD><SCRIPT type=\"text/javascript\">\n\
p = new PhenMenu('p');\n"

#define HTML_LEFT_END_EXT	\
"document.write(p);</SCRIPT></TD></TR></TABLE></BODY></HTML>"

#define HTML_LEFT_BEGIN_NOR	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"><HTML><HEAD>\n\
<LINK href=\"../data/css/result.css\" type=text/css rel=stylesheet>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\">\n\
<META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0 \n\
marginheight=\"0\" marginwidth=\"0\"><CENTER>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0>\n\
<TBODY><TR><TD noWrap align=middle background=\"../data/picture/di1.gif\"\n\
height=55><IMG src=\"../data/picture/contents.gif\">\n\
</TD></TR></TBODY></TABLE><BR><TABLE cellSpacing=5 cellPadding=2 \n\
width=\"100%\" border=0><TBODY>\n"

#define HTML_LEFT_ITEM_NODE	\
"<TR><TD align=left width=32><IMG src=\"../data/picture/%s\" \n\
border=0></TD><TD noWrap align=left>%s</TD></TR>\n"

#define HTML_LEFT_ITEM_SUB	\
"<TR><TD align=left width=32></TD><TD noWrap align=left>\n\
<A href=\"%s?session=%s\" target=basefrm>%s</A></TD></TR>\n"

#define HTML_LEFT_ITEM_EXIT	\
"<TR><TD align=left width=32><IMG src=\"../data/picture/exit.jpg\" \n\
border=0></TD><TD noWrap align=left><A href=\"admin_main?exit=%s\" \n\
target=_parent>%s</A></TD></TR>\n"

#define HTML_LEFT_END_NOR   "</TBODY></TABLE></BODY></HTML>"


static void ui_main_error_html(const char *error_string);

static void ui_main_login_html();

static void ui_main_main_html(const char *session, BOOL b_ext);

static void ui_main_left_html(const char *session, BOOL b_ext);

static BOOL ui_main_get_self(char *url_buff, int length);

static void ui_main_unencode(char *src, char *last, char *dest);

static char g_logo_link[1024];

static char g_resource_path[256];

static LANG_RESOURCE *g_lang_resource;

void ui_main_init(const char *url_link, const char *resource_path)
{
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int ui_main_run()
{
	BOOL b_ext;
	char *cookie;
	char *language;
	char *remote_ip;
	char *query, *request;
	const char *username;
	const char *password;
	const char *session;
	char temp_path[256];
	char post_buff[1024];
	char tmp_session[256];
	REQUEST_PARSER *pparser;
	COOKIE_PARSER *pcookier;


	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		ui_main_error_html(NULL);
		return 0;
	}

	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[ui_main]: fail to init language resource");
		return -1;
	}

	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[ui_main]: fail to get REQUEST_METHOD environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[ui_main]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			ui_main_error_html(lang_resource_get(g_lang_resource, "ERROR_REQUEST",language));
			return 0;
		}

		pparser = request_parser_init(post_buff);
		if (NULL == pparser) {
			system_log_info("[ui_main]: fail to init request_parser");
			ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",language));
			return 0;
		}
		username = request_parser_get(pparser, "username");
		password = request_parser_get(pparser, "password");
		if (NULL == username || NULL == password ||
			strlen(username) > 127 || strlen(password) > 127) {
			system_log_info("[ui_main]: query string of POST format error");
			ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			request_parser_free(pparser);
			return 0;
		}
		if (NULL == request_parser_get(pparser, "extmenu")) {
			b_ext = FALSE;
		} else {
			b_ext = TRUE;
		}
		if (FALSE == acl_control_auth(username, password)) {
			ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_AUTH", language));
		} else {
			if (FALSE == acl_control_produce(username, remote_ip, tmp_session)) {
				system_log_info("[ui_main]: fail to produce session");
				ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
				request_parser_free(pparser);
				return 0;
			}
			ui_main_main_html(tmp_session, b_ext);
		}
		request_parser_free(pparser);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[ui_main]: fail to get QUERY_STRING "
					"environment!");
			ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}

		pparser = request_parser_init(query);
		if (NULL == pparser) {
			system_log_info("[ui_main]: fail to init request_parser");
			ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",language));
			return 0;
		}

		if (0 == request_parser_num(pparser)) {
			request_parser_free(pparser);
			cookie = getenv("HTTP_COOKIE");
			if (NULL == cookie) {
				ui_main_login_html();
				return 0;
			}
			pcookier = cookie_parser_init(cookie);
			if (NULL == pcookier) {
				ui_main_login_html();
				return 0;
			}

			session = cookie_parser_get(pcookier, "session");
			if (NULL == session) {
				ui_main_login_html();
				cookie_parser_free(pcookier);
				return 0;
			}
			
			if (NULL == cookie_parser_get(pcookier, "extmenu")) {
				b_ext = FALSE;
			} else {
				b_ext = TRUE;
			}
			if (ACL_SESSION_OK == acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_IGNORE)) {
				ui_main_main_html(session, b_ext);
				cookie_parser_free(pcookier);
				return 0;
			}
			ui_main_login_html();
			cookie_parser_free(pcookier);
			return 0;
		}

		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			session = request_parser_get(pparser, "exit");
			if (NULL == session) {
				system_log_info("[ui_main]: query string of GET format error");
				ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				request_parser_free(pparser);
				return 0;
			}
			acl_control_remove(session);
			sprintf(temp_path, "/tmp/domain_list.%s", session);
			remove(temp_path);
			ui_main_login_html();
			request_parser_free(pparser);
			return 0;
		}
		if (NULL == request_parser_get(pparser, "extmenu")) {
			b_ext = FALSE;
		} else {
			b_ext = TRUE;
		}
		ui_main_left_html(session, b_ext);
		request_parser_free(pparser);
		return 0;
	} else {
		system_log_info("[ui_main]: unrecognized REQUEST_METHOD \"%s\"!",
					request);
		ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
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
		system_log_info("[ui_main]: fail to get "
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

static void ui_main_main_html(const char *session, BOOL b_ext)
{
	time_t cur_time;
	struct tm *ptm;
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
	printf("Set-Cookie:session=%s;expires=%s\n", session, date_buff);
	if (FALSE == b_ext) {
		printf("Set-Cookie:extmenu=0;expires=%s\n\n", date_buff);
		printf(HTML_MAIN_HTML, lang_resource_get(g_lang_resource,"MAIN_HTML_TITLE",
			language), lang_resource_get(g_lang_resource,"CHARSET", language),
			url_buff, session, session);
	} else {
		printf("Set-Cookie:extmenu=1;expires=%s\n\n", date_buff);
		printf(HTML_MAIN_HTML_EXT, lang_resource_get(g_lang_resource,"MAIN_HTML_TITLE",
			language), lang_resource_get(g_lang_resource,"CHARSET", language),
			url_buff, session, session);
	}
}

static void ui_main_left_html(const char *session, BOOL b_ext)
{
	char *language;
	char username[256];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	if (FALSE == acl_control_naming(session, username)) {
		username[0] = '\0';
	}
	if (TRUE == b_ext) {	
		printf(HTML_LEFT_BEGIN_EXT, lang_resource_get(g_lang_resource,"CHARSET", language));
		printf("p.add(0,-1,'%s','','header','../data/picture/query.jpg');\n",
			lang_resource_get(g_lang_resource,"MENU_QUERY", language));
		printf("p.add(1,0,'%s','admin_log?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_ADMIN_LOG", language), session);
		printf("p.add(2,0,'%s','admin_archive?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_ADMIN_ARCHIVE", language), session);
		printf("p.add(3,0,'%s','admin_insulation?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_ADMIN_INSULATION", language), session);
		printf("p.add(4,-1,'%s','','header','../data/picture/setup.jpg');\n",
			lang_resource_get(g_lang_resource,"MENU_SETUP", language));
		printf("p.add(5,4,'%s','system_setup?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_SYSTEM_SETUP", language), session);
		printf("p.add(6,4,'%s','area_list?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_AREA_LIST", language), session);
		printf("p.add(7,4,'%s','archiver_list?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_ARCHIVER_LIST", language), session);
		printf("p.add(8,4,'%s','relay_table?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_RELAY_TABLE", language), session);
		printf("p.add(9,4,'%s','relay_allow?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_RELAY_ALLOW", language), session);
		printf("p.add(10,-1,'%s','','header','../data/picture/anti-spam.jpg');\n",
			lang_resource_get(g_lang_resource,"MENU_ANTI_SPAM", language));
		printf("p.add(11,10,'%s','boundary_blacklist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_BOUNDARY_BLACKLIST", language), session);
		printf("p.add(12,10,'%s','domain_blacklist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_BLACKLIST", language), session);
		printf("p.add(13,10,'%s','domain_whitelist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_WHITELIST", language), session);
		printf("p.add(14,10,'%s','dynamic_dnslist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DYNAMIC_DNSLIST", language), session);
		printf("p.add(15,10,'%s','ip_blacklist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_IP_BLACKLIST", language), session);
		printf("p.add(16,10,'%s','ip_whitelist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_IP_WHITELIST", language), session);
		printf("p.add(17,10,'%s','ipdomain_table?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_IPDOMAIN_TABLE", language), session);
		printf("p.add(18,10,'%s','keyword_group?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_KEYWORD_GROUP", language), session);
		printf("p.add(19,10,'%s','keyword_upload?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_KEYWORD_UPLOAD", language), session);
		printf("p.add(20,10,'%s','from_blacklist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_FROM_BLACKLIST", language), session);
		printf("p.add(21,10,'%s','rcpt_blacklist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_RCPT_BLACKLIST", language), session);
		printf("p.add(22,10,'%s','tagging_whitelist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_TAGGING_WHITELIST", language), session);
		printf("p.add(23,10,'%s','xmailer_blacklist?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_XMAILER_BLACKLIST", language), session);
		printf("p.add(24,-1,'%s','','header','../data/picture/misc.jpg');\n",
			lang_resource_get(g_lang_resource,"MENU_MISC", language));
		printf("p.add(25,24,'%s','domain_list?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_LIST", language), session);
		printf("p.add(26,24,'%s','org_list?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_ORG_LIST", language), session);
		printf("p.add(27,24,'%s','dns_table?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DNS_TABLE", language), session);
		printf("p.add(28,24,'%s','forward_table?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_FORWARD_TABLE", language), session);
		printf("p.add(29,24,'%s','domain_mailbox?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_MAILBOX", language), session);
		printf("p.add(30,24,'%s','from_replace?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_FROM_REPLACE", language), session);
		printf("p.add(31,24,'%s','relay_domains?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_RELAY_DOMAINS", language), session);
		printf("p.add(32,24,'%s','single_rcpt?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_SINGLE_RCPT", language), session);
		printf("p.add(33,24,'%s','message_sign?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_MESSAGE_SIGN", language), session);
		printf("p.add(34,24,'%s','supervising_list?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_SUPERVISING_LIST", language), session);
		printf("p.add(35,-1,'%s','','header','../data/picture/status.jpg');\n",
			lang_resource_get(g_lang_resource,"MENU_STATUS", language));
		printf("p.add(36,35,'%s','daily_statistic?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DAILY_STATISTIC", language), session);
		printf("p.add(37,35,'%s','daily_status?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_DAILY_STATUS", language), session);
		printf("p.add(38,35,'%s','system_info?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_SYSTEM_INFO", language), session);
		printf("p.add(39,35,'%s','keyword_statistic?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_KEYWORD_STATISTIC", language), session);
		printf("p.add(40,35,'%s','mensual_statistic?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_MENSUAL_STATISTIC", language), session);
		printf("p.add(41,35,'%s','supervising_statistic?session=%s','','','','','','','basefrm');\n",
			lang_resource_get(g_lang_resource,"MENU_SUPERVISING_STATISTIC", language), session);
		printf("p.add(42,-1,'%s','','header','../data/picture/other.jpg');\n",
			lang_resource_get(g_lang_resource,"MENU_OTHER", language));
		if (0 == strcasecmp(username, "administrator")) {
			printf("p.add(43,42,'%s','system_backup?session=%s','','','','','','','basefrm');\n",
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_BACKUP", language), session);
			printf("p.add(44,42,'%s','system_users?session=%s','','','','','','','basefrm');\n",
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_USERS", language), session);
			printf("p.add(45,42,'%s','system_password?session=%s','','','','','','','basefrm');\n",
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_PASSWORD", language), session);
			printf("p.add(46,-1,'%s','admin_main?exit=%s','header','../data/picture/exit.jpg','','','','','_parent');\n",
				lang_resource_get(g_lang_resource,"MENU_EXIT", language), session);
		} else {
			printf("p.add(43,42,'%s','system_password?session=%s','','','','','','','basefrm');\n",
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_PASSWORD", language), session);
			printf("p.add(44,-1,'%s','admin_main?exit=%s','header','../data/picture/exit.jpg','','','','','_parent');\n",
				lang_resource_get(g_lang_resource,"MENU_EXIT", language), session);
		}
		printf(HTML_LEFT_END_EXT);
	} else {
		printf(HTML_LEFT_BEGIN_NOR, lang_resource_get(g_lang_resource,"CHARSET", language));
		printf(HTML_LEFT_ITEM_NODE, "query.jpg",
			lang_resource_get(g_lang_resource,"MENU_QUERY", language));
		printf(HTML_LEFT_ITEM_SUB, "admin_log", session, 
			lang_resource_get(g_lang_resource,"MENU_ADMIN_LOG", language));
		printf(HTML_LEFT_ITEM_SUB, "admin_archive", session,
			lang_resource_get(g_lang_resource,"MENU_ADMIN_ARCHIVE", language));
		printf(HTML_LEFT_ITEM_SUB, "admin_insulation", session,
			lang_resource_get(g_lang_resource,"MENU_ADMIN_INSULATION", language));
		printf(HTML_LEFT_ITEM_NODE, "setup.jpg",
			lang_resource_get(g_lang_resource,"MENU_SETUP", language));
		printf(HTML_LEFT_ITEM_SUB, "system_setup", session,
			lang_resource_get(g_lang_resource,"MENU_SYSTEM_SETUP", language));
		printf(HTML_LEFT_ITEM_SUB, "area_list", session,
			lang_resource_get(g_lang_resource,"MENU_AREA_LIST", language));
		printf(HTML_LEFT_ITEM_SUB, "archiver_list", session,
			lang_resource_get(g_lang_resource,"MENU_ARCHIVER_LIST", language));
		printf(HTML_LEFT_ITEM_SUB, "relay_table", session,
			lang_resource_get(g_lang_resource,"MENU_RELAY_TABLE", language));
		printf(HTML_LEFT_ITEM_SUB, "relay_allow", session,
			lang_resource_get(g_lang_resource,"MENU_RELAY_ALLOW", language));
		printf(HTML_LEFT_ITEM_NODE, "anti-spam.jpg",
			lang_resource_get(g_lang_resource,"MENU_ANTI_SPAM", language));
		printf(HTML_LEFT_ITEM_SUB, "boundary_blacklist", session,
			lang_resource_get(g_lang_resource,"MENU_BOUNDARY_BLACKLIST", language));
		printf(HTML_LEFT_ITEM_SUB, "domain_blacklist", session,
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_BLACKLIST", language));
		printf(HTML_LEFT_ITEM_SUB, "domain_whitelist", session,
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_WHITELIST", language));
		printf(HTML_LEFT_ITEM_SUB, "dynamic_dnslist", session,
			lang_resource_get(g_lang_resource,"MENU_DYNAMIC_DNSLIST", language));
		printf(HTML_LEFT_ITEM_SUB, "ip_blacklist", session,
			lang_resource_get(g_lang_resource,"MENU_IP_BLACKLIST", language));
		printf(HTML_LEFT_ITEM_SUB, "ip_whitelist", session,
			lang_resource_get(g_lang_resource,"MENU_IP_WHITELIST", language));
		printf(HTML_LEFT_ITEM_SUB, "ipdomain_table", session,
			lang_resource_get(g_lang_resource,"MENU_IPDOMAIN_TABLE", language));
		printf(HTML_LEFT_ITEM_SUB, "keyword_group", session,
			lang_resource_get(g_lang_resource,"MENU_KEYWORD_GROUP", language));
		printf(HTML_LEFT_ITEM_SUB, "keyword_upload", session,
			lang_resource_get(g_lang_resource,"MENU_KEYWORD_UPLOAD", language));
		printf(HTML_LEFT_ITEM_SUB, "from_blacklist", session,
			lang_resource_get(g_lang_resource,"MENU_FROM_BLACKLIST", language));
		printf(HTML_LEFT_ITEM_SUB, "rcpt_blacklist", session,
			lang_resource_get(g_lang_resource,"MENU_RCPT_BLACKLIST", language));
		printf(HTML_LEFT_ITEM_SUB, "tagging_whitelist", session,
			lang_resource_get(g_lang_resource,"MENU_TAGGING_WHITELIST", language));
		printf(HTML_LEFT_ITEM_SUB, "xmailer_blacklist", session,
			lang_resource_get(g_lang_resource,"MENU_XMAILER_BLACKLIST", language));
		printf(HTML_LEFT_ITEM_NODE, "misc.jpg",
			lang_resource_get(g_lang_resource,"MENU_MISC", language));
		printf(HTML_LEFT_ITEM_SUB, "domain_list", session,
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_LIST", language));
		printf(HTML_LEFT_ITEM_SUB, "org_list", session,
			lang_resource_get(g_lang_resource,"MENU_ORG_LIST", language));
		printf(HTML_LEFT_ITEM_SUB, "dns_table", session,
			lang_resource_get(g_lang_resource,"MENU_DNS_TABLE", language));
		printf(HTML_LEFT_ITEM_SUB, "forward_table", session,
			lang_resource_get(g_lang_resource,"MENU_FORWARD_TABLE", language));
		printf(HTML_LEFT_ITEM_SUB, "domain_mailbox", session,
			lang_resource_get(g_lang_resource,"MENU_DOMAIN_MAILBOX", language));
		printf(HTML_LEFT_ITEM_SUB, "from_replace", session,
			lang_resource_get(g_lang_resource,"MENU_FROM_REPLACE", language));
		printf(HTML_LEFT_ITEM_SUB, "relay_domains", session,
			lang_resource_get(g_lang_resource,"MENU_RELAY_DOMAINS", language));
		printf(HTML_LEFT_ITEM_SUB, "single_rcpt", session,
			lang_resource_get(g_lang_resource,"MENU_SINGLE_RCPT", language));
		printf(HTML_LEFT_ITEM_SUB, "message_sign", session,
			lang_resource_get(g_lang_resource,"MENU_MESSAGE_SIGN", language));
		printf(HTML_LEFT_ITEM_SUB, "supervising_list", session,
			lang_resource_get(g_lang_resource,"MENU_SUPERVISING_LIST", language));
		printf(HTML_LEFT_ITEM_NODE, "status.jpg",
			lang_resource_get(g_lang_resource,"MENU_STATUS", language));
		printf(HTML_LEFT_ITEM_SUB, "daily_statistic", session,
			lang_resource_get(g_lang_resource,"MENU_DAILY_STATISTIC", language));
		printf(HTML_LEFT_ITEM_SUB, "daily_status", session,
			lang_resource_get(g_lang_resource,"MENU_DAILY_STATUS", language));
		printf(HTML_LEFT_ITEM_SUB, "system_info", session,
			lang_resource_get(g_lang_resource,"MENU_SYSTEM_INFO", language));
		printf(HTML_LEFT_ITEM_SUB, "keyword_statistic", session,
			lang_resource_get(g_lang_resource,"MENU_KEYWORD_STATISTIC", language));
		printf(HTML_LEFT_ITEM_SUB, "mensual_statistic", session,
			lang_resource_get(g_lang_resource,"MENU_MENSUAL_STATISTIC", language));
		printf(HTML_LEFT_ITEM_SUB, "supervising_statistic", session,
			lang_resource_get(g_lang_resource,"MENU_SUPERVISING_STATISTIC", language));
		printf(HTML_LEFT_ITEM_NODE, "other.jpg",
			lang_resource_get(g_lang_resource,"MENU_OTHER", language));
		if (0 == strcasecmp(username, "administrator")) {
			printf(HTML_LEFT_ITEM_SUB, "system_backup", session,
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_BACKUP", language));
			printf(HTML_LEFT_ITEM_SUB, "system_users", session,
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_USERS", language));
			printf(HTML_LEFT_ITEM_SUB, "system_password", session,
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_PASSWORD", language));
			printf(HTML_LEFT_ITEM_EXIT, session,
				lang_resource_get(g_lang_resource,"MENU_EXIT", language));
		} else {
			printf(HTML_LEFT_ITEM_SUB, "system_password", session,
				lang_resource_get(g_lang_resource,"MENU_SYSTEM_PASSWORD", language));
			printf(HTML_LEFT_ITEM_EXIT, session,
				lang_resource_get(g_lang_resource,"MENU_EXIT", language));
		}
		printf(HTML_LEFT_END_NOR);
	}

}

static void ui_main_error_html(const char *error_string)
{
	char *language;
	char url_buff[1024];
	
	if (NULL ==error_string) {
		error_string = "fatal error!!!";
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
	
	if (FALSE == ui_main_get_self(url_buff, 1024)) {
		ui_main_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
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
	printf(lang_resource_get(g_lang_resource,"USERNAME", language));
	printf(HTML_LOGIN_7);
	printf(lang_resource_get(g_lang_resource,"PASSWORD", language));
	printf(HTML_LOGIN_8);
	printf(lang_resource_get(g_lang_resource,"EXTENDED_MENU", language));
	printf(HTML_LOGIN_9);
	printf(lang_resource_get(g_lang_resource,"LOGIN_LABEL", language));
	printf(HTML_LOGIN_10);
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	printf(HTML_LOGIN_11);
}


static void ui_main_unencode(char *src, char *last, char *dest)
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

