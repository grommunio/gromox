#include "list_ui.h"
#include "system_log.h"
#include "acl_control.h"
#include "lang_resource.h"
#include "request_parser.h"
#include "data_source.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <iconv.h>
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
function DeleteOrg(id) {location.href='%s?session=%s\
&action=remove-org&id=' + id;}\n\
function DeleteDomain(domain_id, org_id) {location.href='%s?session=%s\
&action=remove-domain&domain=' + domain_id + '&org=' + org_id;}\n\
</SCRIPT><FORM class=SearchForm name=orgform method=get action=%s >\n\
<TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"add-org\" name=action />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=memo /></TD></TR><TR><TD></TD><TD></TD><TD><INPUT type=submit \n\
tabindex=2 value=\"    %s    \" onclick=\"\
if (orgform.memo.value.length == 0) {\n\
orgform.memo.focus();\n\
return false;}\n\
return true;\" />\n\
</TD></TR></TABLE></FORM><HR><FORM class=SearchForm name=dmnform method=get \n\
action=%s ><TABLE border=0><INPUT type=hidden value=%s \n\
name=session /><INPUT type=hidden value=\"add-domain\" name=action />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=3 \n\
name=domain /></TD></TR><TR><TD></TD><TD>%s:</TD><TD><SELECT name=org>\n"

#define HTML_MAIN_6	\
"</SELECT></TD></TR><TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=4 \n\
value=\"    %s    \" onclick=\"\
if (dmnform.domain.value.length == 0) {\n\
dmnform.domain.focus();\n\
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

#define HTML_MAIN_8 \
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_ORG	\
"<TR class=SolidRow><TD colSpan=2>&nbsp;%s:%s&nbsp;</TD><TD>&nbsp;<A href=\"javascript:DeleteOrg('%d')\">%s</A></TD></TR>\n"

#define HTML_TBITEM_DOMAIN	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;<A href=\"javascript:DeleteDomain('%d', %d)\">%s</A></TD></TR>\n"

#define HTML_OPTION_NORMAL       "<OPTION value=%d>%s</OPTION>"


#define HTML_CHART_32   "<IMG src=\"../data/picture/bar32.png\">"
#define HTML_CHART_16   "<IMG src=\"../data/picture/bar16.png\">"
#define HTML_CHART_8    "<IMG src=\"../data/picture/bar08.png\">"
#define HTML_CHART_4    "<IMG src=\"../data/picture/bar04.png\">"
#define HTML_CHART_2    "<IMG src=\"../data/picture/bar02.png\">"
#define HTML_CHART_1    "<IMG src=\"../data/picture/bar01.png\">"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


			
static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *session);

static BOOL list_ui_get_self(char *url_buff, int length);


static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

static void list_ui_from_utf8(char *src, char *dst, size_t len)
{
	size_t in_len;
	char *pin, *pout;
	iconv_t conv_id;
	
	conv_id = iconv_open(lang_resource_get(g_lang_resource, "CHARSET",
				getenv("HTTP_ACCEPT_LANGUAGE")), "UTF-8");
	pin = src;
	pout = dst;
	in_len = strlen(src);
	memset(dst, 0, len);
	iconv(conv_id, &pin, &in_len, &pout, &len);
	iconv_close(conv_id);
}

static void list_ui_to_utf8(char *src, char *dst, size_t len)
{
	size_t in_len;
	char *pin, *pout;
	iconv_t conv_id;

	conv_id = iconv_open("UTF-8", lang_resource_get(g_lang_resource,
				"CHARSET", getenv("HTTP_ACCEPT_LANGUAGE")));
	pin = src;
	pout = dst;
	in_len = strlen(src);
	memset(dst, 0, len);
	iconv(conv_id, &pin, &in_len, &pout, &len);
	iconv_close(conv_id);
}


void list_ui_init(const char *url_link, const char *resource_path)
{
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int list_ui_run()
{
	int org_id;
	char *query;
	int domain_id;
	char *request;
	char *language;
	char *remote_ip;
	const char *pid;
	const char *memo;
	const char *action;
	const char *session;
	char temp_buff[1024];
	const char *domainname;
	REQUEST_PARSER *pparser;
	

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
			system_log_info("[admin_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		pparser = request_parser_init(query);
		if (NULL == pparser) {
			system_log_info("[list_ui]: fail to init request_parser");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		
		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			system_log_info("[admin_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		
		switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_IGNORE)) {
		case ACL_SESSION_OK:
			break;
		case ACL_SESSION_TIMEOUT:
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT", language));
			return 0;
		case ACL_SESSION_PRIVILEGE:
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",language));
			return 0;
		default:
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION", language));
			return 0;
		}
		
		if (1 == request_parser_num(pparser)) {
			list_ui_main_html(session);
			return 0;
		}

		action = request_parser_get(pparser, "action");
		if (NULL == action) {
			system_log_info("[list_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		
		if (0 == strcasecmp(action, "add-org")) {
			memo = request_parser_get(pparser, "memo");
			if (NULL == memo) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
				return 0;
			}
			list_ui_to_utf8((char*)memo, temp_buff, 1024);
			data_source_add_org(temp_buff);
		} else if (0 == strcasecmp(action, "remove-org")) {
			pid = request_parser_get(pparser, "id");
			if (NULL == pid || 0 == (org_id = atoi(pid))) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
				return 0;
			}
			data_source_remove_org(org_id);
		} else if (0 == strcasecmp(action, "add-domain")) {
			domainname = request_parser_get(pparser, "domain");
			if (NULL == domainname) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
				return 0;
			}
			pid = request_parser_get(pparser, "org");
			if (NULL == pid || 0 == (org_id = atoi(pid))) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
				return 0;
			}
			data_source_add_domain(domainname, org_id);
		} else if (0 == strcasecmp(action, "remove-domain")) {
			pid = request_parser_get(pparser, "domain");
			if (NULL == pid || 0 == (domain_id = atoi(pid))) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
				return 0;
			}
			pid = request_parser_get(pparser, "org");
			if (NULL == pid || 0 == (org_id = atoi(pid))) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
				return 0;
			}
			data_source_remove_domain(domain_id, org_id);
		} else {
			system_log_info("[list_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		list_ui_main_html(session);
		return 0;
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
	int org_id;
	int domain_id;
	char *language;
	ORG_ITEM *porg;
	char url_buff[1024];
	char temp_buff[128];
	DOMAIN_ITEM *pdomain;
	DATA_COLLECT *pcollect;
	
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource, "ERROR_INTERNAL",
			language));
		return;
	}
	
	pcollect = data_source_collect_init();
	if (NULL == pcollect || FALSE == data_source_query(pcollect)) {
		list_ui_error_html(lang_resource_get(g_lang_resource, "ERROR_INTERNAL",
			language));
		return;
	}
	
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
		session, lang_resource_get(g_lang_resource,"MAIN_ORG", language),
		lang_resource_get(g_lang_resource,"ADDORG_LABEL", language), url_buff, session,
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MAIN_ORG", language));
		
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		porg = data_source_collect_get_value(pcollect);
		list_ui_from_utf8(porg->memo, temp_buff, 1024);
		printf(HTML_OPTION_NORMAL, porg->org_id, temp_buff);
	}
	
	
	printf(HTML_MAIN_6, lang_resource_get(g_lang_resource,"ADDDOMAIN_LABEL", language));
	
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	
	printf(HTML_MAIN_7);
	
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN_TITLE", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		porg = data_source_collect_get_value(pcollect);
		list_ui_from_utf8(porg->memo, temp_buff, 1024);
		printf(HTML_TBITEM_ORG, lang_resource_get(g_lang_resource, "MAIN_ORG",
			language), temp_buff, porg->org_id, lang_resource_get(g_lang_resource,
			"DELETE_LABEL", language));
		
		for(data_source_collect_begin(&porg->collect);
			!data_source_collect_done(&porg->collect);
			data_source_collect_forward(&porg->collect)) {
			pdomain = data_source_collect_get_value(&porg->collect);
			list_ui_from_utf8(pdomain->title, temp_buff, 1024);
			printf(HTML_TBITEM_DOMAIN, pdomain->domainname, temp_buff,
				pdomain->domain_id, porg->org_id, lang_resource_get(g_lang_resource,
				"DELETE_LABEL", language));
		}
	}
	data_source_collect_free(pcollect);
	printf(HTML_MAIN_8);
}

