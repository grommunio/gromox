#include "list_ui.h"
#include "mapi_types.h"
#include <gromox/system_log.h>
#include "data_source.h"
#include "lang_resource.h"
#include "request_parser.h"
#include <gromox/session_client.h>
#include "mail_func.h"
#include "rop_util.h"
#include "util.h"
#include "exmdb_client.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <iconv.h>
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
<META http-equiv=Content-Type content=\"text/html; charset=utf-8\">\n\
<META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
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
function DeleteItem(folder_id) {location.href='%s?domain=%s&session=%s&action=remove&folder=' + folder_id;}\n\
function EditItem(folder_id) {location.href='%s?domain=%s&session=%s&action=list-permission&folder=' + folder_id;}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=add name=action />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
name=folder /></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<SELECT name=container tabindex=2>\n\
<OPTION value=\"\" selected></OPTION>\n\
<OPTION value=\"IPF.Note\">%s</OPTION>\n\
<OPTION value=\"IPF.Contact\">%s</OPTION>\n\
<OPTION value=\"IPF.Journal\">%s</OPTION>\n\
<OPTION value=\"IPF.Appointment\">%s</OPTION>\n\
<OPTION value=\"IPF.Stickynote\">%s</OPTION>\n\
<OPTION value=\"IPF.Task\">%s</OPTION>\n\
<OPTION value=\"IPF.Note.Infopathform\">%s</OPTION>\n\
</SELECT></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<INPUT type=text value=\"\" tabindex=3 name=comment /></TD></TR>\n\
<TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=4 value=\"%s\" onclick=\"\n\
if (0 == opeform.folder.value.length) {return false;} return true;\" \n\
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

#define HTML_PERMISSION_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s?domain=%s&session=%s\">%s</A>\n\
</TD></TR></TBODY></TABLE><SCRIPT language=\"JavaScript\">\n\
function DeleteItem(member) {location.href='%s?domain=%s&session=%s\
&action=remove-permission&folder=%llu&member=' + member;}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_PERMISSION_6 \
" ><TABLE border=0><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=%llu name=folder />\n\
<INPUT type=hidden value=add-permission name=action />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
size=30 name=username /><INPUT style=\"display:none\">\n\
</TD></TR><TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=2 \n\
value=\"  %s  \" /></TD></TR></TABLE></FORM>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill table title here */

#define HTML_PERMISSION_7 \
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_PERMISSION_8 \
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=domain_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_RESULT_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<BR><BR><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD> \
<TD>&nbsp;<A href=\"javascript:EditItem(%llu)\">%s</A>&nbsp;|&nbsp;\
<A href=\"javascript:DeleteItem(%llu)\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_USERITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_USERITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\
<A href=\"javascript:DeleteItem(%llu)\">%s</A>&nbsp;</TD></TR>\n"

static BOOL list_ui_add_folder(const char *domain,
	const char *folder_name, const char *container,
	const char *comment);

static void list_ui_remove_folder(const char *domain, uint64_t folder_id);
			
static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *domain, const char *session);

static void list_ui_permission_html(const char *domain,
	const char *session, uint64_t folder_id);

static BOOL	list_ui_add_owner(const char *domain,
	uint64_t folder_id, const char *username);

static void list_ui_remove_owner(const char *domain,
	uint64_t folder_id, uint64_t member_id);

static BOOL list_ui_get_self(char *url_buff, int length);


static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void list_ui_init(const char *url_link, const char *resource_path)
{
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int list_ui_run()
{
	char *query;
	char *request;
	char *language;
	const char *folder;
	const char *action;
	const char *domain;
	const char *member;
	const char *comment;
	const char *session;
	const char *username;
	const char *container;
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
	if (0 == strcmp(request, "POST")) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[list_ui]: fail to get QUERY_STRING "
				"environment!");
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		
		pparser = request_parser_init(query);
		if (NULL == pparser) {
			system_log_info("[list_ui]: fail to init request_parser");
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		
		domain = request_parser_get(pparser, "domain");
		if (NULL == domain) {
			system_log_info("[list_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		
		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			system_log_info("[list_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(
				 g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		if (FALSE == session_client_check(domain, session)) {
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_SESSION", language));
			return 0;
		}
		
		action = request_parser_get(pparser, "action");
		if (NULL == action) {
			list_ui_main_html(domain, session);
			return 0;
		}
		
		folder = request_parser_get(pparser, "folder");
		if (NULL == folder) {
			system_log_info("[list_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		if (0 == strcasecmp(action, "add")) {
			container = request_parser_get(pparser, "container");
			comment = request_parser_get(pparser, "comment");
			if (NULL == comment) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			if (FALSE == list_ui_add_folder(domain, folder, container, comment)) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			list_ui_main_html(domain, session);
			return 0;
		} else if (0 == strcasecmp(action, "remove")) {
			list_ui_remove_folder(domain, atoll(folder));
			list_ui_main_html(domain, session);
			return 0;
		} else if (0 == strcasecmp(action, "list-permission")) {
			list_ui_permission_html(domain, session, atoll(folder));
			return 0;
		} else if (0 == strcasecmp(action, "add-permission")) {
			username = request_parser_get(pparser, "username");
			if (NULL == username) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			if (FALSE == list_ui_add_owner(domain, atoll(folder), username)) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			list_ui_permission_html(domain, session, atoll(folder));
			return 0;
		} else if (0 == strcasecmp(action, "remove-permission")) {
			member = request_parser_get(pparser, "member");
			if (NULL == member) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			list_ui_remove_owner(domain, atoll(folder), atoll(member));
			list_ui_permission_html(domain, session, atoll(folder));
			return 0;
		} else {
			system_log_info("[list_ui]: query string of GET format error");
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
	} else {
		system_log_info("[list_ui]: unrecognized REQUEST_METHOD \"%s\"!", request);
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

static void list_ui_error_html(const char *error_string)
{
	const char *language;
	
	if (NULL == error_string) {
		error_string = "fatal error!!!";
	}
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		language = "en";
	}
	printf("Content-Type:text/html;charset=utf-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ERROR_5, lang_resource_get(g_lang_resource,"BACK_LABEL", language),
		error_string);
}

static void list_ui_main_html(const char *domain, const char *session)
{
	int i;
	const char *language;
	time_t tmp_time;
	uint64_t folder_id;
	char temp_buff[256];
	char url_buff[1024];
	char domain_path[256];
	TARRAY_SET folder_list;
	
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		language = "en";
	}
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	
	if (FALSE == data_source_get_homedir(domain, domain_path, NULL)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	
	if (FALSE == exmdb_client_get_folder_list(domain_path, &folder_list)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=utf-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"MAIN_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"MAIN_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_MAIN_5, url_buff, domain, session, url_buff, domain, session);
	printf(url_buff);
	printf(HTML_MAIN_6, domain, session,
		lang_resource_get(g_lang_resource, "MAIN_FOLDER", language),
		lang_resource_get(g_lang_resource, "MAIN_CLASS", language),
		lang_resource_get(g_lang_resource, "CLASS_NOTE"	, language),
		lang_resource_get(g_lang_resource, "CLASS_CONTACT", language),
		lang_resource_get(g_lang_resource, "CLASS_JOURNAL", language),
		lang_resource_get(g_lang_resource, "CLASS_APPOINTMENT", language),
		lang_resource_get(g_lang_resource, "CLASS_STICKYNOTE", language),
		lang_resource_get(g_lang_resource, "CLASS_TASK", language),
		lang_resource_get(g_lang_resource, "CLASS_NOTE_INFOPATHFORM", language),
		lang_resource_get(g_lang_resource, "MAIN_COMMENT", language),
		lang_resource_get(g_lang_resource, "ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"TIP_DELETE_FOLDER", language));
	printf(lang_resource_get(g_lang_resource, "MAIN_TABLE_TITLE", language));	
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_FOLDER", language),
		lang_resource_get(g_lang_resource,"MAIN_COMMENT", language),
		lang_resource_get(g_lang_resource,"MAIN_CREATETIME", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));	
	for (i=0; i<folder_list.count; i++) {
		tmp_time = rop_util_nttime_to_unix(*(uint64_t*)
			folder_list.pparray[i]->ppropval[3].pvalue);
		strftime(temp_buff, 256, lang_resource_get(g_lang_resource,
					"DATE_FORMAT", language), localtime(&tmp_time));
		folder_id = rop_util_get_gc_value(*(uint64_t*)
			folder_list.pparray[i]->ppropval[0].pvalue);
		printf(HTML_TBITEM_NORMAL, folder_list.pparray[i]->ppropval[1].pvalue,
			folder_list.pparray[i]->ppropval[2].pvalue, temp_buff, folder_id,
			lang_resource_get(g_lang_resource, "EDIT_LABEL", language), folder_id,
			lang_resource_get(g_lang_resource, "DELETE_LABEL", language));
	}
	printf(HTML_MAIN_8);
}

static BOOL list_ui_add_folder(const char *domain,
	const char *folder_name, const char *container,
	const char *comment)
{
	int domain_id;
	char domain_path[256];

	if (FALSE == data_source_get_homedir(domain, domain_path,
		&domain_id) || FALSE == exmdb_client_create_folder(
		domain_path, domain_id, folder_name, container, comment)) {
		return FALSE;
	}
	return TRUE;
}

static void list_ui_remove_folder(const char *domain, uint64_t folder_id)
{
	BOOL b_result;
	char *language;
	char domain_path[256];

	if (FALSE == data_source_get_homedir(domain, domain_path, NULL)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	exmdb_client_delete_folder(domain_path, 0,
		rop_util_make_eid_ex(1, folder_id), TRUE, &b_result);
}

static void list_ui_permission_html(const char *domain,
	const char *session, uint64_t folder_id)
{
	int i;
	char *language;
	char url_buff[1024];
	char domain_path[256];
	TARRAY_SET permission_list;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == data_source_get_homedir(domain, domain_path, NULL)
		|| FALSE == exmdb_client_get_permission_list(domain_path,
		rop_util_make_eid_ex(1, folder_id), &permission_list)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;	
	}
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=utf-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource, "PERMISSION_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource, "PERMISSION_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_PERMISSION_5, url_buff, domain, session,
		lang_resource_get(g_lang_resource, "BACK_TO_MAIN", language),
		url_buff, domain, session, folder_id);
	printf(url_buff);
	printf(HTML_PERMISSION_6, domain, session, folder_id,
		lang_resource_get(g_lang_resource, "MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource, "ADD_LABEL", language));
	printf(lang_resource_get(g_lang_resource, "PERMISSION_TABLE_TITLE", language));
	printf(HTML_PERMISSION_7);
	printf(HTML_USERITEM_FIRST, lang_resource_get(
		g_lang_resource, "MAIN_REALNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<permission_list.count; i++) {
		if (0 == (PERMISSION_FOLDEROWNER & (*(uint32_t*)
			permission_list.pparray[i]->ppropval[2].pvalue)) ||
			0 == *(uint64_t*)permission_list.pparray[i]->ppropval[0].pvalue ||
			0xFFFFFFFFFFFFFFFF == *(uint64_t*)permission_list.pparray[i]->ppropval[0].pvalue) {
			continue;	
		}
		printf(HTML_USERITEM_NORMAL, permission_list.pparray[i]->ppropval[1].pvalue,
			*(uint64_t*)permission_list.pparray[i]->ppropval[0].pvalue,
			lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
	}
	printf(HTML_PERMISSION_8);
}

static BOOL	list_ui_add_owner(const char *domain,
	uint64_t folder_id, const char *username)
{
	char domain_path[256];

	if (FALSE == data_source_get_homedir(domain, domain_path,
		NULL) || FALSE == exmdb_client_add_folder_owner(
		domain_path, rop_util_make_eid_ex(1, folder_id),
		username)) {
		return FALSE;
	}
	return TRUE;
}

static void list_ui_remove_owner(const char *domain,
	uint64_t folder_id, uint64_t member_id)
{
	char domain_path[256];

	if (FALSE == data_source_get_homedir(domain, domain_path, NULL)) {
		return;
	}
	exmdb_client_remove_folder_owner(domain_path,
		rop_util_make_eid_ex(1, folder_id), member_id);
}
