#include "list_ui.h"
#include "lang_resource.h"
#include <gromox/system_log.h>
#include <gromox/session_client.h>
#include "data_source.h"
#include "list_file.h"
#include "util.h"
#include "double_list.h"
#include <dirent.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <iconv.h>
#include <sys/types.h>
#include <sys/stat.h>

#define HTML_COMMON_1	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>"

/* fill html real_name here */

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

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function ViewClass(class_id) {location.href='%s?domain=%s&session=%s&type=view-class&class_id=' + class_id;}\n\
function UnlinkClass(class_id, child_id) {if (confirm('%s')) location.href='%s?domain=%s&session=%s&type=unlink-class&class_id=' + class_id +'&child_id=' + child_id;}\n\
function RenameClass(class_id) {location.href='%s?domain=%s&session=%s&type=rename-class&class_id=' + class_id}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right>\n"


#define HTML_RESULT_6_1	\
"<A href=\"%s\">%s</A></TD></TR></TBODY></TABLE>\n\
<BR><BR><TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle \n\
background=\"../data/picture/di2.gif\">%s</TD>\n\
<TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_RESULT_6_2	\
"<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A>\n\
</TD></TR></TBODY></TABLE>\n\
<BR><BR><TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle \n\
background=\"../data/picture/di2.gif\">%s</TD>\n\
<TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_RESULT_7	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_LINK_CLASS_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}</SCRIPT>\n\
<TR><TD align=right><A href=\"javascript:BackTo()\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><FORM class=SearchForm name=addeditform \n\
method=get action=\"%s\"><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"link-class\" name=\"type\" />\n\
<INPUT type=hidden value=\"%d\" name=\"class_id\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=child_id>\n"

#define HTML_LINK_CLASS_6	\
"</SELECT></TD></TR>\n\
<TR><TD colSpan=3></TD><TD><INPUT value=\"    %s    \" type=submit></TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_ADD_RENAME_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}</SCRIPT>\n\
<TR><TD align=right><A href=\"javascript:BackTo()\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><FORM class=SearchForm name=addeditform \n\
method=get action="

#define HTML_ADD_6	\
"><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"add-class\" name=\"type\" />\n\
<INPUT type=hidden value=0 name=class_id />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=classname /></SPAN></TD></TR>\n\
<TR><TD colSpan=3></TD><TD><INPUT value=\"    %s    \" type=submit \n\
onclick=\"if (0 == classname.value.length || classname.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
} return true;\"\n></TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_RENAME_6	\
"><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"rename-class\" name=\"type\" />\n\
<INPUT type=hidden value=%d name=class_id />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=classname /></SPAN></TD></TR>\n\
<TR><TD colSpan=3></TD><TD><INPUT value=\"    %s    \" type=submit \n\
onclick=\"if (0 == classname.value.length || classname.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
} return true;\"\n></TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=domain_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_BACK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><INPUT type=submit value=\"    %s    \" \n\
onclick=\"window.history.back();\"/></CENTER></BODY></HTML>"

#define HTML_OK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><FORM class=SearchForm method=get action=\"%s\">\n\
<INPUT type=hidden value=\"%s\" name=domain />\n\
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=hidden value=\"view-class\" name=type />\n\
<INPUT type=hidden value=\"%d\" name=class_id />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>"


#define HTML_TBITEM_PARENT     \
"<TR class=%s><TD>&nbsp;<IMG src=\"../data/picture/class.gif\" \n\
align=absmiddle border=0>&nbsp;\n\
<A title=\"%s\" href=\"javascript:ViewClass(%d)\">%s</A>&nbsp;\n\
</TD><TD>&nbsp;<A href=\"javascript:RenameClass(%d)\">%s</A>\n\
&nbsp;|&nbsp;<A href=\"javascript:UnlinkClass(%d, %d)\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_CHILD     \
"<TR class=%s><TD>&nbsp;<IMG src=\"../data/picture/class.gif\" \n\
align=absmiddle border=0>%s&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"javascript:UnlinkClass(%d, %d)\">%s</A>&nbsp;</TD></TR>\n"

#define SELECT_OPTION		"<OPTION value=%d>%s</OPTION>"

#define CSS_ITEMODD			"ItemOdd"

#define CSS_ITEMEVEN		"ItemEven"


#define DEF_MODE                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static void list_ui_error_html(const char *error_string);

static void list_ui_operation_ok_html(const char *domainname,
	const char *session, int class_id, const char *prompt_string,
	const char *title_string);

static void list_ui_operation_error_html(const char *title_string,
	const char *error_string);

static void list_ui_add_class_html(const char *domainname, const char *session);

static void list_ui_rename_class_html(const char *domainname,
	const char *session, int class_id);

static void list_ui_link_class_html(const char *domainname,
	const char *session, int class_id);

static void list_ui_main_html(const char *domainname, const char *session,
	int class_id);

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_unencode(char *src, char *last, char *dest);
static void list_ui_from_utf8(char *src, char *dst, size_t len);

static void list_ui_to_utf8(char *src, char *dst, size_t len);


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
	char *language;
	char *ptr1, *ptr2;
	char *query, *request;
	char type[16];
	char session[256];
	char domainname[128];
	char temp_buff[256];
	char search_buff[1024];
	char temp_name[128];
	int len, result;
	int class_id;
	int child_id;

	g_lang_resource = lang_resource_init(g_resource_path);
	if (g_lang_resource == nullptr) {
		system_log_info("[list_ui]: failed to init language resource");
		return -1;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		list_ui_error_html(NULL);
		return 0;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[list_ui]: fail to get REQUEST_METHOD environment!");
		return -2;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[list_ui]: fail to get QUERY_STRING "
					"environment!");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		} 
		
		len = strlen(query);
		if (0 == len || len > 1024) {
			system_log_info("[list_ui]: query string too long!");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
			return 0;
		}
		list_ui_unencode(query, query + len, search_buff);
		len = strlen(search_buff);
		if ('\n' == search_buff[len - 1]) {
			len --;
			search_buff[len] = '\0';
		}
		ptr1 = search_string(search_buff, "domain=", len);
		if (NULL == ptr1) {
			goto GET_ERROR;
		}
		ptr1 += 7;
		ptr2 = search_string(search_buff, "&session=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >= 64) {
			goto GET_ERROR;
		}
		memcpy(domainname, ptr1, ptr2 - ptr1);
		domainname[ptr2 - ptr1] = '\0';
		
		ptr1 = ptr2 + 9;
		ptr2 = search_string(search_buff, "&type=", len);
		if (NULL == ptr2) {
			if (search_buff + len - ptr1 > 255) {
				goto GET_ERROR;
			}
			memcpy(session, ptr1, search_buff + len - ptr1);
			session[search_buff + len - ptr1] = '\0';
			
			if (FALSE == session_client_check(domainname, session)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			list_ui_main_html(domainname, session, 0);
			return 0;
		}

		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
			
		if (FALSE == session_client_check(domainname, session)) {
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION", language));
			return 0;
		}

		ptr1 = ptr2 + 6;
		ptr2 = strchr(ptr1, '&');
		if (NULL == ptr2) {
			ptr2 = search_buff + len;
		}
		if (ptr2 - ptr1 >= 16) {
			goto GET_ERROR;
		}
		memcpy(type, ptr1, ptr2 - ptr1);
		type[ptr2 - ptr1] = '\0';
		
		if (0 == strncasecmp(ptr2, "&class_id=", 10)) {
			ptr1 = ptr2 + 10;
			ptr2 = strchr(ptr1, '&');
			if (NULL == ptr2) {
				ptr2 = search_buff + len;
			}
			if (ptr2 - ptr1 > 16) {
				goto GET_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			class_id = atoi(temp_buff);
			if (class_id < 0) {
				goto GET_ERROR;
			}
		} else {
			goto GET_ERROR;
		}
			
		if (0 == strcasecmp(type, "view-class")) {
			list_ui_main_html(domainname, session, class_id);
			return 0;
		} else if (0 == strcasecmp(type, "add-class")) {
			if (0 != class_id) {
				goto GET_ERROR;
			}
			if (0 == strncasecmp(ptr2, "&classname=", 11)) {
				ptr1 = ptr2 + 11;
				if (strlen(ptr1) > 32) {
					goto GET_ERROR;
				}
				list_ui_to_utf8(ptr1, temp_name, 128);
				if (FALSE == data_source_add_class(domainname,
					temp_name, &result)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
					
				switch (result) {
				case ADD_RESULT_OK:
					list_ui_operation_ok_html(domainname, session, class_id,
						lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"ADD_RESULT_OK", language));
					break;
				case ADD_RESULT_NODOMAIN:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"ADD_ERROR_NODOMAIN", language));
					break;
				case ADD_RESULT_DOMAINNOTMAIN:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"ADD_ERROR_DOMAINNOTMAIN", language));
					break;
				case ADD_RESULT_FULL:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"ADD_ERROR_FULL", language));
					break;
				case ADD_RESULT_EXIST:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"ADD_ERROR_EXIST", language));
					break;
				case ADD_RESULT_CLASSERR:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"ADD_ERROR_CLASSERR", language));
					break;
				}
			} else {
				list_ui_add_class_html(domainname, session);
			}
			return 0;
		} else if (0 == strcasecmp(type, "link-class")) {
			if (class_id <= 0) {
				goto GET_ERROR;
			}
			if (0 == strncasecmp(ptr2, "&child_id=", 10)) {
				ptr1 = ptr2 + 10;
				child_id = atoi(ptr1);
				if (child_id <= 0 || child_id == class_id) {
					goto GET_ERROR;
				}
				if (FALSE == data_source_link_class(domainname, class_id,
					child_id, &result)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_INTERNAL", language));
					return 0;
				}
				switch (result) {
				case LINK_RESULT_OK:
					list_ui_operation_ok_html(domainname, session, class_id,
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_RESULT_OK", language));
					break;
				case LINK_RESULT_NODOMAIN:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_ERROR_NODOMAIN", language));
					break;
				case LINK_RESULT_DOMAINNOTMAIN:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_ERROR_DOMAINNOTMAIN", language));
					break;
				case LINK_RESULT_NOPARENT:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_ERROR_NOPARENT", language));
					break;
				case LINK_RESULT_PARENTERR:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_ERROR_PARENTERR", language));
					break;
				case LINK_RESULT_NOCLASS:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_ERROR_NOCLASS", language));
					break;
				case LINK_RESULT_EXIST:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_ERROR_EXIST", language));
					break;
				case LINK_RESULT_CLASSERR:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"LINK_ERROR_CLASSERR", language));
					break;
				}	
			} else {
				list_ui_link_class_html(domainname, session, class_id);
			}
			return 0;
		} else if (0 == strcasecmp(type, "rename-class")) {
			if (0 == strncasecmp(ptr2, "&classname=", 11)) {
				ptr1 = ptr2 + 11;
				if (strlen(ptr1) >= 32) {
					goto GET_ERROR;
				}
				list_ui_to_utf8(ptr1, temp_name, 128);	
				if (FALSE == data_source_rename_class(domainname, class_id,
					temp_name, &result)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,
						"ERROR_INTERNAL", language));
					return 0;
				}
				switch (result) {
				case RENAME_RESULT_OK:
					list_ui_operation_ok_html(domainname, session, 0,
						lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"RENAME_RESULT_OK", language));
					break;
				case RENAME_RESULT_NODOMAIN:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"RENAME_ERROR_NODOMAIN", language));
					break;
				case RENAME_RESULT_DOMAINNOTMAIN:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"RENAME_ERROR_DOMAINNOTMAIN", language));
					break;
				case RENAME_RESULT_NOCLASS:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"RENAME_ERROR_NOCLASS", language));
					break;
				case RENAME_RESULT_CLASSERR:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"RENAME_ERROR_CLASSERR", language));
					break;
				case RENAME_RESULT_EXIST:
					list_ui_operation_error_html(
						lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"RENAME_ERROR_EXIST", language));
					break;
				}
			} else {
				list_ui_rename_class_html(domainname, session, class_id);	
			}
			return 0;
		} else if (0 == strcasecmp(type, "unlink-class")) {
			if (0 != strncasecmp(ptr2, "&child_id=", 10)) {
				goto GET_ERROR;
			}
			ptr1 = ptr2 + 10;
			child_id = atoi(ptr1);
			if (child_id <= 0 || child_id == class_id) {
				goto GET_ERROR;
			}
			if (FALSE == data_source_unlink_class(domainname, class_id,
				child_id)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			list_ui_main_html(domainname, session, class_id);
			return 0;
		} else {
			goto GET_ERROR;
		}
	} else {
		system_log_info("[list_ui]: unrecognized REQUEST_METHOD \"%s\"!",
					request);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
GET_ERROR:
	system_log_info("[list_ui]: query string of GET format error");
	list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
	return 0;
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
	
	if (NULL ==error_string) {
		error_string = "fatal error!";
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

static void list_ui_operation_ok_html(const char *domainname,
	const char *session, int class_id, const char *title_string,
	const char *prompt_string)
{
	char *language;
	char url_buff[1024];

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(title_string);
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(title_string);
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_OK_5, prompt_string, url_buff, domainname, session,
		class_id, lang_resource_get(g_lang_resource,"OK_LABEL", language));
}


static void list_ui_operation_error_html(const char *title_string,
	const char *error_string)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(title_string);
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(title_string);
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, error_string,
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_add_class_html(const char *domainname, const char *session)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ADD_RENAME_5, lang_resource_get(g_lang_resource,"BACK_TO_LIST", language));
	printf(url_buff);
	printf(HTML_ADD_6, domainname, session,
		lang_resource_get(g_lang_resource,"MAIN_CLASS", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_CLASSNAME", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_rename_class_html(const char *domainname,
	const char *session, int class_id)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RENAME_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ADD_RENAME_5, lang_resource_get(g_lang_resource,"BACK_TO_LIST", language));
	printf(url_buff);
	printf(HTML_RENAME_6, domainname, session, class_id,
		lang_resource_get(g_lang_resource,"MAIN_CLASS", language),
		lang_resource_get(g_lang_resource,"RENAME_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_CLASSNAME", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_link_class_html(const char *domainname,
	const char *session, int class_id)
{
	char *language;
	char url_buff[1024];
	char temp_name[32];
	CLASS_ITEM *pitem;
	DATA_COLLECT *pcollect;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	pcollect = data_source_collect_init();

	if (NULL == pcollect) {
		system_log_info("[list_ui]: fail to allocate memory for data source "
			"collect object");
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	if (FALSE == data_source_get_class_list(domainname, pcollect)) {
		data_source_collect_free(pcollect);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	if (0 == data_source_collect_total(pcollect)) {
		data_source_collect_free(pcollect);
		list_ui_operation_error_html(lang_resource_get(g_lang_resource,"LINK_HTML_TITLE",
			language), lang_resource_get(g_lang_resource,"LINK_ERROR_EMPTYCLASS", language));
		return;
	}
	
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"LINK_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_LINK_CLASS_5, lang_resource_get(g_lang_resource,"BACK_TO_LIST", language),
		url_buff, domainname, session, class_id,
		lang_resource_get(g_lang_resource,"MAIN_CLASS", language));
	
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		pitem = (CLASS_ITEM*)data_source_collect_get_value(pcollect);
		list_ui_from_utf8(pitem->classname, temp_name, 128);
		printf(SELECT_OPTION, pitem->class_id, temp_name);
	}

	data_source_collect_free(pcollect);
	
	printf(HTML_LINK_CLASS_6,
		lang_resource_get(g_lang_resource,"LINK_CLASS_LABEL", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));

}

static void list_ui_main_html(const char *domainname, const char *session,
	int class_id)
{
	int rows;
	char *language;
	char url_buff[1024];
	char url_add_class[1280];
	char url_link_class[1280];
	char url_link_up[1280];
	char temp_name[32];
	CLASS_ITEM *pitem;
	DATA_COLLECT *pcollect;

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");

	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	sprintf(url_add_class, "%s?domain=%s&session=%s&type=add-class&class_id=0",
		url_buff, domainname, session);
	sprintf(url_link_class, "%s?domain=%s&session=%s&type=link-class&class_id=%d",
		url_buff, domainname, session, class_id);
	sprintf(url_link_up, "%s?domain=%s&session=%s&type=view-class&class_id=0",
		url_buff, domainname, session, class_id);
	
	pcollect = data_source_collect_init();

	if (NULL == pcollect) {
		system_log_info("[list_ui]: fail to allocate memory for data source "
			"collect object");
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (FALSE == data_source_get_childrent_list(domainname,
		class_id, pcollect)) {
		data_source_collect_free(pcollect);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_RESULT_5, url_buff, domainname, session,
		lang_resource_get(g_lang_resource,"CONFIRM_UNLINK", language),
		url_buff, domainname, session,
		url_buff, domainname, session);
	
	if (0 == class_id) {
		printf(HTML_RESULT_6_1, url_add_class,
			lang_resource_get(g_lang_resource,"ADD_LABEL", language),
			lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	} else {
		printf(HTML_RESULT_6_2, url_link_class,
			lang_resource_get(g_lang_resource,"LINK_CLASS_LABEL", language),
			url_link_up, lang_resource_get(g_lang_resource,"UP_LABEL", language),
			lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	}
	
	
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_TITLE", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));

	
	rows = 1;
	
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		pitem = (CLASS_ITEM*)data_source_collect_get_value(pcollect);
		list_ui_from_utf8(pitem->classname, temp_name, 32);
		if (0 == rows%2) {
			if (0 == class_id) {
				printf(HTML_TBITEM_PARENT, CSS_ITEMEVEN,
					lang_resource_get(g_lang_resource,"TIP_ENTER", language),
					pitem->class_id, temp_name, pitem->class_id,
					lang_resource_get(g_lang_resource,"RENAME_LABEL", language),
					class_id, pitem->class_id,
					lang_resource_get(g_lang_resource,"UNLINK_LABEL", language));
			} else {
				printf(HTML_TBITEM_CHILD, CSS_ITEMEVEN,
					temp_name, class_id, pitem->class_id,
					lang_resource_get(g_lang_resource,"UNLINK_LABEL", language));
			}
		} else {
			if (0 == class_id) {
				printf(HTML_TBITEM_PARENT, CSS_ITEMODD,
					lang_resource_get(g_lang_resource,"TIP_ENTER", language),
					pitem->class_id, temp_name,
					pitem->class_id,
					lang_resource_get(g_lang_resource,"RENAME_LABEL", language),
					class_id, pitem->class_id,
					lang_resource_get(g_lang_resource,"UNLINK_LABEL", language));
			} else {
				printf(HTML_TBITEM_CHILD, CSS_ITEMODD,
					temp_name, class_id, pitem->class_id,
					lang_resource_get(g_lang_resource,"UNLINK_LABEL", language));
			}
		}
		rows ++; 
	}
	data_source_collect_free(pcollect);

	printf(HTML_RESULT_7);

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

static void list_ui_from_utf8(char *src, char *dst, size_t len)
{
	size_t in_len;
	char *pin, *pout;
	iconv_t conv_id;

	conv_id = iconv_open(lang_resource_get(g_lang_resource,"CHARSET",
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

	conv_id = iconv_open("UTF-8", lang_resource_get(g_lang_resource,"CHARSET",
				getenv("HTTP_ACCEPT_LANGUAGE")));
	pin = src;
	pout = dst;
	in_len = strlen(src);
	memset(dst, 0, len);
	iconv(conv_id, &pin, &in_len, &pout, &len);
	iconv_close(conv_id);
}

