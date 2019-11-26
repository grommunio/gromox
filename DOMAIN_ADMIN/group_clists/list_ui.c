#include "list_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "session_client.h"
#include "data_source.h"
#include "list_file.h"
#include "util.h"
#include "double_list.h"
#include <dirent.h>
#include <time.h>
#include <stdio.h>
#include <ctype.h>
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

/* fill mlist title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(listname) {if (confirm('%s')) location.href='%s?group=%s&session=%s&type=remove&listname=' + listname;}\n\
function EditItem(listname) {location.href='%s?group=%s&session=%s&type=edit&listname=' + listname;}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><TABLE cellSpacing=0 cellPadding=0 width=\"90%\" \n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle \n\
background=\"../data/picture/di2.gif\">"

/* fill result table title here */

#define HTML_RESULT_6	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_RESULT_7	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_EDIT_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s?group=%s&session=%s\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><FORM class=SearchForm name=editform \n\
method=get action="

#define HTML_EDIT_6	\
"><INPUT type=hidden value=%s name=group />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"edit-privil\" name=type />\n\
<INPUT type=hidden value=\"%s\" name=listname />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"radio\" name=privilege value=\"0\" %s/>%s&nbsp;&nbsp;&nbsp;\n\
<INPUT type=\"radio\" name=privilege value=\"1\" %s/>%s&nbsp;&nbsp;&nbsp;\n\
<INPUT type=\"radio\" name=privilege value=\"2\" %s/>%s&nbsp;&nbsp;&nbsp;\n\
<INPUT type=\"radio\" name=privilege value=\"3\" %s/>%s \n\
<A href=\"%s?group=%s&session=%s&type=expand-spec&listname=%s\">%s</A>\n\
<INPUT type=\"radio\" name=privilege value=\"4\" %s/>%s&nbsp;&nbsp;&nbsp;\n\
</SPAN></TD></TR>\n\
<TR><TD colSpan=3></TD><TD><INPUT type=\"submit\" value=\"    %s    \" />\n\
</TD></TR></TBODY></TABLE></FORM></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_ADD_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}</SCRIPT>\n\
<TR><TD align=right><A href=\"javascript:BackTo()\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><FORM class=SearchForm name=editform \n\
method=get action="


#define HTML_ADD_CLASS_6	\
"><INPUT type=hidden value=%s name=group />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"add-class\" name=type />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=text value=\"\" name=listname></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=class>\n"

#define HTML_ADD_CLASS_7	\
"</SELECT></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN>\n\
<INPUT type=\"radio\" name=privilege value=\"0\" checked/>%s&nbsp;&nbsp;&nbsp;\n\
<INPUT type=\"radio\" name=privilege value=\"1\" />%s&nbsp;&nbsp;&nbsp;\n\
<INPUT type=\"radio\" name=privilege value=\"2\" />%s&nbsp;&nbsp;&nbsp;\n\
<INPUT type=\"radio\" name=privilege value=\"3\" />%s(%s)&nbsp;&nbsp;&nbsp;\n\
<INPUT type=\"radio\" name=privilege value=\"4\" />%s(%s)</SPAN></TD></TR>\n\
<TR><TD colSpan=3></TD><TD><INPUT type=\"submit\" value=\"    %s    \" \n\
onclick=\"if (0 == listname.value.length) {\n\
    alert('%s');\n\
    return false;\n\
}\n\
if (listname.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var apos=listname.value.indexOf('@');\n\
var regstr=/^[\\.\\-_A-Za-z0-9]+@([-_A-Za-z0-9]+\\.)+[A-Za-z0-9]{2,6}$/;\n\
if (0 == apos) {\n\
	alert('%s');\n\
	return false;\n\
} else if (apos > 0) {\n\
	if (listname.value.substring(apos, \n\
		listname.value.length).toLowerCase() != '@%s'.toLowerCase()) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
	if (!regstr.test(listname.value)) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
} else {\n\
	var liststr = listname.value + '@%s';\n\
	if (!regstr.test(liststr)) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
return true;\"/>\n\
</TD></TR></TBODY></TABLE></FORM></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"


#define HTML_SPECIFIED_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s?group=%s&session=%s&type=edit&listname=%s\">%s</A>\n\
</TD></TR></TBODY></TABLE><SCRIPT language=\"JavaScript\">\n\
function DeleteItem(address) {location.href='%s?group=%s&session=%s&type=del-spec&listname=%s&address=' + address;}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_SPECIFIED_6 \
" ><TABLE border=0><INPUT type=hidden value=%s name=group />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=insert-spec name=type />\n\
<INPUT type=hidden value=\"%s\" name=listname />\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=1 \n\
size=30 name=address /><INPUT style=\"display:none\">\n\
</TD></TR><TR><TD></TD><TD></TD><TD>\n\
<INPUT type=submit tabindex=2 value=\"  %s  \" />\n\
</TD></TR><TR><TD colSpan=3>%s</TD></TR></TABLE></FORM>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill table title here */

#define HTML_SPECIFIED_7 \
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_SPECIFIED_8 \
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=group_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
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
<INPUT type=hidden value=\"%s\" name=group />\n\
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_LISTITEM_FIRST	\
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>"

#define HTML_LISTITEM	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\n\
<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>"

#define HTML_TBITEM_ODD     \
"<TR class=ItemOdd><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;<A href=\"javascript:EditItem('%s')\">%s</A>\n\
&nbsp;|&nbsp;<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_EVEN		\
"<TR class=ItemEven><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;<A href=\"javascript:EditItem('%s')\">%s</A>\n\
&nbsp;|&nbsp;<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define SELECT_OPTION		"<OPTION value=%d>%s</OPTION>"

#define OPTION_CHECKED		"checked"

#define OPTION_UNCHECKED	""

static void list_ui_unencode(char *src, char *last, char *dest);

static void list_ui_encode_squote(const char *in, char *out);

static void list_ui_error_html(const char *error_string);

static void list_ui_operation_ok_html(const char *groupname,
	const char *session, const char *title_string, const char *prompt_string);

static void list_ui_operation_error_html(const char *title_string,
	const char *error_string);

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_specified_html(const char *groupname, const char *session,
	const char *listname);

static void list_ui_add_class_html(const char *groupname, const char *session);

static void list_ui_main_html(const char *groupname, const char *session);

static void list_ui_edit_html(const char *groupname, const char *session,
	const char *listname);

static void list_ui_from_utf8(char *src, char *dst, size_t len);

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
	char *pdomain;
	char *pat, type[16];
	char groupname[64];
	char session[256];
	char listname[128];
	char search_buff[1024];
	char temp_address[128];
	char temp_buff[32];
	int len, result, class_id;
	int list_type;
	int list_privilege;
	

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
			ptr1 = search_string(search_buff, "group=", len);
			if (NULL == ptr1) {
				goto GET_ERROR;
			}
			ptr1 += 6;
			ptr2 = search_string(search_buff, "&session=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 64) {
				goto GET_ERROR;
			}
			memcpy(groupname, ptr1, ptr2 - ptr1);
			groupname[ptr2 - ptr1] = '\0';
			pdomain = strchr(groupname, '@');
			if (NULL == pdomain) {
				goto GET_ERROR;
			}
			pdomain ++;
			
			ptr1 = ptr2 + 9;
			ptr2 = search_string(search_buff, "&type=", len);
			if (NULL == ptr2) {
				if (search_buff + len - 1 - ptr1 > 255) {
					goto GET_ERROR;
				}
				memcpy(session, ptr1, search_buff + len - 1 - ptr1);
				session[search_buff + len - 1 - ptr1] = '\0';
			
				if (FALSE == session_client_check(groupname, session)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				list_ui_main_html(groupname, session);
				return 0;
			}

			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			if (FALSE == session_client_check(groupname, session)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}

			ptr1 = ptr2 + 6;
			ptr2 = search_string(search_buff, "&listname=", len);
			if (NULL == ptr2) {
				if (0 == search_buff + len - 1 - ptr1 ||
					search_buff + len - 1 - ptr1 > 15) {
					goto GET_ERROR;
				}
				memcpy(type, ptr1, search_buff + len - 1 - ptr1);
				type[search_buff + len - 1 - ptr1] = '\0';
				if (0 == strcasecmp(type, "add-class")) {
					list_ui_add_class_html(groupname, session);
				}
				return 0;
			}
			memcpy(type, ptr1, ptr2 - ptr1);
			type[ptr2 - ptr1] = '\0';
			ptr1 = ptr2 + 10;
			if (0 == strcasecmp(type, "insert-spec") ||
				0 == strcasecmp(type, "del-spec")) {
				ptr2 = search_string(search_buff, "&address=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 128) {
					goto GET_ERROR;
				}
				memcpy(listname, ptr1, ptr2 - ptr1);
				listname[ptr2 - ptr1] = '\0';
				
				pat = strchr(listname, '@');
				if (NULL == pat) {
					if (strlen(listname) + 1 + strlen(pdomain) >= 128) {
						goto GET_ERROR;
					}
					strcat(listname, "@");
					strcat(listname, pdomain);
				} else {
					if (0 != strcasecmp(pat + 1, pdomain)) {
						goto GET_ERROR;
					}
				}

				ptr1 = ptr2 + 9;
				if (0 == search_buff + len - 1 - ptr1 ||
					search_buff + len - 1 - ptr1 >= 128) {
					goto GET_ERROR;
				}
				memcpy(temp_address, ptr1, search_buff + len - 1 - ptr1);
				temp_address[search_buff + len - 1 - ptr1] = '\0';
				if (0 == strcasecmp(type, "insert-spec")) {
					data_source_specified_insert(groupname, listname,
						temp_address);
					list_ui_specified_html(groupname, session, listname);
				} else if (0 == strcasecmp(type, "del-spec")) {
					data_source_specified_del(groupname, listname,
						temp_address);
					list_ui_specified_html(groupname, session, listname);
				}
			} else if (0 == strcasecmp(type, "remove") ||
				0 == strcasecmp(type, "expand-spec") ||
				0 == strcasecmp(type, "edit")) {
				if (0 == search_buff + len - 1 - ptr1 ||
					search_buff + len - 1 - ptr1 >= 128) {
					goto GET_ERROR;
				}
				memcpy(listname, ptr1, search_buff + len - 1 - ptr1);
				listname[search_buff + len - 1 - ptr1] = '\0';
				
				pat = strchr(listname, '@');
				if (NULL == pat) {
					if (strlen(listname) + 1 + strlen(pdomain) >= 128) {
						goto GET_ERROR;
					}
					strcat(listname, "@");
					strcat(listname, pdomain);
				} else {
					if (0 != strcasecmp(pat + 1, pdomain)) {
						goto GET_ERROR;
					}
				}
				if (0 == strcasecmp(type, "remove")) {
					data_source_remove_clist(groupname, listname);
					list_ui_main_html(groupname, session);
				} else if (0 == strcasecmp(type, "expand-spec")) {
					list_ui_specified_html(groupname, session, listname);
				} else {
					list_ui_edit_html(groupname, session, listname);
				}
			} else if (0 == strcasecmp(type, "add-class")) {
				ptr2 = search_string(search_buff, "&class=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 128) {
					goto GET_ERROR;
				}
				memcpy(listname, ptr1, ptr2 - ptr1);
				listname[ptr2 - ptr1] = '\0';
				
				pat = strchr(listname, '@');
				if (NULL == pat) {
					if (strlen(listname) + 1 + strlen(pdomain) >= 128) {
						goto GET_ERROR;
					}
					strcat(listname, "@");
					strcat(listname, pdomain);
				} else {
					if (0 != strcasecmp(pat + 1, pdomain)) {
						goto GET_ERROR;
					}
				}

				ptr1 = ptr2 + 7;
				ptr2 = search_string(search_buff, "&privilege=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 32) {
					goto GET_ERROR;
				}
				
				memcpy(temp_buff, ptr1, ptr2 - ptr1);
				temp_buff[ptr2 - ptr1] = '\0';
				class_id = atoi(temp_buff);
				
				ptr1 = ptr2 + 11;
				if (1 != search_buff + len - 1 - ptr1 ||
					(*ptr1 != '0' && *ptr1 != '1' &&
					 *ptr1 != '2' && *ptr1 != '3' &&
					 *ptr1 != '4')) {
					goto GET_ERROR;
				}
					
				list_privilege = *ptr1 - '0';
				
				if (FALSE == data_source_add_clist(groupname, class_id,
					listname, list_privilege, &result)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				switch (result) {
				case ADD_RESULT_OK:
					list_ui_operation_ok_html(groupname, session,
						lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
						lang_resource_get(g_lang_resource,"ADD_RESULT_OK", language));
					break;
				case ADD_RESULT_NODOMAIN:
					list_ui_operation_error_html(lang_resource_get(g_lang_resource,
						"ADD_HTML_TITLE", language), lang_resource_get(g_lang_resource,
						"ADD_ERROR_NODOMAIN", language));
					break;
				case ADD_RESULT_DOMAINNOTMAIN:
					list_ui_operation_error_html(lang_resource_get(g_lang_resource,
						"ADD_HTML_TITLE", language), lang_resource_get(g_lang_resource,
						"ADD_ERROR_DOMAINNOTMAIN", language));
					break;
				case ADD_RESULT_NOGROUP:
					list_ui_operation_error_html(lang_resource_get(g_lang_resource,
						"ADD_HTML_TITLE", language), lang_resource_get(g_lang_resource,
						"ADD_ERROR_NOGROUP", language));
					break;
				case ADD_RESULT_NOCLASS:
					list_ui_operation_error_html(lang_resource_get(g_lang_resource,
						"ADD_HTML_TITLE", language), lang_resource_get(g_lang_resource,
						"ADD_ERROR_NOCLASS", language));
					break;
				case ADD_RESULT_USERNAME:
					list_ui_operation_error_html(lang_resource_get(g_lang_resource,
						"ADD_HTML_TITLE", language), lang_resource_get(g_lang_resource,
						"ADD_ERROR_USERNAME", language));
					break;
				case ADD_RESULT_CLASSERR:
					list_ui_operation_error_html(lang_resource_get(g_lang_resource,
						"ADD_HTML_TITLE", language), lang_resource_get(g_lang_resource,
						"ADD_ERROR_CLASSERR", language));
					break;
				case ADD_RESULT_EXIST:
					list_ui_operation_error_html(lang_resource_get(g_lang_resource,
						"ADD_HTML_TITLE", language), lang_resource_get(g_lang_resource,
						"ADD_ERROR_EXIST", language));
					break;
				}
				return 0;
			} else if (0 == strcasecmp(type, "edit-privil")) {
				ptr2 = search_string(search_buff, "&privilege=", len);
				if (NULL == ptr2 || ptr2 - ptr1 > 128) {
					goto GET_ERROR;
				}
				memcpy(listname, ptr1, ptr2 - ptr1);
				listname[ptr2 - ptr1] = '\0';
				
				pat = strchr(listname, '@');
				if (NULL == pat) {
					if (strlen(listname) + 1 + strlen(pdomain) >= 128) {
						goto GET_ERROR;
					}
					strcat(listname, "@");
					strcat(listname, pdomain);
				} else {
					if (0 != strcasecmp(pat + 1, pdomain)) {
						goto GET_ERROR;
					}
				}

				ptr1 = ptr2 + 11;
				if (1 != search_buff + len - 1 - ptr1 ||
					(*ptr1 != '0' && *ptr1 != '1' &&
					 *ptr1 != '2' && *ptr1 != '3' &&
					 *ptr1 != '4')) {
					goto GET_ERROR;
				}
					
				list_privilege = *ptr1 - '0';

				if (FALSE == data_source_edit_clist(groupname, listname,
					list_privilege, &result)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
				} else {
					switch (result) {
					case EDIT_RESULT_OK:
						list_ui_operation_ok_html(groupname, session,
							lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
							lang_resource_get(g_lang_resource,"EDIT_RESULT_OK", language));
						break;
					case EDIT_RESULT_NOGROUP:
						list_ui_operation_error_html(lang_resource_get(g_lang_resource,
							"EDIT_HTML_TITLE", language), lang_resource_get(g_lang_resource,
							"EDIT_ERROR_NOGROUP", language));
						break;
					case EDIT_RESULT_NOCLASS:
						list_ui_operation_error_html(lang_resource_get(g_lang_resource,
							"EDIT_HTML_TITLE", language), lang_resource_get(g_lang_resource,
							"EDIT_ERROR_NOCLASS", language));
						break;
					case EDIT_RESULT_GROUPERR:
						list_ui_operation_error_html(lang_resource_get(g_lang_resource,
							"EDIT_HTML_TITLE", language), lang_resource_get(g_lang_resource,
							"EDIT_ERROR_GROUPERR", language));
						break;
					}
				}
				return 0;
			} else {
				goto GET_ERROR;
			}
			return 0;
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
	char *language;
	
	if (NULL ==error_string) {
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

static void list_ui_operation_ok_html(const char *groupname,
	const char *session, const char *title_string, const char *prompt_string)
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
	printf(HTML_OK_5, prompt_string, url_buff, groupname, session,
		lang_resource_get(g_lang_resource,"OK_LABEL", language));
}


static void list_ui_specified_html(const char *groupname, const char *session,
	const char *listname)
{
	char *language;
	char temp_address[512];
	char url_buff[1024];
	DATA_COLLECT *pcollect;
	char *paddress;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		system_log_info("[list_ui]: fail to allocate memory for data source "
			"object");
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (FALSE == data_source_expand_specified(groupname, listname, pcollect)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"SPECIFIED_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"SPECIFIED_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_SPECIFIED_5,
		url_buff, groupname, session, listname,
		lang_resource_get(g_lang_resource,"BACK_TO_PRIVILEGE", language),
		url_buff, groupname, session, listname);
	printf(url_buff);
	printf(HTML_SPECIFIED_6, groupname, session, listname,
		lang_resource_get(g_lang_resource, "MAIL_ADDRESS_DOMAIN", language),
		lang_resource_get(g_lang_resource, "ADD_LABEL", language),
		lang_resource_get(g_lang_resource, "TIP_PRIVILEGE_CONFIG", language));
	printf(lang_resource_get(g_lang_resource,"SPECIFIED_TABLE_TITLE", language));
	printf(HTML_SPECIFIED_7);
	printf(HTML_LISTITEM_FIRST, lang_resource_get(g_lang_resource,"MAIL_ADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		paddress = (char*)data_source_collect_get_value(pcollect);
		list_ui_encode_squote(paddress, temp_address);
		printf(HTML_LISTITEM, paddress, temp_address,
			lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
	}
	data_source_collect_free(pcollect);
	
	printf(HTML_SPECIFIED_8);
	
	
}

static void list_ui_add_class_html(const char *groupname, const char *session)
{
	char *pdomain;
	char *language;
	char url_buff[1024];
	char new_name[128];
	DATA_COLLECT *pcollect;
	CLASS_ITEM *pitem;
	
	
	pdomain = strchr(groupname, '@') + 1;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		system_log_info("[list_ui]: fail to allocate memory for data source "
			"object");
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (FALSE == data_source_get_classes(groupname, pcollect)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (0 == data_source_collect_total(pcollect)) {
		list_ui_operation_error_html(lang_resource_get(g_lang_resource,"ADD_HTML_TITLE",
			language), lang_resource_get(g_lang_resource,"ADD_ERROR_EMPTYCLASS", language));
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
	printf(HTML_ADD_5, lang_resource_get(g_lang_resource,"BACK_TO_LIST", language));
	printf(url_buff);
	printf(HTML_ADD_CLASS_6, groupname, session,
		lang_resource_get(g_lang_resource,"MAIN_MLIST", language),
		lang_resource_get(g_lang_resource,"MAIN_CLASS", language));
	
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		pitem = (CLASS_ITEM*)data_source_collect_get_value(pcollect);
		list_ui_from_utf8(pitem->classname, new_name, 128);
		printf(SELECT_OPTION, pitem->class_id, new_name);
	}
	data_source_collect_free(pcollect);
	
	printf(HTML_ADD_CLASS_7, lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language),
		lang_resource_get(g_lang_resource,"OPTION_ALL", language),
		lang_resource_get(g_lang_resource,"OPTION_INTERNAL", language),
		lang_resource_get(g_lang_resource,"OPTION_DOMAIN", language),
		lang_resource_get(g_lang_resource,"OPTION_SPECIFIED", language),
		lang_resource_get(g_lang_resource,"TIP_EDIT_SPECIFIED", language),
		lang_resource_get(g_lang_resource,"OPTION_OUTGOING", language),
		lang_resource_get(g_lang_resource,"TIP_OUTGOING", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_LISTNAME", language),
		lang_resource_get(g_lang_resource,"MSGERR_LISTNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_LISTNAME", language), pdomain,
		lang_resource_get(g_lang_resource,"MSGERR_DOMAINDIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language), pdomain,
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_main_html(const char *groupname, const char *session)
{
	int row;
	char *language;
	char new_name[128];
	char temp_list[256];
	char url_buff[1024];
	char url_class[1280];
	const char *list_privils[5];
	DATA_COLLECT *pcollect;
	MLIST_ITEM *pitem;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	sprintf(url_class, "%s?group=%s&session=%s&type=add-class",
		url_buff, groupname, session);
	
	
	list_privils[MLIST_PRIVILEGE_ALL] =
						lang_resource_get(g_lang_resource,"OPTION_ALL", language);
	list_privils[MLIST_PRIVILEGE_INTERNAL] = 
						lang_resource_get(g_lang_resource,"OPTION_INTERNAL", language);
	list_privils[MLIST_PRIVILEGE_DOMAIN] =
						lang_resource_get(g_lang_resource,"OPTION_DOMAIN", language);
	list_privils[MLIST_PRIVILEGE_SPECIFIED] =
						lang_resource_get(g_lang_resource,"OPTION_SPECIFIED", language);
	list_privils[MLIST_PRIVILEGE_OUTGOING] =
						lang_resource_get(g_lang_resource,"OPTION_OUTGOING", language);

	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		system_log_info("[list_ui]: fail to allocate memory for data source "
			"object");
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (FALSE == data_source_get_clists(groupname, pcollect)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
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
	printf(HTML_RESULT_5, lang_resource_get(g_lang_resource,"CONFIRM_DELETE", language),
		url_buff, groupname, session, url_buff, groupname, session,
		url_class, lang_resource_get(g_lang_resource,"ADD_CLASS", language),
		lang_resource_get(g_lang_resource,"HELP_LINK", language),
		lang_resource_get(g_lang_resource,"HELP_LABEL", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	
	printf(HTML_RESULT_6);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_CLASS", language),
		lang_resource_get(g_lang_resource,"MAIN_MLIST", language),
		lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	row = 1;
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		pitem = (MLIST_ITEM*)data_source_collect_get_value(pcollect);
		list_ui_encode_squote(pitem->listname, temp_list);
		list_ui_from_utf8(pitem->classname, new_name, 128);
		if (0 == row%2) {
			printf(HTML_TBITEM_EVEN, new_name, pitem->listname,
				list_privils[pitem->list_privilege], temp_list,
				lang_resource_get(g_lang_resource,"EDIT_LABEL", language),
				temp_list, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		} else {
			printf(HTML_TBITEM_ODD, new_name, pitem->listname,
				list_privils[pitem->list_privilege], temp_list,
				lang_resource_get(g_lang_resource,"EDIT_LABEL", language),
				temp_list, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		}
		row ++;
	}
	data_source_collect_free(pcollect);

	printf(HTML_RESULT_7);

}

static void list_ui_edit_html(const char *groupname, const char *session,
	const char *listname)
{
	char *language;
	char url_buff[1024];
	char option_all[16];
	char option_internal[16];
	char option_domain[16];
	char option_specified[16];
	char option_outgoing[16];
	int list_privilege;

	strcpy(option_all, OPTION_UNCHECKED);
	strcpy(option_internal, OPTION_UNCHECKED);
	strcpy(option_domain, OPTION_UNCHECKED);
	strcpy(option_specified, OPTION_UNCHECKED);
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	if (FALSE == data_source_info_clist(groupname, listname, &list_privilege)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	switch (list_privilege) {
	case MLIST_PRIVILEGE_ALL:
		strcpy(option_all, OPTION_CHECKED);
		break;
	case MLIST_PRIVILEGE_INTERNAL:
		strcpy(option_internal, OPTION_CHECKED);
		break;
	case MLIST_PRIVILEGE_DOMAIN:
		strcpy(option_domain, OPTION_CHECKED);
		break;
	case MLIST_PRIVILEGE_SPECIFIED:
		strcpy(option_specified, OPTION_CHECKED);
		break;
	case MLIST_PRIVILEGE_OUTGOING:
		strcpy(option_outgoing, OPTION_CHECKED);
		break;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_EDIT_5, url_buff, groupname, session,
		lang_resource_get(g_lang_resource,"BACK_TO_LIST", language));
	printf(url_buff);
	printf(HTML_EDIT_6, groupname, session, listname,
		lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language), option_all,
		lang_resource_get(g_lang_resource,"OPTION_ALL", language), option_internal,
		lang_resource_get(g_lang_resource,"OPTION_INTERNAL", language), option_domain,
		lang_resource_get(g_lang_resource,"OPTION_DOMAIN", language), option_specified,
		lang_resource_get(g_lang_resource,"OPTION_SPECIFIED", language),
		url_buff, groupname, session, listname,
		lang_resource_get(g_lang_resource,"SPECIFY_LABEL", language), option_outgoing,
		lang_resource_get(g_lang_resource,"OPTION_OUTGOING", language),
		lang_resource_get(g_lang_resource,"SAVE_LABEL", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));

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

