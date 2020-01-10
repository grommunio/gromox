#include <libHX/string.h>
#include "list_ui.h"
#include "lang_resource.h"
#include <gromox/system_log.h>
#include <gromox/session_client.h>
#include "data_source.h"
#include <gromox/locker_client.h>
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
<LINK href=\"../data/css/calendar.css\" type=text/css rel=stylesheet>\n\
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
function DeleteItem(groupname) {if (confirm('%s')) location.href='%s?domain=%s&session=%s&type=remove&groupname=' + groupname;}\n\
function EditItem(groupname) {location.href='%s?domain=%s&session=%s&type=edit&groupname=' + groupname;}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A></TD></TR></TBODY></TABLE>\n\
<BR><BR><TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
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


#define HTML_ADD_EDIT_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}</SCRIPT>\n\
<TR><TD align=right><A href=\"javascript:BackTo()\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><FORM class=SearchForm name=addeditform \n\
method=post action="

#define HTML_ADD_6	\
"><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"add\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=title /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=groupname /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" size=40 name=new_password /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" size=40 name=retype_password /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=group_status><OPTION value=0 selected>%s</OPTION>\n\
<OPTION value=1>%s</OPTION></SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" class=RightInput size=8 name=max_size />\n\
<B>G</B></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" class=RightInput size=8 \n\
name=max_user /></SPAN><INPUT type=hidden value=\"\" name=privilege_bits />"

#define HTML_EDIT_6	\
"><INPUT type=hidden value=%s name=domain />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"edit\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 value=\"%s\" name=title /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=groupname value=\"%s\" \n\
readonly=\"readonly\"/></SPAN></TD></TR><TR><TD></TD>\n\
<TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" value=\"none-change-password\" size=40 \n\
name=new_password /></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"password\" size=40 \n\
value=\"none-change-password\" name=retype_password /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=group_status><OPTION value=0 %s>%s</OPTION>\n\
<OPTION value=1 %s>%s</OPTION></SELECT></SPAN></TD></TR>\n\
<TR class=%s><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" class=RightInput size=8 value=%d name=max_size />\n\
<B>G</B>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s:&nbsp;%d&nbsp;<B>G</B></SPAN>\n\
</TD></TR><TR class=%s><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" class=RightInput size=8 value=%d name=max_user />\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s:&nbsp;%d</SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>%s</SPAN>\n\
<INPUT type=hidden value=\"\" name=privilege_bits /></TD>"

#define HTML_ADD_EDIT_7 \
"<TD><INPUT value=\"    %s    \" type=submit \n\
onclick=\"if (0 == addeditform.title.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.title.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (0 == addeditform.groupname.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.groupname.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var apos=addeditform.groupname.value.indexOf('@');\n\
var regstr=/^[\\.\\-_A-Za-z0-9]+@([-_A-Za-z0-9]+\\.)+[A-Za-z0-9]{2,6}$/;\n\
if (0 == apos) {\n\
	alert('%s');\n\
	return false;\n\
} else if (apos > 0) {\n\
	if (addeditform.groupname.value.substring(apos, \n\
	addeditform.groupname.value.length).toLowerCase() != '@%s'.toLowerCase()) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
	if (!regstr.test(addeditform.groupname.value)) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
} else {\n\
	var namestr = addeditform.groupname.value + '@%s';\n\
	if (!regstr.test(namestr)) { \n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (0 == addeditform.new_password.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.new_password.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.new_password.value != addeditform.retype_password.value) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var num = parseInt(addeditform.max_size.value);\n\
if (isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
num = parseInt(addeditform.max_user.value);\n\
if (isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var mask_string='';\n\
if (account_management.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (mail_log.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (mail_monitor.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (mail_backup.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
addeditform.privilege_bits.value = mask_string;\n\
return true;\" /></TD></TR></FORM>"

#define HTML_ADD_8	\
"<TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><TABLE border=0><TBODY><TR><TD>\n\
<INPUT type=checkbox name=mail_backup value=\"on\" %s/>%s</TD>\n\
<TD><INPUT type=checkbox name=mail_monitor value=\"on\" %s/>%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=mail_log value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=account_management value=\"on\" />%s</TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_EDIT_8	\
"<TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><TABLE border=0><TBODY><TR><TD>\n\
<INPUT type=checkbox name=mail_backup value=\"on\" %s />%s</TD>\n\
<TD><INPUT type=checkbox name=mail_monitor value=\"on\" %s />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=mail_log value=\"on\" %s />%s</TD>\n\
<TD><INPUT type=checkbox name=account_management value=\"on\" %s />%s</TD></TR>\n\
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
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>"

#define HTML_TBITEM     \
"<TR class=%s><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%dG&nbsp;</TD><TD>&nbsp;%d&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"group_classes?group=%s&session=%s\" target=_blank>%s</A>&nbsp;|\n\
&nbsp;<A href=\"javascript:EditItem('%s')\">%s</A>&nbsp;|&nbsp;\n\
<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define SELECT_OPTION		"<OPTION value=%d>%s</OPTION>"

#define SELECT_OPTION_EX	"<OPTION value=%d selected>%s</OPTION>"

#define CSS_ITEMODD			"ItemOdd"

#define CSS_ITEMEVEN		"ItemEven"

#define CSS_ITEM_SUSPEND	"ItemSuspend"

#define CSS_ITEM_OVERQUOTA  "ItemOverquota"

#define OPTION_DISABLED			"disabled"

#define OPTION_ENABLED			""

#define OPTION_SELECTED			"selected"

#define OPTION_UNSELECTED		""

#define OPTION_CHECKED          "checked"

#define OPTION_UNCHECKED		""

#define DOMAIN_PRIVILEGE_BACKUP				0x1

#define DOMAIN_PRIVILEGE_MONITOR			0x2

#define GROUP_PRIVILEGE_BACKUP				0x1

#define GROUP_PRIVILEGE_MONITOR				0x2

#define GROUP_PRIVILEGE_LOG					0x4

#define GROUP_PRIVILEGE_ACCOUNT				0x8

#define GROUP_PRIVILEGE_DOMAIN_BACKUP		0x100

#define GROUP_PRIVILEGE_DOMAIN_MONITOR      0x200

#define DEF_MODE                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static void list_ui_error_html(const char *error_string);

static void list_ui_add_html(const char *domainname, const char *session);

static void list_ui_operation_ok_html(const char *domainname,
	const char *session, const char *prompt_string, const char *title_string);

static void list_ui_operation_error_html(const char *title_string,
	const char *error_string);

static void list_ui_edit_html(const char *domainname, const char *session,
	const char *groupname);

static void list_ui_main_html(const char *domainname, const char *session);

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_unencode(char *src, char *last, char *dest);

static void list_ui_encode_squote(const char *in, char *out);

static void list_ui_partition_info(char *s, int *pmegas, int *pfiles,
	int *phomes);

static void list_ui_remove_inode(const char *path);

static void list_ui_free_dir(BOOL b_media, const char *maildir);

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
	char *pat, type[16];
	char domainname[64];
	char session[256];
	char title[128];
	char mediadir[128];
	char new_title[128];
	char groupname[128];
	char group_path[256];
	char temp_buff[256];
	char new_password[32];
	char retype_password[32];
	char encrypt_pw[40];
	char post_buff[4096];
	char search_buff[1024];
	char resource_name[256];
	int max_size, max_user;
	int group_status;
	int len, result;
	int privilege_bits;
	struct stat node_stat;
	DATA_COLLECT *pcollect;
	USER_INFO *pinfo;
	LOCKD lockd;

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
		system_log_info("[list_ui]: $REQUEST_METHOD is unset");
		return -2;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 4096) {
			system_log_info("[list_ui]: post buffer too long");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		list_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "domain=", len);
		if (NULL == ptr1) {
			goto POST_ERROR;
		}
		ptr1 += 7;
		ptr2 = search_string(search_buff, "&session=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >= 64) {
			goto POST_ERROR;
		}
		memcpy(domainname, ptr1, ptr2 - ptr1);
		domainname[ptr2 - ptr1] = '\0';

		ptr1 = ptr2 + 9;
		ptr2 = search_string(search_buff, "&type=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
			goto POST_ERROR;
		}
		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
		
		if (FALSE == session_client_check(domainname, session)) {
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION", language));
			return 0;
		}
		
		ptr1 = ptr2 + 6;
		ptr2 = search_string(search_buff, "&title=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 > 15) {
			goto POST_ERROR;
		}
		memcpy(type, ptr1, ptr2 - ptr1);
		type[ptr2 - ptr1] = '\0';
		HX_strrtrim(type);
		HX_strltrim(type);
		if (0 != strcasecmp(type, "add") &&
			0 != strcasecmp(type, "edit")) {
			goto POST_ERROR;
		}
		ptr1 = ptr2 + 7;
		ptr2 = search_string(search_buff, "&groupname=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >= 128) {
			goto POST_ERROR;
		}
		memcpy(title, ptr1, ptr2 - ptr1);
		title[ptr2 - ptr1] = '\0';
		HX_strrtrim(title);
		HX_strltrim(title);

		ptr1 = ptr2 + 11;
		ptr2 = search_string(search_buff, "&new_password=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >= 128) {
			goto POST_ERROR;
		}
		
		memcpy(groupname, ptr1, ptr2 - ptr1);
		groupname[ptr2 - ptr1] = '\0';
		HX_strrtrim(groupname);
		HX_strltrim(groupname);
		HX_strlower(groupname);
		
		pat = strchr(groupname, '@');
		if (NULL == pat) {
			if (strlen(groupname) + 1 + strlen(domainname) >= 128) {
				goto POST_ERROR;
			}
			strcat(groupname, "@");
			strcat(groupname, domainname);
		} else {
			if (0 != strcasecmp(pat + 1, domainname)) {
				goto POST_ERROR;
			}
		}
		
		ptr1 = ptr2 + 14;
		ptr2 = search_string(search_buff, "&retype_password=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >= 32) {
			goto POST_ERROR;
		}
		memcpy(new_password, ptr1, ptr2 - ptr1);
		new_password[ptr2 - ptr1] = '\0';

		ptr1 = ptr2 + 17;
		ptr2 = search_string(search_buff, "&group_status=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >=32) {
			goto POST_ERROR;
		}
		memcpy(retype_password, ptr1, ptr2 - ptr1);
		retype_password[ptr2 - ptr1] = '\0';

		if (0 != strcmp(new_password, retype_password)) {
			goto POST_ERROR;
		}

		ptr1 = ptr2 + 14;
		ptr2 = search_string(search_buff, "&max_size=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >= 4) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		group_status = atoi(temp_buff);
		
		ptr1 = ptr2 + 10;
		ptr2 = search_string(search_buff, "&max_user=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 >= 12) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		max_size = atoi(temp_buff)*1024;
		
		ptr1 = ptr2 + 10;
		ptr2 = search_string(search_buff, "&privilege_bits=", len);
		if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, ptr2 - ptr1);
		temp_buff[ptr2 - ptr1] = '\0';
		max_user = atoi(temp_buff);
		
		ptr1 = ptr2 + 16;

		/* for some browser sunch as firefox */
		ptr2 = strchr(ptr1, '&');
		if (NULL != ptr2) {
			ptr2 ++;
			*ptr2 = '\0';
			len = ptr2 - search_buff;
		}

		if (0 == search_buff + len - 1 - ptr1 ||
			search_buff + len - ptr1 - 1 >= 12) {
			goto POST_ERROR;
		}
		memcpy(temp_buff, ptr1, search_buff + len - 1 - ptr1);
		temp_buff[search_buff + len - 1 - ptr1] = '\0';
		privilege_bits = 0;
		if ('1' == temp_buff[3]) {
			 privilege_bits |= GROUP_PRIVILEGE_BACKUP;
		}
		if ('1' == temp_buff[2]) {
			privilege_bits |= GROUP_PRIVILEGE_MONITOR;
		}
		if ('1' == temp_buff[1]) {
			privilege_bits |= GROUP_PRIVILEGE_LOG;
		}
		if ('1' == temp_buff[0]) {
			privilege_bits |= GROUP_PRIVILEGE_ACCOUNT;
		}
		
		if (0 == strcasecmp(type, "add")) {
			if (FALSE == data_source_get_domain_homedir(domainname,
				group_path) || '\0' == group_path[0]) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			strcat(group_path, "/");
			pat = strchr(groupname, '@');
			if (NULL != pat) {
				memcpy(temp_buff, groupname, pat - groupname);
				temp_buff[pat - groupname] = '\0';
				strcat(group_path, temp_buff);
			} else {
				strcat(group_path, groupname);
			}
			strcpy(encrypt_pw, md5_crypt_wrapper(new_password));
			list_ui_to_utf8(title, new_title, 128);
			if (FALSE == data_source_add_group(groupname, encrypt_pw,
				max_size, max_user, new_title, privilege_bits, group_status,
				&result)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			switch (result) {
			case ADD_RESULT_OK:
				mkdir(group_path, 0777);
				strcat(group_path, "/tmp");
				mkdir(group_path, 0777);
				list_ui_operation_ok_html(domainname, session,
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
			case ADD_RESULT_SIZEEXCEED:
				list_ui_operation_error_html(
					lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"ADD_ERROR_SIZEEXCEED", language));
				break;
			case ADD_RESULT_USREXCEED:
				list_ui_operation_error_html(
					lang_resource_get(g_lang_resource,"ADD_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"ADD_ERROR_USREXCEED", language));
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
			}
		} else {
			if (0 != strcmp(new_password, "none-change-password")) {
				strcpy(encrypt_pw, md5_crypt_wrapper(new_password));
			} else {
				encrypt_pw[0] = '\0';
			}
			list_ui_to_utf8(title, new_title, 128);
			if (FALSE == data_source_edit_group(groupname, encrypt_pw,
				max_size, max_user, new_title, privilege_bits, group_status,
				&result)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			switch (result) {
			case EDIT_RESULT_OK:
				list_ui_operation_ok_html(domainname, session,
					lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"EDIT_RESULT_OK",  language));
				break;
			case EDIT_RESULT_NODOMAIN:
				list_ui_operation_error_html(
					lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"EDIT_ERROR_NODOMAIN", language));
				break;
			case EDIT_RESULT_DOMAINNOTMAIN:
				list_ui_operation_error_html(
					lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"EDIT_ERROR_DOMAINNOTMAIN", language));
				break;
			case EDIT_RESULT_NOEXIST:
				list_ui_operation_error_html(
					lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"EDIT_ERROR_NOEXIST", language));
				break;
			case EDIT_RESULT_SIZEEXCEED:
				list_ui_operation_error_html(
					lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"EDIT_ERROR_SIZEEXCEED", language));
				break;
			case EDIT_RESULT_USREXCEED:
				list_ui_operation_error_html(
					lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
					lang_resource_get(g_lang_resource,"EDIT_ERROR_USREXCEED", language));
				break;
			}
		}
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[list_ui]: $QUERY_STRING is unset");
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
				if (search_buff + len - 1 - ptr1 > 255) {
					goto GET_ERROR;
				}
				memcpy(session, ptr1, search_buff + len - 1 - ptr1);
				session[search_buff + len - 1 - ptr1] = '\0';
			
				if (FALSE == session_client_check(domainname, session)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				list_ui_main_html(domainname, session);
				return 0;
			}

			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			if (FALSE == session_client_check(domainname, session)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}

			ptr1 = ptr2 + 6;
			ptr2 = search_string(search_buff, "&groupname=", len);
			if (NULL != ptr2) {
				memcpy(type, ptr1, ptr2 - ptr1);
				type[ptr2 - ptr1] = '\0';
				ptr1 = ptr2 + 11;
				if ((0 != strcasecmp(type, "edit") &&
					0 != strcasecmp(type, "remove")) ||
					0 == search_buff + len - 1 - ptr1 ||
					search_buff + len - 1 - ptr1 >= 128) {
					goto GET_ERROR;
				}
				memcpy(groupname, ptr1, search_buff + len - 1 - ptr1);
				groupname[search_buff + len - 1 - ptr1] = '\0';
				
				pat = strchr(groupname, '@');
				if (NULL == pat) {
					if (strlen(groupname) + 1 + strlen(domainname) >= 128) {
						goto GET_ERROR;
					}
					strcat(groupname, "@");
					strcat(groupname, domainname);
				} else {
					if (0 != strcasecmp(pat + 1, domainname)) {
						goto GET_ERROR;
					}
				}

				if (0 == strcasecmp(type, "edit")) {
					list_ui_edit_html(domainname, session, groupname);
				} else {
					if (FALSE == data_source_get_domain_homedir(domainname,
						group_path) || '\0' == group_path[0]) {
						list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
							language));
						return 0;
					}
					strcat(group_path, "/");
					pat = strchr(groupname, '@');
					if (NULL != pat) {
						memcpy(temp_buff, groupname, pat - groupname);
						temp_buff[pat - groupname] = '\0';
						strcat(group_path, temp_buff);
					} else {
						strcat(group_path, groupname);
					}
					
					sprintf(resource_name, "DATABASE-%s", domainname);
					HX_strupper(resource_name);
					lockd = locker_client_lock(resource_name);
					pcollect = data_source_collect_init();
					if (NULL == pcollect) {
						locker_client_unlock(lockd);
						system_log_info("[list_ui]: fail to allocate memory "
							"for data source collect object");
						list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
							language));
						return 0;
					}
					if (FALSE == data_source_get_group_users(groupname,
						pcollect)) {
						data_source_collect_free(pcollect);
						locker_client_unlock(lockd);
						list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
							language));
						return 0;
					}
					
					if (FALSE == data_source_remove_group(groupname, &result)) {
						locker_client_unlock(lockd);
						list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
							language));
						return 0;
					}
					switch (result) {
					case REMOVE_RESULT_OK:
						for (data_source_collect_begin(pcollect);
							!data_source_collect_done(pcollect);
							data_source_collect_forward(pcollect)) {
							pinfo = (USER_INFO*)data_source_collect_get_value(
										pcollect);
							if (0 == lstat(pinfo->maildir, &node_stat) &&
								0 != S_ISLNK(node_stat.st_mode)) {
								memset(mediadir, 0, 128);
								if (readlink(pinfo->maildir, mediadir, 128) > 0) {
									list_ui_free_dir(TRUE, mediadir);
									remove(pinfo->maildir);
									mkdir(pinfo->maildir, 0777);
								}
							}

							list_ui_free_dir(FALSE, pinfo->maildir);
						}
						list_ui_remove_inode(group_path);
						list_ui_operation_ok_html(domainname, session,
							lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language),
							lang_resource_get(g_lang_resource,"REMOVE_RESULT_OK", language));
						break;
					case REMOVE_RESULT_NOTEXIST:
						list_ui_operation_error_html(
							lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language),
							lang_resource_get(g_lang_resource,"REMOVE_ERROR_NOTEXIST", language));
						break;
					case REMOVE_RESULT_NODOMAIN:
						list_ui_operation_error_html(
							lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language),
							lang_resource_get(g_lang_resource,"REMOVE_ERROR_NODOMAIN", language));
						break;
					case REMOVE_RESULT_DOMAINERR:
						list_ui_operation_error_html(
							lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language),
							lang_resource_get(g_lang_resource,"REMOVE_ERROR_DOMAINERR", language));
						break;
					}
					
					data_source_collect_free(pcollect);
					locker_client_unlock(lockd);
				}
				return 0;
			}
			
			if (search_buff + len - 1 - ptr1 > 16) {
				goto GET_ERROR;
			}
			memcpy(type, ptr1, search_buff + len - 1 - ptr1);
			type[search_buff + len - 1 - ptr1] = '\0';
			if (0 == strcasecmp(type, "add")) {
				list_ui_add_html(domainname, session);	
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
POST_ERROR:
	system_log_info("[list_ui]: query string of POST format error");
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
	printf(HTML_OK_5, prompt_string, url_buff, domainname, session,
		lang_resource_get(g_lang_resource,"OK_LABEL", language));
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

static void list_ui_add_html(const char *domainname, const char *session)
{
	char *language;
	char url_buff[1024];
	char option_backup[16];
	char option_monitor[16];
	int privilege_bits;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (FALSE == data_source_info_domain(domainname, &privilege_bits)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	if (DOMAIN_PRIVILEGE_BACKUP&privilege_bits) {
		strcpy(option_backup, OPTION_ENABLED);
	} else {
		strcpy(option_backup, OPTION_DISABLED);
	}

	if (DOMAIN_PRIVILEGE_MONITOR&privilege_bits) {
		strcpy(option_monitor, OPTION_ENABLED);
	} else {
		strcpy(option_monitor, OPTION_DISABLED);
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
	printf(HTML_ADD_EDIT_5, lang_resource_get(g_lang_resource,"BACK_TO_LIST", language));
	printf(url_buff);
	printf(HTML_ADD_6, domainname, session,
		lang_resource_get(g_lang_resource,"MAIN_TITLE", language),
		lang_resource_get(g_lang_resource,"MAIN_GROUPNAME_PROMPT", language),
		lang_resource_get(g_lang_resource,"MAIN_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_RETYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_GROUP_STATUS", language),
		lang_resource_get(g_lang_resource,"STATUS_NORMAL", language),
		lang_resource_get(g_lang_resource,"STATUS_SUSPEND", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_USER", language));

	printf(HTML_ADD_EDIT_7, lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_GROUPNAME", language),
		lang_resource_get(g_lang_resource,"MSGERR_GROUPNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_GROUPNAME", language), domainname,
		lang_resource_get(g_lang_resource,"MSGERR_DOMAINDIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language), domainname,
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language),
		lang_resource_get(g_lang_resource,"MSGERR_NULL_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_DIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_USER", language));

	printf(HTML_ADD_8, lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language),
		option_backup, lang_resource_get(g_lang_resource,"OPTION_BACKUP", language),
		option_monitor, lang_resource_get(g_lang_resource,"OPTION_MONITOR", language),
		lang_resource_get(g_lang_resource,"OPTION_LOG", language),
		lang_resource_get(g_lang_resource,"OPTION_ACCOUNT", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_edit_html(const char *domainname, const char *session,
	const char *groupname)
{
	int actual_size;
	int actual_user;
	char *language;
	char new_title[128];
	char url_buff[1024];
	char create_buff[32];
	char class_size[32];
	char class_user[32];
	char option_enabled[16];
	char option_disabled[16];
	char option_backup[16];
	char option_monitor[16];
	char option_log[16];
	char option_account[16];
	GROUP_ITEM temp_item;
	struct tm temp_tm;
	
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");

	if (FALSE == data_source_info_group(groupname, &temp_item,
		&actual_size, &actual_user)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	if ('\0' == temp_item.groupname[0]) {
		list_ui_operation_error_html(
			lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language),
			lang_resource_get(g_lang_resource,"EDIT_ERROR_NOEXIST", language));
		return;
	}

	list_ui_from_utf8(temp_item.title, new_title, 128);
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	class_size[0] = '\0';
	if (actual_size >= temp_item.max_size) {
		strcpy(class_size, CSS_ITEM_OVERQUOTA);
	}
	class_user[0] = '\0';
	if (actual_user >= temp_item.max_user) {
		strcpy(class_user, CSS_ITEM_OVERQUOTA);
	}
	
	if (RECORD_STATUS_NORMAL == temp_item.group_status) {
		strcpy(option_enabled, OPTION_SELECTED);
		strcpy(option_disabled, OPTION_UNSELECTED);
	} else {
		strcpy(option_enabled, OPTION_UNSELECTED);
		strcpy(option_disabled, OPTION_SELECTED);
	}

	if (temp_item.privilege_bits & GROUP_PRIVILEGE_DOMAIN_BACKUP) {
		if (temp_item.privilege_bits & GROUP_PRIVILEGE_BACKUP) {
			strcpy(option_backup, OPTION_CHECKED);
		} else {
			strcpy(option_backup, OPTION_UNCHECKED);
		}
	} else {
		strcpy(option_backup, OPTION_DISABLED);
	}

	if (temp_item.privilege_bits & GROUP_PRIVILEGE_DOMAIN_MONITOR) {
		if (temp_item.privilege_bits & GROUP_PRIVILEGE_MONITOR) {
			strcpy(option_monitor, OPTION_CHECKED);
		} else {
			strcpy(option_monitor, OPTION_UNCHECKED);
		}
	} else {
		strcpy(option_monitor, OPTION_DISABLED);
	}

	if (temp_item.privilege_bits & GROUP_PRIVILEGE_LOG) {
		strcpy(option_log, OPTION_CHECKED);
	} else {
		strcpy(option_log, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & GROUP_PRIVILEGE_ACCOUNT) {
		strcpy(option_account, OPTION_CHECKED);
	} else {
		strcpy(option_account, OPTION_UNCHECKED);
	}
	
	localtime_r(&temp_item.create_day, &temp_tm);
	strftime(create_buff, 32, lang_resource_get(g_lang_resource,"DATE_FORMAT", language),
		&temp_tm);
	
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
	printf(HTML_ADD_EDIT_5, lang_resource_get(g_lang_resource,"BACK_TO_LIST", language));
	printf(url_buff);
	printf(HTML_EDIT_6, domainname, session,
		lang_resource_get(g_lang_resource,"MAIN_TITLE", language), new_title,
		lang_resource_get(g_lang_resource,"MAIN_GROUPNAME_PROMPT", language),
		temp_item.groupname, lang_resource_get(g_lang_resource,"MAIN_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_RETYPE", language),
		lang_resource_get(g_lang_resource,"MAIN_GROUP_STATUS", language), option_enabled,
		lang_resource_get(g_lang_resource,"STATUS_NORMAL", language), option_disabled,
		lang_resource_get(g_lang_resource,"STATUS_SUSPEND", language), class_size,
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language), temp_item.max_size/1024,
		lang_resource_get(g_lang_resource,"ACTUAL_SIZE", language), actual_size/1024,
		class_user, lang_resource_get(g_lang_resource,"MAIN_MAX_USER", language),
		temp_item.max_user, lang_resource_get(g_lang_resource,"ACTUAL_USER", language),
		actual_user, lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language),
		create_buff);

	printf(HTML_ADD_EDIT_7, lang_resource_get(g_lang_resource,"SAVE_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_GROUPNAME", language),
		lang_resource_get(g_lang_resource,"MSGERR_GROUPNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_GROUPNAME", language), domainname,
		lang_resource_get(g_lang_resource,"MSGERR_DOMAINDIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language), domainname,
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language),
		lang_resource_get(g_lang_resource,"MSGERR_NULL_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_DIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_USER", language));

	
	printf(HTML_EDIT_8, lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language),
		option_backup, lang_resource_get(g_lang_resource,"OPTION_BACKUP", language),
		option_monitor, lang_resource_get(g_lang_resource,"OPTION_MONITOR", language),
		option_log, lang_resource_get(g_lang_resource,"OPTION_LOG", language),
		option_account, lang_resource_get(g_lang_resource,"OPTION_ACCOUNT", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	
}

static void list_ui_main_html(const char *domainname, const char *session)
{
	int rows;
	char *language;
	char url_buff[1024];
	char url_add[1280];
	char temp_group[256];
	char temp_title[128];
	GROUP_ITEM *pitem;
	DATA_COLLECT *pcollect;

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");

	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	sprintf(url_add, "%s?domain=%s&session=%s&type=add", url_buff, domainname,
		session);
	
	pcollect = data_source_collect_init();

	if (NULL == pcollect) {
		system_log_info("[list_ui]: fail to allocate memory for data source "
			"collect object");
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	if (FALSE == data_source_get_group_list(domainname, pcollect)) {
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
	printf(HTML_RESULT_5, lang_resource_get(g_lang_resource,"CONFIRM_DELETE", language),
		url_buff, domainname, session, url_buff, domainname, session,
		url_add, lang_resource_get(g_lang_resource,"ADD_LABEL", language));
	
	printf(lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	
	printf(HTML_RESULT_6);
	
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_TITLE", language),
		lang_resource_get(g_lang_resource,"MAIN_GROUPNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_USER", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	
	rows = 1;
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		pitem = (GROUP_ITEM*)data_source_collect_get_value(pcollect);
		list_ui_encode_squote(pitem->groupname, temp_group);
		list_ui_from_utf8(pitem->title, temp_title, 128);
		if (RECORD_STATUS_SUSPEND == pitem->group_status) {
			printf(HTML_TBITEM, CSS_ITEM_SUSPEND, temp_title,
				pitem->groupname, pitem->max_size/1024, pitem->max_user,
				pitem->groupname, session,
				lang_resource_get(g_lang_resource,"EXPAND_LABEL", language),
				temp_group, lang_resource_get(g_lang_resource,"EDIT_LABEL", language),
				temp_group, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		} else {
			if (0 == rows%2) {
				printf(HTML_TBITEM, CSS_ITEMEVEN, temp_title,
					pitem->groupname, pitem->max_size/1024, pitem->max_user,
					pitem->groupname, session,
					lang_resource_get(g_lang_resource,"EXPAND_LABEL", language), temp_group,
					lang_resource_get(g_lang_resource,"EDIT_LABEL", language), temp_group,
					lang_resource_get(g_lang_resource,"DELETE_LABEL", language));	
			} else {
				printf(HTML_TBITEM, CSS_ITEMODD, temp_title,
					pitem->groupname, pitem->max_size/1024, pitem->max_user,
					pitem->groupname, session,
					lang_resource_get(g_lang_resource,"EXPAND_LABEL", language), temp_group,
					lang_resource_get(g_lang_resource,"EDIT_LABEL", language), temp_group,
					lang_resource_get(g_lang_resource,"DELETE_LABEL", language));	
			}
			rows ++;
		} 
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

static void list_ui_free_dir(BOOL b_media, const char *maildir)
{	
	LOCKD lockd;
	time_t cur_time;
	int fd, len;
	int space, files, homes;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[1024];
	struct stat node_stat;


	if (TRUE == b_media) {
		lockd = locker_client_lock("MEDIA-AREA");
	} else {
		lockd = locker_client_lock("USER-AREA");
	}
	if (0 != lstat(maildir, &node_stat)) {
		locker_client_unlock(lockd);
		return;
	}


	time(&cur_time);
	sprintf(temp_path, "%s/../vinfo", maildir);
	sprintf(temp_path1, "%s/../vinfo.%d", maildir, cur_time);
	fd = open(temp_path, O_RDONLY);
	
	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}
	
	len = read(fd, temp_buff, 1024);
	close(fd);
	if (len <= 0) {
		locker_client_unlock(lockd);
		return;
	}
	temp_buff[len] = '\0';
	homes = atoi(temp_buff);
	
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}
	len = sprintf(temp_buff, "%dH", homes - 1);
	write(fd, temp_buff, len);
	close(fd);
	rename(temp_path1, temp_path);
	
	sprintf(temp_path, "%s/../../pinfo", maildir);
	sprintf(temp_path1, "%s/../../pinfo.%d", maildir, cur_time);
	fd = open(temp_path, O_RDONLY);

	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}
	
	len = read(fd, temp_buff, 1024);
	close(fd);
	if (len <= 0) {
		locker_client_unlock(lockd);
		return;
	}
	temp_buff[len] = '\0';
	
	list_ui_partition_info(temp_buff, &space, &files, &homes);
	if (-1 == space || -1== files || -1 == homes) {
		locker_client_unlock(lockd);
		return;
	}
	
	fd = open(temp_path1, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		locker_client_unlock(lockd);
		return;
	}

	len = sprintf(temp_buff, "%dM,%dC,%dH", space, files, homes - 1);
	write(fd, temp_buff, len);
	close(fd);
	rename(temp_path1, temp_path);
	
	list_ui_remove_inode(maildir);
	
	locker_client_unlock(lockd);
}

static void list_ui_partition_info(char *s, int *pmegas, int *pfiles,
	int *phomes)
{
	char *plast;
	char *ptoken;

	plast = s;
	ptoken = strchr(plast, 'M');
	if (NULL == ptoken) {
		*pmegas = -1;
	} else {
		*ptoken = '\0';
		*pmegas = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'C');
	if (NULL == ptoken) {
		*pfiles = -1;
	} else {
		*ptoken = '\0';
		*pfiles = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'H');
	if (NULL == ptoken) {
		*phomes = -1;
	} else {
		*ptoken = '\0';
		*phomes = atoi(plast);
	}
}

static void list_ui_remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

	if (0 != lstat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", path, direntp->d_name);
		list_ui_remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
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


