#include "util.h"
#include "list_ui.h"
#include "list_file.h"
#include "midb_tool.h"
#include "system_log.h"
#include "exmdb_tool.h"
#include "double_list.h"
#include "data_source.h"
#include "exmdb_client.h"
#include "lang_resource.h"
#include "locker_client.h"
#include "request_parser.h"
#include "session_client.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <crypt.h>
#include <fcntl.h>
#include <iconv.h>
#include <time.h>

#define HTML_COMMON_1	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>"

/* fill html title here */

#define HTML_COMMON_2	\
"</TITLE><LINK href=\"../data/css/result.css\" type=text/css rel=stylesheet>\n\
<LINK href=\"../data/css/calendar.css\" type=text/css rel=stylesheet>\n\
<SCRIPT type=\"text/javascript\" src=\"../data/script/jquery.js\"></SCRIPT>\n\
<SCRIPT type=\"text/javascript\" src=\"../data/script/calendar.js\"></SCRIPT>\n\
<META http-equiv=Content-Type content=\"text/html; charset="

/* fill charset here */

#define HTML_COMMON_3	\
"\"><META content=\"MSHTML 6.00.2900.2963\" name=GENERATOR></HEAD>\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\n\
marginheight=\"0\" marginwidth=\"0\"><CENTER>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0>\n\
<TBODY><TR><TD noWrap align=middle background=\"../data/picture/di1.gif\"\n\
height=55><SPAN class=ReportTitle> "

/* fill user list title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(username) {if (confirm('%s')) location.href='%s?group=%s&session=%s&type=remove&username=' + username;}\n\
function EditItem(username) {location.href='%s?group=%s&session=%s&type=edit&username=' + username;}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A>\n\
&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A></TD></TR>\n\
<TR><TD noWrap align=left height=23>"

#define HTML_RESULT_5_1	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(username) {if (confirm('%s')) location.href='%s?group=%s&session=%s&type=remove&username=' + username;}\n\
function EditItem(username) {location.href='%s?group=%s&session=%s&type=edit&username=' + username;}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A></TD></TR>\n\
<TR><TD noWrap align=left height=23>"

/* fill rows num here */

#define HTML_RESULT_6	\
"</TD></TR><TR><TD noWrap align=right>%s:%d&nbsp;&nbsp;&nbsp;&nbsp;\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;<A href=\"%s\" %s>%s</A>&nbsp;&nbsp;\n\
<A href=\"%s\" %s>%s</A>&nbsp;&nbsp;<A href=\"%s\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle \n\
background=\"../data/picture/di2.gif\">"


/* fill result table title here */

#define HTML_RESULT_7	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_RESULT_8	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_SEARCH_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}\n\
$(function(){$(\"#create_min\").datepicker({\n\
monthText:[%s],\n\
weekText:[%s],\n\
yearText:[%s],\n\
todayText:[%s]\n\
})})\n\
$(function(){$(\"#create_max\").datepicker({\n\
monthText:[%s],\n\
weekText:[%s],\n\
yearText:[%s],\n\
todayText:[%s]\n\
})})\n</SCRIPT>\n\
<TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><FORM class=SearchForm \n\
name=searchpattern method=post action="

#define HTML_SEARCH_6	\
"><INPUT type=hidden value=%s name=group />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"search\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" \n\
border=0><TBODY><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=username />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><SELECT name=address_status>\n\
<OPTION value=-1 selected>%s</OPTION><OPTION value=0>%s</OPTION>\n\
<OPTION value=1>%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=address_type><OPTION value=-1 selected>%s</OPTION>\n\
<OPTION value=0>%s</OPTION><OPTION value=1>%s</OPTION>\n\
<OPTION value=4>%s</OPTION><OPTION value=5>%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" size=8 name=size_min />&nbsp;-&nbsp;\n\
<INPUT type=\"text\" size=8 name=size_max />&nbsp;<B>G</B></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=title /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=real_name /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=nickname /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=tel /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=cell /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=homeaddress /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=memo /></SPAN></TD></TR>\n"


#define HTML_SEARCH_7	\
"<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" id=create_min name=create_min style=\"border:solid 1px; \n\
width:100px; background:url(../data/picture/calendar-button.gif) \n\
no-repeat right; height:22px; padding-right:19px; cursor:default;\" \n\
readonly=\"readonly\" />&nbsp;-&nbsp; <INPUT type=\"text\" id=create_max \n\
name=create_max style=\"border:solid 1px; width:100px; \n\
background:url(../data/picture/calendar-button.gif) no-repeat\n\
right; height:22px; padding-right:19px; cursor:default;\" readonly=\"readonly\"\n\
 /></SPAN></TD><TD><INPUT type=submit value=\"    %s    \"\n\
onclick=\"if (username.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (username.value.length > 0) {\n\
	var apos=username.value.indexOf('@');\n\
	if (apos > 0 && username.value.substring(apos, \n\
		username.value.length).toLowerCase() != '@%s'.toLowerCase()) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (size_min.value.length > 0) {\n\
	var num=parseInt(searchpattern.size_min.value);\n\
	if(isNaN(num) || num < 0) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (size_max.value.length > 0) {\n\
	var num=parseInt(searchpattern.size_max.value);\n\
	if (isNaN(num) || num <= 0) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (title.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (real_name.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (memo.value.length >= 128) {\n\
	alter('%s');\n\
	return false;\n\
}\n\" /></TD></TR></TBODY></TABLE></FORM></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"


#define HTML_ADD_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A>\n\
</TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=addform method=post action="

#define HTML_ALIAS_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A>\n\
</TD></TR></TBODY></TABLE><BR><BR><BR><BR><BR>\n\
<FORM class=SearchForm name=aliasform method=post action="

#define HTML_EDIT_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}</SCRIPT>\n\
<TR><TD align=right><A href=\"javascript:BackTo()\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><DIV align=left>&nbsp;&nbsp;&nbsp;&nbsp;<B>%s</B></DIV>\n\
<FORM class=SearchForm name=editform method=post action="

#define HTML_ADD_6	\
"><INPUT type=hidden value=%s name=group />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"add\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=username /></SPAN></TD></TR>\n\
<TR class=ItemRandpasswd><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" value=\"%s\" size=40 name=new_password />&nbsp;&nbsp;%s:%s</SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" value=\"%s\" size=40 name=retype_password />&nbsp;&nbsp;%s</SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=extpass_type %s><OPTION value=0 selected>%s</OPTION>\n\
<OPTION value=1>%s</OPTION><OPTION value=2>%s</OPTION>\n\
<OPTION value=3>%s</OPTION><OPTION value=4>%s</OPTION>\n\
<OPTION value=5>%s</OPTION></SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=sub_type><OPTION value=0 selected>%s</OPTION>\n\
<OPTION value=1>%s</OPTION><OPTION value=2>%s</OPTION>\n\
</SELECT></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><SELECT name=lang>\n"

#define HTML_ADD_7	\
"</SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=address_status><OPTION value=0 selected>%s</OPTION>\n\
<OPTION value=1>%s</OPTION></SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" class=RightInput size=8 name=max_size />\n\
<B>G</B></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=title />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=real_name />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=nickname />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=tel />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=cell />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=homeaddress />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=memo />\n\
</SPAN><INPUT type=hidden value=\"\" name=privilege_bits /></TD>\n"

#define HTML_ALIAS_6	\
"><INPUT type=hidden value=%s name=group />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"alias\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=username /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=aliasname /></SPAN></TD>\n\
<TD><INPUT type=\"submit\" value=\"    %s    \" \n\
onclick=\"if (0 == aliasform.username.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (aliasform.username.value.length >= 128) {\n\
	alert('%s\');\n\
	return false;\n\
}\n\
var apos=aliasform.username.value.indexOf('@');\n\
if (apos > 0 && aliasform.username.value.substring(apos, \n\
	aliasform.username.value.length).toLowerCase() != '@%s'.toLowerCase()) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (0 == aliasform.aliasname.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (aliasform.aliasname.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var apos=aliasform.aliasname.value.indexOf('@');\n\
if (apos > 0 && aliasform.aliasname.value.substring(apos, \n\
	aliasform.aliasname.value.length).toLowerCase() != '@%s'.toLowerCase()) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
return true;\" /></TD></TR></TBODY></TABLE></FORM></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_EDIT_6	\
"><INPUT type=hidden value=%s name=group />\n\
<INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"edit\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=username \n\
readonly=\"readonly\"/></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" size=40 value=\"none-change-password\" \n\
name=new_password /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" size=40 value=\"none-change-password\" \n\
name=retype_password /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=extpass_type %s><OPTION value=0 %s>%s</OPTION>\n\
<OPTION value=1 %s>%s</OPTION><OPTION value=2 %s>%s</OPTION>\n\
<OPTION value=3 %s>%s</OPTION><OPTION value=4 %s>%s</OPTION>\n\
<OPTION value=5 %s>%s</OPTION></SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=address_status><OPTION value=0 %s>%s</OPTION>\n\
<OPTION value=1 %s>%s</OPTION></SELECT></SPAN></TD></TR>\n"

#define HTML_EDIT_7_1 \
"<TR class=%s><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=8 class=RightInput \n\
value=\"%d\" name=max_size />&nbsp;<B>G</B>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
(%.1lf&nbsp;M)</SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=title /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=real_name /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=nickname /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=tel /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=cell /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=homeaddress /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=memo /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
%s</SPAN><INPUT type=hidden name=privilege_bits /></TD>"

#define HTML_EDIT_7_2 \
"<TR class=%s><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=8 class=RightInput \n\
value=\"%d\" name=max_size />&nbsp;<B>G</B>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
(%d&nbsp;K)</SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=title /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=real_name /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=nickname /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=tel /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=cell /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=homeaddress /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=memo /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
%s</SPAN><INPUT type=hidden name=privilege_bits /></TD>"

#define HTML_ADD_8 \
"<TD><INPUT value=\"    %s    \" type=submit \n\
onclick=\"if (0 == addform.username.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addform.username.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var apos=addform.username.value.indexOf('@');\n\
var regstr=/^[\\.\\-_A-Za-z0-9]+@([-_A-Za-z0-9]+\\.)+[A-Za-z0-9]{2,6}$/;\n\
if (0 == apos) {\n\
	alert('%s');\n\
	return false;\n\
} else if (apos > 0) {\n\
	if (addform.username.value.substring(apos, \n\
	addform.username.value.length).toLowerCase() != '@%s'.toLowerCase()) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
	if (!regstr.test(addform.username.value)) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
} else {\n\
	var addressstr = username.value + '@%s';\n\
	if (!regstr.test(addressstr)) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (0 == addform.new_password.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addform.new_password.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addform.new_password.value != addform.retype_password.value) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var num = parseInt(addform.max_size.value);\n\
if (isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addform.title.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addform.real_name.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addform.memo.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var mask_string='';\n\
if (pop3_imap.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (smtp.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (chgpasswd.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (pubaddr.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (netdisk.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
addform.privilege_bits.value = mask_string;\n\
return true;\" /></TD></TR></FORM><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><TABLE border=0><TBODY><TR><TD>\n\
<INPUT type=checkbox name=pop3_imap checked value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=smtp checked value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=chgpasswd checked value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=pubaddr checked value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=netdisk checked %s value=\"on\" />%s</TD><TD></TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_EDIT_8 \
"<TD><INPUT value=\"    %s    \" type=submit %s \n\
onclick=\"if (0 == editform.new_password.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (editform.new_password.value.length > 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (editform.new_password.value != editform.retype_password.value) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var num = parseInt(editform.max_size.value);\n\
if (isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (editform.title.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (editform.real_name.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (editform.memo.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var mask_string='';\n\
if (pop3_imap.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (smtp.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (chgpasswd.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (pubaddr.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
if (netdisk.checked == true) {\n\
    mask_string += '1';\n\
} else {\n\
    mask_string += '0';\n\
}\n\
editform.privilege_bits.value = mask_string;\n\
return true;\" /></TD></TR></FORM><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><TABLE border=0><TBODY><TR><TD>\n\
<INPUT type=checkbox name=pop3_imap %s value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=smtp %s value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=chgpasswd %s value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=pubaddr %s value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=netdisk %s %s value=\"on\" />%s</TD><TD></TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

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

#define HTML_PAGE_OK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><FORM class=SearchForm method=get action=\"%s\">\n\
<INPUT type=hidden value=\"%s\" name=group />\n\
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=hidden value=paging name=\"type\" />\n\
<INPUT type=hidden value=%d name=\"index\" />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_ADD_OK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><FORM class=SearchForm method=get action=\"%s\">\n\
<INPUT type=hidden value=\"%s\" name=group />\n\
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=hidden value=add name=\"type\" />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_ALIAS_OK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><FORM class=SearchForm method=get action=\"%s\">\n\
<INPUT type=hidden value=\"%s\" name=group />\n\
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=hidden value=alias name=\"type\" />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>"

#define HTML_TBITEM     \
"<TR class=%s><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%dG&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"javascript:EditItem('%s')\">%s</A>&nbsp;|&nbsp;\n\
<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_EX     \
"<TR class=%s><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%dG&nbsp;(%.1lfM)&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"javascript:EditItem('%s')\">%s</A>&nbsp;|&nbsp;\n\
<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_DELETED	\
"<TR class=ItemDeleted><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%dG&nbsp;</TD><TD></TD></TR>\n"

#define SELECT_OPTION		"<OPTION value=%d>%s</OPTION>"

#define SELECT_OPTION_EX	"<OPTION value=%d selected>%s</OPTION>"

#define LANG_OPTION		"<OPTION value='%s'>%s</OPTION>"

#define LANG_OPTION_EX	"<OPTION value='%s' selected>%s</OPTION>"

#define CSS_ITEMODD			"ItemOdd"

#define CSS_ITEMEVEN		"ItemEven"

#define CSS_ITEM_SUSPEND	"ItemSuspend"

#define CSS_ITEM_OVERQUOTA	"ItemOverquota"

#define OPTION_DISABLED			"disabled"

#define OPTION_ENABLED			""

#define OPTION_SELECTED			"selected"

#define OPTION_UNSELECTED		""

#define OPTION_CHECKED			"checked"

#define OPTION_UNCHECKED		""

#define ITEMS_PER_PAGE          50

#define VDIR_PER_PARTITION      200

#define MAILDIR_PER_VDIR        250

#define DIGEST_BUFLEN           256

#define GROUP_PRIVILEGE_ACCOUNT 0x8

#define DEF_MODE                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _AREA_ITEM {
	char type[12];
	char master[256];
	char slave[256];
	int space;
	int files;
} AREA_ITEM;

typedef struct _AREA_NODE {
	DOUBLE_LIST_NODE node;
	char master[256];
	char database[256];
	char slave[256];
	int max_space;
	int used_space;
	int used_files;
	int homes;
} AREA_NODE;

static void list_ui_error_html(const char *error_string);

static void list_ui_search_html(const char *groupname, const char *session);

static void list_ui_add_html(const char *groupname, const char *session);

static void list_ui_alias_html(const char *groupname, const char *session);

static void list_ui_add_ok_html(const char *groupname,
	const char *session, const char *username);

static void list_ui_remove_ok_html(const char *groupname,
	const char *session, int page_index);

static void list_ui_alias_ok_html(const char *groupname,
	const char *session);

static void list_ui_edit_ok_html(const char *groupname,
	const char *session, int page_index);

static void list_ui_add_error_html(const char *error_string);

static void list_ui_alias_error_html(const char *error_string);

static void list_ui_edit_error_html(const char *error_string);

static void list_ui_edit_html(const char *groupname,
	const char *session, const char *username);

static void list_ui_result_html(const char *groupname, const char *session,
	const char *username, int size_min, int size_max, const char *title,
	const char *real_name, const char *nickname, const char *tel,
	const char *cell, const char *homeaddress, const char *memo,
	time_t create_min, time_t create_max, int address_status,
	int address_type);

static void list_ui_page_html(const char *groupname,
	const char *session, int page_index);

static void list_ui_page_ex_html(const char *groupname,
	const char *session, int page_index);

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_encode_squote(const char *in, char *out);

static void list_ui_partition_info(char *s,
	int *pmegas, int *pfiles, int *phomes);

static void list_ui_remove_inode(const char *path);

static unsigned int list_ui_cache_result(const char *groupname,
	const char *session, const char *username, int size_min,
	int size_max, const char *title, const char *real_name,
	const char *nickname, const char *tel, const char *cell,
	const char *homeaddress, const char *memo, time_t create_min,
	time_t create_max, int address_status, int address_type);

static BOOL list_ui_cache_retrieve(const char *groupname,
	const char *session, const char *username, USER_ITEM *pitem);

static unsigned int list_ui_cache_edit(const char *groupname,
	const char *session, const char *username, int max_size,
	const char *title, const char *real_name, const char *nickname,
	const char *tel, const char *cell, const char *homeaddress,
	const char *memo, int privilege_bits, int address_status);

static unsigned int list_ui_cache_delete(const char *groupname,
	const char *session, const char *username);

static void list_ui_update_extpasscfg(const char *maildir, int extpasswd_type);

static BOOL list_ui_allocate_dir(const char *media_area, char *path_buff);

static void list_ui_free_dir(BOOL b_media, const char *maildir);

static void list_ui_from_utf8(char *src, char *dst, size_t len);

static void list_ui_to_utf8(const char *src, char *dst, size_t len);

static char g_logo_link[1024];
static char g_list_path[256];
static int g_max_file;
static char g_resource_path[256];
static char g_thumbnail_path[256];
static LANG_RESOURCE *g_lang_resource;

void list_ui_init(const char *list_path, int max_file,
	const char *url_link, const char *resource_path,
	const char *thumbnail_path)
{
	g_max_file = max_file;
	strcpy(g_list_path, list_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
	strcpy(g_thumbnail_path, thumbnail_path);
}

int list_ui_run()
{
	BOOL b_alias;
	int sub_type;
	BOOL b_migrating;
	struct tm temp_tm;
	struct stat node_stat;
	char *pat, *language;
	char *query, *request;
	const char *pvalue;
	char *pdomain;
	const char *type;
	const char *groupname;
	const char *session;
	const char *title;
	char new_title[128];
	const char *real_name;
	char new_name[128];
	const char *nickname;
	char new_nick[128];
	const char *tel;
	char new_tel[64];
	const char *cell;
	char new_cell[64];
	const char *homeaddress;
	char new_home[128];
	const char *memo;
	const char *lang;
	char new_memo[128];
	char username[256];
	char maildir[128];
	char mediadir[128];
	char path_buff[256];
	char media_area[128];
	char aliasname[256];
	const char *new_password;
	const char *retype_password;
	char encrypt_pw[40];
	char post_buff[4096];
	uint64_t tmp_int64;
	int size_min, size_max;
	int max_size, temp_size;
	int address_type, lockd;
	int address_status, result;
	int page_index;
	int total_users;
	int user_id, fd;
	int extpasswd_type;
	int privilege_bits;
	time_t create_min;
	time_t create_max;
	time_t create_day;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	REQUEST_PARSER *pparser;
	DATA_COLLECT *pcollection;
	USER_ITEM *pitem, temp_item;
	TAGGED_PROPVAL propval_buff[2];
	
	
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
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 4096, stdin)) {
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		pparser = request_parser_init(post_buff);
		groupname = request_parser_get(pparser, "group");
		if (NULL == groupname) {
			goto POST_ERROR;
		}
		pdomain = strchr(groupname, '@');
		if (NULL == pdomain) {
			goto POST_ERROR;
		}
		pdomain ++;
		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			goto POST_ERROR;
		}
		if (FALSE == session_client_check(groupname, session)) {
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_SESSION", language));
			return 0;
		}
		type = request_parser_get(pparser, "type");
		if (NULL == type) {
			goto POST_ERROR;
		}
		data_source_info_group(groupname, &privilege_bits);

		if ((privilege_bits&GROUP_PRIVILEGE_ACCOUNT) == 0) {
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_PRIVILEGE", language));
			return 0;
		}
		pvalue = request_parser_get(pparser, "username");
		if (NULL == pvalue || strlen(pvalue) >= sizeof(username)) {
			goto POST_ERROR;
		}
		strcpy(username, pvalue);
		pat = strchr(username, '@');
		if (NULL == pat) {
			strcat(username, "@");
			strcat(username, pdomain);
		} else {
			if (pat == username || 0 != strcasecmp(pat + 1, pdomain)) {
				goto POST_ERROR;
			}
		}
		if (0 == strcasecmp(type, "search")) {
			pvalue = request_parser_get(pparser, "address_status");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			address_status = atoi(pvalue);
			pvalue = request_parser_get(pparser, "address_type");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			address_type = atoi(pvalue);
			pvalue = request_parser_get(pparser, "size_min");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			size_min = atoi(pvalue)*1024;
			pvalue = request_parser_get(pparser, "size_max");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			size_max = atoi(pvalue)*1024;
			title = request_parser_get(pparser, "title");
			if (NULL == title) {
				goto POST_ERROR;
			}
			real_name = request_parser_get(pparser, "real_name");
			if (NULL == real_name) {
				goto POST_ERROR;
			}
			nickname = request_parser_get(pparser, "nickname");
			if (NULL == nickname) {
				goto POST_ERROR;
			}
			tel = request_parser_get(pparser, "tel");
			if (NULL == tel) {
				goto POST_ERROR;
			}
			cell = request_parser_get(pparser, "cell");
			if (NULL == cell) {
				goto POST_ERROR;
			}
			homeaddress = request_parser_get(pparser, "homeaddress");
			if (NULL == homeaddress) {
				goto POST_ERROR;
			}
			memo = request_parser_get(pparser, "memo");
			if (NULL == memo) {
				goto POST_ERROR;
			}
			pvalue = request_parser_get(pparser, "create_min");
			if (NULL == pvalue) {
				create_min = 0;
			} else {
				memset(&temp_tm, 0, sizeof(temp_tm));
				if (NULL != strptime(pvalue, "%Y-%m-%d", &temp_tm)) {
					create_min = mktime(&temp_tm);
				} else {
					create_min = 0;
				}
			}
			pvalue = request_parser_get(pparser, "create_max");
			if (NULL == pvalue) {
				create_max = 0;
			} else {
				memset(&temp_tm, 0, sizeof(temp_tm));
				if (NULL != strptime(pvalue, "%Y-%m-%d", &temp_tm)) {
					create_max = mktime(&temp_tm);
				} else {
					create_max = 0;
				}
			}
			list_ui_result_html(groupname, session, username, size_min,
				size_max, title, real_name, nickname, tel, cell, homeaddress,
				memo, create_min, create_max, address_status, address_type);
			return 0;
		} else if (0 == strcasecmp(type, "add") ||
			0 == strcasecmp(type, "edit")) { 
			new_password = request_parser_get(pparser, "new_password");
			if (NULL == new_password) {
				goto POST_ERROR;
			}
			retype_password = request_parser_get(pparser, "retype_password");
			if (NULL == retype_password) {
				goto POST_ERROR;
			}
			pvalue = request_parser_get(pparser, "extpass_type");
			if (NULL == pvalue) {
				extpasswd_type = 0;
			} else {
				extpasswd_type = atoi(pvalue);
			}
			pvalue = request_parser_get(pparser, "address_status");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			address_status = atoi(pvalue);
			lang = request_parser_get(pparser, "lang");
			if (0 == strcasecmp(type, "add") && NULL == lang) {
				goto POST_ERROR;
			}
			pvalue = request_parser_get(pparser, "max_size");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			max_size = atoi(pvalue)*1024;
			title = request_parser_get(pparser, "title");
			if (NULL == title) {
				goto POST_ERROR;
			}
			real_name = request_parser_get(pparser, "real_name");
			if (NULL == real_name) {
				goto POST_ERROR;
			}
			nickname = request_parser_get(pparser, "nickname");
			if (NULL == nickname) {
				goto POST_ERROR;
			}
			tel = request_parser_get(pparser, "tel");
			if (NULL == tel) {
				goto POST_ERROR;
			}
			cell = request_parser_get(pparser, "cell");
			if (NULL == cell) {
				goto POST_ERROR;
			}
			homeaddress = request_parser_get(pparser, "homeaddress");
			if (NULL == homeaddress) {
				goto POST_ERROR;
			}
			memo = request_parser_get(pparser, "memo");
			if (NULL == memo) {
				goto POST_ERROR;
			}
			pvalue = request_parser_get(pparser, "privilege_bits");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			privilege_bits = 0;
			if ('1' == pvalue[0]) {
				privilege_bits |= USER_PRIVILEGE_POP3_IMAP;
			}
			if ('1' == pvalue[1]) {
			    privilege_bits |= USER_PRIVILEGE_SMTP;
			}
			if ('1' == pvalue[2]) {
			    privilege_bits |= USER_PRIVILEGE_CHGPASSWD;
			}
			if ('1' == pvalue[3]) {
			    privilege_bits |= USER_PRIVILEGE_PUBADDR;
			}
			if ('1' == pvalue[4]) {
			    privilege_bits |= USER_PRIVILEGE_NETDISK;
			}
			if (0 == strcasecmp(type, "add")) {
				pvalue = request_parser_get(pparser, "sub_type");
				if (NULL == pvalue) {
					goto POST_ERROR;
				}
				sub_type = atoi(pvalue);
				if (sub_type < 0 || sub_type > 2) {
					goto POST_ERROR;
				}
				if (TRUE == data_source_check_domain_migration(pdomain,
					&b_migrating, media_area) && TRUE == b_migrating) {
					list_ui_error_html(lang_resource_get(
						g_lang_resource, "ERROR_MIGRATING", language));
					return;
				}
				if (FALSE == list_ui_allocate_dir(NULL, maildir)) {
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_MAILDIR", language));
					return 0;
				}
				if ('\0' != media_area[0]) {
					if (FALSE == list_ui_allocate_dir(media_area, mediadir)) {
						list_ui_free_dir(FALSE, maildir);
						list_ui_add_error_html(lang_resource_get(
							g_lang_resource, "ADD_ERROR_MAILDIR", language));
						return 0;
					}
				}
				if (0 != strcmp(new_password, "NO")) {
					strcpy(encrypt_pw, md5_crypt_wrapper(new_password));
				} else {
					encrypt_pw[0] = '\0';
				}
				list_ui_to_utf8(title, new_title, 128);
				list_ui_to_utf8(real_name, new_name, 128);
				list_ui_to_utf8(nickname, new_nick, 128);
				list_ui_to_utf8(tel, new_tel, 64);
				list_ui_to_utf8(cell, new_cell, 64);
				list_ui_to_utf8(homeaddress, new_home, 128);
				list_ui_to_utf8(memo, new_memo, 128);
				if (FALSE == data_source_add_user(groupname, username,
					encrypt_pw, new_title, new_name, new_nick, new_tel,
					new_cell, new_home, new_memo, maildir, max_size,
					g_max_file, privilege_bits, address_status,
					sub_type, &result, &user_id)) {
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_error_html(lang_resource_get(
						g_lang_resource, "ERROR_INTERNAL", language));
					return 0;
				}
				switch (result) {
				case ADD_RESULT_OK:
					if ('\0' != media_area[0]) {
						list_ui_remove_inode(maildir);
						symlink(mediadir, maildir);
					}
					 if (FALSE == exmdb_tool_create(maildir,
						((uint64_t)max_size)*1024, lang, user_id) ||
						FALSE == midb_tool_create(maildir, username)) {
						list_ui_free_dir(FALSE, maildir);
						if ('\0' != media_area[0]) {
							list_ui_free_dir(TRUE, mediadir);
						}
						data_source_remove_user(groupname,
									username, NULL, NULL);
						system_log_info("[list_ui]: fail to "
							"create sqlite database under %s", maildir);
						list_ui_error_html(lang_resource_get(
							g_lang_resource, "ERROR_INTERNAL", language));
						return 0;
					}
					if (0 != extpasswd_type) {
						list_ui_update_extpasscfg(maildir, extpasswd_type);
					}
					list_ui_add_ok_html(groupname, session, username);
					break;
				case ADD_RESULT_NOGROUP:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_NOGROUP", language));
					break;
				case ADD_RESULT_GROUPSIZEFULL:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_GROUPSIZEFULL", language));
					break;
				case ADD_RESULT_GROUPUSERFULL:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_GROUPUSERFULL", language));
					break;
				case ADD_RESULT_NODOMAIN:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_NODOMAIN", language));
					break;	
				case ADD_RESULT_DOMAINNOTMAIN:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_DOMAINNOTMAIN", language));
					break;
				case ADD_RESULT_DOMAINSIZEFULL:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_DOMAINSIZEFULL", language));
					break;
				case ADD_RESULT_DOMAINUSERFULL:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_DOMAINUSERFULL", language));
					break;
				case ADD_RESULT_MLIST:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_MLIST", language));
					break;
				case ADD_RESULT_EXIST:
					list_ui_free_dir(FALSE, maildir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_error_html(lang_resource_get(
						g_lang_resource, "ADD_ERROR_EXIST", language));
					break;
				}
			} else {
				if (FALSE == list_ui_cache_retrieve(groupname,
					session, username, &temp_item)) {
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_NOCACHE", language));
					return 0;
				}
				if (0 != strcmp(new_password, "none-change-password")) {
					strcpy(encrypt_pw, md5_crypt_wrapper(new_password));
				} else {
					encrypt_pw[0] = '\0';
				}
				list_ui_to_utf8(title, new_title, 128);
				list_ui_to_utf8(real_name, new_name, 128);
				list_ui_to_utf8(nickname, new_nick, 128);
				list_ui_to_utf8(tel, new_tel, 64);
				list_ui_to_utf8(cell, new_cell, 64);
				list_ui_to_utf8(homeaddress, new_home, 128);
				list_ui_to_utf8(memo, new_memo, 128);
				if (FALSE == data_source_edit_user(groupname, username,
					encrypt_pw, new_title, new_name, new_nick, new_tel,
					new_cell, new_home, new_memo, max_size, privilege_bits,
					address_status, &result)) {
					list_ui_error_html(lang_resource_get(
						g_lang_resource, "ERROR_INTERNAL", language));
					return 0;
				}
				switch (result) {
				case EDIT_RESULT_OK:
					pcollection = data_source_collect_init();
					if (NULL != pcollection) {
						data_source_get_aliases(username, pcollection);
						for (data_source_collect_begin(pcollection);
							!data_source_collect_done(pcollection);
							data_source_collect_forward(pcollection)) {
							pitem = data_source_collect_get_value(pcollection);
							list_ui_cache_edit(groupname, session,
								pitem->username, max_size, title, real_name,
								nickname, tel, cell, homeaddress, memo,
								privilege_bits, address_status);
						}
					}
					data_source_collect_free(pcollection);
					
					page_index = list_ui_cache_edit(groupname, session,
									username, max_size, title, real_name,
									nickname, tel, cell, homeaddress, memo,
									privilege_bits, address_status);
					if (TRUE == data_source_get_user_maildir(
						username, maildir)) {
						if (temp_item.max_size != max_size) {
							tmp_int64 = max_size*1024;
							propvals.count = 2;
							propvals.ppropval = propval_buff;
							propval_buff[0].proptag = PROP_TAG_PROHIBITRECEIVEQUOTA;
							propval_buff[0].pvalue = &tmp_int64;
							propval_buff[1].proptag = PROP_TAG_PROHIBITSENDQUOTA;
							propval_buff[1].pvalue = &tmp_int64;
							exmdb_client_set_store_properties(
								maildir, 0, &propvals, &problems);
						}
						list_ui_update_extpasscfg(maildir, extpasswd_type);
					}
					list_ui_edit_ok_html(groupname, session, page_index);
					break;
				case EDIT_RESULT_NOGROUP:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_NOGROUP", language));
					break;
				case EDIT_RESULT_NODOMAIN:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_NODOMAIN", language));
					break;
				case EDIT_RESULT_DOMAINNOTMAIN:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_DOMAINNOTMAIN", language));
					break;
				case EDIT_RESULT_NOEXIST:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_NOEXIST", language));
					break;
				case EDIT_RESULT_GROUPERR:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_GROUPERR", language));
					break;
				case EDIT_RESULT_GROUPSIZEFULL:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_GROUPSIZEFULL", language));
					break;
				case EDIT_RESULT_DOMAINSIZEFULL:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_DOMAINSIZEFULL", language));
					break;
				case EDIT_RESULT_NOTMAIN:
					list_ui_edit_error_html(lang_resource_get(
						g_lang_resource, "EDIT_ERROR_NOTMAIN", language));
					break;
				}
			}
			return 0;
		} else if (0 == strcasecmp(type, "alias")) {
			pvalue = request_parser_get(pparser, "aliasname");
			if (NULL == pvalue) {
				goto POST_ERROR;
			}
			strcpy(aliasname, pvalue);
			pat = strchr(aliasname, '@');
			if (NULL == pat) {
				strcat(aliasname, "@");
				strcat(aliasname, pdomain);
			} else {
				if (pat == aliasname || 0 != strcasecmp(pat + 1, pdomain)) {
					goto POST_ERROR;
				}
			}
			if (FALSE == data_source_add_alias(groupname,
				username, aliasname, &result)) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_INTERNAL", language));
				return 0;
			}
			switch (result) {
			case ALIAS_RESULT_OK:
				list_ui_alias_ok_html(groupname, session);
				break;
			case ALIAS_RESULT_NOGROUP:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_NOGROUP", language));
				break;
			case ALIAS_RESULT_NODOMAIN:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_NODOMAIN", language));
				break;
			case ALIAS_RESULT_DOMAINNOTMAIN:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_DOMAINNOTMAIN", language));
				break;
			case  ALIAS_RESULT_FULL:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_FULL", language));
				break;
			case ALIAS_RESULT_MLIST:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_MLIST", language));
				break;
			case ALIAS_RESULT_EXIST:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_EXIST", language));
				break;
			case ALIAS_RESULT_NOEXIST:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_NOEXIST", language));
				break;
			case ALIAS_RESULT_GROUPERR:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_GROUPERR", language));
				break;
			case ALIAS_RESULT_NOTMAIN:
				list_ui_alias_error_html(lang_resource_get(
					g_lang_resource, "ALIAS_ERROR_NOTMAIN", language));
				break;
			}
			return 0;
		} else {
			goto POST_ERROR;
		}
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[list_ui]: fail to get QUERY_STRING environment!");
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_REQUEST", language));
			return 0;
		}
		pparser = request_parser_init(query);
		groupname = request_parser_get(pparser, "group");
		if (NULL == groupname) {
			goto GET_ERROR;
		}
		pdomain = strchr(groupname, '@');
		if (NULL == pdomain) {
			goto GET_ERROR;
		}
		pdomain ++;
		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			goto GET_ERROR;
		}
		if (FALSE == session_client_check(groupname, session)) {
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_SESSION", language));
			return 0;
		}
		type = request_parser_get(pparser, "type");
		if (NULL == type) {	
			data_source_info_group(groupname, &privilege_bits);
			if ((privilege_bits&GROUP_PRIVILEGE_ACCOUNT) == 0) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_PRIVILEGE", language));
				return 0;
			}
			if (FALSE == data_source_num_user(groupname, &total_users)) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_INTERNAL", language));
				return 0;
			}
			if (total_users <= 10000) {
				list_ui_result_html(groupname, session, "", 0,
					0, "", "", "", "", "", "", "", 0, 0, -1, -1);
			} else {
				list_ui_search_html(groupname, session);
			}
			return 0;
		}
		data_source_info_group(groupname, &privilege_bits);

		if ((privilege_bits&GROUP_PRIVILEGE_ACCOUNT) == 0) {
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_PRIVILEGE", language));
			return 0;
		}
		pvalue = request_parser_get(pparser, "username");
		if (NULL != pvalue) {
			strcpy(username, pvalue);
			pat = strchr(username, '@');
			if (NULL == pat) {
				strcat(username, "@");
				strcat(username, pdomain);
			} else {
				if (pat == username || 0 != strcasecmp(pat + 1, pdomain)) {
					goto POST_ERROR;
				}
			}
			if (0 == strcasecmp(type, "edit")) {
				list_ui_edit_html(groupname, session, username);
			} else if (0 == strcasecmp(type, "remove")) {
				if (TRUE == data_source_check_domain_migration(pdomain,
					&b_migrating, NULL) && TRUE == b_migrating) {
					list_ui_error_html(lang_resource_get(
						g_lang_resource, "ERROR_MIGRATING", language));
					return;
				}
				pcollection = data_source_collect_init();
				if (NULL == pcollection) {
					system_log_info("[list_ui]: fail to create "
							"collection object for remove user");
					list_ui_error_html(lang_resource_get(
						g_lang_resource, "ERROR_INTERNAL", language));
					return 0;
				}
				if (FALSE == data_source_get_user_maildir(username,
					path_buff) || FALSE == data_source_remove_user(
					groupname, username, &b_alias, pcollection)) {
					data_source_collect_free(pcollection);
					list_ui_error_html(lang_resource_get(
						g_lang_resource, "ERROR_INTERNAL", language));
					return 0;
				}
				if (FALSE == b_alias) {
					data_source_get_aliases(username, pcollection);
					for (data_source_collect_begin(pcollection);
						!data_source_collect_done(pcollection);
						data_source_collect_forward(pcollection)) {
						pitem = data_source_collect_get_value(pcollection);
						list_ui_cache_delete(groupname,
							session, pitem->username);
					}
					exmdb_client_unload_store(path_buff);
					if (0 == lstat(path_buff, &node_stat) &&
						0 != S_ISLNK(node_stat.st_mode)) {
						memset(mediadir, 0, 128);
						if (readlink(path_buff, mediadir, 128) > 0) {
							list_ui_free_dir(TRUE, mediadir);
							remove(path_buff);
							mkdir(path_buff, 0777);
						}
					}
					list_ui_free_dir(FALSE, path_buff);
				}
				data_source_collect_free(pcollection);
				page_index = list_ui_cache_delete(
					groupname, session, username);
				list_ui_remove_ok_html(groupname, session, page_index);
			} else {
				goto GET_ERROR;
			}
			return 0;
		}
		pvalue = request_parser_get(pparser, "index");
		if (NULL != pvalue) {
			page_index = atoi(pvalue);
			if (page_index < 1) {
				goto GET_ERROR;
			}
			if (0 == strcasecmp(type, "paging")) {
				list_ui_page_html(groupname, session, page_index);
			} else if (0 == strcasecmp(type, "paging-ex")) {
				list_ui_page_ex_html(groupname, session, page_index);
			} else {
				goto GET_ERROR;
			}
			return 0;
		}
		if (0 == strcasecmp(type, "add")) {
			if (TRUE == data_source_check_domain_migration(pdomain,
				&b_migrating, NULL) && TRUE == b_migrating) {
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_MIGRATING", language));
			} else {
				list_ui_add_html(groupname, session);
			}
		} else if (0 == strcasecmp(type, "alias")) {
			list_ui_alias_html(groupname, session);
		} else if (0 == strcasecmp(type, "search")) {
			list_ui_search_html(groupname, session);
		} else if (0 == strcasecmp(type, "list")) {
			list_ui_result_html(groupname, session, "", 0,
				0, "", "", "", "", "", "", "", 0, 0, -1, -1);
		} else {
			goto GET_ERROR;
		}
		return 0;
	} else {
		system_log_info("[list_ui]: unrecognized"
			" REQUEST_METHOD \"%s\"!", request);
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return 0;
	}
GET_ERROR:
	system_log_info("[list_ui]: query string of GET format error");
	list_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_REQUEST", language));
	return 0;
POST_ERROR:
	system_log_info("[list_ui]: query string of POST format error");
	list_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_REQUEST", language));
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
	printf(HTML_ERROR_5, lang_resource_get(
		g_lang_resource, "BACK_LABEL", language),
		error_string);
}

static void list_ui_add_ok_html(const char *groupname,
	const char *session, const char *username)
{
	char *language;
	char url_buff[1024];

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ADDING_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ADDING_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ADD_OK_5, lang_resource_get(g_lang_resource,
		"ADDING_OK", language), url_buff, groupname, session,
		lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_edit_ok_html(const char *groupname,
	const char *session, int page_index)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
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
	printf(HTML_PAGE_OK_5, lang_resource_get(g_lang_resource,
		"EDIT_OK", language), url_buff, groupname, session, page_index,
		lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_add_error_html(const char *error_string)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
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
	printf(HTML_BACK_5, error_string, lang_resource_get(
		g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_alias_error_html(const char *error_string)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, error_string, lang_resource_get(
		g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_alias_ok_html(const char *groupname, const char *session)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ALIAS_OK_5, lang_resource_get(g_lang_resource,
		"ALIAS_OK", language), url_buff, groupname, session,
		lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_edit_error_html(const char *error_string)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
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
	printf(HTML_BACK_5, error_string, lang_resource_get(
		g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_remove_ok_html(const char *groupname,
	const char *session, int page_index)
{
	char *language;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_PAGE_OK_5, lang_resource_get(g_lang_resource,
		"REMOVE_OK", language), url_buff, groupname, session,
		page_index, lang_resource_get(g_lang_resource,
		"OK_LABEL", language));
}

static void list_ui_add_html(const char *groupname, const char *session)
{
	char *ptr;
	char *ptr1;
	char *ptr2;
	char *langs;
	BOOL b_first;
	int privilege;
	char *pdomain;
	char *language;
	char randpasswd[10];
	char url_buff[1024];
	char url_list[1280];
	char url_alias[1280];
	char url_search[1280];
	char option_domain[16];
	const char *str_default;
	
	
	pdomain = strchr(groupname, '@') + 1;
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}

	if (FALSE == data_source_get_domain_privilege(pdomain, &privilege)) {
		list_ui_error_html(lang_resource_get(
		g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	
	randstring(randpasswd, 8);
	sprintf(url_search, "%s?group=%s&session=%s&type=search", url_buff,
		groupname, session);
	sprintf(url_alias, "%s?group=%s&session=%s&type=alias", url_buff,
		groupname, session);
	sprintf(url_list, "%s?group=%s&session=%s&type=list", url_buff,
		groupname, session);
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
	printf(HTML_ADD_5, url_search, lang_resource_get(g_lang_resource,
		"SEARCH_LABEL", language), url_alias, lang_resource_get(
		g_lang_resource, "ALIAS_LABEL", language), url_list,
		lang_resource_get(g_lang_resource,"WHOLE_LIST", language));
	printf(url_buff);
	if (privilege & DOMAIN_PRIVILEGE_EXTPASSWD) {
		strcpy(option_domain, OPTION_ENABLED);
		str_default = lang_resource_get(g_lang_resource,
					"PASSWORD_AGING_DEFAULT", language);
	} else {
		strcpy(option_domain, OPTION_DISABLED);
		str_default = lang_resource_get(g_lang_resource,
						"PASSWORD_AGING_NEVER", language);
	}
	printf(HTML_ADD_6, groupname, session,
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_PASSWORD", language), randpasswd,
		lang_resource_get(g_lang_resource,"MAIN_RAND", language), randpasswd,
		lang_resource_get(g_lang_resource,"MAIN_RETYPE", language), randpasswd,
		lang_resource_get(g_lang_resource,"TIP_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MAIN_EXTPASS_TYPE", language), option_domain,
		str_default, lang_resource_get(g_lang_resource,"PASSWORD_AGING_NEVER", language),
		lang_resource_get(g_lang_resource,"PASSWORD_AGING_1YEAR", language),
		lang_resource_get(g_lang_resource,"PASSWORD_AGING_6MONTH", language),
		lang_resource_get(g_lang_resource,"PASSWORD_AGING_3MONTH", language),
		lang_resource_get(g_lang_resource,"PASSWORD_AGING_1MONTH", language),
		lang_resource_get(g_lang_resource, "MAIN_TYPE", language),
		lang_resource_get(g_lang_resource, "USER_TYPE_NORMAL", language),
		lang_resource_get(g_lang_resource, "USER_TYPE_ROOM", language),
		lang_resource_get(g_lang_resource, "USER_TYPE_EQUIPMENT", language),
		lang_resource_get(g_lang_resource,"MAIN_LANGUAGE", language));
	langs = (char*)lang_resource_get(g_lang_resource,
						"LANGUAGE_ITEMS", language);
	ptr = langs;
	b_first = FALSE;
	while (TRUE) {
		ptr2 = strchr(ptr, '|');
		if (NULL != ptr2) {
			*ptr2 = '\0';
			ptr2 ++;
		}
		ptr1 = strchr(ptr, ':');
		if (NULL == ptr1) {
			exit(-1);
		}
		*ptr1 = '\0';
		if (FALSE == b_first) {
			printf(LANG_OPTION_EX, ptr, ptr1 + 1);
			b_first = TRUE;
		} else {
			printf(LANG_OPTION, ptr, ptr1 + 1);
		}
		if (NULL == ptr2) {
			break;
		}
		ptr = ptr2;
	}
	printf(HTML_ADD_7, lang_resource_get(g_lang_resource,"MAIN_ADDRESS_STATUS",
		language), lang_resource_get(g_lang_resource,"STATUS_NORMAL", language),
		lang_resource_get(g_lang_resource,"STATUS_SUSPEND", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource,"MAIN_USER_TITLE", language),
		lang_resource_get(g_lang_resource,"MAIN_REAL_NAME", language),
		lang_resource_get(g_lang_resource,"MAIN_NICKNAME",language),
		lang_resource_get(g_lang_resource,"MAIN_TEL", language),
		lang_resource_get(g_lang_resource,"MAIN_CELL", language),
		lang_resource_get(g_lang_resource,"MAIN_HOMEADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language));

	if (privilege & DOMAIN_PRIVILEGE_NETDISK) {
		strcpy(option_domain, OPTION_ENABLED);
	} else {
		strcpy(option_domain, OPTION_DISABLED);
	}

	printf(HTML_ADD_8, lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_USERNAME", language),
		lang_resource_get(g_lang_resource,"MSGERR_USERNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_USERNAME", language), pdomain,
		lang_resource_get(g_lang_resource,"MSGERR_DOMAINDIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language), pdomain,
		lang_resource_get(g_lang_resource,"MSGERR_LOCALERR", language),
		lang_resource_get(g_lang_resource,"MSGERR_NULL_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_DIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),	
		lang_resource_get(g_lang_resource,"MSGERR_REALNAME_LEN", language),	
		lang_resource_get(g_lang_resource,"MSGERR_MEMO_LEN", language),	
		lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language),
		lang_resource_get(g_lang_resource,"OPTION_POP3_IMAP", language),
		lang_resource_get(g_lang_resource,"OPTION_SMTP", language),
		lang_resource_get(g_lang_resource,"OPTION_CHGPASSWD", language),
		lang_resource_get(g_lang_resource,"OPTION_PUBADDR", language), option_domain,
		lang_resource_get(g_lang_resource,"OPTION_NETDISK", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_alias_html(const char *groupname, const char *session)
{
	char *pdomain;
	char *language;
	char url_buff[1024];
	char url_list[1280];
	char url_add[1280];
	char url_search[1280];
	
	pdomain = strchr(groupname, '@') + 1;
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	sprintf(url_search, "%s?group=%s&session=%s&type=search",
		url_buff, groupname, session);
	sprintf(url_add, "%s?group=%s&session=%s&type=add",
		url_buff, groupname, session);
	sprintf(url_list, "%s?group=%s&session=%s&type=list",
		url_buff, groupname, session);
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ALIAS_5, url_search, lang_resource_get(g_lang_resource,
		"SEARCH_LABEL", language), url_add, lang_resource_get(g_lang_resource,
		"ADD_LABEL", language), url_list, lang_resource_get(g_lang_resource,
		"WHOLE_LIST", language));
	printf(url_buff);
	printf(HTML_ALIAS_6, groupname, session,
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_ALIAS", language),
		lang_resource_get(g_lang_resource,"OK_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_USERNAME", language),
		lang_resource_get(g_lang_resource,"MSGERR_USERNAME_LEN", language), pdomain,
		lang_resource_get(g_lang_resource,"MSGERR_DOMAINDIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_ALIAS", language),
		lang_resource_get(g_lang_resource,"MSGERR_ALIAS_LEN", language), pdomain,
		lang_resource_get(g_lang_resource,"MSGERR_DOMAINDIFF", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_edit_html(const char *groupname, const char *session,
	const char *username)
{
	int fd;
	int i, len;
	int mb_files;
	char type[16];
	int privilege;
	char *pdomain;
	char *language;
	uint32_t proptag;
	uint64_t mb_size;
	char temp_path[256];
	char url_buff[1024];
	char temp_buff[1024];
	char create_buff[32];
	char class_size[16];
	char end_buff[32];
	char temp_user[128];
	char prompt[1024];
	char option_submit[16];
	char option_enabled[16];
	char option_disabled[16];
	char option_domain[16];
	char option_pop3_imap[16];
	char option_smtp[16];
	char option_chgpasswd[16];
	char option_pubaddr[16];
	char option_netdisk[16];
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	char* options_extpass[6] = {"","","","","",""};
	const char *str_default;
	struct tm temp_tm;
	int extpasswd_type;
	struct stat node_stat;
	USER_ITEM temp_item;
	
	
	pdomain = strchr(groupname, '@') + 1;
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	
	if (FALSE == list_ui_cache_retrieve(groupname,
		session, username, &temp_item)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return;
	}

	if (FALSE == data_source_get_domain_privilege(pdomain, &privilege)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}

	snprintf(temp_path, 256, "%s/config/extpasswd.cfg", temp_item.maildir);
	if (0 == stat(temp_path, &node_stat) && node_stat.st_size < sizeof(temp_buff)) {
		fd = open(temp_path, O_RDONLY);
		if (-1 != fd) {
			if (node_stat.st_size == read(fd, temp_buff, node_stat.st_size)) {
				temp_buff[node_stat.st_size] = '\0';
				if (TRUE == get_digest(temp_buff, "type", type, 16)) {
					extpasswd_type = atoi(type);
					if (extpasswd_type < 0 || extpasswd_type > 5) {
						extpasswd_type = 0;
					}
				} else {
					extpasswd_type = 0;
				}
			} else {
				extpasswd_type = 0;
			}
			close(fd);
		} else {
			extpasswd_type = 0;
		}
	} else {
		extpasswd_type = 0;
	}
	
	options_extpass[extpasswd_type] = "selected";
	
	len  = 0;
	prompt[0] = '\0';
	if (ADDRESS_TYPE_ALIAS == temp_item.address_type) {
		if (FALSE == data_source_get_username_by_alias(username, temp_user)) {
			list_ui_error_html(lang_resource_get(
				g_lang_resource, "ERROR_INTERNAL", language));
			return;
		}
		len = sprintf(prompt, lang_resource_get(
				g_lang_resource,"PROMPT_ALIAS",
				language), temp_user);
		strcpy(option_submit, OPTION_DISABLED);
	} else {
		if (SUB_TYPE_ROOM == temp_item.sub_type) {
			sprintf(prompt, lang_resource_get(g_lang_resource,
						"PROMPT_ROOM", language), temp_user);
		} else if (SUB_TYPE_EQUIPMENT == temp_item.sub_type) {
			sprintf(prompt, lang_resource_get(g_lang_resource,
					"PROMPT_EQUIPMENT", language), temp_user);
		}
		strcpy(option_submit, OPTION_ENABLED);
	}

	if (RECORD_STATUS_NORMAL == temp_item.address_status) {
		strcpy(option_enabled, OPTION_SELECTED);	
		strcpy(option_disabled, OPTION_UNSELECTED);
	} else {
		strcpy(option_enabled, OPTION_UNSELECTED);	
		strcpy(option_disabled, OPTION_SELECTED);
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
	printf(HTML_EDIT_5, lang_resource_get(g_lang_resource,
						"BACK_TO_LIST", language), prompt);
	printf(url_buff);
	if (privilege & DOMAIN_PRIVILEGE_EXTPASSWD) {
		strcpy(option_domain, OPTION_ENABLED);
		str_default = lang_resource_get(g_lang_resource,
					"PASSWORD_AGING_DEFAULT", language);
	} else {
		strcpy(option_domain, OPTION_DISABLED);
		str_default = lang_resource_get(g_lang_resource,
						"PASSWORD_AGING_NEVER", language);
	}
	printf(HTML_EDIT_6, groupname, session,
			lang_resource_get(g_lang_resource,"MAIN_USERNAME", language), username,
			lang_resource_get(g_lang_resource,"MAIN_PASSWORD", language),
			lang_resource_get(g_lang_resource,"MAIN_RETYPE", language),
			lang_resource_get(g_lang_resource,"MAIN_EXTPASS_TYPE", language),
			option_domain, options_extpass[0], str_default,
			options_extpass[1],
			lang_resource_get(g_lang_resource,"PASSWORD_AGING_NEVER", language),
			options_extpass[2],
			lang_resource_get(g_lang_resource,"PASSWORD_AGING_1YEAR", language),
			options_extpass[3],
			lang_resource_get(g_lang_resource,"PASSWORD_AGING_6MONTH", language),
			options_extpass[4],
			lang_resource_get(g_lang_resource,"PASSWORD_AGING_3MONTH", language),
			options_extpass[5],
			lang_resource_get(g_lang_resource,"PASSWORD_AGING_1MONTH", language),
			lang_resource_get(g_lang_resource,"MAIN_ADDRESS_STATUS", language), option_enabled,
			lang_resource_get(g_lang_resource,"STATUS_NORMAL", language), option_disabled,
			lang_resource_get(g_lang_resource,"STATUS_SUSPEND", language));
	
	localtime_r(&temp_item.create_day, &temp_tm);
	strftime(create_buff, 32, lang_resource_get(
		g_lang_resource, "DATE_FORMAT", language), &temp_tm);

	class_size[0] = '\0';

	proptags.count = 1;
	proptags.pproptag = &proptag;
	proptag = PROP_TAG_MESSAGESIZEEXTENDED;
	mb_size = 0;
	if (FALSE == exmdb_client_get_store_properties(
		temp_item.maildir, 0, &proptags, &propvals)
		|| 0 == propvals.count) {
		strcpy(class_size, CSS_ITEM_OVERQUOTA);
	} else {
		mb_size = *(uint64_t*)propvals.ppropval[0].pvalue;
		if (mb_size >= ((uint64_t)temp_item.max_size)*1024*1024) {
			strcpy(class_size, CSS_ITEM_OVERQUOTA);
		}
	}

	if (mb_size >= 1024*1024) {
		printf(HTML_EDIT_7_1, class_size, lang_resource_get(
			g_lang_resource,"MAIN_MAX_SIZE", language),
			temp_item.max_size/1024, ((double)mb_size)/(1024*1024),
			lang_resource_get(g_lang_resource,"MAIN_USER_TITLE", language), temp_item.title,
			lang_resource_get(g_lang_resource,"MAIN_REAL_NAME", language), temp_item.real_name,
			lang_resource_get(g_lang_resource,"MAIN_NICKNAME", language), temp_item.nickname,
			lang_resource_get(g_lang_resource,"MAIN_TEL", language), temp_item.tel,
			lang_resource_get(g_lang_resource,"MAIN_CELL", language), temp_item.cell,
			lang_resource_get(g_lang_resource,"MAIN_HOMEADDRESS", language), temp_item.homeaddress,
			lang_resource_get(g_lang_resource,"MAIN_MEMO", language), temp_item.memo,
			lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language), create_buff);
	} else {
		printf(HTML_EDIT_7_2, class_size,
			lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE",
			language), temp_item.max_size/1024, mb_size/1024,
			lang_resource_get(g_lang_resource,"MAIN_USER_TITLE", language), temp_item.title,
			lang_resource_get(g_lang_resource,"MAIN_REAL_NAME", language), temp_item.real_name,
			lang_resource_get(g_lang_resource,"MAIN_NICKNAME", language), temp_item.nickname,
			lang_resource_get(g_lang_resource,"MAIN_TEL", language), temp_item.tel,
			lang_resource_get(g_lang_resource,"MAIN_CELL", language), temp_item.cell,
			lang_resource_get(g_lang_resource,"MAIN_HOMEADDRESS", language), temp_item.homeaddress,
			lang_resource_get(g_lang_resource,"MAIN_MEMO", language), temp_item.memo,
			lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language), create_buff);
	}

	if (temp_item.privilege_bits & USER_PRIVILEGE_POP3_IMAP) {
		strcpy(option_pop3_imap, OPTION_CHECKED);
	} else {
		strcpy(option_pop3_imap, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & USER_PRIVILEGE_SMTP) {
		strcpy(option_smtp, OPTION_CHECKED);
	} else {
		strcpy(option_smtp, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & USER_PRIVILEGE_CHGPASSWD) {
		strcpy(option_chgpasswd, OPTION_CHECKED);
	} else {
		strcpy(option_chgpasswd, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & USER_PRIVILEGE_PUBADDR) {
		strcpy(option_pubaddr, OPTION_CHECKED);
	} else {
		strcpy(option_pubaddr, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & USER_PRIVILEGE_NETDISK) {
		strcpy(option_netdisk, OPTION_CHECKED);
	} else {
		strcpy(option_netdisk, OPTION_UNCHECKED);
	}

	if (privilege & DOMAIN_PRIVILEGE_NETDISK) {
		strcpy(option_domain, OPTION_ENABLED);
	} else {
		strcpy(option_domain, OPTION_DISABLED);
	}

	printf(HTML_EDIT_8, lang_resource_get(g_lang_resource,"SAVE_LABEL", language),
		option_submit, lang_resource_get(g_lang_resource,"MSGERR_NULL_PASSWORD", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_PASSWORD_DIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_REALNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_MEMO_LEN", language),
		lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language), option_pop3_imap,
		lang_resource_get(g_lang_resource,"OPTION_POP3_IMAP", language), option_smtp,
		lang_resource_get(g_lang_resource,"OPTION_SMTP", language), option_chgpasswd,
		lang_resource_get(g_lang_resource,"OPTION_CHGPASSWD", language), option_pubaddr,
		lang_resource_get(g_lang_resource,"OPTION_PUBADDR", language), option_netdisk,
		option_domain, lang_resource_get(g_lang_resource,"OPTION_NETDISK", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_search_html(const char *groupname, const char *session)
{
	int i, len;
	char *language;
	char *pdomain;
	char url_buff[1024];
	char url_add[1280];
	char url_list[1280];
	char url_alias[1280];
	
	pdomain = strchr(groupname, '@') + 1;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}

	sprintf(url_add, "%s?group=%s&session=%s&type=add",
		url_buff, groupname, session);
	sprintf(url_alias, "%s?group=%s&session=%s&type=alias",
		url_buff, groupname, session);
	sprintf(url_list, "%s?group=%s&session=%s&type=list",
		url_buff, groupname, session);
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_SEARCH_5,
		lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		url_add, lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		url_alias, lang_resource_get(g_lang_resource,"ALIAS_LABEL", language),
		url_list, lang_resource_get(g_lang_resource,"WHOLE_LIST", language));
	printf(url_buff);
	
	printf(HTML_SEARCH_6, groupname, session,
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_ADDRESS_STATUS", language),
		lang_resource_get(g_lang_resource,"OPTION_UNSELECTED", language),
		lang_resource_get(g_lang_resource,"STATUS_NORMAL", language),
		lang_resource_get(g_lang_resource,"STATUS_SUSPEND", language),
		lang_resource_get(g_lang_resource,"MAIN_ADDRESS_TYPE", language),
		lang_resource_get(g_lang_resource,"OPTION_UNSELECTED", language),
		lang_resource_get(g_lang_resource,"TYPE_NORMAL", language),
		lang_resource_get(g_lang_resource,"TYPE_ALIAS", language),
		lang_resource_get(g_lang_resource,"USER_TYPE_ROOM", language),
		lang_resource_get(g_lang_resource,"USER_TYPE_EQUIPMENT", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource,"MAIN_USER_TITLE", language),
		lang_resource_get(g_lang_resource,"MAIN_REAL_NAME", language),
		lang_resource_get(g_lang_resource,"MAIN_NICKNAME",language),
		lang_resource_get(g_lang_resource,"MAIN_TEL", language),
		lang_resource_get(g_lang_resource,"MAIN_CELL", language),
		lang_resource_get(g_lang_resource,"MAIN_HOMEADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_MEMO", language));

	printf(HTML_SEARCH_7,
		lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language),
		lang_resource_get(g_lang_resource,"SEARCH_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_USERNAME_LEN", language), pdomain,
		lang_resource_get(g_lang_resource,"MSGERR_DOMAINDIFF", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_REALNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_MEMO_LEN", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static unsigned int list_ui_cache_delete(const char *groupname,
	const char *session, const char *username)
{
	int i, fd, page_index;
	char *pat, *pdomain;
	char temp_path[256];
	char fake_group[256];
	char domain_path[256];
	char temp_address[256];
	USER_ITEM temp_item;

	pdomain = strchr(groupname, '@') + 1;
	strcpy(temp_address, username);
	pat = strchr(temp_address, '@');
	if (NULL == pat) {
		strcat(temp_address, "@");
		strcat(temp_address, pdomain);
	}
	page_index = 1;
	if (FALSE == data_source_get_domain_homedir(pdomain, domain_path)) {
		return page_index;
	}
	strcpy(fake_group, groupname);
	pat = strchr(fake_group, '@');
	*pat = '\0';
	sprintf(temp_path, "%s/%s/tmp/group_users.%s", domain_path, fake_group,
		session);
	fd = open(temp_path, O_RDWR, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		while (sizeof(temp_item) == read(fd, &temp_item, sizeof(temp_item))) {
			if (0 == strcasecmp(temp_item.username, temp_address)) {
				temp_item.address_status = RECORD_STATUS_DELETED;
				lseek(fd, -sizeof(USER_ITEM), SEEK_CUR);
				write(fd, &temp_item, sizeof(temp_item));
				page_index = i / ITEMS_PER_PAGE + 1;
				break;
			}
			i ++;
		}
		close(fd);
	}
	return page_index;
}

static unsigned int list_ui_cache_edit(const char *groupname,
	const char *session, const char *username, int max_size,
	const char *title, const char *real_name, const char *nickname,
	const char *tel, const char *cell, const char *homeaddress,
	const char *memo, int privilege_bits, int address_status)
{
	int i, fd;
	int page_index;
	char *pat, *pdomain;
	char fake_group[256];
	char temp_path[256];
	char domain_path[256];
	char temp_address[256];
	USER_ITEM temp_item;

	pdomain = strchr(groupname, '@') + 1;
	strcpy(temp_address, username);
	pat = strchr(temp_address, '@');
	if (NULL == pat) {
		strcat(temp_address, "@");
		strcat(temp_address, pdomain);
	}
	page_index = 1;
	if (FALSE == data_source_get_domain_homedir(pdomain, domain_path)) {
		return page_index;
	}
	strcpy(fake_group, groupname);
	pat= strchr(fake_group, '@');
	*pat = '\0';
	sprintf(temp_path, "%s/%s/tmp/group_users.%s", domain_path, fake_group,
		session);
	fd = open(temp_path, O_RDWR, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		while (sizeof(temp_item) == read(fd, &temp_item, sizeof(temp_item))) {
			if (0 == strcasecmp(temp_item.username, temp_address)) {
				temp_item.max_size = max_size;
				strcpy(temp_item.title, title);
				strcpy(temp_item.real_name, real_name);
				strcpy(temp_item.nickname, nickname);
				strcpy(temp_item.tel, tel);
				strcpy(temp_item.cell, cell);
				strcpy(temp_item.homeaddress, homeaddress);
				strcpy(temp_item.memo, memo);
				temp_item.privilege_bits = privilege_bits;
				temp_item.address_status = address_status;
				lseek(fd, -sizeof(USER_ITEM), SEEK_CUR);
				write(fd, &temp_item, sizeof(temp_item));
				page_index = i / ITEMS_PER_PAGE + 1;
				break;
			}
			i ++;
		}
		close(fd);
	}
	return page_index;
}
	
static BOOL list_ui_cache_retrieve(const char *groupname,
	const char *session, const char *username, USER_ITEM *pitem)
{
	int i, fd;
	BOOL b_found;
	char *pat, *pdomain;
	char fake_group[256];
	char temp_path[256];
	char domain_path[256];
	char temp_address[256];
	USER_ITEM temp_item;

	b_found = FALSE;
	pdomain = strchr(groupname, '@') + 1;
	strcpy(temp_address, username);
	pat = strchr(temp_address, '@');
	if (NULL == pat) {
		strcat(temp_address, "@");
		strcat(temp_address, pdomain);
	}
	if (FALSE == data_source_get_domain_homedir(pdomain, domain_path)) {
		return FALSE;
	}
	strcpy(fake_group, groupname);
	pat = strchr(fake_group, '@');
	*pat = '\0';
	sprintf(temp_path, "%s/%s/tmp/group_users.%s",
		domain_path, fake_group, session);
	fd = open(temp_path, O_RDWR, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		while (sizeof(temp_item) == read(fd, &temp_item, sizeof(temp_item))) {
			if (0 == strcasecmp(temp_item.username, temp_address)) {
				memcpy(pitem, &temp_item, sizeof(USER_ITEM));
				b_found = TRUE;
				break;
			}
			i ++;
		}
		close(fd);
	}
	return b_found;
}

static unsigned int list_ui_cache_result(const char *groupname,
	const char *session, const char *username, int size_min, int size_max,
	const char *title, const char *real_name, const char *nickname,
	const char *tel, const char *cell, const char *homeaddress,
	const char *memo, time_t create_min, time_t create_max,
	int address_status, int address_type)
{
	DIR *dirp;
	char *language;
	time_t cur_time;
	int i, fd, page_index;
	char temp_path[256];
	char group_path[256];
	char temp_address[256];
	char fake_group[256];
	char temp_title[128];
	char temp_name[128];
	char temp_nick[128];
	char temp_tel[64];
	char temp_cell[64];
	char temp_home[128];
	char temp_memo[128];
	char *pdomain;
	char *pusername, *pat;
	const char *ptitle;
	const char *preal_name;
	const char *pnickname;
	const char *ptel;
	const char *pcell;
	const char *phomeaddress;
	const char *pmemo;
	DATA_COLLECT *pcollection;
	USER_ITEM *pitem;
	struct dirent *direntp;
	struct stat node_stat;
	
	pdomain = strchr(groupname, '@') + 1;

	if ('\0' == username[0]) {
		pusername = NULL;
	} else {
		strcpy(temp_address, username);
		pat = strchr(temp_address, '@');
		if (NULL == pat) {
			strcat(temp_address, "@");
			strcat(temp_address, pdomain);
			pusername = temp_address;
		 } else {
			pusername = (char*)username;
		 }
	}
	
	if ('\0' == title[0]) {
		ptitle = NULL;
	} else {
		list_ui_to_utf8(title, temp_title, 128);
		ptitle = temp_title;
	}

	if ('\0' == real_name[0]) {
		preal_name = NULL;
	} else {
		list_ui_to_utf8(real_name, temp_name, 128);
		preal_name = temp_name;
	}

	if ('\0' == nickname[0]) {
		pnickname = NULL;
	} else {
		list_ui_to_utf8(nickname, temp_nick, 128);
		pnickname = temp_nick;
	}

	if ('\0' == tel[0]) {
		ptel = NULL;
	} else {
		list_ui_to_utf8(tel, temp_tel, 64);
		ptel = temp_tel;
	}

	if ('\0' == cell[0]) {
		pcell = NULL;
	} else {
		list_ui_to_utf8(cell, temp_cell, 64);
		pcell = temp_cell;
	}

	if ('\0' == homeaddress[0]) {
		phomeaddress = NULL;
	} else {
		list_ui_to_utf8(homeaddress, temp_home, 128);
		phomeaddress = temp_home;
	}

	if ('\0' == memo[0]) {
		pmemo = NULL;
	} else {
		list_ui_to_utf8(memo, temp_memo, 128);
		pmemo = temp_memo;
	}

	pdomain = strchr(groupname, '@') + 1;
	if (FALSE == data_source_get_domain_homedir(pdomain, group_path)) {
		return 0;
	}
	strcpy(fake_group, groupname);
	pat = strchr(fake_group, '@');
	*pat = '\0';
	pcollection = data_source_collect_init();
	if (NULL == pcollection) {
		system_log_info("[list_ui]: fail to init collection object!");
		return 0;
	}
	if (FALSE == data_source_query(groupname, pusername, ptitle, preal_name,
		pnickname, ptel, pcell, phomeaddress, pmemo, size_min, size_max,
		create_min, create_max, address_status, address_type, pcollection)) {
		return 0;
	}
	time(&cur_time);
	strcat(group_path, "/");
	strcat(group_path, fake_group);
	strcat(group_path, "/tmp");
	dirp = opendir(group_path);
	if (NULL != dirp) {
		while (direntp = readdir(dirp)) {
			if (0 == strcmp(direntp->d_name, ".") ||
				0 == strcmp(direntp->d_name, "..")) {
				continue;
			}
			if (0 != strncmp(direntp->d_name, "group_users.", 12)) {
				continue;
			}
			sprintf(temp_path, "%s/%s", group_path, direntp->d_name);
			if (0 == stat(temp_path, &node_stat) &&
				cur_time - node_stat.st_mtime > 6*60*60) {
				remove(temp_path);
			}
		}
	}
	closedir(dirp);

	page_index = 1;
	sprintf(temp_path, "%s/group_users.%s", group_path, session);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		for (data_source_collect_begin(pcollection);
			!data_source_collect_done(pcollection);
			data_source_collect_forward(pcollection)) {
			i ++;
			pitem = (USER_ITEM*)data_source_collect_get_value(pcollection);
			list_ui_from_utf8(pitem->title, temp_title, 128);
			strcpy(pitem->title, temp_title);
			list_ui_from_utf8(pitem->real_name, temp_name, 128);
			strcpy(pitem->real_name, temp_name);
			list_ui_from_utf8(pitem->nickname, temp_nick, 128);
			strcpy(pitem->nickname, temp_nick);
			list_ui_from_utf8(pitem->tel, temp_tel, 64);
			strcpy(pitem->tel, temp_tel);
			list_ui_from_utf8(pitem->cell, temp_cell, 64);
			strcpy(pitem->cell, temp_cell);
			list_ui_from_utf8(pitem->homeaddress, temp_home, 128);
			strcpy(pitem->homeaddress, temp_home);
			list_ui_from_utf8(pitem->memo, temp_memo, 128);
			strcpy(pitem->memo, temp_memo);
			if (NULL != username &&
				0 == strcasecmp(pitem->username, username)) {
				page_index = i / ITEMS_PER_PAGE + 1;
			}
			write(fd, pitem, sizeof(USER_ITEM));
		}
		close(fd);
	}
	data_source_collect_free(pcollection);

	return page_index;

}

static void list_ui_result_html(const char *groupname, const char *session,
	const char *username, int size_min, int size_max, const char *title,
	const char *real_name, const char *nickname, const char *tel,
	const char *cell, const char *homeaddress, const char *memo,
	time_t create_min, time_t create_max, int address_status,
	int address_type)
{
	int page_index;
	char *language;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	page_index = list_ui_cache_result(groupname, session, username,
		size_min, size_max, title, real_name, nickname, tel, cell,
		homeaddress, memo, create_min, create_max, address_status,
		address_type);
	if (0 == page_index) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	
	list_ui_page_html(groupname, session, page_index);
}

static void list_ui_page_html(const char *groupname,
	const char *session, int page_index)
{
	int i, fd, total;
	int pages, num, rows;
	char *language;
	char *pdomain, *pat;
	char fake_group[256];
	char str_create[32];
	char url_buff[1024];
	char url_add[1280];
	char url_alias[1280];
	char url_search[1280];
	char url_paging_ex[1280];
	char url_paging_prev[1280];
	char url_paging_next[1280];
	char url_paging_first[1280];
	char url_paging_last[1280];
	char temp_user[256];
	char temp_path[256];
	char domain_path[256];
	char option_prev[12];
	char option_next[12];
	USER_ITEM temp_item;
	struct stat node_stat;
	struct tm temp_tm;

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	pdomain = strchr(groupname, '@') + 1;
	if (FALSE == data_source_get_domain_homedir(pdomain, domain_path)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	strcpy(fake_group, groupname);
	pat = strchr(fake_group, '@');
	*pat = '\0';
	sprintf(temp_path, "%s/%s/tmp/group_users.%s",
		domain_path, fake_group, session);
	if (0 != stat(temp_path, &node_stat)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return;
	}
	
	total = node_stat.st_size/sizeof(USER_ITEM);
	pages = (total - 1)/ITEMS_PER_PAGE + 1;
	
	if (pages < page_index) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return;
	}

	if (total > page_index * ITEMS_PER_PAGE) {
		num = page_index * ITEMS_PER_PAGE;
	} else {
		num = total;
	}
	
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}

	lseek(fd, ITEMS_PER_PAGE*sizeof(USER_ITEM)*(page_index - 1), SEEK_SET);
	
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
	list_ui_get_self(url_buff, 1024);
	sprintf(url_search, "%s?group=%s&session=%s&type=search", url_buff,
		groupname, session);
	sprintf(url_add, "%s?group=%s&session=%s&type=add", url_buff,
		groupname, session);
	sprintf(url_alias, "%s?group=%s&session=%s&type=alias", url_buff,
		groupname, session);

	sprintf(url_paging_ex, "%s?group=%s&session=%s&type=paging-ex&index=%d",
		url_buff, groupname, session, page_index);
	
	sprintf(url_paging_first, "%s?group=%s&session=%s&type=paging&index=1",
		url_buff, groupname, session);
	sprintf(url_paging_last, "%s?group=%s&session=%s&type=paging&index=%d",
		url_buff, groupname, session, pages);
	
	printf(HTML_RESULT_5, lang_resource_get(g_lang_resource,"CONFIRM_DELETE",
		language), url_buff, groupname, session, url_buff, groupname, session,
		url_search, lang_resource_get(g_lang_resource,"SEARCH_LABEL", language),
		url_add, lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		url_alias, lang_resource_get(g_lang_resource,"ALIAS_LABEL", language),
		url_paging_ex, lang_resource_get(g_lang_resource,"PAGING_EX_LABEL", language));
	
	printf(lang_resource_get(g_lang_resource,"RESULT_SUMMARY", language), total, pages);

	if (page_index < pages) {
		sprintf(url_paging_next, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index + 1);
		strcpy(option_next, OPTION_ENABLED);
	} else {
		sprintf(url_paging_next, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index);
		strcpy(option_next, OPTION_DISABLED);
	}

	if (page_index > 1) {
		sprintf(url_paging_prev, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index - 1);
		strcpy(option_prev, OPTION_ENABLED);
	} else {
		sprintf(url_paging_prev, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index);
		strcpy(option_prev, OPTION_DISABLED);
	}
	
	printf(HTML_RESULT_6,
		lang_resource_get(g_lang_resource,"CURRENT_PAGE", language), page_index,
		url_paging_first, lang_resource_get(g_lang_resource,"FIRST_PAGE", language),
		url_paging_prev, option_prev, lang_resource_get(g_lang_resource, "PREV_PAGE",
		language), url_paging_next, option_next, lang_resource_get(g_lang_resource,
		"NEXT_PAGE", language), url_paging_last, lang_resource_get(g_lang_resource,
		"LAST_PAGE", language));
	
	printf(lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	
	printf(HTML_RESULT_7);
	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_USERNAME", language),
		lang_resource_get(g_lang_resource,"MAIN_REAL_NAME", language),
		lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	
	rows = 1;
	
	for (i=(page_index-1)*ITEMS_PER_PAGE+1; i<=num; i++) {
		read(fd, &temp_item, sizeof(temp_item));
		list_ui_encode_squote(temp_item.username, temp_user);
		localtime_r(&temp_item.create_day, &temp_tm);
		strftime(str_create, 32, lang_resource_get(
			g_lang_resource, "DATE_FORMAT", language), &temp_tm);
		if (RECORD_STATUS_DELETED == temp_item.address_status) {
			printf(HTML_TBITEM_DELETED, temp_item.username,
				temp_item.real_name, str_create, temp_item.max_size/1024);
		} else if (RECORD_STATUS_SUSPEND == temp_item.address_status) {
			printf(HTML_TBITEM, CSS_ITEM_SUSPEND, temp_item.username,
				temp_item.real_name, str_create, temp_item.max_size/1024,
				temp_user, lang_resource_get(g_lang_resource,"EDIT_LABEL",
				language), temp_user, lang_resource_get(g_lang_resource,
				"DELETE_LABEL", language));
		} else {
			if (0 == rows%2) {
				printf(HTML_TBITEM, CSS_ITEMEVEN, temp_item.username,
					temp_item.real_name, str_create, temp_item.max_size/1024,
					temp_user, lang_resource_get(g_lang_resource,"EDIT_LABEL",
					language), temp_user, lang_resource_get(g_lang_resource,
					"DELETE_LABEL", language));
			} else {
				printf(HTML_TBITEM, CSS_ITEMODD, temp_item.username,
					temp_item.real_name, str_create, temp_item.max_size/1024,
					temp_user, lang_resource_get(g_lang_resource,"EDIT_LABEL",
					language), temp_user, lang_resource_get(g_lang_resource,
					"DELETE_LABEL", language));
			}
			rows ++;
		} 
	}
}

static void list_ui_page_ex_html(const char *groupname,
	const char *session, int page_index)
{
	int i, fd, total;
	uint32_t proptag;
	int pages, num, rows;
	uint64_t mb_size;
	char *language;
	char *pdomain, *pat;
	char fake_group[256];
	char str_create[32];
	char url_buff[1024];
	char url_add[1280];
	char url_alias[1280];
	char url_search[1280];
	char url_paging_prev[1280];
	char url_paging_next[1280];
	char url_paging_first[1280];
	char url_paging_last[1280];
	char temp_user[256];
	char temp_path[256];
	char domain_path[256];
	char option_prev[12];
	char option_next[12];
	USER_ITEM temp_item;
	struct stat node_stat;
	struct tm temp_tm;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");

	pdomain = strchr(groupname, '@') + 1;
	if (FALSE == data_source_get_domain_homedir(pdomain, domain_path)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}
	strcpy(fake_group, groupname);
	pat = strchr(fake_group, '@');
	*pat = '\0';
	sprintf(temp_path, "%s/%s/tmp/group_users.%s", domain_path, fake_group,
		session);
	if (0 != stat(temp_path, &node_stat)) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return;
	}
	
	total = node_stat.st_size/sizeof(USER_ITEM);
	pages = (total - 1)/ITEMS_PER_PAGE + 1;
	
	if (pages < page_index) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_REQUEST", language));
		return;
	}
	
	if (total > page_index * ITEMS_PER_PAGE) {
		num = page_index * ITEMS_PER_PAGE;
	} else {
		num = total;
	}
	
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		list_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}

	lseek(fd, ITEMS_PER_PAGE*sizeof(USER_ITEM)*(page_index - 1), SEEK_SET);
	
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource, "RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource, "CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource, "RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	list_ui_get_self(url_buff, 1024);
	sprintf(url_search, "%s?group=%s&session=%s&type=search",
		url_buff, groupname, session);
	sprintf(url_add, "%s?group=%s&session=%s&type=add",
		url_buff, groupname, session);
	sprintf(url_alias, "%s?group=%s&session=%s&type=alias",
		url_buff, groupname, session);
	
	sprintf(url_paging_first, "%s?group=%s&session=%s&type=paging&index=1",
		url_buff, groupname, session);
	sprintf(url_paging_last, "%s?group=%s&session=%s&type=paging&index=%d",
		url_buff, groupname, session, pages);
	
	printf(HTML_RESULT_5_1, lang_resource_get(g_lang_resource, "CONFIRM_DELETE",
		language), url_buff, groupname, session, url_buff, groupname, session,
		url_search, lang_resource_get(g_lang_resource, "SEARCH_LABEL", language),
		url_add, lang_resource_get(g_lang_resource, "ADD_LABEL", language),
		url_alias, lang_resource_get(g_lang_resource, "ALIAS_LABEL", language));
	
	printf(lang_resource_get(g_lang_resource, "RESULT_SUMMARY", language), total, pages);

	if (page_index < pages) {
		sprintf(url_paging_next, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index + 1);
		strcpy(option_next, OPTION_ENABLED);
	} else {
		sprintf(url_paging_next, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index);
		strcpy(option_next, OPTION_DISABLED);
	}

	if (page_index > 1) {
		sprintf(url_paging_prev, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index - 1);
		strcpy(option_prev, OPTION_ENABLED);
	} else {
		sprintf(url_paging_prev, "%s?group=%s&session=%s&type=paging&index=%d",
			url_buff, groupname, session, page_index);
		strcpy(option_prev, OPTION_DISABLED);
	}
	
	printf(HTML_RESULT_6, lang_resource_get(g_lang_resource, "CURRENT_PAGE",
		language), page_index, url_paging_first, lang_resource_get(g_lang_resource,
		"FIRST_PAGE", language), url_paging_prev, option_prev, lang_resource_get(
		g_lang_resource, "PREV_PAGE", language), url_paging_next, option_next,
		lang_resource_get(g_lang_resource,"NEXT_PAGE", language), url_paging_last,
		lang_resource_get(g_lang_resource,"LAST_PAGE", language));
	
	printf(lang_resource_get(g_lang_resource, "RESULT_TABLE_TITLE", language));
	
	printf(HTML_RESULT_7);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource, "MAIN_USERNAME",
		language), lang_resource_get(g_lang_resource, "MAIN_REAL_NAME", language),
		lang_resource_get(g_lang_resource, "MAIN_CREATING_DAY", language),
		lang_resource_get(g_lang_resource, "MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource, "MAIN_OPERATION", language));
	
	rows = 1;
	
	for (i=(page_index-1)*ITEMS_PER_PAGE+1; i<=num; i++) {
		read(fd, &temp_item, sizeof(temp_item));
		list_ui_encode_squote(temp_item.username, temp_user);
		localtime_r(&temp_item.create_day, &temp_tm);
		strftime(str_create, 32, lang_resource_get(g_lang_resource,
			"DATE_FORMAT", language), &temp_tm);
		if (RECORD_STATUS_DELETED != temp_item.address_status) {
			proptags.count = 1;
			proptags.pproptag = &proptag;
			proptag = PROP_TAG_MESSAGESIZEEXTENDED;
			if (TRUE == exmdb_client_get_store_properties(
				temp_item.maildir, 0, &proptags, &propvals)
				&& 0 != propvals.count) {
				mb_size = *(uint64_t*)propvals.ppropval[0].pvalue;
			}
		}
		if (RECORD_STATUS_DELETED == temp_item.address_status) {
			printf(HTML_TBITEM_DELETED, temp_item.username,
				temp_item.real_name, str_create, temp_item.max_size/1024);
		} else if (RECORD_STATUS_SUSPEND == temp_item.address_status) {
			printf(HTML_TBITEM_EX, CSS_ITEM_SUSPEND, temp_item.username,
				temp_item.real_name, str_create, temp_item.max_size/1024,
				((double)mb_size)/(1024*1024), temp_user,lang_resource_get(
				g_lang_resource, "EDIT_LABEL", language), temp_user,
				lang_resource_get(g_lang_resource, "DELETE_LABEL", language));
		} else {
			if (0 == rows%2) {
				printf(HTML_TBITEM_EX, CSS_ITEMEVEN, temp_item.username,
					temp_item.real_name, str_create, temp_item.max_size/1024,
					((double)mb_size)/(1024*1024), temp_user, lang_resource_get(
					g_lang_resource,"EDIT_LABEL", language), temp_user,
					lang_resource_get(g_lang_resource, "DELETE_LABEL", language));
			} else {
				printf(HTML_TBITEM_EX, CSS_ITEMODD, temp_item.username,
					temp_item.real_name, str_create, temp_item.max_size/1024,
					((double)mb_size)/(1024*1024), temp_user,lang_resource_get(
					g_lang_resource,"EDIT_LABEL", language), temp_user,
					lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
			}
			rows ++;
		} 
	}
}

static void list_ui_update_extpasscfg(const char *maildir, int extpasswd_type)
{
	int fd, len;
	char type[16];
	char path_buff[256];
	char temp_buff[1024];
	struct stat node_stat;
	
	
	snprintf(path_buff, 256, "%s/config/extpasswd.cfg", maildir);
	if (0 == stat(path_buff, &node_stat)) {
		if (node_stat.st_size >= sizeof(temp_buff)) {
			return;
		}
		fd = open(path_buff, O_RDONLY);
		if (-1 == fd) {
			return;
		}
		if (node_stat.st_size != read(fd, temp_buff,
			node_stat.st_size)) {
			close(fd);
			return;
		}
		
		temp_buff[node_stat.st_size] = '\0';
		close(fd);
		if (TRUE == get_digest(temp_buff, "type", type, 16)) {
			if (0 == extpasswd_type) {
				remove_digest(temp_buff, "type");
				fd = open(path_buff, O_CREAT|O_TRUNC|O_WRONLY, 0666);
				if (-1 != fd) {
					write(fd, temp_buff, strlen(temp_buff));
					close(fd);
				}
			} else {
				if (atoi(type) != extpasswd_type) {
					sprintf(type, "%d", extpasswd_type);
					set_digest(temp_buff, sizeof(temp_buff), "type", type);
					fd = open(path_buff, O_CREAT|O_TRUNC|O_WRONLY, 0666);
					if (-1 != fd) {
						write(fd, temp_buff, strlen(temp_buff));
						close(fd);
					}
				}
			}
		} else {
			if (0 != extpasswd_type) {
				sprintf(type, "%d", extpasswd_type);
				add_digest(temp_buff, sizeof(temp_buff), "type", type);
				fd = open(path_buff, O_CREAT|O_TRUNC|O_WRONLY, 0666);
				if (-1 != fd) {
					write(fd, temp_buff, strlen(temp_buff));
					close(fd);
				}
			}
		}
	} else {
		if (0 != extpasswd_type) {
			fd = open(path_buff, O_CREAT|O_TRUNC|O_WRONLY, 0666);
			if (-1!= fd) {
				len = sprintf(temp_buff, "{\"obsolete\":0,\"type\":%d}", extpasswd_type);
				write(fd, temp_buff, len);
				close(fd);
			}
		}
	}
}

static void list_ui_copy_file(const char *src_file, const char *dst_file)
{
	int fd;
	char *pbuff;
	struct stat node_stat;

	if (0 != stat(src_file, &node_stat)) {
		return;
	}
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return;
	}
	fd = open(src_file, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		free(pbuff);
		close(fd);
		return;
	}
	close(fd);
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	write(fd, pbuff, node_stat.st_size);
	free(pbuff);
	close(fd);
}

static BOOL list_ui_allocate_dir(const char *media_area, char *path_buff)
{
	time_t cur_time;
	LOCKD lockd;
	int v_index;
	int mini_vdir;
	int mini_homes;
	int total_space;
	int total_used;
	int total_homes;
	int i, fd, len, item_num;
	int space, files, homes;
	int average_space;
	char *pdb_storage;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[DIGEST_BUFLEN];
	struct stat node_stat;
	LIST_FILE *pfile;
	AREA_ITEM *pitem;
	AREA_NODE *parea;
	DOUBLE_LIST_NODE *pnode;
	AREA_NODE *pleast_area;
	DOUBLE_LIST temp_list;
	
	
	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");

	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to init list file %s", g_list_path);
		return FALSE;
	}
	if (NULL == media_area) {
		lockd = locker_client_lock("USER-AREA");
	} else {
		lockd = locker_client_lock("MEDIA-AREA");
	}
	total_space = 0;
	total_used = 0;
	total_homes = 0;
	double_list_init(&temp_list);
	pitem = (AREA_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (NULL == media_area) {
			if (0 != strcmp(pitem[i].type, "USER")) {
				continue;
			}
		} else {
			if (0 != strcmp(pitem[i].type, "MEDIA") ||
				0 != strcmp(pitem[i].master, media_area)) {
				continue;
			}
		}
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL != pdb_storage) {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		sprintf(temp_path, "%s/pinfo", pitem[i].master);
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			continue;
		}
		len = read(fd, temp_buff, 1024);
		close(fd);
		if (len <= 0) {
			close(fd);
			continue;
		}
		temp_buff[len] = '\0';
		
		list_ui_partition_info(temp_buff, &space, &files, &homes);
		
		if (-1 == space || -1 == files || -1 == homes) {
			continue;
		}
		total_space += pitem[i].space;
		total_used += space;
		total_homes += homes;
		if (space < pitem[i].space && files < pitem[i].files &&
			homes < VDIR_PER_PARTITION*MAILDIR_PER_VDIR) {
			parea = (AREA_NODE*)malloc(sizeof(AREA_NODE));
			if (NULL == parea) {
				continue;
			}
			parea->node.pdata = parea;
			strcpy(parea->master, pitem[i].master);
			if (NULL != pdb_storage) {
				strcpy(parea->database, pdb_storage);
			} else {
				parea->database[0] = '\0';
			}
			parea->max_space = pitem[i].space;
			parea->used_space = space;
			parea->used_files = files;
			parea->homes = homes;
			double_list_append_as_tail(&temp_list, &parea->node);
		}
	}
	list_file_free(pfile);
	
	if (0 == double_list_get_nodes_num(&temp_list)) {
		double_list_free(&temp_list);
		system_log_info("[list_ui]: cannot find"
			" a available data area for user");
		locker_client_unlock(lockd);
		return FALSE;
	}
	if (0 == total_homes) {
		average_space = 1;
	} else {
		average_space = total_space / total_homes;
	}
	if (average_space < 1) {
		average_space = 1;
	}
	pleast_area = NULL;
	for (pnode=double_list_get_head(&temp_list); NULL!=pnode;
		pnode=double_list_get_after(&temp_list, pnode)) {
		parea = (AREA_NODE*)pnode->pdata;
		if (NULL == pleast_area) {
			pleast_area = parea;
		} else {
			if (parea->homes/(((double)parea->max_space)/average_space) <
				pleast_area->homes/(((double)pleast_area->max_space)/average_space)) {
				pleast_area = parea;
			}
		}
	}
	mini_homes = -1;
	for (i=1; i<=VDIR_PER_PARTITION; i++) {
		sprintf(temp_path, "%s/v%d/vinfo", pleast_area->master, i);
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			continue;
		}

		len = read(fd, temp_buff, 1024);
		
		close(fd);
		
		if (len <= 0) {
			continue;
		}
		temp_buff[len] = '\0';
		homes = atoi(temp_buff);
		if (mini_homes < 0) {
			mini_homes = homes;
			mini_vdir = i;
		} else if (mini_homes > homes) {
			mini_homes = homes;
			mini_vdir = i;
		}
	}
	if (-1 == mini_homes || mini_homes >= MAILDIR_PER_VDIR) {
		system_log_info("[list_ui]: seems allocation information of data"
			" area %s or it's vdir information error, please check it!",
			pleast_area->master);
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		locker_client_unlock(lockd);
		return FALSE;
	}
	
	for (i=1; i<=MAILDIR_PER_VDIR; i++) {
		sprintf(temp_path, "%s/v%d/%d", pleast_area->master, mini_vdir, i);
		if (0 != lstat(temp_path, &node_stat)) {
			break;
		}
	}
	if (i > MAILDIR_PER_VDIR) {
		system_log_info("[list_ui]: seems allocation information of vdir"
			" %d under data area %s error, please check it!", mini_vdir,
			pleast_area->master);
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		locker_client_unlock(lockd);
		return FALSE;	
	}
	
	v_index = i;
	
	time(&cur_time);
	sprintf(temp_path, "%s/v%d/vinfo.%d", pleast_area->master,
		mini_vdir, cur_time);
	sprintf(temp_path1, "%s/v%d/vinfo", pleast_area->master, mini_vdir);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		len = sprintf(temp_buff, "%dH", mini_homes + 1);
		write(fd, temp_buff, len);
		close(fd);
		rename(temp_path, temp_path1);
	}
	sprintf(temp_path, "%s/pinfo.%d", pleast_area->master, cur_time);
	sprintf(temp_path1, "%s/pinfo", pleast_area->master);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		len = sprintf(temp_buff, "%dM,%dC,%dH", pleast_area->used_space,
				pleast_area->used_files, pleast_area->homes + 1);
		write(fd, temp_buff, len);
		close(fd);
		rename(temp_path, temp_path1);
	}
	
	sprintf(temp_path, "%s/v%d/%d", pleast_area->master, mini_vdir, v_index);
	
	if ('\0' != pleast_area->database[0]) {
		sprintf(temp_path1, "%s/v%d/%d", pleast_area->database, mini_vdir, v_index);
		if (0 == mkdir(temp_path1, 0777)) {
			locker_client_unlock(lockd);
			while (pnode=double_list_get_from_head(&temp_list)) {
				free(pnode->pdata);
			}
			double_list_free(&temp_list);
			system_log_info("[list_ui]: fail to make directory "
				"under %s/v%d", pleast_area->database, mini_vdir);
			return FALSE;
		}
	}
	
	if (0 == mkdir(temp_path, 0777)) {
		strcpy(path_buff, temp_path);
		sprintf(temp_path, "%s/exmdb", path_buff);
		if ('\0' != pleast_area->database[0]) {
			symlink(temp_path1, temp_path);
		} else {
			mkdir(temp_path, 0777);
		}
		sprintf(temp_path, "%s/tmp", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/tmp/imap.rfc822", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/tmp/faststream", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/eml", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/ext", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/cid", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/disk", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/config", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/config/portrait.jpg", path_buff);
		srand(time(NULL));
		sprintf(temp_path1, "%s/%d.jpg", g_thumbnail_path, rand()%100 + 1);
		list_ui_copy_file(temp_path1, temp_path);
		strcpy(temp_buff, "{\"size\":0,\"files\":0}");
		memset(temp_buff + 20, ' ', 512 - 20);
		sprintf(temp_path, "%s/disk/index", path_buff);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 != fd) {
			write(fd, temp_buff, 512);
			close(fd);
		}
		locker_client_unlock(lockd);
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		return TRUE;
	} else {
		locker_client_unlock(lockd);
		if ('\0' != pleast_area->database[0]) {
			remove(temp_path1);
		}
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		system_log_info("[list_ui]: fail to make directory "
			"under %s/v%d", pleast_area->master, mini_vdir);
		return FALSE;
	}
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
	
	sprintf(temp_path, "%s/exmdb", maildir);
	if (0 == lstat(temp_path, &node_stat) &&
		0 != S_ISLNK(node_stat.st_mode)) {
		memset(temp_path1, 0, 256);
		if (readlink(temp_path, temp_path1, 256) > 0) {
			list_ui_remove_inode(temp_path1);
		}
	}
	list_ui_remove_inode(maildir);
	
	locker_client_unlock(lockd);
}

static void list_ui_partition_info(char *s,
	int *pmegas, int *pfiles, int *phomes)
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
		snprintf(temp_path, 256, "%s/%s", path, direntp->d_name);
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

	conv_id = iconv_open(lang_resource_get(g_lang_resource,
		"CHARSET", getenv("HTTP_ACCEPT_LANGUAGE")), "UTF-8");
	pin = src;
	pout = dst;
	in_len = strlen(src);
	memset(dst, 0, len);
	iconv(conv_id, &pin, &in_len, &pout, &len);
	iconv_close(conv_id);
}

static void list_ui_to_utf8(const char *src, char *dst, size_t len)
{
	size_t in_len;
	char *pin, *pout;
	iconv_t conv_id;

	conv_id = iconv_open("UTF-8", lang_resource_get(g_lang_resource,
						"CHARSET", getenv("HTTP_ACCEPT_LANGUAGE")));
	pin = (char*)src;
	pout = dst;
	in_len = strlen(src);
	memset(dst, 0, len);
	iconv(conv_id, &pin, &in_len, &pout, &len);
	iconv_close(conv_id);
}
