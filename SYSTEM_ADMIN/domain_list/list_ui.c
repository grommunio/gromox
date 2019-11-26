#include "util.h"
#include "list_ui.h"
#include "list_file.h"
#include "system_log.h"
#include "exmdb_tool.h"
#include "double_list.h"
#include "acl_control.h"
#include "data_source.h"
#include "locker_client.h"
#include "lang_resource.h"
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <iconv.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

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

/* fill search result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function DeleteItem(domain) {if (confirm('%s')) location.href='%s?session=%s&type=remove&domainname=' + domain;}\n\
function EditItem(domain) {location.href='%s?session=%s&type=edit&domainname=' + domain;}\n\
function RestoreItem(domain) {location.href='%s?session=%s&type=restore&domainname=' + domain;}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A></TD></TR>\n\
<TR><TD noWrap align=left height=23>"

/* fill rows num here */

#define HTML_RESULT_6	\
"</TD></TR><TR><TD noWrap align=right>%s:%d&nbsp;&nbsp&nbsp;&nbsp;\n\
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
})})\n\
$(function(){$(\"#end_min\").datepicker({\n\
monthText:[%s],\n\
weekText:[%s],\n\
yearText:[%s],\n\
todayText:[%s]\n\
})})\n\
$(function(){$(\"#end_max\").datepicker({\n\
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
"><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"search\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" \n\
border=0><TBODY><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=domainname />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><SELECT name=domain_status>\n\
<OPTION value=-1 selected>%s</OPTION><OPTION value=0>%s</OPTION>\n\
<OPTION value=1>%s</OPTION><OPTION value=2>%s\n\
</OPTION><OPTION value=3>%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=domain_type><OPTION value=-1 selected>%s</OPTION>\n\
<OPTION value=0>%s</OPTION><OPTION value=1>%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" size=8 name=size_min />&nbsp;-&nbsp;\n\
<INPUT type=\"text\" size=8 name=size_max />&nbsp;<B>G</B></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" size=8 name=user_min />&nbsp;-&nbsp;\n\
<INPUT type=\"text\" size=8 name=user_max /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=title /></SPAN></TD></TR>\n"

#define HTML_SEARCH_7	\
"<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=address /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=admin_name /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=tel /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n"

#define HTML_SEARCH_8	\
"<INPUT type=\"text\" id=create_min name=create_min style=\"border:solid 1px; \n\
width:100px; background:url(../data/picture/calendar-button.gif) \n\
no-repeat right; height:22px; padding-right:19px; cursor:default;\" \n\
readonly=\"readonly\" />&nbsp;-&nbsp; <INPUT type=\"text\" id=create_max \n\
name=create_max style=\"border:solid 1px; width:100px; \n\
background:url(../data/picture/calendar-button.gif) no-repeat\n\
right; height:22px; padding-right:19px; cursor:default;\" readonly=\"readonly\"\n\
 /></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" id=end_min name=end_min style=\"border:solid 1px; \n\
width:100px; background:url(../data/picture/calendar-button.gif) \n\
no-repeat right; height:22px; padding-right:19px; cursor:default;\" \n\
readonly=\"readonly\" />&nbsp;-&nbsp; <INPUT type=\"text\" id=end_max \n\
name=end_max style=\"border:solid 1px; width:100px; \n\
background:url(../data/picture/calendar-button.gif) no-repeat right; \n\
height:22px; padding-right:19px; cursor:default;\" readonly=\"readonly\" /></SPAN>\n"

#define HTML_SEARCH_9	\
"</TD><TD><INPUT type=submit value=\"    %s    \"\n\
onclick=\"if (searchpattern.domainname.value.length >= 64) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (searchpattern.size_min.value.length > 0) {\n\
	var num=parseInt(searchpattern.size_min.value);\n\
	if(isNaN(num) || num < 0) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (searchpattern.size_max.value.length > 0) {\n\
	var num=parseInt(searchpattern.size_max.value);\n\
	if (isNaN(num) || num <= 0) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (searchpattern.user_min.value.length > 0) {\n\
	var num=parseInt(searchpattern.user_min.value);\n\
	if (isNaN(num) || num < 0) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (searchpattern.user_max.value.length > 0) {\n\
	var num=parseInt(searchpattern.user_max.value);\n\
	if (isNaN(num) || num <= 0) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
if (searchpattern.title.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (searchpattern.address.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (searchpattern.admin_name.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (searchpattern.tel.value.length >= 64) {\n\
	alert('%s');\n\
	return false;\n\
}\n\""

#define HTML_SEARCH_10	\
"/></TD></TR></TBODY></TABLE></FORM></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"


#define HTML_ADD_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}\n\
$(function(){$(\"#create_day\").datepicker({\n\
monthText:[%s],\n\
weekText:[%s],\n\
yearText:[%s],\n\
todayText:[%s]\n\
})})\n\
$(function(){$(\"#end_day\").datepicker({\n\
monthText:[%s],\n\
weekText:[%s],\n\
yearText:[%s],\n\
todayText:[%s]\n\
})})\n</SCRIPT>\n\
<TR><TD align=right><A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;\n\
<A href=\"%s\">%s</A>&nbsp;&nbsp;&nbsp;&nbsp;<A href=\"%s\">%s</A>\n\
</TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=addeditform method=post action="

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
function BackTo() {window.history.back();}\n\
$(function(){$(\"#create_day\").datepicker({\n\
monthText:[%s],\n\
weekText:[%s],\n\
yearText:[%s],\n\
todayText:[%s]\n\
})})\n\
$(function(){$(\"#end_day\").datepicker({\n\
monthText:[%s],\n\
weekText:[%s],\n\
yearText:[%s],\n\
todayText:[%s]\n\
})})\n</SCRIPT>\n\
<TR><TD align=right><A href=\"%s\" %s>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;\n\
<A href=\"javascript:BackTo()\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR><DIV align=left>&nbsp;&nbsp;&nbsp;&nbsp;<B>%s</B></DIV>\n\
<FORM class=SearchForm name=addeditform method=post action="

#define HTML_ADD_6	\
"><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"add\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=domainname /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=media>%s</SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=domain_status><OPTION value=0 selected>%s</OPTION>\n\
<OPTION value=1>%s</OPTION></SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" class=RightInput size=8 name=max_size />\n\
<B>G</B></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" class=RightInput size=8 \n\
name=max_user /></SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" size=40 name=title />\n\
</SPAN></TD></TR>\n"

#define HTML_ALIAS_6	\
"><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"alias\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=domainname /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=aliasname /></SPAN></TD>\n\
<TD><INPUT type=\"submit\" value=\"    %s    \" \n\
onclick=\"if (0 == aliasform.domainname.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (aliasform.domainname.value.length >= 64) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (0 == aliasform.aliasname.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (aliasform.aliasname.value.length >= 64) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
return true;\" /></TD></TR></TBODY></TABLE></FORM></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_EDIT_6	\
"><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"edit\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=domainname \n\
readonly=\"readonly\"/></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=media>%s</SELECT></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<SELECT name=domain_status><OPTION value=0 %s>%s</OPTION>\n\
<OPTION value=1 %s>%s</OPTION></SELECT></SPAN></TD></TR>\n\
<TR class=%s><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" size=8 class=RightInput value=\"%d\" \n\
name=max_size />&nbsp;<B>G</B>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s:&nbsp;%d&nbsp;\n\
<B>G</B></SPAN></TD></TR><TR class=%s><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" value=\"%d\" class=RightInput \n\
size=8 name=max_user />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;%s:&nbsp;%d</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" value=\"%s\" size=40 \n\
name=title /></SPAN></TD></TR>\n"

#define HTML_EDIT_OUTOFDATE_6	\
"><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"edit\" name=\"type\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=domainname \n\
readonly=\"readonly\"/></SPAN><INPUT type=hidden value=\"nochange\" name=media />\
<INPUT type=hidden value=2 name=domain_status />\n\
</TD></TR><TR class=%s><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center>\n\
<SPAN><INPUT type=\"text\" size=8 class=RightInput value=\"%d\" \n\
name=max_size />&nbsp;<B>G</B>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s:&nbsp;%d&nbsp;\n\
<B>G</B></SPAN></TD></TR><TR class=%s><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" value=\"%d\" class=RightInput \n\
size=8 name=max_user />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;%s:&nbsp;%d</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><INPUT type=\"text\" value=\"%s\" size=40 \n\
name=title /></SPAN></TD></TR>\n"

#define HTML_ADD_7	\
"<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=address /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=admin_name /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" size=40 name=tel /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n"

#define HTML_EDIT_7	\
"<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=address /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=admin_name /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"text\" value=\"%s\" size=40 name=tel /></SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n"

#define HTML_ADD_8	\
"<INPUT type=\"text\" id=create_day name=create_day style=\"border:solid 1px; \n\
width:100px; background:url(../data/picture/calendar-button.gif) \n\
no-repeat right; height:22px; padding-right:19px; cursor:default;\" \n\
readonly=readonly /></SPAN></TD></TR><TR><TD></TD>\n\
<TD vAlign=center>%s</TD><TD vAlign=center><SPAN><INPUT type=\"text\" \n\
id=end_day name=end_day style=\"border:solid 1px; width:100px; \n\
background:url(../data/picture/calendar-button.gif) no-repeat \n\
right; height:22px; padding-right:19px; cursor:default;\" \n\
readonly=readonly /></SPAN><INPUT type=hidden value=\"\" \n\
name=privilege_bits /></TD>"

#define HTML_EDIT_8	\
"<INPUT type=\"text\" id=create_day name=create_day value=\"%s\" \n\
style=\"border:solid 1px; width:100px; \n\
background:url(../data/picture/calendar-button.gif) no-repeat right; \n\
height:22px; padding-right:19px; cursor:default;\" \n\
readonly=readonly /></SPAN></TD></TR><TR><TD></TD>\n\
<TD vAlign=center>%s</TD><TD vAlign=center><SPAN><INPUT type=\"text\" \n\
id=end_day name=end_day value=\"%s\" style=\"border:solid 1px; width:100px; \n\
background:url(../data/picture/calendar-button.gif) no-repeat \n\
right; height:22px; padding-right:19px; cursor:default;\" \n\
readonly=readonly /></SPAN><INPUT type=hidden name=privilege_bits /></TD>"

#define HTML_ADD_9 \
"<TD><INPUT value=\"    %s    \" type=submit \n\
onclick=\"if (0 == addeditform.domainname.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.domainname.value.length >= 64) {\n\
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
if (addeditform.title.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.address.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.admin_name.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.tel.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.end_day.value.length == 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var mask_string='';\n\
if (extpasswd.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (sms.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (sub_system.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (uncheck_user.checked == true) {\n\
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
return true;\" /></TD></TR></FORM><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><TABLE border=0><TBODY><TR><TD>\n\
<INPUT type=checkbox name=mail_backup value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=mail_monitor value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=uncheck_user value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=sub_system value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=sms value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=extpasswd value=\"on\" />%s</TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_EDIT_9 \
"<TD><INPUT value=\"    %s    \" type=submit %s \n\
onclick=\"var num = parseInt(addeditform.max_size.value);\n\
if (isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
num = parseInt(addeditform.max_user.value);\n\
if (isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.title.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.address.value.length >= 128) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.admin_name.value.length >= 32) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.tel.value.length >= 64) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (addeditform.end_day.value.length == 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var mask_string='';\n\
if (extpasswd.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (sms.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (sub_system.checked == true) {\n\
	mask_string += '1';\n\
} else {\n\
	mask_string += '0';\n\
}\n\
if (uncheck_user.checked == true) {\n\
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
return true;\" /></TD></TR></FORM><TR><TD></TD><TD vAlign=center>%s</TD>\n\
<TD vAlign=center><SPAN><TABLE border=0><TBODY><TR><TD>\n\
<INPUT type=checkbox name=mail_backup %s value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=mail_monitor %s value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=uncheck_user %s value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=sub_system %s value=\"on\" />%s</TD></TR>\n\
<TR><TD><INPUT type=checkbox name=sms %s value=\"on\" />%s</TD>\n\
<TD><INPUT type=checkbox name=extpasswd %s value=\"on\" />%s</TD></TR>\n\
</TBODY></TABLE></SPAN></TD></TR></TBODY></TABLE></TBODY></TABLE></TD></TR>\n\
</TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy;%s</CENTER></BODY></HTML>"

#define HTML_PASSWORD_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><SCRIPT type=\"text/javascript\" language=\"javascript\">\n\
function BackTo() {window.history.back();}</SCRIPT>\n\
<TR><TD align=right><A href=\"javascript:BackTo()\">%s</A></TD></TR>\n\
</TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=addeditform method=post action="

#define HTML_PASSWORD_6	\
"><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"password\" name=\"type\" />\n\
<INPUT type=hidden value=\"%s\" name=\"domainname\" />\n\
<TABLE class=SearchTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY><TR class=ItemRandpasswd><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\" value=\"%s\" name=new_password />&nbsp;&nbsp;%s:%s</SPAN></TD></TR>\n\
<TR><TD></TD><TD vAlign=center>%s</TD><TD vAlign=center><SPAN>\n\
<INPUT type=\"password\"  value=\"%s\" name=retype_password /></SPAN></TD>\n\
<TD><INPUT type=submit value=\"    %s    \"  onclick=\"\n\
if (0 == new_password.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (new_password.value.length >=32) { \n\
	alert('%s');\n\
	return false;\n\
}\n\
if (new_password.value != retype_password.value) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
return true;\"/></TD></TR></TBODY></TABLE></FORM>\n\
</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR><P></P>\n\
<BR><BR>&copy;%s</CENTER></BODY></HTML>"


#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
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
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=hidden value=paging name=\"type\" />\n\
<INPUT type=hidden value=%d name=\"index\" />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_ADD_OK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><FORM class=SearchForm method=get action=\"%s\">\n\
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=hidden value=add name=\"type\" />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_ALIAS_OK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><FORM class=SearchForm method=get action=\"%s\">\n\
<INPUT type=hidden value=\"%s\" name=session />\n\
<INPUT type=hidden value=alias name=\"type\" />\n\
<INPUT type=submit value=\"    %s    \"/></FORM></CENTER></BODY></HTML>"

#define HTML_PASSWORD_OK_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR><BR>\n\
<BR><BR>%s<BR><BR><BR><BR><BR><INPUT type=submit value=\"    %s    \" \n\
onclick=\"window.history.go(-2);\"/></CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>"

#define HTML_TBITEM     \
"<TR class=%s><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%dG&nbsp;</TD><TD>&nbsp;%d&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"javascript:EditItem('%s')\">%s</A>&nbsp;|&nbsp;\n\
<A href=\"javascript:DeleteItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_DELETED	\
"<TR class=%s><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%dG&nbsp;</TD><TD>&nbsp;%d&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"javascript:EditItem('%s')\">%s</A>&nbsp;|&nbsp;\n\
<A href=\"javascript:RestoreItem('%s')\">%s</A>&nbsp;</TD></TR>\n"


#define CSS_ITEMODD			"ItemOdd"

#define CSS_ITEMEVEN		"ItemEven"

#define CSS_ITEM_DELETED	"ItemDeleted"

#define CSS_ITEM_OUTOFDATE	"ItemOutofdate"

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

#define HOME_PER_VDIR           10

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

static void list_ui_search_html(const char *session);

static void list_ui_add_html(const char *session);

static void list_ui_alias_html(const char *session);

static void list_ui_password_html(const char *session, const char *domainname);

static void list_ui_password_noexist_html(const char *session);

static void list_ui_password_alias_html(const char *session);

static void list_ui_password_ok_html(const char *session,
	const char *domainname);

static void list_ui_add_ok_html(const char *session, const char *domainname);

static void list_ui_remove_ok_html(const char *session, int page_index);

static void list_ui_restore_ok_html(const char *session, int page_index);

static void list_ui_add_exist_html(const char *session);

static void list_ui_add_fail_html(const char *session);

static void list_ui_alias_exist_html(const char *session);

static void list_ui_alias_noexist_html(const char *session);

static void list_ui_alias_notmain_html(const char *session);

static void list_ui_alias_ok_html(const char *session);

static void list_ui_restore_error_html(const char *session);

static void list_ui_restore_alias_html(const char *session);

static void list_ui_edit_ok_html(const char *session, int page_index);

static void list_ui_edit_noexist_html(const char *session);

static void list_ui_edit_html(const char *session, const char *domainname);

static void list_ui_result_html(const char *session, const char *domainname,
	int size_min, int size_max, int user_min, int user_max, const char *title,
	const char *address, const char *admin_name, const char *tel,
	time_t create_min, time_t create_max, time_t end_min, time_t end_max,
	int domain_status, int domain_type);

static void list_ui_page_html(const char *session, int page_index);

static BOOL list_ui_get_self(char *url_buff, int length);

static void list_ui_unencode(char *src, char *last, char *dest);

static void list_ui_encode_squote(const char *in, char *out);

static void list_ui_partition_info(char *s, int *pmegas, int *pfiles,
	int *phomes);

static void list_ui_remove_inode(const char *path);

static unsigned int list_ui_cache_result(const char *session,
	const char *domainname, int size_min, int size_max, int user_min,
	int user_max, const char *title, const char *address,
	const char *admin_name, const char *tel, time_t create_min,
	time_t create_max, time_t end_min, time_t end_max,
	int domain_status, int domain_type);

static unsigned int list_ui_cache_edit(const char *session,
	const char *domainname, int max_size, int max_user, const char *title,
	const char *address, const char *admin_name, const char *tel,
	time_t create_day, time_t end_day, int domain_status);

static unsigned int list_ui_cache_remove(const char *session,
	const char *domainname);

static unsigned int list_ui_cache_restore(const char *session,
	const char *domainname, int domain_status);

static BOOL list_ui_allocate_dir(const char *media_area, char *path_buff);

static void list_ui_free_dir(BOOL b_media, const char *homedir);

static void list_ui_from_utf8(char *src, char *dst, size_t len);

static void list_ui_to_utf8(char *src, char *dst, size_t len);

static int g_store_ratio;
static char g_logo_link[1024];
static char g_list_path[256];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void list_ui_init(const char *list_path, const char *url_link,
	const char *resource_path, int store_ratio)
{
	strcpy(g_list_path, list_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
	g_store_ratio = store_ratio;
}

int list_ui_run()
{
	struct tm temp_tm;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char *query, *request;
	char type[16];
	char tel[64];
	char new_tel[64];
	char session[256];
	char title[128];
	char new_title[128];
	char address[128];
	char new_address[128];
	char admin_name[32];
	char new_name[32];
	char domainname[64];
	char homedir[128];
	char mediadir[128];
	char media_area[128];
	char aliasname[64];
	char new_password[32];
	char retype_password[32];
	char encrypt_pw[40];
	char temp_buff[256];
	char post_buff[4096];
	char search_buff[1024];
	int domain_id;
	int max_user;
	uint64_t max_size;
	int privilege_bits;
	int size_min, size_max;
	int user_min, user_max;
	int temp_size, temp_user;
	int len, domain_status;
	int total_domains, result;
	int domain_type, page_index;
	time_t create_min, end_min;
	time_t create_max, end_max;
	time_t create_day, end_day;
	DATA_COLLECT *pcollection;
	DOMAIN_ITEM *pitem;

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
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[list_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
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
		ptr1 = search_string(search_buff, "session=", len);
		if (NULL == ptr1) {
			goto POST_ERROR;
		}
		ptr1 += 8;
		ptr2 = search_string(search_buff, "&type=", len);
		if (NULL == ptr2) {
			goto POST_ERROR;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			goto POST_ERROR;
		}
		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
		
		switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_MISC)) {
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
		
		ptr1 = ptr2 + 6;
		ptr2 = search_string(search_buff, "&domainname=", len);
		if (ptr2 <= ptr1 || ptr2 - ptr1 > 15) {
			goto POST_ERROR;
		}
		memcpy(type, ptr1, ptr2 - ptr1);
		type[ptr2 - ptr1] = '\0';
		ltrim_string(type);
		rtrim_string(type);
		if (0 == strcasecmp(type, "password")) {
			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&new_password=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 64) {
				goto POST_ERROR;
			}
			memcpy(domainname, ptr1, ptr2 - ptr1);
			domainname[ptr2 - ptr1] = '\0';
			ltrim_string(domainname);
			rtrim_string(domainname);

			ptr1 = ptr2 + 14;
			ptr2 = search_string(search_buff, "&retype_password=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 32) {
				goto POST_ERROR;
			}
			memcpy(new_password, ptr1, ptr2 - ptr1);
			new_password[ptr2 - ptr1] = '\0';

			ptr1 = ptr2 + 17;
			if (search_buff + len - 1 - ptr1 >= 32 ||
				search_buff + len - 1 - ptr1 == 0) {
				goto POST_ERROR;
			}
			memcpy(retype_password, ptr1, search_buff + len - ptr1 - 1);
			retype_password[search_buff + len - ptr1 - 1] = '\0';
			if (0 != strcmp(new_password, retype_password)) {
				goto POST_ERROR;
			}
			strcpy(encrypt_pw, md5_crypt_wrapper(new_password));
			if (FALSE == data_source_domain_password(domainname, encrypt_pw,
				&result)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
					language));
				return 0;
			}
			if (PASSWORD_RESULT_NOEXIST == result) {
				list_ui_password_noexist_html(session);
			} else if (PASSWORD_RESULT_ALIAS == result) {
				list_ui_password_alias_html(session);
			} else {
				list_ui_password_ok_html(session, domainname);
			}
			return 0;
		} else if (0 == strcasecmp(type, "search")) {
			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&domain_status=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 64) {
				goto POST_ERROR;
			}
			memcpy(domainname, ptr1, ptr2 - ptr1);
			domainname[ptr2 - ptr1] = '\0';
			ltrim_string(domainname);
			rtrim_string(domainname);

			ptr1 = ptr2 + 15;
			ptr2 = search_string(search_buff, "&domain_type=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 4) {
				goto POST_ERROR;
			}	
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			domain_status = atoi(temp_buff);

			ptr1 = ptr2 + 13;
			ptr2 = search_string(search_buff, "&size_min=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 64) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			domain_type = atoi(temp_buff);
			
			ptr1 = ptr2 + 10;
			ptr2 = search_string(search_buff, "&size_max=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			size_min = atoi(temp_buff)*1024;

			ptr1 = ptr2 + 10;
			ptr2 = search_string(search_buff, "&user_min=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			size_max = atoi(temp_buff)*1024;

			ptr1 = ptr2 + 10;
			ptr2 = search_string(search_buff, "&user_max=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			user_min = atoi(temp_buff);

			ptr1 = ptr2 + 10;
			ptr2 = search_string(search_buff, "&title=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			user_max = atoi(temp_buff);

			ptr1 = ptr2 + 7;
			ptr2 = search_string(search_buff, "&address=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 128) {
				goto POST_ERROR;
			}
			memcpy(title, ptr1, ptr2 - ptr1);
			title[ptr2 - ptr1] = '\0';
			ltrim_string(title);
			rtrim_string(title);
			
			ptr1 = ptr2 + 9;
			ptr2 = search_string(search_buff, "&admin_name=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >=128) {
				goto POST_ERROR;
			}
			memcpy(address, ptr1, ptr2 - ptr1);
			address[ptr2 - ptr1] = '\0';
			ltrim_string(address);
			rtrim_string(address);

			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&tel=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 32) {
				goto POST_ERROR;
			}
			memcpy(admin_name, ptr1, ptr2 - ptr1);
			admin_name[ptr2 - ptr1] = '\0';
			ltrim_string(admin_name);
			rtrim_string(admin_name);
			
			ptr1 = ptr2 + 5;
			ptr2 = search_string(search_buff, "&create_min=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 64) {
				goto POST_ERROR;
			}
			memcpy(tel, ptr1, ptr2 - ptr1);
			tel[ptr2 - ptr1] = '\0';
			ltrim_string(tel);
			rtrim_string(tel);

			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&create_max=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			if ('\0' == temp_buff[0]) {
				create_min = 0;
			} else {
				memset(&temp_tm, 0, sizeof(temp_tm));
				if (NULL != strptime(temp_buff, "%Y-%m-%d", &temp_tm)) {
					create_min = mktime(&temp_tm);
				} else {
					create_min = 0;
				}
			}
			
			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&end_min=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			if ('\0' == temp_buff[0]) {
				create_max = 0;
			} else {
				memset(&temp_tm, 0, sizeof(temp_tm));
				if (NULL != strptime(temp_buff, "%Y-%m-%d", &temp_tm)) {
					create_max = mktime(&temp_tm);
				} else {
					create_max = 0;
				}
			}
			
			ptr1 = ptr2 + 9;
			ptr2 = search_string(search_buff, "&end_max=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			if ('\0' == temp_buff[0]) {
				end_min = 0;
			} else {
				memset(&temp_tm, 0, sizeof(temp_tm));
				if (NULL != strptime(temp_buff, "%Y-%m-%d", &temp_tm)) {
					end_min = mktime(&temp_tm);
				} else {
					end_min = 0;
				}
			}

			ptr1 = ptr2 + 9;

			if (search_buff + len - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, search_buff + len - ptr1);
			temp_buff[search_buff + len - ptr1] = '\0';
			if ('\0' == temp_buff[0]) {
				end_max = 0;
			} else {
				memset(&temp_tm, 0, sizeof(temp_tm));
				if (NULL != strptime(temp_buff, "%Y-%m-%d", &temp_tm)) {
					end_max = mktime(&temp_tm);
				} else {
					end_max = 0;
				}
			}

			list_ui_result_html(session, domainname, size_min, size_max,
				user_min, user_max, title, address, admin_name, tel,
				create_min, create_max, end_min, end_max, domain_status,
				domain_type);
			return 0;
		} else if (0 == strcasecmp(type, "add") ||
			0 == strcasecmp(type, "edit")) {
			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&media=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 64) {
				goto POST_ERROR;
			}
			memcpy(domainname, ptr1, ptr2 - ptr1);
			domainname[ptr2 - ptr1] = '\0';
			ltrim_string(domainname);
			rtrim_string(domainname);
			
			ptr1 = ptr2 + 7;
			ptr2 = search_string(search_buff, "&domain_status=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 128) {
				goto POST_ERROR;
			}
			memcpy(media_area, ptr1, ptr2 - ptr1);
			media_area[ptr2 - ptr1] = '\0';
			ltrim_string(media_area);
			rtrim_string(media_area);

			ptr1 = ptr2 + 15;
			ptr2 = search_string(search_buff, "&max_size=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 4) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			domain_status = atoi(temp_buff);
			
			ptr1 = ptr2 + 10;
			ptr2 = search_string(search_buff, "&max_user=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			max_size = atoll(temp_buff)*1024;

			ptr1 = ptr2 + 10;
			ptr2 = search_string(search_buff, "&title=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			max_user = atoi(temp_buff);

			ptr1 = ptr2 + 7;
			ptr2 = search_string(search_buff, "&address=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 128) {
				goto POST_ERROR;
			}
			memcpy(title, ptr1, ptr2 - ptr1);
			title[ptr2 - ptr1] = '\0';
			ltrim_string(title);
			rtrim_string(title);

			ptr1 = ptr2 + 9;

			ptr2 = search_string(search_buff, "&admin_name=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >=128) {
				goto POST_ERROR;
			}
			memcpy(address, ptr1, ptr2 - ptr1);
			address[ptr2 - ptr1] = '\0';
			ltrim_string(address);
			rtrim_string(address);

			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&tel=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 32) {
				goto POST_ERROR;
			}
			memcpy(admin_name, ptr1, ptr2 - ptr1);
			admin_name[ptr2 - ptr1] = '\0';
			ltrim_string(admin_name);
			rtrim_string(admin_name);
			
			ptr1 = ptr2 + 5;
			ptr2 = search_string(search_buff, "&create_day=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 64) {
				goto POST_ERROR;
			}
			memcpy(tel, ptr1, ptr2 - ptr1);
			tel[ptr2 - ptr1] = '\0';
			ltrim_string(tel);
			rtrim_string(tel);

			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&end_day=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			if ('\0' == temp_buff[0]) {
				time(&create_day);
			} else {
				memset(&temp_tm, 0, sizeof(temp_tm));
				if (NULL != strptime(temp_buff, "%Y-%m-%d", &temp_tm)) {
					create_day = mktime(&temp_tm);
				} else {
					time(&create_day);
				}
			}
			
			ptr1 = ptr2 + 9;

			ptr2 = search_string(search_buff, "&privilege_bits=", len);
			if (ptr2 <= ptr1 || ptr2 - ptr1 >= 12) {
				goto POST_ERROR;
			}
			memcpy(temp_buff, ptr1, ptr2 - ptr1);
			temp_buff[ptr2 - ptr1] = '\0';
			memset(&temp_tm, 0, sizeof(temp_tm));
			if (NULL != strptime(temp_buff, "%Y-%m-%d", &temp_tm)) {
				end_day = mktime(&temp_tm);
			} else {
				goto POST_ERROR;
			}

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
			if ('1' == temp_buff[5]) {
				privilege_bits |= DOMAIN_PRIVILEGE_BACKUP;
			}
			if ('1' == temp_buff[4]) {
				privilege_bits |= DOMAIN_PRIVILEGE_MONITOR;
			}
			if ('1' == temp_buff[3]) {
				privilege_bits |= DOMAIN_PRIVILEGE_UNCHECKUSR;
			}
			if ('1' == temp_buff[2]) {
				privilege_bits |= DOMAIN_PRIVILEGE_SUBSYSTEM;
			}
			if ('1' == temp_buff[1]) {
				privilege_bits |= DOMAIN_PRIVILEGE_NETDISK;
			}
			if ('1' == temp_buff[0]) {
				privilege_bits |= DOMAIN_PRIVILEGE_EXTPASSWD;
			}
			
			if (0 == strcasecmp(type, "add")) {
				if (FALSE == list_ui_allocate_dir(NULL, homedir)) {
					list_ui_add_fail_html(session);
					return 0;
				}
				if ('\0' != media_area[0]) {
					if (FALSE == list_ui_allocate_dir(media_area, mediadir)) {
						list_ui_free_dir(FALSE, homedir);
						list_ui_add_fail_html(session);
						return 0;
					}
				}

				list_ui_to_utf8(title, new_title, 128);
				list_ui_to_utf8(address, new_address, 128);
				list_ui_to_utf8(admin_name, new_name, 32);
				list_ui_to_utf8(tel, new_tel, 64);
				if (FALSE == data_source_add_domain(domainname, homedir, media_area,
					max_size, max_user, new_title, new_address, new_name, new_tel,
					create_day, end_day, privilege_bits, domain_status,  &result,
					&domain_id)) {
					list_ui_free_dir(FALSE, homedir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				if (ADD_RESULT_EXIST == result) {
					list_ui_free_dir(FALSE, homedir);
					if ('\0' != media_area[0]) {
						list_ui_free_dir(TRUE, mediadir);
					}
					list_ui_add_exist_html(session);
					return 0;
				}
				if ('\0' != media_area[0]) {
					list_ui_remove_inode(homedir);
					symlink(mediadir, homedir);
				}
				exmdb_tool_create(homedir, domain_id, max_size*1024*1024/g_store_ratio);
				list_ui_add_ok_html(session, domainname);
			} else {
				list_ui_to_utf8(title, new_title, 128);
				list_ui_to_utf8(address, new_address, 128);
				list_ui_to_utf8(admin_name, new_name, 32);
				list_ui_to_utf8(tel, new_tel, 64);
				if (FALSE == data_source_edit_domain(domainname, media_area,
					max_size, max_user, new_title, new_address, new_name,
					new_tel, create_day, end_day, privilege_bits,
					domain_status, &result)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				if (EDIT_RESULT_NOEXIST == result) {
					list_ui_edit_noexist_html(session);
					return 0;
				} else if (EDIT_RESULT_MIGRATING == result) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_MIGRATING",
						language));
					return 0;
				} else if (EDIT_RESULT_ERROR == result) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				pcollection = data_source_collect_init();
				if (NULL != pcollection) {
					data_source_get_alias(domainname, pcollection);
					for (data_source_collect_begin(pcollection);
						!data_source_collect_done(pcollection);
						data_source_collect_forward(pcollection)) {
						pitem = data_source_collect_get_value(pcollection);
						list_ui_cache_edit(session, pitem->domainname, max_size,
							max_user, title, address, admin_name, tel,
							create_day, end_day, domain_status);
					}
					data_source_collect_free(pcollection);
				}
				page_index = list_ui_cache_edit(session, domainname, max_size,
					max_user, title, address, admin_name, tel, create_day,
					end_day, domain_status);
				list_ui_edit_ok_html(session, page_index);
			}
			return 0;
		} else if (0 == strcasecmp(type, "alias")) {
			ptr1 = ptr2 + 12;
			ptr2 = search_string(search_buff, "&aliasname=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 >= 64) {
				goto POST_ERROR;
			}
			memcpy(domainname, ptr1, ptr2 - ptr1);
			domainname[ptr2 - ptr1] = '\0';
			ltrim_string(domainname);
			rtrim_string(domainname);
			
			ptr1 = ptr2 + 11;
			if (search_buff + len - ptr1 - 1>= 64 ||
				0 == search_buff + len - ptr1 - 1) {
				goto POST_ERROR;
			}
			memcpy(aliasname, ptr1, search_buff + len - ptr1 - 1);
			aliasname[search_buff + len - ptr1 - 1] = '\0';
			ltrim_string(aliasname);
			rtrim_string(aliasname);
			if (FALSE == data_source_add_alias(domainname,
				aliasname, &result)) {
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
				return 0;
			}
			if (ALIAS_RESULT_EXIST == result) {
				list_ui_alias_exist_html(session);
				return 0;
			} else if (ALIAS_RESULT_NOEXIST == result) {
				list_ui_alias_noexist_html(session);
				return 0;
			} else if (ALIAS_RESULT_NOTMAIN == result) {
				list_ui_alias_notmain_html(session);
				return 0;
			}
			list_ui_alias_ok_html(session);
			return 0;
		} else {
			goto POST_ERROR;
		}
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[list_ui]: fail to get QUERY_STRING "
					"environment!");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 256) {
				system_log_info("[list_ui]: query string too long!");
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 = search_string(query, "session=", len);
			if (NULL == ptr1) {
				goto GET_ERROR;
			}
			ptr1 += 8;
			ptr2 = search_string(query, "&type=", len);
			if (NULL == ptr2) {
				if (query + len - ptr1 > 255) {
					goto GET_ERROR;
				}
				memcpy(session, ptr1, query + len - ptr1);
				session[query + len - ptr1] = '\0';
			
				switch (acl_control_check(session, remote_ip,
						ACL_PRIVILEGE_MISC)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				if (FALSE == data_source_num_domain(&total_domains)) {
					list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
						language));
					return 0;
				}
				if (total_domains <= 10000) {
					list_ui_result_html(session, "", 0, 0, 0, 0, "", "", "", "",
						0, 0, 0, 0, -1, -1);
				} else {
					list_ui_search_html(session);
				}
				return 0;
			}

			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_MISC)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			default:
				list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			ptr1 = ptr2 + 6;
			ptr2 = search_string(query, "&domainname=", len);
			if (NULL != ptr2) {
				memcpy(type, ptr1, ptr2 - ptr1);
				type[ptr2 - ptr1] = '\0';
				ptr1 = ptr2 + 12;
				if ((0 != strcasecmp(type, "edit") &&
					0 != strcasecmp(type, "remove") &&
					0 != strcasecmp(type, "restore") &&
					0 != strcasecmp(type, "password")) ||
					0 == query + len - ptr1 ||
					query + len - ptr1 >= 64) {
					goto GET_ERROR;
				}
				memcpy(domainname, ptr1, query + len - ptr1);
				domainname[query + len - ptr1] = '\0';
				if (0 == strcasecmp(type, "edit")) {
					list_ui_edit_html(session, domainname);
				} else if (0 == strcasecmp(type, "password")) {
					list_ui_password_html(session, domainname);
				} else if (0 == strcasecmp(type, "restore")) {
					if (FALSE == data_source_restore_domain(domainname,
						&result, &domain_status)) {
						list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
							language));
						return 0;
					}
					if (RESTORE_RESULT_OK == result) {
						page_index = list_ui_cache_restore(session, domainname,
										domain_status);
						list_ui_restore_ok_html(session, page_index);
					} else if (RESTORE_RESULT_ALIAS == result) {
						list_ui_restore_alias_html(session);
					} else {
						list_ui_restore_error_html(session);
					}
				} else {
					if (FALSE == data_source_remove_domain(domainname)) {
						list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
							language));
						return 0;
					}
					pcollection = data_source_collect_init();
					if (NULL != pcollection) {
						data_source_get_alias(domainname, pcollection);
						for (data_source_collect_begin(pcollection);
							!data_source_collect_done(pcollection);
							data_source_collect_forward(pcollection)) {
							pitem = data_source_collect_get_value(pcollection);
							list_ui_cache_remove(session, pitem->domainname);
						}
						data_source_collect_free(pcollection);
					}
					
					page_index = list_ui_cache_remove(session, domainname);
					list_ui_remove_ok_html(session, page_index);
				}
				return 0;
			}
			ptr2 = search_string(query, "&index=", len);
			if (NULL != ptr2) {
				memcpy(type, ptr1, ptr2 - ptr1);
				type[ptr2 - ptr1] = '\0';
				ptr1 = ptr2 + 7;
				if (0 != strcasecmp(type, "paging") || query + len - ptr1 >= 12) {
					goto GET_ERROR;
				}
				memcpy(temp_buff, ptr1, query + len - ptr1);
				temp_buff[query + len - ptr1] = '\0';
				page_index = atoi(temp_buff);
				if (page_index < 1) {
					goto GET_ERROR;
				}
				list_ui_page_html(session, page_index);
				return 0;
			}
			
			if (query + len - ptr1 > 16) {
				goto GET_ERROR;
			}
			memcpy(type, ptr1, query + len - ptr1);
			type[query + len - ptr1] = '\0';
			if (0 == strcasecmp(type, "add")) {
				list_ui_add_html(session);	
			} else if (0 == strcasecmp(type, "alias")) {
				list_ui_alias_html(session);
			} else if (0 == strcasecmp(type, "search")) {
				list_ui_search_html(session);
			} else if (0 == strcasecmp(type, "list")) {
				list_ui_result_html(session, "", 0, 0, 0, 0, "", "", "", "",
					0, 0, 0, 0, -1, -1);
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

static void list_ui_add_ok_html(const char *session, const char *domainname)
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
	printf(lang_resource_get(g_lang_resource,"ADDING_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ADDING_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ADD_OK_5, lang_resource_get(g_lang_resource,"ADDING_OK", language),
		url_buff, session, lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_edit_ok_html(const char *session, int page_index)
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
	printf(lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_PAGE_OK_5, lang_resource_get(g_lang_resource,"EDIT_OK", language), url_buff,
		session, page_index, lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_add_exist_html(const char *session)
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
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"ADDING_EXIST", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_add_fail_html(const char *session)
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
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"HOMEDIR_FAIL", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_alias_exist_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"ALIAS_EXIST", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));


}

static void list_ui_alias_noexist_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"ALIAS_MAIN_NOTEXIST", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_alias_notmain_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"ALIAS_NOT_MAIN", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_alias_ok_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ALIAS_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ALIAS_OK_5, lang_resource_get(g_lang_resource,"ALIAS_OK", language), url_buff,
		session, lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_restore_error_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"RESTORE_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RESTORE_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"RESTORE_ERROR", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_restore_alias_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"RESTORE_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RESTORE_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"RESTORE_ALIAS", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_password_noexist_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"PASSWORD_NOEXIST", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_password_alias_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"PASSWORD_ALIAS", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_password_ok_html(const char *session,
	const char *domainname)
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
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_PASSWORD_OK_5, lang_resource_get(g_lang_resource,"PASSWORD_OK", language),
		lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_edit_noexist_html(const char *session)
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
	printf(lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"EDIT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_BACK_5, lang_resource_get(g_lang_resource,"EDIT_NOEXIST", language),
		lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
}

static void list_ui_remove_ok_html(const char *session, int page_index)
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
	printf(lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"REMOVE_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_PAGE_OK_5, lang_resource_get(g_lang_resource,"REMOVE_OK", language), url_buff,
		session, page_index, lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_restore_ok_html(const char *session, int page_index)
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
	printf(lang_resource_get(g_lang_resource,"RESTORE_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RESTORE_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_PAGE_OK_5,lang_resource_get(g_lang_resource,"RESTORE_OK", language), url_buff,
		session, page_index, lang_resource_get(g_lang_resource,"OK_LABEL", language));
}

static void list_ui_add_html(const char *session)
{
	char *pitem;
	int item_num;
	int i, offset;
	char *language;
	LIST_FILE *pfile;
	char url_buff[1024];
	char url_list[1280];
	char url_alias[1280];
	char url_search[1280];
	char media_options[64*1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}


	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");

	if (NULL == pfile) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	
	offset = snprintf(media_options, 64*1024, "<OPTION value=\"\">%s</OPTION>",
				lang_resource_get(g_lang_resource,"STORAGE_DEFAULT", language));
	
	pitem = (char*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	if (item_num > 1024) {
		item_num = 1024;
	}
	for (i=0; i<item_num; i++) {
		if (0 == strcmp(pitem + (524 + 2*sizeof(int))*i, "MEDIA")) {
			offset += snprintf(media_options + offset, 64*1024 - offset,
						"<OPTION value=\"%s\">%s</OPTION>",
						pitem + (524 + 2*sizeof(int))*i + 12,
						pitem + (524 + 2*sizeof(int))*i + 12);
		}
	}
	list_file_free(pfile);
	


	sprintf(url_search, "%s?session=%s&type=search", url_buff, session);
	sprintf(url_alias, "%s?session=%s&type=alias", url_buff, session);
	sprintf(url_list, "%s?session=%s&type=list", url_buff, session);
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
	printf(HTML_ADD_5, lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		url_search, lang_resource_get(g_lang_resource,"SEARCH_LABEL",
		language), url_alias, lang_resource_get(g_lang_resource,"ALIAS_LABEL", language),
		url_list, lang_resource_get(g_lang_resource,"WHOLE_LIST", language));
	printf(url_buff);
	printf(HTML_ADD_6, session, lang_resource_get(g_lang_resource,"MAIN_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN_STROAGE", language), media_options,
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN_STATUS", language),
		lang_resource_get(g_lang_resource,"STATUS_NORMAL", language),
		lang_resource_get(g_lang_resource,"STATUS_SUSPEND", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_USER", language),
		lang_resource_get(g_lang_resource,"MAIN_TITLE", language));

	printf(HTML_ADD_7, lang_resource_get(g_lang_resource,"MAIN_ADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_ADMINISTRATOR", language),
		lang_resource_get(g_lang_resource,"MAIN_TELEPHONE", language),
		lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language));

	printf(HTML_ADD_8, lang_resource_get(g_lang_resource,"MAIN_ENDDING_DAY", language));
	printf(HTML_ADD_9, lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MSGERR_DOMAIN_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_USER", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ADDRESS_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ADMINNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_TEL_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ENDDING_DAY", language),
		lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language),
		lang_resource_get(g_lang_resource,"OPTION_BACKUP", language),
		lang_resource_get(g_lang_resource,"OPTION_MONITOR", language),
		lang_resource_get(g_lang_resource,"OPTION_UNCHECKUSR", language),
		lang_resource_get(g_lang_resource,"OPTION_SUBSYSTEM", language),
		lang_resource_get(g_lang_resource,"OPTION_NETDISK", language),
		lang_resource_get(g_lang_resource,"OPTION_EXTPASSWD", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_alias_html(const char *session)
{
	char *language;
	char url_buff[1024];
	char url_list[1280];
	char url_add[1280];
	char url_search[1280];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	sprintf(url_search, "%s?session=%s&type=search", url_buff, session);
	sprintf(url_add, "%s?session=%s&type=add", url_buff, session);
	sprintf(url_list, "%s?session=%s&type=list", url_buff, session);
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
	printf(HTML_ALIAS_5, url_search, lang_resource_get(g_lang_resource,"SEARCH_LABEL",
		language), url_add, lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		url_list, lang_resource_get(g_lang_resource,"WHOLE_LIST", language));
	printf(url_buff);
	printf(HTML_ALIAS_6, session, lang_resource_get(g_lang_resource,"MAIN_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MAIN_ALIAS", language),
		lang_resource_get(g_lang_resource,"OK_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MSGERR_DOMAIN_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ALIAS", language),
		lang_resource_get(g_lang_resource,"MSGERR_ALIAS_LEN", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_password_html(const char *session, const char *domainname)
{
	char *language;
	char url_buff[1024];
	char randpasswd[10];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	randstring(randpasswd, 8);
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf(lang_resource_get(g_lang_resource,"CHARSET", language));
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"PASSWORD_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_PASSWORD_5, lang_resource_get(g_lang_resource,"RETRYING_LABEL", language));
	printf(url_buff);
	printf(HTML_PASSWORD_6, session, domainname,
		lang_resource_get(g_lang_resource,"NEW_PASSWORD", language), randpasswd,
		lang_resource_get(g_lang_resource,"RAND_PASSWORD", language), randpasswd,
		lang_resource_get(g_lang_resource,"RETYPE_NEW_PASSWORD", language), randpasswd,
		lang_resource_get(g_lang_resource,"SAVE_LABEL", language),
		lang_resource_get(g_lang_resource,"NULL_PASSWORD_ERROR", language),
		lang_resource_get(g_lang_resource,"LENGTH_PASSWORD_ERROR", language),
		lang_resource_get(g_lang_resource,"NEW_PASSWORD_ERROR", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));

}

static void list_ui_edit_html(const char *session, const char *domainname)
{
	int i, len;
	int offset;
	char *pitem;
	int item_num;
	int actual_size;
	int actual_user;
	char *language;
	LIST_FILE *pfile;
	char option_backup[16];
	char option_monitor[16];
	char option_uncheckusr[16];
	char option_subsystem[16];
	char option_sms[16];
	char option_extpasswd[16];
	char url_buff[1024];
	char url_password[1280];
	char create_buff[32];
	char end_buff[32];
	char temp_domain[128];
	char prompt[1024];
	char class_size[16];
	char class_user[16];
	char option_submit[16];
	char option_enabled[16];
	char option_disabled[16];
	char temp_title[128];
	char temp_address[128];
	char temp_name[32];
	char temp_tel[64];
	struct tm temp_tm;
	DOMAIN_ITEM temp_item;
	char media_options[64*1024];


	language = getenv("HTTP_ACCEPT_LANGUAGE");
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	
	if (FALSE == data_source_info_domain(domainname, &temp_item, &actual_size,
		&actual_user)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	if ('\0' == temp_item.domainname[0]) {
		list_ui_edit_noexist_html(session);
		return;
	}

	
	
	if ('\0' == temp_item.media[0]) {
		pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");

		if (NULL == pfile) {
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			return;
		}
		pitem = (char*)list_file_get_list(pfile);
		item_num = list_file_get_item_num(pfile);
		if (item_num > 1024) {
			item_num = 1024;
		}

		offset = snprintf(media_options, 64*1024,
					"<OPTION value=\"nochange\">%s</OPTION>",
					lang_resource_get(g_lang_resource,"STORAGE_DEFAULT", language));

		for (i=0; i<item_num; i++) {
			if (0 == strcmp(pitem + (524 + 2*sizeof(int))*i, "MEDIA")) {
				offset += snprintf(media_options + offset, 64*1024 - offset,
							"<OPTION value=\"%s\">%s</OPTION>",
							pitem + (524 + 2*sizeof(int))*i + 12,
							pitem + (524 + 2*sizeof(int))*i + 12);
			}
		}
		list_file_free(pfile);
	} else {
		if (0 == strncmp(temp_item.media, "=>", 2) ||
			0 == strncmp(temp_item.media, ">>", 2)) {
			snprintf(media_options, 64*1024,
				"<OPTION value=\"nochange\">%s</OPTION>"
				"<OPTION value=\"\">%s</OPTION>",
				temp_item.media + 2,
				lang_resource_get(g_lang_resource,"STORAGE_DEFAULT", language));
		} else if (0 == strncmp(temp_item.media, "<=", 2) ||
			0 == strncmp(temp_item.media, "<<", 2)) {
			snprintf(media_options, 64*1024,
				"<OPTION value=\"nochange\">%s</OPTION>"
				"<OPTION value=\"%s\">%s</OPTION>",
				lang_resource_get(g_lang_resource,"STORAGE_DEFAULT", language),
						temp_item.media + 2, temp_item.media + 2);
		} else {
			snprintf(media_options, 64*1024,
				"<OPTION value=\"nochange\">%s</OPTION>"
				"<OPTION value=\"\">%s</OPTION>",
				temp_item.media,
				lang_resource_get(g_lang_resource,"STORAGE_DEFAULT", language));
		}
	}

	
	class_size[0] = '\0';
	class_user[0] = '\0';
	if (actual_size >= temp_item.max_size) {
		strcpy(class_size, CSS_ITEM_OVERQUOTA);
	}

	if (actual_user >= temp_item.max_user) {
		strcpy(class_user, CSS_ITEM_OVERQUOTA);
	}

	strcpy(temp_title, temp_item.title);
	strcpy(temp_address, temp_item.address);
	strcpy(temp_name, temp_item.admin_name);
	strcpy(temp_tel, temp_item.tel);

	list_ui_from_utf8(temp_title, temp_item.title, 128);
	list_ui_from_utf8(temp_address, temp_item.address, 128);
	list_ui_from_utf8(temp_name, temp_item.admin_name, 32);
	list_ui_from_utf8(temp_tel, temp_item.tel, 64);
	
	len  = 0;
	prompt[0] = '\0';
	if (DOMAIN_TYPE_ALIAS == temp_item.domain_type) {
		if (FALSE == data_source_get_domain_by_alias(domainname, temp_domain)) {
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			return;
		}
		len = sprintf(prompt, lang_resource_get(g_lang_resource,"PROMPT_ALIAS", language),
				temp_domain);
		strcpy(option_submit, OPTION_DISABLED);
		sprintf(url_password, "%s?session=%s&type=edit&domainname=%s",
			url_buff, session, domainname);
	} else {
		strcpy(option_submit, OPTION_ENABLED);
		sprintf(url_password, "%s?session=%s&type=password&domainname=%s",
			url_buff, session, domainname);
	}
	
	if (RECORD_STATUS_DELETED == temp_item.domain_status) {
		sprintf(url_password, "%s?session=%s&type=edit&domainname=%s",
			url_buff, session, domainname);
		strcpy(option_submit, OPTION_DISABLED);
	}

	if (RECORD_STATUS_OUTOFDATE == temp_item.domain_status) {
		strcpy(prompt + len, lang_resource_get(g_lang_resource,"PROMPT_OUTOFDATE", language));
	}

	if (RECORD_STATUS_NORMAL == temp_item.domain_status) {
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
	printf(HTML_EDIT_5, lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		url_password, option_submit,
		lang_resource_get(g_lang_resource,"CHANGE_PASSWORD", language),
		lang_resource_get(g_lang_resource,"BACK_TO_LIST", language), prompt);
	printf(url_buff);
	if (RECORD_STATUS_OUTOFDATE == temp_item.domain_status ||
		RECORD_STATUS_DELETED == temp_item.domain_status) {
		printf(HTML_EDIT_OUTOFDATE_6, session, lang_resource_get(g_lang_resource,
			"MAIN_DOMAIN", language), domainname, class_size,
			lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language), temp_item.max_size/1024,
			lang_resource_get(g_lang_resource,"ACTUAL_SIZE", language), actual_size,
			class_user, lang_resource_get(g_lang_resource,"MAIN_MAX_USER", language),
			temp_item.max_user, lang_resource_get(g_lang_resource,"ACTUAL_USER", language),
			actual_user, lang_resource_get(g_lang_resource,"MAIN_TITLE", language),
			temp_item.title);
	} else {
		printf(HTML_EDIT_6, session, lang_resource_get(g_lang_resource,"MAIN_DOMAIN",
			language), domainname, lang_resource_get(g_lang_resource,"MAIN_DOMAIN_STROAGE",
			language), media_options, lang_resource_get(g_lang_resource,"MAIN_DOMAIN_STATUS",
			language), option_enabled, lang_resource_get(g_lang_resource,"STATUS_NORMAL",
			language), option_disabled, lang_resource_get(g_lang_resource,"STATUS_SUSPEND",
			language), class_size, lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE",
			language), temp_item.max_size/1024, lang_resource_get(g_lang_resource,"ACTUAL_SIZE",
			language), actual_size/1024, class_user, lang_resource_get(g_lang_resource,
			"MAIN_MAX_USER", language), temp_item.max_user,
			lang_resource_get(g_lang_resource,"ACTUAL_USER", language), actual_user,
			lang_resource_get(g_lang_resource,"MAIN_TITLE", language), temp_item.title);
	}

	printf(HTML_EDIT_7, lang_resource_get(g_lang_resource,"MAIN_ADDRESS", language),
		temp_item.address, lang_resource_get(g_lang_resource,"MAIN_ADMINISTRATOR", language),
		temp_item.admin_name, lang_resource_get(g_lang_resource,"MAIN_TELEPHONE", language),
		temp_item.tel, lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language));

	localtime_r(&temp_item.create_day, &temp_tm);
	strftime(create_buff, 32, "%Y-%m-%d", &temp_tm);
	localtime_r(&temp_item.end_day, &temp_tm);
	strftime(end_buff, 32, "%Y-%m-%d", &temp_tm);

	printf(HTML_EDIT_8, create_buff, 
		lang_resource_get(g_lang_resource,"MAIN_ENDDING_DAY", language), end_buff);
	
	if (temp_item.privilege_bits & DOMAIN_PRIVILEGE_BACKUP) {
		strcpy(option_backup, OPTION_CHECKED);
	} else {
		strcpy(option_backup, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & DOMAIN_PRIVILEGE_MONITOR) {
		strcpy(option_monitor, OPTION_CHECKED);
	} else {
		strcpy(option_monitor, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & DOMAIN_PRIVILEGE_UNCHECKUSR) {
		strcpy(option_uncheckusr, OPTION_CHECKED);
	} else {
		strcpy(option_uncheckusr, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & DOMAIN_PRIVILEGE_SUBSYSTEM) {
		strcpy(option_subsystem, OPTION_CHECKED);
	} else {
		strcpy(option_subsystem, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & DOMAIN_PRIVILEGE_NETDISK) {
		strcpy(option_sms, OPTION_CHECKED);
	} else {
		strcpy(option_sms, OPTION_UNCHECKED);
	}

	if (temp_item.privilege_bits & DOMAIN_PRIVILEGE_EXTPASSWD) {
		strcpy(option_extpasswd, OPTION_CHECKED);
	} else {
		strcpy(option_extpasswd, OPTION_UNCHECKED);
	}
	
	printf(HTML_EDIT_9,  lang_resource_get(g_lang_resource,"SAVE_LABEL", language),
		option_submit, lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_USER", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ADDRESS_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ADMINNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_TEL_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ENDDING_DAY", language),
		lang_resource_get(g_lang_resource,"MAIN_PRIVILEGE", language), option_backup,
		lang_resource_get(g_lang_resource,"OPTION_BACKUP", language), option_monitor,
		lang_resource_get(g_lang_resource,"OPTION_MONITOR", language), option_uncheckusr,
		lang_resource_get(g_lang_resource,"OPTION_UNCHECKUSR", language), option_subsystem,
		lang_resource_get(g_lang_resource,"OPTION_SUBSYSTEM", language), option_sms,
		lang_resource_get(g_lang_resource,"OPTION_NETDISK", language), option_extpasswd,
		lang_resource_get(g_lang_resource,"OPTION_EXTPASSWD", language),
		lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static void list_ui_search_html(const char *session)
{
	int i, len;
	char *language;
	char url_buff[1024];
	char url_add[1280];
	char url_list[1280];
	char url_alias[1280];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	sprintf(url_add, "%s?session=%s&type=add", url_buff, session);
	sprintf(url_alias, "%s?session=%s&type=alias", url_buff, session);
	sprintf(url_list, "%s?session=%s&type=list", url_buff, session);
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
	printf(HTML_SEARCH_5, lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		lang_resource_get(g_lang_resource,"CALENDAR_MONTH", language),
		lang_resource_get(g_lang_resource,"CALENDAR_WEEK", language),
		lang_resource_get(g_lang_resource,"CALENDAR_YEAR", language),
		lang_resource_get(g_lang_resource,"CALENDAR_TODAY", language),
		url_add, lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		url_alias, lang_resource_get(g_lang_resource,"ALIAS_LABEL", language), url_list,
		lang_resource_get(g_lang_resource,"WHOLE_LIST", language));
	printf(url_buff);
	
	printf(HTML_SEARCH_6, session,
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN_STATUS", language),
		lang_resource_get(g_lang_resource,"OPTION_UNSELECTED", language),
		lang_resource_get(g_lang_resource,"STATUS_NORMAL", language),
		lang_resource_get(g_lang_resource,"STATUS_SUSPEND", language),
		lang_resource_get(g_lang_resource,"STATUS_OUTOFDATE", language),
		lang_resource_get(g_lang_resource,"STATUS_DELETED", language),
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"OPTION_UNSELECTED", language),
		lang_resource_get(g_lang_resource,"TYPE_NORMAL", language),
		lang_resource_get(g_lang_resource,"TYPE_ALIAS", language),	
		lang_resource_get(g_lang_resource,"MAIN_MAX_SIZE", language),
		lang_resource_get(g_lang_resource,"MAIN_MAX_USER", language),
		lang_resource_get(g_lang_resource,"MAIN_TITLE", language));

	printf(HTML_SEARCH_7, lang_resource_get(g_lang_resource,"MAIN_ADDRESS", language),
		lang_resource_get(g_lang_resource,"MAIN_ADMINISTRATOR", language),
		lang_resource_get(g_lang_resource,"MAIN_TELEPHONE", language),
		lang_resource_get(g_lang_resource,"MAIN_CREATING_DAY", language));

	printf(HTML_SEARCH_8, lang_resource_get(g_lang_resource,"MAIN_ENDDING_DAY", language));

	printf(HTML_SEARCH_9,
		lang_resource_get(g_lang_resource,"SEARCH_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_DOMAIN_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_USER", language),
		lang_resource_get(g_lang_resource,"MSGERR_SIZE", language),
		lang_resource_get(g_lang_resource,"MSGERR_TITLE_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ADDRESS_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_ADMINNAME_LEN", language),
		lang_resource_get(g_lang_resource,"MSGERR_TEL_LEN", language));
	
	printf(HTML_SEARCH_10, lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
}

static unsigned int list_ui_cache_remove(const char *session,
	const char *domainname)
{
	int i, fd, page_index;
	char temp_path[256];
	DOMAIN_ITEM temp_item;

	page_index = 1;
	sprintf(temp_path, "/tmp/domain_list.%s", session);
	fd = open(temp_path, O_RDWR, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		while (sizeof(temp_item) == read(fd, &temp_item, sizeof(temp_item))) {
			if (0 == strcasecmp(temp_item.domainname, domainname)) {
				temp_item.domain_status = RECORD_STATUS_DELETED;
				lseek(fd, -sizeof(DOMAIN_ITEM), SEEK_CUR);
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

static unsigned int list_ui_cache_restore(const char *session,
	const char *domainname, int domain_status)
{
	int i, fd, page_index;
	char temp_path[256];
	DOMAIN_ITEM temp_item;

	page_index = 1;
	sprintf(temp_path, "/tmp/domain_list.%s", session);
	fd = open(temp_path, O_RDWR, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		while (sizeof(temp_item) == read(fd, &temp_item, sizeof(temp_item))) {
			if (0 == strcasecmp(temp_item.domainname, domainname)) {
				temp_item.domain_status = domain_status;
				lseek(fd, -sizeof(DOMAIN_ITEM), SEEK_CUR);
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
	
static unsigned int list_ui_cache_edit(const char *session,
	const char *domainname, int max_size, int max_user, const char *title,
	const char *address, const char *admin_name, const char *tel,
	time_t create_day, time_t end_day, int domain_status)
{
	time_t now_time;
	int i, fd, page_index;
	char temp_path[256];
	DOMAIN_ITEM temp_item;

	time(&now_time);
	page_index = 1;
	sprintf(temp_path, "/tmp/domain_list.%s", session);
	fd = open(temp_path, O_RDWR, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		while (sizeof(temp_item) == read(fd, &temp_item, sizeof(temp_item))) {
			if (0 == strcasecmp(temp_item.domainname, domainname)) {
				temp_item.max_size = max_size;
				temp_item.max_user = max_user;
				strcpy(temp_item.title, title);
				strcpy(temp_item.address, address);
				strcpy(temp_item.admin_name, admin_name);
				strcpy(temp_item.tel, tel);
				temp_item.create_day = create_day;
				temp_item.end_day = end_day;
				if (RECORD_STATUS_DELETED == temp_item.domain_status &&
					DOMAIN_TYPE_ALIAS == temp_item.domain_type) {
					/* do not change status */
				} else if (RECORD_STATUS_OUTOFDATE == temp_item.domain_status &&
					temp_item.end_day > now_time) {
					temp_item.domain_status = RECORD_STATUS_NORMAL;
				} else {
					temp_item.domain_status = domain_status;
				}
				lseek(fd, -sizeof(DOMAIN_ITEM), SEEK_CUR);
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
	

static unsigned int list_ui_cache_result(const char *session,
	const char *domainname, int size_min, int size_max, int user_min,
	int user_max, const char *title, const char *address,
	const char *admin_name, const char *tel, time_t create_min,
	time_t create_max, time_t end_min, time_t end_max,
	int domain_status, int domain_type)
{
	DIR *dirp;
	char *language;
	time_t cur_time;
	int i, fd, page_index;
	char temp_path[256];
	DATA_COLLECT *pcollection;
	DOMAIN_ITEM *pitem;
	struct dirent *direntp;
	struct stat node_stat;
	char new_title[128];
	char new_address[128];
	char new_name[32];
	char new_tel[64];
	
	
	pcollection = data_source_collect_init();
	if (NULL == pcollection) {
		system_log_info("[list_ui]: fail to init collection object!");
		return 0;
	}

	list_ui_to_utf8((char*)title, new_title, 128);
	list_ui_to_utf8((char*)address, new_address, 128);
	list_ui_to_utf8((char*)admin_name, new_name, 32);
	list_ui_to_utf8((char*)tel, new_tel, 64);
	
	if (FALSE == data_source_query(domainname, size_min, size_max, user_min,
		user_max, new_title, new_address, new_name, new_tel, create_min,
		create_max, end_min, end_max, domain_status, domain_type,
		pcollection)) {
		return 0;
	}
	time(&cur_time);
	dirp = opendir("/tmp");
	if (NULL != dirp) {
		while (direntp = readdir(dirp)) {
			if (0 == strcmp(direntp->d_name, ".") ||
				0 == strcmp(direntp->d_name, "..")) {
				continue;
			}
			if (0 != strncmp(direntp->d_name, "domain_list.", 12)) {
				continue;
			}
			sprintf(temp_path, "/tmp/%s", direntp->d_name);
			if (0 == stat(temp_path, &node_stat) &&
				cur_time - node_stat.st_mtime > 6*60*60) {
				remove(temp_path);
			}
		}
	}
	closedir(dirp);

	page_index = 1;
	sprintf(temp_path, "/tmp/domain_list.%s", session);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		i = 0;
		for (data_source_collect_begin(pcollection);
			!data_source_collect_done(pcollection);
			data_source_collect_forward(pcollection)) {
			i ++;
			pitem = (DOMAIN_ITEM*)data_source_collect_get_value(pcollection);
			if (NULL != domainname &&
				0 == strcasecmp(pitem->domainname, domainname)) {
				page_index = i / ITEMS_PER_PAGE + 1;
			}
			strcpy(new_title, pitem->title);
			strcpy(new_address, pitem->address);
			strcpy(new_name, pitem->admin_name);
			strcpy(new_tel, pitem->tel);
			list_ui_from_utf8(new_title, pitem->title, 128);
			list_ui_from_utf8(new_address, pitem->address, 128);
			list_ui_from_utf8(new_name, pitem->admin_name, 32);
			list_ui_from_utf8(new_tel, pitem->tel, 64);
			write(fd, pitem, sizeof(DOMAIN_ITEM));
		}
		close(fd);
	}
	data_source_collect_free(pcollection);

	return page_index;

}

static void list_ui_result_html(const char *session, const char *domainname,
	int size_min, int size_max, int user_min, int user_max, const char *title,
	const char *address, const char *admin_name, const char *tel,
	time_t create_min, time_t create_max, time_t end_min, time_t end_max,
	int domain_status, int domain_type)
{
	int page_index;
	char *language;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	page_index = list_ui_cache_result(session, domainname, size_min, size_max,
					user_min, user_max, title, address, admin_name, tel,
					create_min, create_max, end_min, end_max, domain_status,
					domain_type);
	if (0 == page_index) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	
	list_ui_page_html(session, page_index);
}

static void list_ui_page_html(const char *session, int page_index)
{
	int i, fd, total;
	int pages, num, rows;
	char *language;
	char url_buff[1024];
	char url_add[1280];
	char url_alias[1280];
	char url_search[1280];
	char url_paging_prev[1280];
	char url_paging_next[1280];
	char url_paging_first[1280];
	char url_paging_last[1280];
	char temp_domain[128];
	char temp_path[256];
	char option_prev[12];
	char option_next[12];
	DOMAIN_ITEM temp_item;
	struct stat node_stat;

	
	language = getenv("HTTP_ACCEPT_LANGUAGE");

	sprintf(temp_path, "/tmp/domain_list.%s", session);
	if (0 != stat(temp_path, &node_stat)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return;
	}
	
	total = node_stat.st_size/sizeof(DOMAIN_ITEM);
	pages = (total - 1)/ITEMS_PER_PAGE + 1;
	
	if (pages < page_index) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return;
	}
	

	if (total > page_index * ITEMS_PER_PAGE) {
		num = page_index * ITEMS_PER_PAGE;
	} else {
		num = total;
	}
	
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}

	lseek(fd, ITEMS_PER_PAGE*sizeof(DOMAIN_ITEM)*(page_index - 1), SEEK_SET);
	
	
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
	sprintf(url_search, "%s?session=%s&type=search", url_buff, session);
	sprintf(url_add, "%s?session=%s&type=add", url_buff, session);
	sprintf(url_alias, "%s?session=%s&type=alias", url_buff, session);
	
	sprintf(url_paging_first, "%s?session=%s&type=paging&index=1",
		url_buff, session);
	sprintf(url_paging_last, "%s?session=%s&type=paging&index=%d",
		url_buff, session, pages);
	
	printf(HTML_RESULT_5, lang_resource_get(g_lang_resource,"CONFIRM_DELETE", language),
		url_buff, session, url_buff, session, url_buff, session, url_search,
		lang_resource_get(g_lang_resource,"SEARCH_LABEL", language), url_add,
		lang_resource_get(g_lang_resource,"ADD_LABEL", language), url_alias,
		lang_resource_get(g_lang_resource,"ALIAS_LABEL", language));
	
	
	printf(lang_resource_get(g_lang_resource,"RESULT_SUMMARY", language), total, pages);

	if (page_index < pages) {
		sprintf(url_paging_next, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index + 1);
		strcpy(option_next, OPTION_ENABLED);
	} else {
		sprintf(url_paging_next, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index);
		strcpy(option_next, OPTION_DISABLED);
	}

	if (page_index > 1) {
		sprintf(url_paging_prev, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index - 1);
		strcpy(option_prev, OPTION_ENABLED);
	} else {
		sprintf(url_paging_prev, "%s?session=%s&type=paging&index=%d",
			url_buff, session, page_index);
		strcpy(option_prev, OPTION_DISABLED);
	}
	
	printf(HTML_RESULT_6, lang_resource_get(g_lang_resource,"CURRENT_PAGE", language),
		page_index, url_paging_first, lang_resource_get(g_lang_resource,"FIRST_PAGE",
		language), url_paging_prev, option_prev, lang_resource_get(g_lang_resource,
		"PREV_PAGE", language), url_paging_next, option_next,
		lang_resource_get(g_lang_resource,"NEXT_PAGE", language), url_paging_last,
		lang_resource_get(g_lang_resource,"LAST_PAGE", language));
		
	
	printf(lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	
	printf(HTML_RESULT_7);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_DOMAIN", language),
		lang_resource_get(g_lang_resource,"MAIN_TITLE", language), lang_resource_get(g_lang_resource,
		"MAIN_MAX_SIZE", language), lang_resource_get(g_lang_resource,"MAIN_MAX_USER", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	
	rows = 1;
	
	for (i=(page_index-1)*ITEMS_PER_PAGE+1; i<=num; i++) {
		read(fd, &temp_item, sizeof(temp_item));
		list_ui_encode_squote(temp_item.domainname, temp_domain);
		if (RECORD_STATUS_DELETED == temp_item.domain_status) {
			printf(HTML_TBITEM_DELETED, CSS_ITEM_DELETED, temp_item.domainname,
				temp_item.title, temp_item.max_size/1024, temp_item.max_user,
				temp_domain, lang_resource_get(g_lang_resource,"VIEW_LABEL",
				language), temp_domain, lang_resource_get(g_lang_resource,
				"RESTORE_LABEL", language));
		} else if (RECORD_STATUS_SUSPEND == temp_item.domain_status) {
			printf(HTML_TBITEM, CSS_ITEM_SUSPEND, temp_item.domainname,
				temp_item.title, temp_item.max_size/1024, temp_item.max_user,
				temp_domain, lang_resource_get(g_lang_resource,"EDIT_LABEL",
				language), temp_domain, lang_resource_get(g_lang_resource,
				"DELETE_LABEL", language));
		} else if (RECORD_STATUS_OUTOFDATE == temp_item.domain_status) {
			printf(HTML_TBITEM, CSS_ITEM_OUTOFDATE, temp_item.domainname,
				temp_item.title, temp_item.max_size/1024, temp_item.max_user,
				temp_domain, lang_resource_get(g_lang_resource,"EDIT_LABEL",
				language), temp_domain, lang_resource_get(g_lang_resource,
				"DELETE_LABEL", language));
		} else {
			if (0 == rows%2) {
				printf(HTML_TBITEM, CSS_ITEMEVEN, temp_item.domainname,
					temp_item.title, temp_item.max_size/1024, temp_item.max_user,
					temp_domain, lang_resource_get(g_lang_resource,"EDIT_LABEL",
					language), temp_domain, lang_resource_get(g_lang_resource,
					"DELETE_LABEL", language));
			} else {
				printf(HTML_TBITEM, CSS_ITEMODD, temp_item.domainname,
					temp_item.title, temp_item.max_size/1024, temp_item.max_user,
					temp_domain, lang_resource_get(g_lang_resource,"EDIT_LABEL",
					language), temp_domain, lang_resource_get(g_lang_resource,
					"DELETE_LABEL", language));
			}
			rows ++;
		} 
	}
	
	printf(HTML_RESULT_8);

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

static BOOL list_ui_allocate_dir(const char *media_area, char *path_buff)
{
	LOCKD lockd;
	int v_index;
	int mini_vdir;
	int mini_homes;
	int total_space;
	int total_used;
	int total_homes;
	time_t cur_time;
	int i, fd, len, item_num;
	int space, files, homes;
	int average_space;
	char *pdb_storage;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[1024];
	struct stat node_stat;
	LIST_FILE *pfile;
	AREA_ITEM *pitem;
	AREA_NODE *parea;
	DOUBLE_LIST_NODE *pnode;
	AREA_NODE *pleast_area;
	DOUBLE_LIST temp_list;

	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");

	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to init list file %s",
			g_list_path);
		return FALSE;
	}
	if (NULL == media_area) {
		lockd = locker_client_lock("DOMAIN-AREA");
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
			if (0 != strcmp(pitem[i].type, "DOMAIN")) {
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
			homes < VDIR_PER_PARTITION*HOME_PER_VDIR) {
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
		system_log_info("[list_ui]: cannot find a available data area for "
			"domain");
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
	if (-1 == mini_homes || mini_homes >= HOME_PER_VDIR) {
		system_log_info("[list_ui]: seems allocation information of data area "
			"%s or it's vdir information error, please check it!",
			pleast_area->master);
		while (pnode=double_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		double_list_free(&temp_list);
		locker_client_unlock(lockd);
		return FALSE;
	}
	
	for (i=1; i<=HOME_PER_VDIR; i++) {
		sprintf(temp_path, "%s/v%d/%d", pleast_area->master, mini_vdir, i);
		if (0 != lstat(temp_path, &node_stat)) {
			break;
		}
	}
	if (i > HOME_PER_VDIR) {
		system_log_info("[list_ui]: seems allocation information of vdir %d "
			"under data area %s error, please check it!", mini_vdir,
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
		if (0 != mkdir(temp_path1, 0777)) {
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
		sprintf(temp_path, "%s/cid", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/log", path_buff);
		mkdir(temp_path, 0777);
		sprintf(temp_path, "%s/tmp", path_buff);
		mkdir(temp_path, 0777);
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

static void list_ui_free_dir(BOOL b_media, const char *homedir)
{	
	LOCKD lockd;
	int fd, len;
	time_t cur_time;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[1204];
	struct stat node_stat;
	int space, files, homes;

	if (TRUE == b_media) {
		lockd = locker_client_lock("MEDIA-AREA");
	} else {
		lockd = locker_client_lock("DOMAIN-AREA");
	}

	if (0 != lstat(homedir, &node_stat)) {
		locker_client_unlock(lockd);
		return;
	}

	time(&cur_time);
	sprintf(temp_path, "%s/../vinfo", homedir);
	sprintf(temp_path1, "%s/../vinfo.%d", homedir, cur_time);
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
	
	sprintf(temp_path, "%s/../../pinfo", homedir);
	sprintf(temp_path1, "%s/../../pinfo.%d", homedir, cur_time);
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
	
	sprintf(temp_path, "%s/exmdb", homedir);
	if (0 == lstat(temp_path, &node_stat) &&
		0 != S_ISLNK(node_stat.st_mode)) {
		memset(temp_path1, 0, 256);
		if (readlink(temp_path, temp_path1, 256) > 0) {
			list_ui_remove_inode(temp_path1);
		}
	}
	list_ui_remove_inode(homedir);
	
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

