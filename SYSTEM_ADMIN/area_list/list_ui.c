#include "util.h"
#include "list_ui.h"
#include "list_file.h"
#include "system_log.h"
#include "acl_control.h"
#include "lang_resource.h"
#include "request_parser.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

/* fill table title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<SCRIPT language=\"JavaScript\">\n\
function RemoveItem(master) {location.href='%s?session=%s&master=' + master;}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="


#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<TR><TD></TD><TD>%s:</TD><TD><SELECT name=type tabindex=1>\n\
<OPTION value=0>%s</OPTION><OPTION value=1>%s</OPTION>\n\
<OPTION value=2>%s</OPTION></SELECT></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text value=\"\" tabindex=2 \n\
name=master /></TD></TR><TR><TD></TD><TD>%s:</TD><TD><INPUT type=text \n\
value=\"\" tabindex=3 name=database /></TD></TR><TR><TD></TD><TD>%s:</TD>\n\
<TD><INPUT type=text value=\"\" tabindex=4 name=slave /></TD></TR>\n\
<TR><TD></TD><TD>%s:</TD><TD><INPUT type=text class=RightInput size=8 \n\
value=\"\" tabindex=5 name=space /><B>M</B></TD></TR><TR><TD></TD><TD>%s:</TD><TD>\n\
<INPUT type=text class=RightInput size=8 value=\"\" tabindex=6 name=files />\n\
</TD></TR><TR><TD></TD><TD></TD><TD><INPUT type=submit tabindex=7 \n\
value=\"    %s    \" onclick=\"if (opeform.master.value.length == 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (opeform.slave.value.length == 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var num = parseInt(opeform.space.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
num = parseInt(opeform.files.value);\n\
if(isNaN(num) || num <= 0) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
var str_array = [%s];\n\
for (i=0; i<str_array.length; i++) {\n\
	if (str_array[i] == opeform.master.value || \n\
		str_array[i] == opeform.slave.value) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
}\n\
return true;\" /></TD></TR>\n\
</TABLE></FORM><TABLE cellSpacing=0 cellPadding=0 \n\
width=\"90%\" border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill table title here */

#define HTML_MAIN_7 \
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_MAIN_8	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR>\n\
<TABLE width=\"90%\" border=0 cellpadding=1 cellspacing=1><TR>\n\
<TD height=\"23\" align=\"left\" nowrap>\n"

#define HTML_MAIN_9	"</TD></TR></TABLE><P></P><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST	\
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s</TD><TD>&nbsp;%s</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%dM&nbsp;</TD><TD>&nbsp;%d</TD>\n\
<TD>&nbsp;%dM</TD><TD>&nbsp;%d&nbsp;</TD><TD>&nbsp;%d&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"javascript:RemoveItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_ERROR	\
"<TR class=ItemError><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%d&nbsp;</TD><TD>&nbsp;%d</TD>\n\
<TD>&nbsp;%s</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;<A href=\"javascript:RemoveItem('%s')\">%s</A>&nbsp;</TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define TYPE_USER_AREA			0
#define TYPE_DOMAIN_AREA		1
#define TYPE_MEDIA_AREA			2

#define TOKEN_CONTROL               100
#define CTRL_RESTART_SUPERVISOR     2
#define CTRL_RESTART_SCANNER        4

typedef struct _AREA_ITEM {
	char type[12];
	char master[256];
	char slave[256];
	int space;
	int files;
} AREA_ITEM;


static void	list_ui_add_item(int type, const char *master,
	const char *database, const char *slave, int space, int files);

static void list_ui_remove_item(const char *master);
			
static void list_ui_error_html(const char *error_string);

static void list_ui_main_html(const char *session);

static void list_ui_broadcast_list();

static BOOL list_ui_get_self(char *url_buff, int length);


static char g_list_path[256];
static char g_logo_link[1024];
static char g_token_path[256];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void list_ui_init(const char *list_path, const char *token_path,
	const char *url_link, const char *resource_path)
{
	strcpy(g_list_path, list_path);
	strcpy(g_token_path, token_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int list_ui_run()
{
	int type;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	int space, files;
	const char *slave;
	const char *pvalue;
	char temp_buff[16];
	const char *master;
	const char *session;
	const char *database;
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
			system_log_info("[list_ui]: fail to get QUERY_STRING "
				"environment!");
			list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			pparser = request_parser_init(query);
			session = request_parser_get(pparser, "session");
			if (NULL == session) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_SETUP)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_TIMEOUT", language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_PRIVILEGE", language));
				return 0;
			default:
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_SESSION", language));
				return 0;
			}
			pvalue = request_parser_get(pparser, "type");
			if (NULL == pvalue) {
				master = request_parser_get(pparser, "master");
				if (NULL != master) {	
					list_ui_remove_item(master);
					list_ui_main_html(session);
					return 0;
				}
				list_ui_main_html(session);
				return 0;
			}
			master = request_parser_get(pparser, "master");
			if (NULL == master) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			if (1 != strlen(pvalue)) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			if ('0' == *pvalue) {
				type = TYPE_USER_AREA;
			} else if ('1' == *pvalue) {
				type = TYPE_DOMAIN_AREA;
			} else if ('2' == *pvalue) {
				type = TYPE_MEDIA_AREA;
			} else {
				system_log_info("[list_ui]: type in GET query string error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			database = request_parser_get(pparser, "database");
			slave = request_parser_get(pparser, "slave");
			if (NULL == slave) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			pvalue = request_parser_get(pparser, "space");
			if (NULL == pvalue) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			space = atoi(pvalue);
			pvalue = request_parser_get(pparser, "files");
			if (NULL == pvalue) {
				system_log_info("[list_ui]: query string of GET format error");
				list_ui_error_html(lang_resource_get(
					g_lang_resource, "ERROR_REQUEST", language));
				return 0;
			}
			files = atoi(pvalue);
			
			list_ui_add_item(type, master, database, slave, space, files);
			list_ui_main_html(session);
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
	int offset;
	int item_num;
	int i, len, fd;
	int files, homes, space;
	char *plast;
	char *ptoken;
	char *language;
	char *pdb_storage;
	char temp_buff[1024];
	char temp_path[256];
	char url_buff[1024];
	char array_buff[16*1024];
	LIST_FILE *pfile;
	AREA_ITEM *pitem;
	
	
	if (FALSE == list_ui_get_self(url_buff, 1024)) {
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");
	if (NULL == pfile) {
		system_log_info("[list_ui]: fail to open list file %s",
			g_list_path);
		list_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	pitem = (AREA_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	
	offset = 0;
	for (i=0; i<item_num; i++) {
		if (0 != offset) {
			offset += snprintf(array_buff, 16*1024 - offset, ",'%s','%s'",
						pitem[i].master, pitem[i].slave);
		} else {
			offset = snprintf(array_buff, 16*1024, "'%s','%s'", pitem[i].master,
				pitem[i].slave);
		}

	}

	array_buff[offset] = '\0';
	
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
	printf(HTML_MAIN_5, url_buff, session);
	printf(url_buff);
	printf(HTML_MAIN_6, session,
		lang_resource_get(g_lang_resource,"MAIN_TYPE", language),
		lang_resource_get(g_lang_resource,"TYPE_USER", language),
		lang_resource_get(g_lang_resource,"TYPE_DOMAIN", language),
		lang_resource_get(g_lang_resource,"TYPE_MEDIA", language),
		lang_resource_get(g_lang_resource,"MAIN_MASTER", language),
		lang_resource_get(g_lang_resource,"MAIN_DB_STORAGE", language),
		lang_resource_get(g_lang_resource,"MAIN_SLAVE", language),
		lang_resource_get(g_lang_resource,"MAIN_SPACE", language),
		lang_resource_get(g_lang_resource,"MAIN_FILES", language),
		lang_resource_get(g_lang_resource,"ADD_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_MASTER", language),
		lang_resource_get(g_lang_resource,"MSGERR_SLAVE", language),
		lang_resource_get(g_lang_resource,"MSGERR_SPACE", language),
		lang_resource_get(g_lang_resource,"MSGERR_FILES", language), array_buff,
		lang_resource_get(g_lang_resource,"MSGERR_DUP", language));
	
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	
	printf(HTML_MAIN_7);
	
	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_USER_MASTER", language),
		lang_resource_get(g_lang_resource,"MAIN_DB_STORAGE", language),
		lang_resource_get(g_lang_resource,"MAIN_USER_SLAVE", language),
		lang_resource_get(g_lang_resource,"MAIN_SPACE", language),
		lang_resource_get(g_lang_resource,"MAIN_FILES", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_SPACE", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_FILES", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_USERS", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		if (0 != strcmp("USER", pitem[i].type)) {
			continue;
		}
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL == pdb_storage) {
			pdb_storage = "N/A";
		} else {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		files = -1;
		homes = -1;
		space = -1;
		sprintf(temp_path, "%s/pinfo", pitem[i].master);
		fd = open(temp_path, O_RDONLY);
		if (-1 != fd) {
			len = read(fd, temp_buff, 1024);
			if (len > 0) {
				temp_buff[len] = '\0';
				plast = temp_buff;
				ptoken = strchr(plast, 'M');
				if (NULL != ptoken) {
					*ptoken = '\0';
					space = atoi(plast);
					if (',' == *(ptoken + 1)) {
						ptoken ++;
					}
					plast = ptoken + 1;
				}
				ptoken = strchr(plast, 'C');
				if (NULL != ptoken) {
					*ptoken = '\0';
					files = atoi(plast);
					if (',' == *(ptoken + 1)) {
						ptoken ++;
					}
					plast = ptoken + 1;
				}
				ptoken = strchr(plast, 'H');
				if (NULL != ptoken) {
					*ptoken = '\0';
					homes = atoi(plast);
				}
			}
			close(fd);
		}

		if (-1 == files || -1 == space || -1 == homes) {
			printf(HTML_TBITEM_ERROR, pitem[i].master, pdb_storage, pitem[i].slave,
				pitem[i].space, pitem[i].files, lang_resource_get(g_lang_resource,"NUM_ERROR",
				language), lang_resource_get(g_lang_resource,"NUM_ERROR", language),
				lang_resource_get(g_lang_resource,"NUM_ERROR", language), 
				pitem[i].master, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		} else {
			printf(HTML_TBITEM_NORMAL, pitem[i].master, pdb_storage, pitem[i].slave,
				pitem[i].space, pitem[i].files, space, files, homes,
				pitem[i].master, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		}
	}

	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN_MASTER", language),
		lang_resource_get(g_lang_resource,"MAIN_DB_STORAGE", language),
		lang_resource_get(g_lang_resource,"MAIN_DOMAIN_SLAVE", language),
		lang_resource_get(g_lang_resource,"MAIN_SPACE", language),
		lang_resource_get(g_lang_resource,"MAIN_FILES", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_SPACE", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_FILES", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_DOMAINS", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		if (0 != strcmp("DOMAIN", pitem[i].type)) {
			continue;
		}
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL == pdb_storage) {
			pdb_storage = "N/A";
		} else {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		files = -1;
		homes = -1;
		space = -1;
		sprintf(temp_path, "%s/pinfo", pitem[i].master);
		fd = open(temp_path, O_RDONLY);
		if (-1 != fd) {
			len = read(fd, temp_buff, 1024);
			if (len > 0) {
				temp_buff[len] = '\0';
				plast = temp_buff;
				ptoken = strchr(plast, 'M');
				if (NULL != ptoken) {
					*ptoken = '\0';
					space = atoi(plast);
					if (',' == *(ptoken + 1)) {
						ptoken ++;
					}
					plast = ptoken + 1;
				}
				ptoken = strchr(plast, 'C');
				if (NULL != ptoken) {
					*ptoken = '\0';
					files = atoi(plast);
					if (',' == *(ptoken + 1)) {
						ptoken ++;
					}
					plast = ptoken + 1;
				}
				ptoken = strchr(plast, 'H');
				if (NULL != ptoken) {
					*ptoken = '\0';
					homes = atoi(plast);
				}
			}
			close(fd);
		}

		if (-1 == files || -1 == space || -1 == homes) {
			printf(HTML_TBITEM_ERROR, pitem[i].master, pdb_storage, pitem[i].slave,
				pitem[i].space, pitem[i].files, lang_resource_get(g_lang_resource,"NUM_ERROR",
				language), lang_resource_get(g_lang_resource,"NUM_ERROR", language),
				lang_resource_get(g_lang_resource,"NUM_ERROR", language), 
				pitem[i].master, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		} else {
			printf(HTML_TBITEM_NORMAL, pitem[i].master, pdb_storage, pitem[i].slave,
				pitem[i].space, pitem[i].files, space, files, homes,
				pitem[i].master, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		}
	}

	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"MAIN_MEDIA_MASTER", language),
		lang_resource_get(g_lang_resource,"MAIN_DB_STORAGE", language),
		lang_resource_get(g_lang_resource,"MAIN_MEDIA_SLAVE", language),
		lang_resource_get(g_lang_resource,"MAIN_SPACE", language),
		lang_resource_get(g_lang_resource,"MAIN_FILES", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_SPACE", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_FILES", language),
		lang_resource_get(g_lang_resource,"MAIN_USED_MEDIAS", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	for (i=0; i<item_num; i++) {
		if (0 != strcmp("MEDIA", pitem[i].type)) {
			continue;
		}
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL == pdb_storage) {
			pdb_storage = "N/A";
		} else {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		files = -1;
		homes = -1;
		space = -1;
		sprintf(temp_path, "%s/pinfo", pitem[i].master);
		fd = open(temp_path, O_RDONLY);
		if (-1 != fd) {
			len = read(fd, temp_buff, 1024);
			if (len > 0) {
				temp_buff[len] = '\0';
				plast = temp_buff;
				ptoken = strchr(plast, 'M');
				if (NULL != ptoken) {
					*ptoken = '\0';
					space = atoi(plast);
					if (',' == *(ptoken + 1)) {
						ptoken ++;
					}
					plast = ptoken + 1;
				}
				ptoken = strchr(plast, 'C');
				if (NULL != ptoken) {
					*ptoken = '\0';
					files = atoi(plast);
					if (',' == *(ptoken + 1)) {
						ptoken ++;
					}
					plast = ptoken + 1;
				}
				ptoken = strchr(plast, 'H');
				if (NULL != ptoken) {
					*ptoken = '\0';
					homes = atoi(plast);
				}
			}
			close(fd);
		}

		if (-1 == files || -1 == space || -1 == homes) {
			printf(HTML_TBITEM_ERROR, pitem[i].master, pdb_storage, pitem[i].slave,
				pitem[i].space, pitem[i].files, lang_resource_get(g_lang_resource,"NUM_ERROR",
				language), lang_resource_get(g_lang_resource,"NUM_ERROR", language),
				lang_resource_get(g_lang_resource,"NUM_ERROR", language), 
				pitem[i].master, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		} else {
			printf(HTML_TBITEM_NORMAL, pitem[i].master, pdb_storage, pitem[i].slave,
				pitem[i].space, pitem[i].files, space, files, homes,
				pitem[i].master, lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
		}
	}

	list_file_free(pfile);
	printf(HTML_MAIN_8);
}

static void	list_ui_add_item(int type, const char *master,
	const char *database, const char *slave, int space, int files)
{
	int len, fd;
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;
	int i, item_num;
	LIST_FILE *pfile;
	AREA_ITEM *pitem;
	char *pdb_storage;
	char temp_line[1024];
	

	if (type != TYPE_USER_AREA && type != TYPE_DOMAIN_AREA &&
		type != TYPE_MEDIA_AREA) {
		return;
	}
	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");
	if (NULL == pfile) {
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL != pdb_storage) {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		if (0 == strcmp(master, pitem[i].master) ||
			0 == strcmp(slave, pitem[i].slave) ||
			(NULL != pdb_storage && NULL != database
			&& 0 == strcmp(pdb_storage, database))) {
			list_file_free(pfile);
			return;
		}
	}
	list_file_free(pfile);
	fd = open(g_list_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		system_log_info("[list_ui]: fail to open %s in append mode",
			g_list_path);
		return;
	}
	if (NULL == database || '\0' == *database) {
		if (TYPE_USER_AREA == type) {
			len = sprintf(temp_line, "USER\t%s\t%s\t%d\t%d\n",
								master, slave, space, files);
		} else if (TYPE_DOMAIN_AREA == type) {
			len = sprintf(temp_line, "DOMAIN\t%s\t%s\t%d\t%d\n",
								master, slave, space, files);
		} else {
			len = sprintf(temp_line, "MEDIA\t%s\t%s\t%d\t%d\n",
								master, slave, space, files);
		}
	} else {
		if (TYPE_USER_AREA == type) {
			len = sprintf(temp_line, "USER\t%s:%s\t%s\t%d\t%d\n",
						master, database, slave, space, files);
		} else if (TYPE_DOMAIN_AREA == type) {
			len = sprintf(temp_line, "DOMAIN\t%s:%s\t%s\t%d\t%d\n",
							master, database, slave, space, files);
		} else {
			len = sprintf(temp_line, "MEDIA\t%s:%s\t%s\t%d\t%d\n",
							master, database, slave, space, files);
		}
	}
	write(fd, temp_line, len);
	close(fd);
	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[list_ui]: cannot open key for control\n");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 != ctrl_id) {
		ctrl_type = CTRL_RESTART_SCANNER;
		msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
	}
}

static void list_ui_remove_item(const char *master)
{
	int len, fd;
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;
	int i, item_num;
	LIST_FILE *pfile;
	AREA_ITEM *pitem;
	char *pdb_storage;
	char temp_path[256];
	char temp_line[1024];
	

	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");
	if (NULL == pfile) {
		return;
	}
	sprintf(temp_path, "%s.tmp", g_list_path);
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[list_ui]: fail to create %s", temp_path);
		list_file_free(pfile);
		return;
	}
	for (i=0; i<item_num; i++) {
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL != pdb_storage) {
			*pdb_storage = '\0';
		}
		if (0 == strcmp(pitem[i].master, master)) {
			continue;
		}
		len = sprintf(temp_line, "%s\t%s\t%s\t%d\t%d\n", pitem[i].type,
				pitem[i].master, pitem[i].slave, pitem[i].space,
				pitem[i].files);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	remove(g_list_path);
	link(temp_path, g_list_path);
	remove(temp_path);
	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[list_ui]: cannot open key for control\n");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 != ctrl_id) {
		ctrl_type = CTRL_RESTART_SCANNER;
		msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
	}
}

