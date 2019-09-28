#include "backup_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
#include "gateway_control.h"
#include "file_operation.h"
#include "list_file.h"
#include "config_file.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
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

/* fill blacklist title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE>\n\
<iframe src=\"\" style=\"display:none\" width=\"0\" height=\"0\" name=\"dummy_window\"></iframe>\n\
<BR><BR><SCRIPT language=\"JavaScript\">\n\
function RestoreItem(file) {\n\
dummy_window.location.href='%s?session=%s&restore=' + file;}\n\
function DeleteItem(file) {location.href='%s?session=%s&delete=' + file;}\n\
</SCRIPT><FORM class=SearchForm name=opeform method=get action="

#define HTML_MAIN_6	\
" ><TABLE border=0><INPUT type=hidden value=%s name=session />\n\
<INPUT type=hidden value=\"current\" name=backup />\n\
<TR><TD><INPUT type=submit value=\"  %s  \" /></TD></TR></TABLE></FORM>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\"\n\
border=0><TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill list table title here */

#define HTML_MAIN_7	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=3><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_MAIN_8	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_RESTORE_OK  \
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>ststem restored OK</TITLE>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\"\n\
</HEAD><BODY onload=\"alert('%s');\"> system restored OK </BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_NORMAL	\
"<TR class=ItemRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\n\
<A href=\"javascript:RestoreItem('%s')\">%s</A> | \
<A href=\"javascript:DeleteItem('%s')\">%s</A></TD></TR>\n"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define UNIT_BYTE       1
#define UNIT_KILO       2
#define UNIT_MEGA       3
#define UNIT_SECOND     1
#define UNIT_MINUTE     2
#define UNIT_HOUR       3

#define TOKEN_CONTROL               100
#define CTRL_RESTART_SUPERVISOR     2
#define CTRL_RESTART_ADAPTOR        3
#define CTRL_RESTART_SCANNER        4
#define CTRL_RESTART_LOCKER         5

static void backup_ui_error_html(const char *error_string);

static void backup_ui_main_html(const char *session);

static void backup_ui_restore_html(const char *file_name);

static void backup_ui_restore_error(const char *error_string);

static void backup_ui_delete_file(const char *file_name);

static void backup_ui_backup_file();

static void backup_ui_restart_supervisor();

static void backup_ui_restart_adaptor();

static void backup_ui_restart_scanner();

static void backup_ui_restart_locker();

static BOOL backup_ui_get_self(char *url_buff, int length);

static void backup_ui_encode_line(const char *in, char *out);

static void backup_ui_unencode(char *src, char *last, char *dest);

static char g_data_path[256];
static char g_mount_path[256];
static char g_backup_path[256];
static char g_config_path[256];
static char g_token_path[256];
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void backup_ui_init(const char *backup_path, const char *config_path,
	const char *data_path, const char *mount_path, const char *token_path,
	const char *url_link, const char *resource_path)
{
	strcpy(g_backup_path, backup_path);
	strcpy(g_config_path, config_path);
	strcpy(g_data_path, data_path);
	strcpy(g_mount_path, mount_path);
	strcpy(g_token_path, token_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int backup_ui_run()
{
	int len;
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char session[256];
	char username[256];
	char search_buff[1024];
	char temp_file[256];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		backup_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[backup_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[backup_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[backup_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[backup_ui]: fail to get QUERY_STRING "
				"environment!");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 1024) {
				system_log_info("[backup_ui]: query string too long!");
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			backup_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[backup_ui]: query string of GET "
					"format error");
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = strchr(ptr1, '&');
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 256) {
					system_log_info("[backup_ui]: query string of GET "
						"format error");
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_IGNORE)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				default:
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}

				if (FALSE == acl_control_naming(session, username) ||
					0 != strcasecmp(username, "administrator")) {
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				}
				
				backup_ui_main_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[backup_ui]: query string of GET "
					"format error");
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			if (0 == strncasecmp(ptr2, "&restore=", 9)) {
				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_IGNORE)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					backup_ui_restore_error(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				default:
					backup_ui_restore_error(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}

				if (FALSE == acl_control_naming(session, username) ||
					0 != strcasecmp(username, "administrator")) {
					backup_ui_restore_error(lang_resource_get(g_lang_resource,
						"ERROR_PRIVILEGE", language));
					return 0;
				}
				ptr1 = ptr2 + 9;
				if (search_buff + len - ptr1 - 1 > 256 ||
					search_buff + len - ptr1 - 1 == 0) {
					system_log_info("[backup_ui]: query string of GET "
						"format error");
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_file, ptr1, search_buff + len - ptr1 - 1);
				temp_file[search_buff + len - ptr1 - 1] = '\0';
				backup_ui_restore_html(temp_file);
			} else if (0 == strncasecmp(ptr2, "&delete=", 8)) {
				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_IGNORE)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				default:
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}

				if (FALSE == acl_control_naming(session, username) ||
					0 != strcasecmp(username, "administrator")) {
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				}
				ptr1 = ptr2 + 8;
				if (search_buff + len - ptr1 - 1 > 256 ||
					search_buff + len - ptr1 - 1 == 0) {
					system_log_info("[backup_ui]: query string of GET "
						"format error");
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(temp_file, ptr1, search_buff + len - ptr1 - 1);
				temp_file[search_buff + len - ptr1 - 1] = '\0';
				backup_ui_delete_file(temp_file);
				backup_ui_main_html(session);
			} else if (0 == strncasecmp(ptr2, "&backup=", 8)) {
				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_IGNORE)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				default:
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}

				if (FALSE == acl_control_naming(session, username) ||
					0 != strcasecmp(username, "administrator")) {
					backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				}
				backup_ui_backup_file();
				backup_ui_main_html(session);
			} else {
				system_log_info("[backup_ui]: query string of GET "
					"format error");
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
			}
			return 0;
		}
	} else {
		system_log_info("[backup_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int backup_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void backup_ui_free()
{
	/* do nothing */
}

static BOOL backup_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[backup_ui]: fail to get "
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

static void backup_ui_error_html(const char *error_string)
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

static void backup_ui_main_html(const char *session)
{
	DIR *dirp;
	char *language;
	char url_buff[1024];
	char temp_buff[1024];
	struct tm temp_tm, *ptm;
	struct dirent *direntp;
	
	
	if (FALSE == backup_ui_get_self(url_buff, 1024)) {
		backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		return;
	}
	
	dirp = opendir(g_backup_path);
	if (NULL == dirp){
		backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
		system_log_info("[backup_ui]: fail to open directory %s\n",
			g_backup_path);
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
	printf(HTML_MAIN_5, url_buff, session, url_buff, session);
	printf(url_buff);
	printf(HTML_MAIN_6, session,
		lang_resource_get(g_lang_resource,"BACKUP_LABEL", language));
	printf(lang_resource_get(g_lang_resource,"MAIN_TABLE_TITLE", language));
	printf(HTML_MAIN_7);
	printf(HTML_TBITEM_FIRST, lang_resource_get(g_lang_resource,"MAIN_TIME", language),
		lang_resource_get(g_lang_resource,"MAIN_OPERATION", language));
	
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		memset(&temp_tm, 0, sizeof(temp_tm));
		strptime(direntp->d_name, "%Y-%m-%d-%H-%M-%S.tgz", &temp_tm);
		strftime(temp_buff, 1024, lang_resource_get(g_lang_resource,"MAIN_TIME_FORMAT",
			language), &temp_tm);
		printf(HTML_TBITEM_NORMAL, temp_buff, direntp->d_name,
			lang_resource_get(g_lang_resource,"RESTORE_LABEL", language), direntp->d_name,
			lang_resource_get(g_lang_resource,"DELETE_LABEL", language));
	}
	closedir(dirp);
	printf(HTML_MAIN_8);
}

static void backup_ui_delete_file(const char *file_name)
{
	char temp_path[256];

	sprintf(temp_path, "%s/%s", g_backup_path, file_name);
	remove(temp_path);
	
	return;
}

static void backup_ui_restore_html(const char *file_name)
{
	char *pitem;
	char *str_value1;
	char *str_value2;
	char *str_value3;
	char *str_value4;
	char *str_value5;
	char *str_value6;
	char *language;
	const char *charset;
	int item_num;
	int unit_num;
	int i, fd, fd1, len;
	char src_file[256];
	char dst_dir[256];
	char dst_file[256];
	char temp_file[256];
	char temp_file1[256];
	char temp_line[2048];
	char temp_buff[2048];
	LIST_FILE *pfile;
	CONFIG_FILE *pconfig;
	
	sprintf(dst_dir, "%s/data_files", g_backup_path);
	mkdir(dst_dir, 0777);
	snprintf(dst_file, 256, "%s/%s", g_backup_path, file_name);
	file_operation_decompress(dst_file, dst_dir);

	
AREA_LIST:
	sprintf(src_file, "%s/data_files/area_list.txt", g_backup_path);
	sprintf(dst_file, "%s/area_list.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);

ARCHIVER_LIST:
	sprintf(src_file, "%s/data_files/cidb_list.txt", g_backup_path);
	sprintf(dst_file, "%s/cidb_list.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(dst_file, "data/delivery/cidb_list.txt");
	
BOUNDARY_LIST:
	sprintf(src_file, "%s/data_files/boundary_blacklist.txt", g_backup_path);
	sprintf(dst_file, "%s/boundary_blacklist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init bounday list file\n");
		goto DNS_TABLE;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto DNS_TABLE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		sprintf(temp_line, "%s\n", pitem + i * (2 * 256 + sizeof(long)));
		backup_ui_encode_line(temp_line, temp_buff);
		len = strlen(temp_buff);
		write(fd, temp_buff, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/boundary_list.txt");

DNS_TABLE:
	sprintf(src_file, "%s/data_files/dns_table.txt", g_backup_path);
	sprintf(dst_file, "%s/dns_table.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%s:8%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init dns list file\n");
		goto DOMAIN_BLACKLIST;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto DOMAIN_BLACKLIST;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\t%s\t%s\n",
				pitem + i * (2 * 256 + 8) + 256,
				pitem + i * (2 * 256 + 8),
				pitem + i * (2 * 256 + 8) + 256 + 8);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/dns_adaptor.txt");

DOMAIN_BLACKLIST:
	sprintf(src_file, "%s/data_files/domain_blacklist.txt", g_backup_path);
	sprintf(dst_file, "%s/domain_blacklist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init domain black list file\n");
		goto DOMAIN_MAILBOX;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto DOMAIN_MAILBOX;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n",
				pitem + i * (2 * 256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/forbidden_domain.txt");

DOMAIN_MAILBOX:
	sprintf(src_file, "%s/data_files/domain_mailbox.txt", g_backup_path);
	sprintf(dst_file, "%s/domain_mailbox.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init domain mailbox list file\n");
		goto DOMAIN_WHITELIST;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto DOMAIN_WHITELIST;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\t%s\n",
				pitem + 3*256*i, pitem + 3*256*i + 256);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/domain_mailbox.txt");

DOMAIN_WHITELIST:
	sprintf(src_file, "%s/data_files/domain_whitelist.txt", g_backup_path);
	sprintf(dst_file, "%s/domain_whitelist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init domain white list file\n");
		goto DYNAMIC_LIST;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto DYNAMIC_LIST;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n",
				pitem + i * (2 * 256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/domain_whitelist.txt");

DYNAMIC_LIST:
	sprintf(src_file, "%s/data_files/dynamic_dnslist.txt", g_backup_path);
	sprintf(dst_file, "%s/dynamic_dnslist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init dynamic domain list file\n");
		goto FORWARD_TABLE;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto FORWARD_TABLE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n",
				pitem + i * (2 * 256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/ddns_filter.txt");

FORWARD_TABLE:
	sprintf(src_file, "%s/data_files/forward_table.txt", g_backup_path);
	sprintf(dst_file, "%s/forward_table.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%s:12%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init forward table file\n");
		goto FROM_BLACKLIST;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto FROM_BLACKLIST;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "F_%s\t%s\t%s\n",
					pitem + i * (2 * 256 + 12) + 256,
					pitem + i * (2 * 256 + 12),
					pitem + i * (2 * 256 + 12) + 256 + 12);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/mail_forwarder.txt");

FROM_BLACKLIST:
	sprintf(src_file, "%s/data_files/from_blacklist.txt", g_backup_path);
	sprintf(dst_file, "%s/from_blacklist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init from black list file\n");
		goto FROM_REPLACE;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto FROM_REPLACE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n",
				pitem + i * (2 * 256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/forbidden_from.txt");

FROM_REPLACE:
	sprintf(src_file, "%s/data_files/from_replace.txt", g_backup_path);
	sprintf(dst_file, "%s/from_replace.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init from black list file\n");
		goto IP_GREYLIST;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto IP_GREYLIST;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\t%s\n",
				pitem + 3*256*i, pitem + 3*256*i + 256);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/from_replace.txt");

IP_GREYLIST:
	sprintf(src_file, "%s/data_files/ip_whitelist.txt", g_backup_path);
	sprintf(dst_file, "%s/ip_whitelist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:16%l%s:8%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init ip white list file\n");
		goto IPDOMAIN_TABLE;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto IPDOMAIN_TABLE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcmp("ABS", pitem + i * (8 + 16 + 256 + sizeof(long)) +
			16 + sizeof(long))) {
			len = sprintf(temp_line, "%s\n",
					pitem + i * (8 + 16 + 256 + sizeof(long)));
			write(fd, temp_line, len);
		}
	}
	close(fd);
	file_operation_broadcast(temp_file, "data/smtp/relay_list.txt");
	
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto IPDOMAIN_TABLE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		if (0 != strcmp("ABS", pitem + i * (8 + 16 + 256 + sizeof(long)) +
			16 + sizeof(long))) {
			len = sprintf(temp_line, "%s\n",
					pitem + i * (8 + 16 + 256 + sizeof(long)));
			write(fd, temp_line, len);
		}
	}
	close(fd);
	file_operation_broadcast(temp_file, "data/smtp/ip_whitelist.txt");
	
	fd = open(temp_file, O_TRUNC|O_WRONLY, DEF_MODE);	
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto IPDOMAIN_TABLE;
	}
	for (i=0; i<item_num; i++) {
		if (0 == strcmp("EXT", pitem + i * (8 + 16 + 256 + sizeof(long)) + 
			16 + sizeof(long))) {
			len = sprintf(temp_line, "%s\t1\t0second\n",
					pitem + i * (8 + 16 + 256 + sizeof(long)));
			write(fd, temp_line, len);
		}
	}
	list_file_free(pfile);

	sprintf(src_file, "%s/data_files/ip_blacklist.txt", g_backup_path);
	sprintf(dst_file, "%s/ip_blacklist.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:16%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init ip black list file\n");
		close(fd);
		goto IPDOMAIN_TABLE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\t0\t0second\n",
				pitem + i * (16 + 256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/ip_filter.txt");

IPDOMAIN_TABLE:
	sprintf(src_file, "%s/data_files/ipdomain_table.txt", g_backup_path);
	sprintf(dst_file, "%s/ipdomain_table.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%s:8%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init ip-domain list file\n");
		goto KEYWORD_GROUP;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto KEYWORD_GROUP;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "M_%s\t%s\t%s\n",
				pitem + i * (2 * 256 + 8) + 256, pitem + (i * (2 * 256 + 8)),
				pitem + i * (2 * 256 + 8) + 256 + 8);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/site_protection.txt");

KEYWORD_GROUP:
	sprintf(src_file, "%s/data_files/keyword_group.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_group.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init keyword group list file\n");
		goto KEYWORD_UPLOAD;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto KEYWORD_UPLOAD;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n", pitem + i *(256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/anonymous_keyword/keyword.txt");

KEYWORD_UPLOAD:
	sprintf(src_file, "%s/data_files/keyword_subject.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_subject.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(src_file, "data/smtp/keyword_filter/subject.txt");
	
	sprintf(src_file, "%s/data_files/keyword_from.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_from.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(src_file, "data/smtp/keyword_filter/from.txt");
	
	sprintf(src_file, "%s/data_files/keyword_to.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_to.txx", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(src_file, "data/smtp/keyword_filter/to.txt");

	sprintf(src_file, "%s/data_files/keyword_cc.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_cc.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(src_file, "data/smtp/keyword_filter/cc.txt");
	
	sprintf(src_file, "%s/data_files/keyword_content.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_content.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(src_file, "data/smtp/keyword_filter/content.txt");
	
	sprintf(src_file, "%s/data_files/keyword_attachment.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_attachment.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(src_file, "data/smtp/keyword_filter/attachment.txt");
	
	sprintf(src_file, "%s/data_files/keyword_charset.txt", g_backup_path);
	sprintf(dst_file, "%s/keyword_charset.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);
	file_operation_broadcast(src_file, "data/smtp/keyword_filter/charset.txt");

MESSAGE_SIGN:
	sprintf(src_file, "%s/data_files/system_sign", g_backup_path);
	sprintf(dst_file, "%s/system_sign", g_data_path);
	file_operation_copy_dir(src_file, dst_file);
	file_operation_broadcast_dir(src_file, "data/delivery/system_sign");
	
RCPT_BLACKLIST:
	sprintf(src_file, "%s/data_files/rcpt_blacklist.txt", g_backup_path);
	sprintf(dst_file, "%s/rcpt_blacklist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init rcpt black list file\n");
		goto RELAY_ALLOW;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto RELAY_ALLOW;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n",
				pitem + i * (2 * 256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/forbidden_rcpt.txt");

RELAY_ALLOW:
	sprintf(src_file, "%s/data_files/relay_allow.txt", g_backup_path);
	sprintf(dst_file, "%s/relay_allow.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:16%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init relay allow list file\n");
		goto RELAY_DOMAINS;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto RELAY_DOMAINS;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n", pitem + i * (16 + 256));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/relay_allow.txt");
	
RELAY_DOMAINS:
	sprintf(src_file, "%s/data_files/relay_domains.txt", g_backup_path);
	sprintf(dst_file, "%s/relay_domains.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init relay domains list file\n");
		goto RELAY_TABLE;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto RELAY_TABLE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n", pitem + i * (2 * 256));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/relay_domains.txt");

RELAY_TABLE:
	sprintf(src_file, "%s/data_files/relay_table.txt", g_backup_path);
	sprintf(dst_file, "%s/relay_table.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:16%s:256%d%d");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init relay service list file\n");
		goto SINGLE_RCPT;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto SINGLE_RCPT;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s:%d\t%d\n",
				pitem + i * (16 + 256 + 2*sizeof(int)),
				*(int*)(pitem + i * (16 + 256 + 2*sizeof(int)) + 16 + 256),
				*(int*)(pitem + i * (16 + 256 + 2*sizeof(int)) + 16 + 256 + sizeof(int)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/relay_agent.txt");

SINGLE_RCPT:
	sprintf(src_file, "%s/data_files/single_rcpt.txt", g_backup_path);
	sprintf(dst_file, "%s/single_rcpt.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init single rcpt file\n");
		goto SUPERVISING_LIST;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto SUPERVISING_LIST;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n", pitem + i * (2 * 256));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/delivery/single_rcpt.txt");

	
SUPERVISING_LIST:
	sprintf(src_file, "%s/data_files/supervising_list.txt", g_backup_path);
	sprintf(dst_file, "%s/supervising_list.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);

SYSTEM_USERS:
	sprintf(src_file, "%s/data_files/system_users.txt", g_backup_path);
	sprintf(dst_file, "%s/system_users.txt", g_data_path);
	file_operation_copy_file(src_file, dst_file);

TAGGING_WHITELIST:
	sprintf(src_file, "%s/data_files/tagging_whitelist.txt", g_backup_path);
	sprintf(dst_file, "%s/tagging_whitelist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:256%l%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to tagging white list file\n");
		goto XMAILER_LIST;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto XMAILER_LIST;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n",
				pitem + i * (2 * 256 + sizeof(long)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/tagging_table.txt");

XMAILER_LIST:
	sprintf(src_file, "%s/data_files/xmailer_blacklist.txt", g_backup_path);
	sprintf(dst_file, "%s/xmailer_blacklist.txt", g_data_path);
	sprintf(temp_file, "%s/data_files/temp.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	pfile = list_file_init(src_file, "%s:64%l%s:8%s:256");
	if (NULL == pfile) {
		system_log_info("[backup_ui]: fail to init xmailer black list file\n");
		goto SYSTEM_SETUP;
	}
	fd = open(temp_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		system_log_info("[backup_ui]: fail to create temporary file\n");
		list_file_free(pfile);
		goto SYSTEM_SETUP;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		backup_ui_encode_line(pitem + i * (64 + sizeof(long) + 8 + 256), temp_buff);
		len = sprintf(temp_line, "M_%s\t%s\n",
				pitem + i * (64 + sizeof(long) + 8 + 256) + 64 + sizeof(long), temp_buff);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
	file_operation_broadcast(temp_file, "data/smtp/xmailer_filter.txt");

SYSTEM_SETUP:
	sprintf(src_file, "%s/data_files/athena.cfg", g_backup_path);
	file_operation_copy_file(src_file, g_config_path);

	pconfig = config_file_init(g_config_path);
	if (NULL == pconfig) {
		system_log_info("[backup_ui]: fail to init config file\n");
		goto CONSOLE_FLUSH;
	}
	
	str_value1 = config_file_get_value(pconfig, "SMTP_SESSION_MAIL_NUM");
	if (NULL != str_value1) {
		sprintf(temp_line, "smtp set max-mails %s", str_value1);
		gateway_control_notify(temp_line, NOTIFY_SMTP);
	}
	str_value1 = config_file_get_value(pconfig, "SMTP_MAX_RCPT_NUM");
	if (NULL != str_value1) {
		sprintf(temp_line, "rcpt_limit.pas set max-rcpt %s", str_value1);
		gateway_control_notify(temp_line, NOTIFY_SMTP);
	}
	str_value1 = config_file_get_value(pconfig, "SMTP_MAIL_LEN_NUM");
	str_value2 = config_file_get_value(pconfig, "SMTP_MAIL_LEN_UNIT");
	if (NULL != str_value1 && NULL != str_value2) {
		unit_num = atoi(str_value2);
		switch (unit_num) {
		case UNIT_KILO:
			sprintf(temp_line, "smtp set mail-length %sK", str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MEGA:
			sprintf(temp_line, "smtp set mail-length %sM", str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "SMTP_TIMEOUT_NUM");
	str_value2 = config_file_get_value(pconfig, "SMTP_TIMEOUT_UNIT");
	if (NULL != str_value1 && NULL != str_value2) {
		unit_num = atoi(str_value2);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "smtp set time-out %sseconds", str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "smtp set time-out %sminutes", str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "VIRUS_SCANNING_NUM");
	str_value2 = config_file_get_value(pconfig, "VIRUS_SCANNING_UNIT");
	if (NULL != str_value1 && NULL != str_value2) {
		unit_num = atoi(str_value2);
		switch (unit_num) {
		case UNIT_BYTE:
			sprintf(temp_line, "flusher set scanning-size %s", str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_KILO:
			sprintf(temp_line, "flusher set scanning-size %sK", str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MEGA:
			sprintf(temp_line, "flusher set scanning-size %sM", str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "CONNECTION_TIMES");
	str_value2 = config_file_get_value(pconfig, "CONNECTION_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "CONNECTION_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "ip_filter.svc audit set %s/%s", str_value1,
				str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "ip_filter.svc audit set %s/%sminutes",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "INMAIL_TIMES");
	str_value2 = config_file_get_value(pconfig, "INMAIL_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "INMAIL_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "inmail_frequency_audit.svc audit set %s/%s",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "inmail_frequency_audit.svc audit set %s/%s"
				"minutes", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "inmail_frequency_audit.svc audit set %s/%s"
				"hours", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "OUTMAIL_TIMES");
	str_value2 = config_file_get_value(pconfig, "OUTMAIL_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "OUTMAIL_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "outmail_frequency_audit.svc audit set %s/%s",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "outmail_frequency_audit.svc audit set %s/%s"
				"minutes", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "outmail_frequency_audit.svc audit set %s/%s"
				"hours", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "LIMITATION_TIMES");
	str_value2 = config_file_get_value(pconfig, "LIMITATION_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "LIMITATION_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "outmail_limitation_audit.svc audit set %s/%s",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "outmail_limitation_audit.svc audit set %s/%s"
				"minutes", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "outmail_limitation_audit.svc audit set %s/%s"
				"hours", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "EMPTYADDR_TIMES");
	str_value2 = config_file_get_value(pconfig, "EMPTYADDR_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "EMPTYADDR_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "mail_from_audit.svc audit set %s/%s",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "mail_from_audit.svc audit set %s/%sminutes",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "mail_from_audit.svc audit set %s/%shours",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "SPECPROTECT_TIMES");
	str_value2 = config_file_get_value(pconfig, "SPECPROTECT_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "SPECPROTECT_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "special_protection_audit.svc audit set %s/%s",
				str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "special_protection_audit.svc audit set %s/%s"
				"minutes", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "special_protection_audit.svc audit set %s/%s"
				"hours", str_value1, str_value2);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "SUBSYSTEM_RETRING_TIMES");
	str_value2 = config_file_get_value(pconfig, "SUBSYSTEM_RETRING_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "SUBSYSTEM_RETRING_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "domain_subsystem.hook set times %s",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			sprintf(temp_line, "domain_subsystem.hook set interval %s",
				str_value2);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "domain_subsystem.hook set times %s",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			sprintf(temp_line, "domain_subsystem.hook set interval %sminutes",
				str_value2);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "domain_subsystem.hook set times %s",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			sprintf(temp_line, "domain_subsystem.hook set interval %shours",
				str_value2);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "LOCAL_RETRING_TIMES");
	str_value2 = config_file_get_value(pconfig, "LOCAL_RETRING_INTERVAL_NUM");
	str_value3 = config_file_get_value(pconfig, "LOCAL_RETRING_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3) {
		unit_num = atoi(str_value3);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "maildir_local.hook set retrying-times %s",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			sprintf(temp_line, "maildir_local.hook set cache-scan %s",
				str_value2);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "maildir_local.hook set retrying-times %s",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			sprintf(temp_line, "maildir_local.hook set cache-scan %sminutes",
				str_value2);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "maildir_local.hook set retrying-times %s",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			sprintf(temp_line, "maildir_local.hook set cache-scan %shours",
				str_value2);
			gateway_control_notify(temp_line, NOTIFY_DELIVERY);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "DELIVERY_FIRST_INTERVAL_NUM");
	str_value2 = config_file_get_value(pconfig, "DELIVERY_FIRST_INTERVAL_UNIT");
	str_value3 = config_file_get_value(pconfig, "DELIVERY_SECOND_INTERVAL_NUM");
	str_value4 = config_file_get_value(pconfig, "DELIVERY_SECOND_INTERVAL_UNIT");
	str_value5 = config_file_get_value(pconfig, "DELIVERY_THIRD_INTERVAL_NUM");
	str_value6 = config_file_get_value(pconfig, "DELIVERY_THIRD_INTERVAL_UNIT");
	if (NULL != str_value1 && NULL != str_value2 && NULL != str_value3 &&
		NULL != str_value4 && NULL != str_value5 && NULL != str_value6) {
		unit_num = atoi(str_value2);
		switch (unit_num) {
		case UNIT_MINUTE:
			len = sprintf(temp_line, "remote_postman.hook set timer-intervals "
					"1minute %sminutes ", str_value1);
			break;
		case UNIT_HOUR:
			len = sprintf(temp_line, "remote_postman.hook set timer-intervals "
					"1minute %shours ", str_value1);
			break;
		}
		unit_num = atoi(str_value4);
		switch (unit_num) {
		case UNIT_MINUTE:
			len += sprintf(temp_line + len, "%sminutes ", str_value3);
			break;
		case UNIT_HOUR:
			len += sprintf(temp_line + len, "%shours ", str_value3);
			break;
		}
		unit_num = atoi(str_value6);
		switch (unit_num) {
		case UNIT_MINUTE:
			len += sprintf(temp_line + len, "%sminutes", str_value5);
			break;
		case UNIT_HOUR:
			len += sprintf(temp_line + len, "%shours", str_value5);
			break;
		}
		gateway_control_notify(temp_line, NOTIFY_DELIVERY);
	}
	str_value1 = config_file_get_value(pconfig, "DELIVERY_RETRYING_TIMES");
	if (NULL != str_value1) {
		sprintf(temp_line, "remote_postman.hook set trying-times %s",
			str_value1);
		gateway_control_notify(temp_line, NOTIFY_DELIVERY);
	}
	str_value1 = config_file_get_value(pconfig, "ANTISPAM_RETRYING_MIN_NUM");
	str_value2 = config_file_get_value(pconfig, "ANTISPAM_RETRYING_MIN_UNIT");
	if (NULL != str_value1 && NULL != str_value2) {
		unit_num = atoi(str_value2);
		switch (unit_num) {
		case UNIT_SECOND:
			sprintf(temp_line, "retrying_table.svc set min-interval %s",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_MINUTE:
			sprintf(temp_line, "retrying_table.svc set min-interval %sminutes",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}
	str_value1 = config_file_get_value(pconfig, "ANTISPAM_RETRYING_MAX_NUM");
	str_value2 = config_file_get_value(pconfig, "ANTISPAM_RETRYING_MAX_UNIT");
	if (NULL != str_value1 && NULL != str_value2) {
		unit_num = atoi(str_value2);
		switch (unit_num) {
		case UNIT_MINUTE:
			sprintf(temp_line, "retrying_table.svc set valid-interval %sminutes",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		case UNIT_HOUR:
			sprintf(temp_line, "retrying_table.svc set valid-interval %shours",
				str_value1);
			gateway_control_notify(temp_line, NOTIFY_SMTP);
			break;
		}
	}

	str_value1 = config_file_get_value(pconfig, "ANTISPAM_URIRBL_POLICY");
	if (NULL != str_value1) {
		if (0 == strcasecmp(str_value1, "TRUE")) {
			strcpy(temp_line, "uri_rbl.pas set immediate-reject TRUE");
		} else {
			strcpy(temp_line, "uri_rbl.pas set immediate-reject FALSE");
		}
		gateway_control_notify(temp_line, NOTIFY_SMTP);
	}

	str_value1 = config_file_get_value(pconfig, "OVERSEA_RELAY_SWITCH");
	if (NULL != str_value1) {
		if (0 == strcasecmp(str_value1, "TRUE")) {
			strcpy(temp_line, "relay_agent.hook switch ON");
		} else {
			strcpy(temp_line, "relay_agent.hook switch OFF");
		}
		gateway_control_notify(temp_line, NOTIFY_DELIVERY);
	}

	str_value1 = config_file_get_value(pconfig, "LOG_VALID_DAYS");
	if (NULL != str_value1) {
		sprintf(temp_line, "log_plugin.svc set valid-days %s", str_value1);
		gateway_control_notify(temp_line, NOTIFY_SMTP|NOTIFY_DELIVERY);
	}
	str_value1 = config_file_get_value(pconfig, "DEFAULT_DOMAIN");
	if (NULL != str_value1) {
		sprintf(temp_line, "system set default-domain %s", str_value1);
		gateway_control_notify(temp_line, NOTIFY_SMTP|NOTIFY_DELIVERY);
	}
	str_value1 = config_file_get_value(pconfig, "ADMIN_MAILBOX");
	if (NULL != str_value1) {
		sprintf(temp_line, "system set admin-mailbox %s", str_value1);
		gateway_control_notify(temp_line, NOTIFY_DELIVERY);
	}

	config_file_free(pconfig);	

CONSOLE_FLUSH:
	gateway_control_notify("archive_agent.hook reload", NOTIFY_DELIVERY);
	gateway_control_notify("boundary_list.svc reload", NOTIFY_SMTP);
	gateway_control_notify("dns_adaptor.svc reload fixed", NOTIFY_DELIVERY);
	gateway_control_notify("forbidden_domain.svc reload", NOTIFY_SMTP);
	gateway_control_notify("domain_mailbox.hook reload", NOTIFY_DELIVERY);
	gateway_control_notify("domain_whitelist.svc reload", NOTIFY_SMTP);
	gateway_control_notify("ddns_filter.pas reload", NOTIFY_SMTP);
	gateway_control_notify("mail_forwarder.hook reload", NOTIFY_DELIVERY);
	gateway_control_notify("forbidden_from.svc reload", NOTIFY_SMTP);
	gateway_control_notify("from_replace.hook reload", NOTIFY_DELIVERY);
	gateway_control_notify("ip_filter.svc grey-list reload", NOTIFY_SMTP);
	gateway_control_notify("ip_whitelist.svc reload", NOTIFY_SMTP);
	gateway_control_notify("relay_list.svc reload", NOTIFY_SMTP);
	gateway_control_notify("site_protection.pas reload", NOTIFY_SMTP);
	gateway_control_notify("anonymous_keyword.hook reload", NOTIFY_DELIVERY);
	gateway_control_notify("keyword_filter.pas charset reload", NOTIFY_SMTP);
	gateway_control_notify("forbidden_rcpt.svc reload", NOTIFY_SMTP);
	gateway_control_notify("system_sign.hook reload", NOTIFY_DELIVERY);
	gateway_control_notify("relay_domains.svc reload", NOTIFY_DELIVERY);
	gateway_control_notify("relay_agent.hook reload agent", NOTIFY_DELIVERY);
	gateway_control_notify("relay_agent.hook reload allow", NOTIFY_DELIVERY);
	gateway_control_notify("single_rcpt.svc reload", NOTIFY_DELIVERY);
	gateway_control_notify("tagging_table.svc reload", NOTIFY_SMTP);
	gateway_control_notify("xmailer_filter.pas reload", NOTIFY_SMTP);

	backup_ui_restart_adaptor();
	backup_ui_restart_supervisor();
	backup_ui_restart_scanner();
	backup_ui_restart_locker();
	file_operation_remove_dir(dst_dir);

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_RESTORE_OK, charset,
		lang_resource_get(g_lang_resource,"MSGERR_RESTORED", language));
	
}

static void backup_ui_restore_error(const char *error_string)
{
	char *language;
	const char *charset;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_RESTORE_OK, charset, error_string);
}

static void backup_ui_backup_file()
{
	char temp_buff[256];
	char dst_dir[256];
	char src_file[256];
	char dst_file[256];
	time_t now_time;
	struct tm *ptm;

	time(&now_time);
	sprintf(dst_dir, "%s/data_files", g_backup_path);
	mkdir(dst_dir, 0777);

	sprintf(src_file, "%s/area_list.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/area_list.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/cidb_list.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/cidb_list.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/boundary_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/boundary_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/dns_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/dns_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/domain_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/domain_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/domain_mailbox.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/domain_mailbox.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/domain_whitelist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/domain_whitelist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/dynamic_dnslist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/dynamic_dnslist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/forward_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/forward_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/from_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/from_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/from_replace.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/from_replace.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/ip_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/ip_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/ip_whitelist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/ip_whitelist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/ipdomain_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/ipdomain_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/keyword_group.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_group.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/keyword_charset.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_charset.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_subject.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_subject.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_from.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_from.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_to.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_to.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_cc.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_cc.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_content.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_content.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_attachment.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_attachment.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/system_sign", g_data_path);
	sprintf(dst_file, "%s/data_files/system_sign", g_backup_path);
	file_operation_copy_dir(src_file, dst_file);

	sprintf(src_file, "%s/rcpt_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/rcpt_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/relay_allow.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/relay_allow.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/relay_domains.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/relay_domains.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/relay_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/relay_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/single_rcpt.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/single_rcpt.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/supervising_list.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/supervising_list.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/system_users.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/system_users.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/tagging_whitelist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/tagging_whitelist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/xmailer_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/xmailer_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(dst_file, "%s/data_files/athena.cfg", g_backup_path);
	file_operation_copy_file(g_config_path, dst_file);
	
	strftime(temp_buff, 256, "%Y-%m-%d-%H-%M-%S", localtime(&now_time));
	sprintf(dst_file, "%s/%s.tgz", g_backup_path, temp_buff);
	file_operation_compress(dst_dir, dst_file);
	file_operation_remove_dir(dst_dir);
}

static void backup_ui_restart_supervisor()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;

	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[backup_ui]: cannot open key for control\n");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_SUPERVISOR;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

static void backup_ui_restart_adaptor()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;

	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[backup_ui]: cannot open key for control\n");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_ADAPTOR;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

static void backup_ui_restart_scanner()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;

	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[backup_ui]: cannot open key for control\n");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_SCANNER;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

static void backup_ui_restart_locker()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;

	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[backup_ui]: cannot open key for control\n");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_LOCKER;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

static void backup_ui_unencode(char *src, char *last, char *dest)
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

static void backup_ui_encode_line(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if (' ' == in[i] || '\\' == in[i] || '\t' == in[i] || '#' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

