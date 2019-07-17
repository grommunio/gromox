#include "setup_ui.h"
#include "lang_resource.h"
#include "system_log.h"
#include "acl_control.h"
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

/* fill setup title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_MAIN_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<iframe src=\"\" style=\"display:none\" width=\"0\" height=\"0\" name=\"dummy_window\"></iframe>\n\
<FORM class=SearchForm name=opeform onSubmit=\"return false\">\n\
<TABLE border=0 width=\"90%\"><TR>\n\
<TD>%s: <SELECT tabindex=1 name=enable_switch>"

#define OPTION_SELECT		"<OPTION value=%d selected>%s</OPTION>"

#define OPTION_NORMAL		"<OPTION value=%d>%s</OPTION>"

#define HTML_MAIN_6	\
"</SELECT></TD><TD>%s: <INPUT type=text size=16 tabindex=2 name=master_ip \n\
value=\"%s\"></TD><TD><INPUT type=submit tabindex=3 value=\"    %s    \" \n\
onclick=\"var scount = 0;\n\
var str_ip = opeform.master_ip.value;\n\
var iplength = str_ip.length;\n\
if (opeform.enable_switch.value == '1' || (iplength != 0 && str_ip != 'N/A')) {\n\
var letters = \'1234567890. \';\n\
if (iplength == 0) return false;\n\
for (i=0; i<iplength; i++) {\n\
var check_char = str_ip.charAt(i);\n\
if (letters.indexOf(check_char) == -1) {\n\
alert (\'%s\');\n\
opeform.master_ip.value=\'\';\n\
opeform.master_ip.focus();\n\
return false;\n}\n}\n\
for (var i=0;i<iplength;i++)\n\
(str_ip.substr(i,1)==\'.\')?scount++:scount;\n\
if(scount!=3) {\n\
alert (\'%s\');\n\
opeform.master_ip.value=\'\';\n\
opeform.master_ip.focus();\n\
return false;}\n}\n\
var mask_string='';\n\
if (opeform.root_password.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.default_domain.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.admin_mailbox.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.huge_domain.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.session_num.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.rcpt_num.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.mail_length.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.time_out.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.scanning_size.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.conn_freq.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.dispatch_freq.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.log_days.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.local_domain.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.backend_list.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.dns_table.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.forward_table.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.from_replace.checked == true) mask_string += '1'; else mask_string += '0';\n\
if (opeform.domain_mailbox.checked == true) mask_string += '1'; else mask_string += '0';\n\
dummy_window.location.href='%s?session=%s&enable_switch=' + \
opeform.enable_switch.value + '&master_ip=' + str_ip + \
'&mask_string=' + mask_string;\n\
return false;\" />\n\
</TD></TR><TR><TD colSpan=3><HR><BR><BR></TD></TR>"

#define LINE_BEGINE		"<TR class=SolidRow>"

#define LINE_END		"</TR>\n"

#define CELL_BEGINE		"<TD>"

#define CELL_END		"</TD>"

#define PARAM_CHECKED	"checked"

#define PARAM_UNCHECKED " "

#define INDEX_ROOT_PASSWORD		0

#define CHECKBOX_ROOT_PASSWORD	"<INPUT type=checkbox name=root_password value=\"on\" %s/>"

#define INDEX_DEFAULT_DOMAIN	1

#define CHECKBOX_DEFAULT_DOMAIN	"<INPUT type=checkbox name=default_domain value=\"on\" %s/>"

#define INDEX_ADMIN_MAILBOX		2

#define CHECKBOX_ADMIN_MAILBOX	"<INPUT type=checkbox name=admin_mailbox value=\"on\" %s/>"

#define INDEX_HUGE_DOMAIN		3

#define CHECKBOX_HUGE_DOMAIN	"<INPUT type=checkbox name=huge_domain value=\"on\" %s/>"

#define INDEX_SESSION_NUM		4

#define CHECKBOX_SESSION_NUM	"<INPUT type=checkbox name=session_num value=\"on\" %s/>"

#define INDEX_RCPT_NUM			5

#define CHECKBOX_RCPT_NUM		"<INPUT type=checkbox name=rcpt_num value=\"on\" %s/>"

#define INDEX_MAIL_LENGTH		6

#define CHECKBOX_MAIL_LENGTH	"<INPUT type=checkbox name=mail_length value=\"on\" %s/>"

#define INDEX_TIME_OUT			7

#define CHECKBOX_TIME_OUT		"<INPUT type=checkbox name=time_out value=\"on\" %s/>"

#define INDEX_SCANNING_SIZE		8

#define CHECKBOX_SCANNING_SIZE	"<INPUT type=checkbox name=scanning_size value=\"on\" %s/>"

#define INDEX_CONN_FREQ			9

#define CHECKBOX_CONN_FREQ		"<INPUT type=checkbox name=conn_freq value=\"on\" %s/>"

#define INDEX_DISPARCH_FREQ		10

#define CHECKBOX_DISPARCH_FREQ	"<INPUT type=checkbox name=dispatch_freq value=\"on\" %s/>"

#define INDEX_LOG_DAYS			11

#define CHECKBOX_LOG_DAYS		"<INPUT type=checkbox name=log_days value=\"on\" %s/>"

#define INDEX_LOCAL_DOMAIN		12

#define CHECKBOX_LOCAL_DOMAIN	"<INPUT type=checkbox name=local_domain value=\"on\" %s/>"

#define INDEX_BACKEND_LIST		13

#define CHECKBOX_BACKEND_LIST	"<INPUT type=checkbox name=backend_list value=\"on\" %s/>"

#define INDEX_DNS_TABLE			14

#define CHECKBOX_DNS_TABLE	"<INPUT type=checkbox name=dns_table value=\"on\" %s/>"

#define INDEX_FORWARD_TABLE		15

#define CHECKBOX_FORWARD_TABLE	"<INPUT type=checkbox name=forward_table value=\"on\" %s/>"

#define INDEX_FROM_REPLACE		16

#define CHECKBOX_FROM_REPLACE	"<INPUT type=checkbox name=from_replace value=\"on\" %s/>"

#define INDEX_DOMAIN_MAILBOX	17

#define CHECKBOX_DOMAIN_MAILBOX	"<INPUT type=checkbox name=domain_mailbox value=\"on\" %s/>"


#define HTML_MAIN_7	\
"</TBODY></TABLE><TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_ERROR_5    \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"


#define HTML_ACTIVE_OK  \
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>message is actived</TITLE>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\"\n\
</HEAD><BODY onload=\"alert('%s');\"> messgae is actived! </BODY></HTML>"

#define TOKEN_CONTROL					100

#define CTRL_RESTART_SYNCHRONIZER		4

static void setup_ui_error_html(const char *error_string);

static void setup_ui_error_alert(const char *error_string);

static void setup_ui_main_html(const char *session);

static void setup_ui_valid_html(BOOL b_enable, char *ip, char *mask_string);

static void setup_ui_restart_synchronizer();

static BOOL setup_ui_get_self(char *url_buff, int length);

static void setup_ui_unencode(char *src, char *last, char *dest);

static char g_token_path[256];
static char g_logo_link[1024];
static CONFIG_FILE *g_cfg_file;
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void setup_ui_init(CONFIG_FILE *pfile, const char *token_path,
	const char *url_link, const char *resource_path)
{
	g_cfg_file = pfile;
	strcpy(g_token_path, token_path);
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int setup_ui_run()
{
	char *query;
	char *request;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char memo[256];
	char ip_addr[16];
	char temp_ip[16];
	char temp_port[16];
	char session[256];
	char search_buff[1024];
	char mask_string[19];
	BOOL b_enable;
	int len, port;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		setup_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[setup_ui]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[setup_ui]: fail to get REQUEST_METHOD"
			" environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[setup_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[setup_ui]: fail to get QUERY_STRING "
				"environment!");
			setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
				language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 1024) {
				system_log_info("[setup_ui]: query string too long!");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			setup_ui_unencode(query, query + len, search_buff);
			len = strlen(search_buff);
			ptr1 = search_string(search_buff, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[setup_ui]: query string of GET "
					"format error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = search_string(search_buff, "&enable_switch=", len);
			if (NULL == ptr2) {
				if (search_buff + len - ptr1 - 1 > 256) {
					system_log_info("[setup_ui]: query string of GET "
						"format error");
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
					return 0;
				}
				memcpy(session, ptr1, search_buff + len - ptr1 - 1);
				session[search_buff + len - ptr1 - 1] = '\0';

				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_SETUP)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				case ACL_SESSION_PRIVILEGE:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
						language));
					return 0;
				default:
					setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				setup_ui_main_html(session);
				return 0;
			}
			if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[setup_ui]: query string of GET "
					"format error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			
			ptr1 = ptr2 + 15;
			ptr2 = search_string(search_buff, "&master_ip=", len);
			if (NULL == ptr2) {
				system_log_info("[setup_ui]: query string of GET "
					"format error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if (ptr2 - ptr1 != 1) {
				system_log_info("[setup_ui]: query string of GET "
					"format error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			if ('0' == *ptr1) {
				b_enable = FALSE;
			} else {
				b_enable = TRUE;
			}
			ptr1 = ptr2 + 11;
			ptr2 = search_string(search_buff, "&mask_string=", len);
			if (ptr2 < ptr1 || ptr2 - ptr1 > 16) {
				system_log_info("[setup_ui]: ip address in GET query "
					"string error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_ip, ptr1, ptr2 - ptr1);
			temp_ip[ptr2 - ptr1] = '\0';			
			ltrim_string(temp_ip);
			rtrim_string(temp_ip);
			if ('\0' != temp_ip[0] && 0 != strcmp(temp_ip, "N/A") &&
				NULL == extract_ip(temp_ip, ip_addr)) {
				system_log_info("[setup_ui]: ip address in GET query "
					"string error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			ptr1 = ptr2 + 13;
			if (search_buff + len - 1 - ptr1 != sizeof(mask_string) - 1) {
				system_log_info("[setup_ui]: ip address in GET query "
					"string error");
				setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(mask_string, ptr1, sizeof(mask_string) - 1);
			mask_string[sizeof(mask_string) - 1] = '\0';
			
			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_SETUP)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				setup_ui_error_alert(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			case ACL_SESSION_PRIVILEGE:
				setup_ui_error_alert(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			default:
				setup_ui_error_alert(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			setup_ui_valid_html(b_enable, temp_ip, mask_string);
			return 0;
		}
	} else {
		system_log_info("[setup_ui]: unrecognized REQUEST_METHOD \"%s\"!",
			request);
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int setup_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void setup_ui_free()
{
	/* do nothing */
}

static BOOL setup_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *script;
	
	host = getenv("SERVER_NAME");
	script = getenv("SCRIPT_NAME");
	if (NULL == host || NULL == script) {
		system_log_info("[setup_ui]: fail to get SERVER_NAME or "
			"SCRIPT_NAME environment!");
		return FALSE;
	}
	snprintf(url_buff, length, "http://%s%s", host, script);
	return TRUE;
}

static void setup_ui_error_html(const char *error_string)
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

static void setup_ui_error_alert(const char *error_string)
{
	char *language;
	const char *charset;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset, error_string);
}

static void setup_ui_main_html(const char *session)
{
	BOOL b_switch;
	int string_len;
	char *language;
	char *str_value;
	char url_buff[1024];
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == setup_ui_get_self(url_buff, 1024)) {
		setup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL",
			language));
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
	printf(HTML_MAIN_5, lang_resource_get(g_lang_resource,"MAIN_SYNC_SWITCH", language));
	str_value = config_file_get_value(g_cfg_file, "SYNC_SWITCH");
	if (NULL == str_value) {
		b_switch = FALSE;
	} else {
		if (0 == strcasecmp(str_value, "TRUE")) {
			b_switch = TRUE;
		} else {
			b_switch = FALSE;
		}
	}
	if (TRUE == b_switch) {
		printf(OPTION_NORMAL, 0, lang_resource_get(g_lang_resource,"SWITCH_OFF", language));
		printf(OPTION_SELECT, 1, lang_resource_get(g_lang_resource,"SWITCH_ON", language));
	} else {
		printf(OPTION_SELECT, 0, lang_resource_get(g_lang_resource,"SWITCH_OFF", language));
		printf(OPTION_NORMAL, 1, lang_resource_get(g_lang_resource,"SWITCH_ON", language));
	}
	str_value = config_file_get_value(g_cfg_file, "MASTER_ADDRESS");
	if (NULL == str_value) {
		str_value = "N/A";
	}
	printf(HTML_MAIN_6, lang_resource_get(g_lang_resource,"MAIN_MASTER_ADDRESS", language),
		str_value, lang_resource_get(g_lang_resource,"SUBMIT_LABEL", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		lang_resource_get(g_lang_resource,"MSGERR_IPADDRESS", language),
		url_buff, session);

	str_value = config_file_get_value(g_cfg_file, "SYNC_MASK_STRING");
	if (NULL == str_value) {
		string_len = 0;
	} else {
		string_len = strlen(str_value);
	}
	printf(LINE_BEGINE);
	printf(CELL_BEGINE);
	if (INDEX_ROOT_PASSWORD >= string_len ||
		'1' != str_value[INDEX_ROOT_PASSWORD]) {
		printf(CHECKBOX_ROOT_PASSWORD, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_ROOT_PASSWORD, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_ROOT_PASSWORD", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_DEFAULT_DOMAIN > string_len ||
		'1' != str_value[INDEX_DEFAULT_DOMAIN]) {
		printf(CHECKBOX_DEFAULT_DOMAIN, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_DEFAULT_DOMAIN, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_DEFAULT_DOMAIN", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_ADMIN_MAILBOX >= string_len ||
		'1' != str_value[INDEX_ADMIN_MAILBOX]) {
		printf(CHECKBOX_ADMIN_MAILBOX, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_ADMIN_MAILBOX, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_ADMIN_MAILBOX", language));
	printf(CELL_END);
	printf(LINE_END);
	printf(LINE_BEGINE);
	printf(CELL_BEGINE);
	if (INDEX_HUGE_DOMAIN >= string_len ||
		'1' != str_value[INDEX_HUGE_DOMAIN]) {
		printf(CHECKBOX_HUGE_DOMAIN, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_HUGE_DOMAIN, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_HUGE_DOMAIN", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_SESSION_NUM >= string_len ||
		'1' != str_value[INDEX_SESSION_NUM]) {
		printf(CHECKBOX_SESSION_NUM, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_SESSION_NUM, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_SESSION_NUM", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_RCPT_NUM >= string_len ||
		'1' != str_value[INDEX_RCPT_NUM]) {
		printf(CHECKBOX_RCPT_NUM, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_RCPT_NUM, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_RCPT_NUM", language));
	printf(CELL_END);
	printf(LINE_END);
	printf(LINE_BEGINE);
	printf(CELL_BEGINE);
	if (INDEX_MAIL_LENGTH >= string_len ||
		'1' != str_value[INDEX_MAIL_LENGTH]) {
		printf(CHECKBOX_MAIL_LENGTH, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_MAIL_LENGTH, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_MAIL_LENGTH", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_TIME_OUT >= string_len ||
		'1' != str_value[INDEX_TIME_OUT]) {
		printf(CHECKBOX_TIME_OUT, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_TIME_OUT, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_TIME_OUT", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_SCANNING_SIZE >= string_len ||
		'1' != str_value[INDEX_SCANNING_SIZE]) {
		printf(CHECKBOX_SCANNING_SIZE, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_SCANNING_SIZE, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_SCANNING_SIZE", language));
	printf(CELL_END);
	printf(LINE_END);
	printf(LINE_BEGINE);
	printf(CELL_BEGINE);
	if (INDEX_CONN_FREQ >= string_len ||
		'1' != str_value[INDEX_CONN_FREQ]) {
		printf(CHECKBOX_CONN_FREQ, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_CONN_FREQ, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_CONN_FREQ", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_DISPARCH_FREQ >= string_len ||
		'1' != str_value[INDEX_DISPARCH_FREQ]) {
		printf(CHECKBOX_DISPARCH_FREQ, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_DISPARCH_FREQ, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_DISPATCH_FREQ", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_LOG_DAYS >= string_len ||
		'1' != str_value[INDEX_LOG_DAYS]) {
		printf(CHECKBOX_LOG_DAYS, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_LOG_DAYS, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_LOG_DAYS", language));
	printf(CELL_END);
	printf(LINE_END);
	printf(LINE_BEGINE);
	printf(CELL_BEGINE);
	if (INDEX_LOCAL_DOMAIN >= string_len ||
		'1' != str_value[INDEX_LOCAL_DOMAIN]) {
		printf(CHECKBOX_LOCAL_DOMAIN, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_LOCAL_DOMAIN, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_LOCAL_DOMAIN", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_BACKEND_LIST >= string_len ||
		'1' != str_value[INDEX_BACKEND_LIST]) {
		printf(CHECKBOX_BACKEND_LIST, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_BACKEND_LIST, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_BACKEND_LIST", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_DNS_TABLE >= string_len ||
		'1' != str_value[INDEX_DNS_TABLE]) {
		printf(CHECKBOX_DNS_TABLE, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_DNS_TABLE, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_DNS_TABLE", language));
	printf(CELL_END);
	printf(LINE_END);
	printf(LINE_BEGINE);
	printf(CELL_BEGINE);
	if (INDEX_FORWARD_TABLE >= string_len ||
		'1' != str_value[INDEX_FORWARD_TABLE]) {
		printf(CHECKBOX_FORWARD_TABLE, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_FORWARD_TABLE, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_FORWARD_TABLE", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_FROM_REPLACE >= string_len ||
		'1' != str_value[INDEX_FROM_REPLACE]) {
		printf(CHECKBOX_FROM_REPLACE, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_FROM_REPLACE, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_FROM_REPLACE", language));
	printf(CELL_END);
	printf(CELL_BEGINE);
	if (INDEX_DOMAIN_MAILBOX >= string_len ||
		'1' != str_value[INDEX_DOMAIN_MAILBOX]) {
		printf(CHECKBOX_DOMAIN_MAILBOX, PARAM_UNCHECKED);
	} else {
		printf(CHECKBOX_DOMAIN_MAILBOX, PARAM_CHECKED);
	}
	printf(lang_resource_get(g_lang_resource,"MAIN_DOMAIN_MAILBOX", language));
	printf(CELL_END);
	printf(LINE_END);
	printf(HTML_MAIN_7);
}

static void setup_ui_valid_html(BOOL b_enable, char *ip, char *mask_string)
{
	char *language;
	const char *charset;

	if (FALSE == b_enable) {
		config_file_set_value(g_cfg_file, "SYNC_SWITCH", "FALSE");
	} else {
		config_file_set_value(g_cfg_file, "SYNC_SWITCH", "TRUE");
	}
	config_file_set_value(g_cfg_file, "MASTER_ADDRESS", ip);
	config_file_set_value(g_cfg_file, "SYNC_MASK_STRING", mask_string);
	config_file_save(g_cfg_file);
	
	setup_ui_restart_synchronizer();
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	charset = lang_resource_get(g_lang_resource,"CHARSET", language);
	printf("Content-Type:text/html;charset=%s\n\n", charset);
	printf(HTML_ACTIVE_OK, charset, lang_resource_get(g_lang_resource,"MSGERR_SAVED", language));
}

static void setup_ui_unencode(char *src, char *last, char *dest)
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

static void setup_ui_restart_synchronizer()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;
	
	k_ctrl = ftok(g_token_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		system_log_info("[setup_ui]: cannot open key for control");
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_SYNCHRONIZER;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

