#include "backup_ui.h"
#include "lang_resource.h"
#include "request_parser.h"
#include "system_log.h"
#include "session_client.h"
#include "message_lookup.h"
#include "data_source.h"
#include "util.h"
#include "mail_func.h"
#include "midb_client.h"
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
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

/* fill search result title here */

#define HTML_COMMON_4	\
"</SPAN></TD><TD vAlign=bottom noWrap width=\"22%\"\n\
background=\"../data/picture/di1.gif\"><A href=\""

/* fill logo url link here */

#define HTML_RESULT_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR>\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\""

/* fill search URL link here */

#define HTML_RESULT_6	"\">"

/* fill search again label here */


#define HTML_RESULT_7	"</A></TD></TR></TBODY></TABLE><BR><BR>%s<BR><BR></BODY></HTML>"

#define HTML_SEARCH_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=searchpattern method=post action="

/* fill form action here */

#define HTML_SEARCH_6	">\n<INPUT type=hidden value="

#define HTML_SEARCH_7	" name=domain><INPUT type=hidden value="

#define HTML_SEARCH_8	\
" name=session><BR><BR><TABLE class=SearchTable cellSpacing=0 cellPadding=2 \n\
width=\"100%\" border=0><TBODY><TR><TD></TD><TD vAlign=center>\n"

/* fill mailbox tag here */

#define HTML_SEARCH_9 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=username size=30/>\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

#define HTML_OPTION_1	"<OPTION value="

#define HTML_OPTION_SELECTED	" selected>"

#define HTML_OPTION_2	">"

#define HTML_OPTION_3	"</OPTION>\n"

/* fill archive time here */

#define HTML_SEARCH_10	"</TD><TD vAlign=center><SPAN><SELECT name=start_day>\n"

#define HTML_SEARCH_11	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=start_hour>\n\
<OPTION value=0 selected>00:00</OPTION>\n\
<OPTION value=1>01:00</OPTION>\n\
<OPTION value=2>02:00</OPTION>\n\
<OPTION value=3>03:00</OPTION>\n\
<OPTION value=4>04:00</OPTION>\n\
<OPTION value=5>05:00</OPTION>\n\
<OPTION value=6>06:00</OPTION>\n\
<OPTION value=7>07:00</OPTION>\n\
<OPTION value=8>08:00</OPTION>\n\
<OPTION value=9>09:00</OPTION>\n\
<OPTION value=10>10:00</OPTION>\n\
<OPTION value=11>11:00</OPTION>\n\
<OPTION value=12>12:00</OPTION>\n\
<OPTION value=13>13:00</OPTION>\n\
<OPTION value=14>14:00</OPTION>\n\
<OPTION value=15>15:00</OPTION>\n\
<OPTION value=16>16:00</OPTION>\n\
<OPTION value=17>17:00</OPTION>\n\
<OPTION value=18>18:00</OPTION>\n\
<OPTION value=19>19:00</OPTION>\n\
<OPTION value=20>20:00</OPTION>\n\
<OPTION value=21>21:00</OPTION>\n\
<OPTION value=22>22:00</OPTION>\n\
<OPTION value=23>23:00</OPTION>\n</SELECT>&nbsp;&nbsp;-&nbsp;&nbsp;<SELECT name=end_day>\n"

#define HTML_SEARCH_12	\
"</SELECT>&nbsp;&nbsp;&nbsp;&nbsp;<SELECT name=end_hour>\n\
<OPTION value=0>00:00</OPTION>\n\
<OPTION value=1>01:00</OPTION>\n\
<OPTION value=2>02:00</OPTION>\n\
<OPTION value=3>03:00</OPTION>\n\
<OPTION value=4>04:00</OPTION>\n\
<OPTION value=5>05:00</OPTION>\n\
<OPTION value=6>06:00</OPTION>\n\
<OPTION value=7>07:00</OPTION>\n\
<OPTION value=8>08:00</OPTION>\n\
<OPTION value=9>09:00</OPTION>\n\
<OPTION value=10>10:00</OPTION>\n\
<OPTION value=11>11:00</OPTION>\n\
<OPTION value=12>12:00</OPTION>\n\
<OPTION value=13>13:00</OPTION>\n\
<OPTION value=14>14:00</OPTION>\n\
<OPTION value=15>15:00</OPTION>\n\
<OPTION value=16>16:00</OPTION>\n\
<OPTION value=17>17:00</OPTION>\n\
<OPTION value=18>18:00</OPTION>\n\
<OPTION value=19>19:00</OPTION>\n\
<OPTION value=20>20:00</OPTION>\n\
<OPTION value=21>21:00</OPTION>\n\
<OPTION value=22>22:00</OPTION>\n\
<OPTION value=23 selected>23:00</OPTION>\n\
</SELECT></TD><TD><INPUT type=submit onclick=\"\
if (0 == searchpattern.username.value.length) {\n\
	alert('%s');\n\
	return false;\n\
}\n\
if (searchpattern.username.value.length != 0) {\n\
	var apos;\n\
	var dotpos;\n\
	with (searchpattern.username) {\n\
    apos=value.indexOf('@');\n\
    dotpos=value.lastIndexOf('.');\n\
    if (apos<1||dotpos-apos<2) {\n\
		alert('%s');\n\
		return false;\n\
	}\n\
	if (searchpattern.username.value.substring(apos, \n\
		searchpattern.username.value.length).toLowerCase() != '@%s'.toLowerCase()) {\n\
		alert('%s');\n\
		return false;}\n\
	}\n\
}\n\
return true;\" value=\"    "

/* fill button label here */

#define HTML_SEARCH_13	\
"    \"/></TD></TR></TBODY></TABLE></FORM>\n\
</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy; "

#define HTML_SEARCH_14	"</CENTER></BODY></HTML>"

#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=domain_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"


#define HTML_NORESULT_LABEL	"<TR class=ItemRow><TD colSpan=5>%s</TD></TR>"


#define DOMAIN_PRIVILEGE_BACKUP				0x1


static void backup_ui_error_html(const char *error_string);

static void backup_ui_search_html(const char *domain, const char *session);

static void backup_ui_result_html(const char *domain, const char *session,
	const char *username);

static BOOL backup_ui_delivery_all(const char *username,
	const char *maildir, VAL_SCOPE *atime);

static BOOL backup_ui_insert_mail(int seq_id, int server_id,
	uint64_t mail_id, const char *dst_path);

static BOOL backup_ui_get_self(char *url_buff, int length);


static int g_valid_days;
static char g_logo_link[1024];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;

void backup_ui_init(int valid_days, const char *url_link,
	const char *resource_path)
{
	g_valid_days = valid_days;
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int backup_ui_run()
{
	char *ptoken;
	struct tm *ptm;
	time_t tmp_time;
	time_t current_time;
	int start_day, end_day;
	int start_hour, end_hour;
	int privilege_bits;
	char *language;
	char *query, *request;
	const char *pvalue;
	const char *domain;
	const char *session;
	const char *username;
	char post_buff[1024];
	char maildir[256];
	REQUEST_PARSER *pparser;
	VAL_SCOPE *patime, tmp_atime;

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
		system_log_info("[backup_ui]: fail to get REQUEST_METHOD environment!");
		return -2;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		
		pparser = request_parser_init(post_buff);
		if (NULL == pparser) {
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
			return 0;
		}
		
		domain = request_parser_get(pparser, "domain");
		if (NULL == domain) {
			system_log_info("[backup_ui]: query string of POST format error");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		session = request_parser_get(pparser, "session");
		if (NULL == session) {
			system_log_info("[backup_ui]: query string of POST format error");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		
		if (FALSE == session_client_check(domain, session)) {
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",language));
			return 0;
		}
		
		data_source_info_domain(domain, &privilege_bits);

		if ((privilege_bits&DOMAIN_PRIVILEGE_BACKUP) == 0) {
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
				language));
			return 0;
		}
		
		username = request_parser_get(pparser, "username");
		if (NULL == username) {
			system_log_info("[backup_ui]: query string of POST format error");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		
		ptoken = strchr(username, '@');
		if (NULL == ptoken || 0 != strcasecmp(ptoken + 1, domain)) {
			backup_ui_result_html(domain, session, lang_resource_get(g_lang_resource,
				"MSGERR_USERNAME_DOMAIN", language));
			return 0;
		}
		
		pvalue = request_parser_get(pparser, "start_day");
		if (NULL == pvalue) {
			system_log_info("[backup_ui]: query string of POST format error");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}	
		if (0 == strcasecmp(pvalue, "NULL")) {
			start_day = -1;
		} else {
			start_day = atoi(pvalue);
		}

		pvalue = request_parser_get(pparser, "start_hour");
		if (NULL == pvalue) {
			system_log_info("[backup_ui]: query string of POST format error");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		start_hour = atoi(pvalue);

		pvalue = request_parser_get(pparser, "end_day");
		if (NULL == pvalue) {
			system_log_info("[backup_ui]: query string of POST format error");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (0 == strcasecmp(pvalue, "NULL")) {
			end_day = -1;
		} else {
			end_day = atoi(pvalue);
		}

		pvalue = request_parser_get(pparser, "end_hour");
		if (NULL == pvalue) {
			system_log_info("[backup_ui]: query string of POST format error");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		end_hour = atoi(pvalue);

		if (-1 == start_day && -1 == end_day) {
			patime = NULL;
		} else {
			time(&current_time);
			ptm = localtime(&current_time);
			if (-1 == start_day) {
				tmp_atime.begin = 0;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_atime.begin = tmp_time - 24*60*60*start_day + 
							60*60*start_hour;
			}
			
			if (-1 == end_day) {
				tmp_atime.end = -1;
			} else {
				tmp_time = current_time - 
							(ptm->tm_hour*3600 + ptm->tm_min*60 + ptm->tm_sec);
				tmp_atime.end = tmp_time - 24*60*60*end_day  + 60*60*end_hour;
			}
			
			patime = &tmp_atime;
		}
		
		if (FALSE == data_source_get_maildir(username, maildir)) {
			backup_ui_result_html(domain, session, lang_resource_get(g_lang_resource,
				"MSGERR_USERNAME_UNKNOWN", language));
			return 0;
		}

		
		if (TRUE == backup_ui_delivery_all(username, maildir, patime)) {
			backup_ui_result_html(domain, session, lang_resource_get(g_lang_resource,
				"MSGERR_RESTORE_EXCUTED", language));
		} else {
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		}
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[backup_ui]: fail to get QUERY_STRING "
					"environment!");
			backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		} else {
			pparser = request_parser_init(query);
			if (NULL == pparser) {
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
				return 0;
			}
			domain = request_parser_get(pparser, "domain");
			if (NULL == domain) {
				system_log_info("[backup_ui]: query string of GET format error");
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			session = request_parser_get(pparser, "session");
			if (NULL == session) {
				system_log_info("[backup_ui]: query string of GET format error");
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			
			if (FALSE == session_client_check(domain, session)) {
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",language));
				return 0;
			}
			
			data_source_info_domain(domain, &privilege_bits);
				
			if ((privilege_bits&DOMAIN_PRIVILEGE_BACKUP) == 0) {
				backup_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_PRIVILEGE",
					language));
				return 0;
			}
				
			backup_ui_search_html(domain, session);
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

static void backup_ui_error_html(const char *error_string)
{
	char *language;
	
	if (NULL ==error_string) {
		error_string = "fatal error!!!";
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		language = "en";
	}
	printf("Content-Type:text/html;charset=UTF-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf("UTF-8");
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"ERROR_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_ERROR_5, lang_resource_get(g_lang_resource,"BACK_LABEL", language),
		error_string);
}


static void backup_ui_search_html(const char *domain, const char *session)
{
	int i, len;
	char *language;
	char time_buff[64];
	char url_buff[1024];
	time_t current_time;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (FALSE == backup_ui_get_self(url_buff, 1024)) {
		backup_ui_error_html(lang_resource_get(
			g_lang_resource, "ERROR_INTERNAL", language));
		return;
	}

	printf("Content-Type:text/html;charset=UTF-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf("UTF-8");
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"SEARCH_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	printf(HTML_SEARCH_5);
	printf(url_buff);
	printf(HTML_SEARCH_6);
	printf(domain);
	printf(HTML_SEARCH_7);
	printf(session);
	printf(HTML_SEARCH_8);
	printf(lang_resource_get(g_lang_resource,"USERNAME_ADDRESS", language));
	printf(HTML_SEARCH_9);
	printf(lang_resource_get(g_lang_resource,"ARCHIVE_TIME", language));
	printf(HTML_SEARCH_10);
	time(&current_time);
	current_time -= 24*60*60*g_valid_days;
	for (i=g_valid_days; i>=0; i--) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,
			"SEARCH_TIME_FORMAT", language), localtime(&current_time));
		if (0 == i) {
			printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_SELECTED,
				time_buff, HTML_OPTION_3);
		} else {
			printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2,
				time_buff, HTML_OPTION_3);
		}
		current_time += 24*60*60;
	}
	
	printf(HTML_SEARCH_11);
	
	time(&current_time);
	current_time -= 24*60*60*g_valid_days;
	strftime(time_buff, 64, lang_resource_get(g_lang_resource,"SEARCH_TIME_FORMAT", language),
		localtime(&current_time));
	printf("%s0%s%s%s", HTML_OPTION_1, HTML_OPTION_SELECTED, time_buff,
		HTML_OPTION_3);
	for (i=g_valid_days; i>=0; i--) {
		strftime(time_buff, 64, lang_resource_get(g_lang_resource,
			"SEARCH_TIME_FORMAT", language), localtime(&current_time));
		if (0 == i) {
			printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_SELECTED,
				time_buff, HTML_OPTION_3);
		} else {
			printf("%s%d%s%s%s", HTML_OPTION_1, i, HTML_OPTION_2,
				time_buff, HTML_OPTION_3);
		}
		current_time += 24*60*60;
	}
	printf(HTML_SEARCH_12, lang_resource_get(g_lang_resource,"MSGERR_USERNAME_EMPTY", language),
			lang_resource_get(g_lang_resource,"MSGERR_USERNAME_ERROR", language), domain,
			lang_resource_get(g_lang_resource,"MSGERR_USERNAME_DOMAIN", language));
	printf(lang_resource_get(g_lang_resource,"ACTIVE_LABEL", language));
	printf(HTML_SEARCH_13);
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	printf(HTML_SEARCH_14);
}

static void backup_ui_result_html(const char *domain, const char *session,
	const char *msg)
{
	char *language;
	char temp_buff[64];
	char url_buff[1024];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=UTF-8\n\n");
	printf(HTML_COMMON_1);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_2);
	printf("UTF-8");
	printf(HTML_COMMON_3);
	printf(lang_resource_get(g_lang_resource,"RESULT_HTML_TITLE", language));
	printf(HTML_COMMON_4);
	printf(g_logo_link);
	backup_ui_get_self(url_buff, 1024);
	printf(HTML_RESULT_5);
	printf(url_buff);
	printf("?domain=%s&session=%s", domain, session);
	printf(HTML_RESULT_6);
	printf(lang_resource_get(g_lang_resource,"SEARCH_AGAIN_LABEL", language));
	printf(HTML_RESULT_7, msg);
}

static BOOL backup_ui_delivery_all(const char *username,
	const char *maildir, VAL_SCOPE *atime)
{
	int fd;
	pid_t pid;
	int seq_id;
	char *language;
	char temp_path[256];
	MESSAGE_ITEM *pitem;
	char temp_buff[1200];
	DOUBLE_LIST_NODE *pnode;
	LOOKUP_COLLECT *pcollection;
	
	
	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		return FALSE;
	} else if (pid > 0) {
		return TRUE;
	}
	
	setsid();
	fclose (stdout);
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	
	pcollection = message_lookup_collect_init();
	if (FALSE == message_lookup_search(-1,
		lang_resource_get(g_lang_resource, "CHARSET", language),
		username, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, atime, NULL, NULL, NULL, NULL, NULL, NULL,
		pcollection)) {
		exit(0);
	}
	
	seq_id = 1;
	
	for (message_lookup_collect_begin(pcollection);
		!message_lookup_collect_done(pcollection);
		message_lookup_collect_forward(pcollection)) {
		pitem = message_lookup_collect_get_value(pcollection);
		
		
		if (FALSE == backup_ui_insert_mail(seq_id, pitem->server_id,
			pitem->mail_id, maildir)) {
			message_lookup_collect_free(pcollection);
			exit(0);
		}
		seq_id ++;
	}
	
	message_lookup_collect_free(pcollection);
	
	exit(0);
}

static BOOL backup_ui_insert_mail(int seq_id, int server_id,
	uint64_t mail_id, const char *dst_path)
{
	int fd;
	char *pbuff;
	time_t rcv_time;
	time_t now_time;
	size_t decode_len;
	char msg_path[128];
	char file_name[128];
	char temp_path[256];
	char temp_rcv[1024];
	char temp_rcv1[1024];
	char digest[256*1024];
	struct stat node_stat;

	if (FALSE == message_lookup_match(server_id, mail_id, msg_path, digest)) {
		return FALSE;
	}
	
	if (FALSE == get_digest(digest, "received", temp_rcv, 1024)) {
		return 1;
	}
	decode_len = 1024;
	decode64(temp_rcv, strlen(temp_rcv), temp_rcv1, &decode_len);
	temp_rcv1[decode_len] = '\0';
	ltrim_string(temp_rcv1);
	if (FALSE == parse_rfc822_timestamp(temp_rcv1, &rcv_time)) {
		rcv_time = 0;
	}
	
	time(&now_time);
	sprintf(file_name, "%ld.%d.archive", now_time, seq_id);
	snprintf(temp_path, 255, "%s/%lld", msg_path, mail_id);
	if (0 != stat(temp_path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}

	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		return FALSE;
	}

	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		close(fd);
		return FALSE;
	}

	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		return FALSE;
	}
	close(fd);
	
	sprintf(temp_path, "%s/eml/%s", dst_path, file_name);
	fd = open(temp_path, O_CREAT|O_WRONLY, 0666);
	if (-1 == fd) {
		free(pbuff);
		return FALSE;
	}
	write(fd, pbuff, node_stat.st_size);
	close(fd);
	free(pbuff);
	
	if (FALSE == midb_client_insert(dst_path,
		"inbox", file_name, "()", rcv_time)) {
		remove(temp_path);
		return FALSE;
	}
	return TRUE;
}
