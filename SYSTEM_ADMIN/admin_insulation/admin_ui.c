#include "admin_ui.h"
#include "system_log.h"
#include "acl_control.h"
#include "lang_resource.h"
#include "message_lookup.h"
#include "gateway_control.h"
#include "util.h"
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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
<SCRIPT language=\"JavaScript\">\n\
function ActivateItem(path) {\n\
dummy_window.location.href='%s?session=%s&message=' + path;}\n\
function DownloadItem(path) {\n\
dummy_window.location.href='%s?session=%s&message=' + path;}\n\
</SCRIPT><TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0>\n\
<TBODY><TR><TD align=right><A href=\""

/* fill search URL link here */

#define HTML_RESULT_6	"\">"

/* fill search again label here */


#define HTML_RESULT_7	"</A></TD></TR><TR><TD noWrap align=left height=23>"

/* fill search condition here */

#define HTML_RESULT_8	\
"<iframe src=\"\" style=\"display:none\" width=\"0\" height=\"0\" name=\"dummy_window\"></iframe>\n\
</TD></TR></TBODY></TABLE><BR><BR>\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\n\
<TBODY><TR><TD background=\"../data/picture/di2.gif\">\n\
<IMG height=30 src=\"../data/picture/kl.gif\" width=3></TD>\n\
<TD class=TableTitle noWrap align=middle background=\"../data/picture/di2.gif\">"

/* fill result table title here */

#define HTML_RESULT_9	\
"</TD><TD align=right background=\"../data/picture/di2.gif\"><IMG height=30\n\
src=\"../data/picture/kr.gif\" width=3></TD></TR><TR bgColor=#bfbfbf>\n\
<TD colSpan=5><TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0>\n\
<TBODY>"

#define HTML_RESULT_10	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR><BR></CENTER></BODY></HTML>"

#define HTML_SEARCH_5 \
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<FORM class=SearchForm name=searchpattern method=post action="

/* fill form action here */

#define HTML_SEARCH_6	" >\n<INPUT type=hidden value="

#define HTML_SEARCH_7	\
" name=session><TABLE class=SearchTable cellSpacing=0 cellPadding=2 \n\
width=\"100%\" border=0><TBODY><TR><TD></TD><TD vAlign=center>\n"

/* fill recipient domain or address tag here */

#define HTML_SEARCH_8 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=recipient /></SPAN>\n\
</TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill sender tag here */

#define HTML_SEARCH_9 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=from />\n\
</SPAN></TD></TR><TR><TD></TD><TD vAlign=center>"

/* fill reason tag here */

#define HTML_SEARCH_10 \
"</TD><TD vAlign=center><SPAN><INPUT type=\"text\" name=reason />\n\
</SPAN></TD><TD><INPUT type=submit value=\"    "

/* fill button label here */

#define HTML_SEARCH_11	\
"    \"/></TD></TR></TBODY></TABLE></FORM>\n\
</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR><P></P><BR><BR>&copy; "

#define HTML_SEARCH_12	"</CENTER></BODY></HTML>"

#define HTML_ERROR_5	\
"\" target=_blank><IMG height=48 src=\"../data/picture/logo_bb.gif\"\n\
width=195 align=right border=0></A></TD></TR></TBODY></TABLE><BR><BR>\n\
<P align=right><A href=admin_main target=_parent>%s</A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\n\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp\n\
</P><BR><BR>%s</CENTER></BODY></HTML>"

#define HTML_TBITEM_FIRST   \
"<TR class=SolidRow><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s\
&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD></TR>\n"

#define HTML_TBITEM_ODD  \
"<TR class=ItemOdd><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\n\
<A href=\"javascript:ActivateItem('%s')\">%s</A>|\
<A href=\"javascript:DownloadItem('%s/%s')\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_TBITEM_EVEN  \
"<TR class=ItemEven><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD>\n\
<TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;\n\
<A href=\"javascript:ActivateItem('%s')\">%s</A>|\
<A href=\"javascript:DownloadItem('%s/%s')\">%s</A>&nbsp;</TD></TR>\n"

#define HTML_NORESULT_LABEL	"<TR class=ItemRow><TD colSpan=5>%s</TD></TR>"

#define HTML_ACTIVE_OK	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>message is actived</TITLE>\n\
<META http-equiv=Content-Type content=\"text/html; charset=%s\"\n\
</HEAD><BODY onload=\"alert('%s');\"> messgae is actived! </BODY></HTML>"

static void admin_ui_error_html(const char *error_string);

static void admin_ui_search_html(const char *session);

static void admin_ui_result_html(const char *session, const char *recipient,
	const char *from, const char *reason);

static void admin_ui_activate_error(const char *error_string);

static void admin_ui_activate_message(const char *temp_path);

static void admin_ui_download_message(const char *temp_path);

static BOOL admin_ui_get_self(char *url_buff, int length);

static void admin_ui_unencode(char *src, char *last, char *dest);

static char g_logo_link[1024];

static char g_resource_path[256];

static LANG_RESOURCE *g_lang_resource;

void admin_ui_init(const char *url_link, const char *resource_path)
{
	strcpy(g_logo_link, url_link);
	strcpy(g_resource_path, resource_path);
}

int admin_ui_run()
{
	struct tm *ptm;
	time_t current_time;
	int scan_num, type, len;
	char *language;
	char *remote_ip;
	char *ptr1, *ptr2;
	char *query, *request;
	char *precipient;
	char *preason, *pfrom;
	char password[256];
	char session[256];
	char post_buff[1024];
	char search_buff[1024];
	char temp_path[256];
	char tmp_reason[256];
	char tmp_recipient[512];
	char tmp_from[256];

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	if (NULL == language) {
		admin_ui_error_html(NULL);
		return 0;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		system_log_info("[ui_main]: fail to init language resource");
		return -1;
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		system_log_info("[admin_ui]: fail to get REQUEST_METHOD environment!");
		return -2;
	}
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		system_log_info("[admin_ui]: fail to get REMOTE_ADDR environment!");
		return -3;
	}
	if (0 == strcmp(request, "POST")) {
		if (NULL == fgets(post_buff, 1024, stdin)) {
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		len = strlen(post_buff);
		if (len > 1024) {
			system_log_info("[admin_ui]: post buffer too long");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		admin_ui_unencode(post_buff, post_buff + len, search_buff);
		len = strlen(search_buff);
		ptr1 = search_string(search_buff, "session=", len);
		if (NULL == ptr1) {
			system_log_info("[admin_ui]: query string of POST "
				"format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
			return 0;
		}
		ptr1 += 8;
		ptr2 = search_string(search_buff, "&recipient=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		memcpy(session, ptr1, ptr2 - ptr1);
		session[ptr2 - ptr1] = '\0';
		ptr1 = ptr2 + 11;
		ptr2 = search_string(search_buff, "&from=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 == ptr1) {
			precipient = NULL;
		} else {
			memcpy(tmp_recipient, ptr1, ptr2 - ptr1);
			tmp_recipient[ptr2 - ptr1] = '\0';
			ltrim_string(tmp_recipient);
			rtrim_string(tmp_recipient);
			precipient = tmp_recipient;
		}
		ptr1 = ptr2 + 6;
		ptr2 = search_string(search_buff, "&reason=", len);
		if (NULL == ptr2) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 < ptr1 || ptr2 - ptr1 > 255) {
			system_log_info("[admin_ui]: query string of POST format error");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		}
		if (ptr2 == ptr1) {
			pfrom = NULL;
		} else {
			memcpy(tmp_from, ptr1, ptr2 - ptr1);
			tmp_from[ptr2 - ptr1] = '\0';
			ltrim_string(tmp_from);
			rtrim_string(tmp_from);
			pfrom = tmp_from;
		}
		ptr1 = ptr2 + 8;
		if (0 == search_buff + len - 1 - ptr1) {
			preason = NULL;
		} else {
			memcpy(tmp_reason, ptr1, search_buff + len - 1 - ptr1);
			tmp_reason[search_buff + len - 1 - ptr1] = '\0';
			ltrim_string(tmp_reason);
			rtrim_string(tmp_reason);
			preason = tmp_reason;
		}
		
		switch (acl_control_check(session, remote_ip, ACL_PRIVILEGE_IGNORE)) {
		case ACL_SESSION_OK:
			break;
		case ACL_SESSION_TIMEOUT:
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT", language));
			return 0;
		default:
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION", language));
			return 0;
		}
		admin_ui_result_html(session, precipient, pfrom, preason);
		return 0;
	} else if (0 == strcmp(request, "GET")) {
		query = getenv("QUERY_STRING");
		if (NULL == query) {
			system_log_info("[admin_ui]: fail to get QUERY_STRING "
					"environment!");
			admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",language));
			return 0;
		} else {
			len = strlen(query);
			if (0 == len || len > 256) {
				system_log_info("[admin_ui]: query string too long!");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 = search_string(query, "session=", len);
			if (NULL == ptr1) {
				system_log_info("[admin_ui]: query string of GET format error");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
						language));
				return 0;
			}
			ptr1 += 8;
			ptr2 = search_string(ptr1, "&message=", len);
			if (NULL == ptr2) {
				if (query + len - ptr1 > 255) {
					system_log_info("[admin_ui]: query string of GET format "
						"error");
					admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
							language));
					return 0;
				}
				memcpy(session, ptr1, query + len - ptr1);
				session[query + len - ptr1] = '\0';
			
				switch (acl_control_check(session, remote_ip,
					ACL_PRIVILEGE_IGNORE)) {
				case ACL_SESSION_OK:
					break;
				case ACL_SESSION_TIMEOUT:
					admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
						language));
					return 0;
				default:
					admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_SESSION",
						language));
					return 0;
				}
				
				admin_ui_search_html(session);
				return 0;
			}
			if (ptr2 <= ptr1 || ptr2 - ptr1 > 255) {
				system_log_info("[admin_ui]: query string of POST format "
					"error");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(session, ptr1, ptr2 - ptr1);
			session[ptr2 - ptr1] = '\0';
			ptr1 = ptr2 + 9;
			if (query + len - ptr1 > 255) {
				system_log_info("[admin_ui]: query string of GET format error");
				admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST",
					language));
				return 0;
			}
			memcpy(temp_path, ptr1, query + len - ptr1);
			temp_path[query + len - ptr1] = '\0';

			switch (acl_control_check(session, remote_ip,
				ACL_PRIVILEGE_IGNORE)) {
			case ACL_SESSION_OK:
				break;
			case ACL_SESSION_TIMEOUT:
				admin_ui_activate_error(lang_resource_get(g_lang_resource,"ERROR_TIMEOUT",
					language));
				return 0;
			default:
				admin_ui_activate_error(lang_resource_get(g_lang_resource,"ERROR_SESSION",
					language));
				return 0;
			}
			
			if (NULL == strchr(temp_path, '/')) {
				admin_ui_activate_message(temp_path);
			} else {
				admin_ui_download_message(temp_path);
			}
			return 0;
		}
	} else {
		system_log_info("[admin_ui]: unrecognized REQUEST_METHOD \"%s\"!",
					request);
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_REQUEST", language));
		return 0;
	}
}

int admin_ui_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	return 0;

}

void admin_ui_free()
{
	/* do nothing */
}

static BOOL admin_ui_get_self(char *url_buff, int length)
{
	char *host;
	char *https;
	char *script;
	
	host = getenv("HTTP_HOST");
	script = getenv("SCRIPT_NAME");
	https = getenv("HTTPS");
	if (NULL == host || NULL == script) {
		system_log_info("[admin_ui]: fail to get "
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

static void admin_ui_error_html(const char *error_string)
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

static void admin_ui_search_html(const char *session)
{
	int i, len;
	char *language;
	char time_buff[64];
	char url_buff[1024];
	time_t current_time;
	
	if (FALSE == admin_ui_get_self(url_buff, 1024)) {
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
		return;
	}
	language = getenv("HTTP_ACCEPT_LANGUAGE");
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
	printf(HTML_SEARCH_5);
	printf(url_buff);
	printf(HTML_SEARCH_6);
	printf(session);
	printf(HTML_SEARCH_7);
	printf(lang_resource_get(g_lang_resource,"TO_ADDRESS", language));
	printf(HTML_SEARCH_8);
	printf(lang_resource_get(g_lang_resource,"FROM_ADDRESS", language));
	printf(HTML_SEARCH_9);
	printf(lang_resource_get(g_lang_resource,"INSULATION_REASON", language));
	printf(HTML_SEARCH_10);
	printf(lang_resource_get(g_lang_resource,"SEARCH_LABEL", language));
	printf(HTML_SEARCH_11);
	printf(lang_resource_get(g_lang_resource,"COMPANY_INFORMATION", language));
	printf(HTML_SEARCH_12);
}

static void admin_ui_result_html(const char *session, const char *recipient,
	const char *from, const char *reason)
{
	int i;
	char *language;
	char temp_buff[64];
	char url_buff[1024];
	MESSAGE_ITEM *pitem;
	LOOKUP_COLLECT *pcollection;

	language = getenv("HTTP_ACCEPT_LANGUAGE");
	pcollection = message_lookup_collect_init();
	if (FALSE == message_lookup_match((char*)from, (char*)recipient,
		(char*)reason, pcollection)) {
		admin_ui_error_html(lang_resource_get(g_lang_resource,"ERROR_INTERNAL", language));
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
	admin_ui_get_self(url_buff, 1024);
	printf(HTML_RESULT_5, url_buff, session, url_buff, session);
	printf(url_buff);
	printf("?session=%s", session);
	printf(HTML_RESULT_6);
	printf(lang_resource_get(g_lang_resource,"SEARCH_AGAIN_LABEL", language));
	printf(HTML_RESULT_7);
	if (NULL != recipient) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"TO_ADDRESS", language),
			recipient);
	}
	if (NULL != from) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"FROM_ADDRESS", language), from);
	}
	if (NULL != reason) {
		printf("%s: %s; ", lang_resource_get(g_lang_resource,"INSULATION_REASON",
			language), reason);
	}
	printf(HTML_RESULT_8);
	printf(lang_resource_get(g_lang_resource,"RESULT_TABLE_TITLE", language));
	printf(HTML_RESULT_9);

	printf(HTML_TBITEM_FIRST,
		lang_resource_get(g_lang_resource,"TIME_TAG", language),
		lang_resource_get(g_lang_resource,"FROM_TAG", language),
		lang_resource_get(g_lang_resource,"TO_TAG", language),
		lang_resource_get(g_lang_resource,"INSULATION_REASON", language),
		lang_resource_get(g_lang_resource,"MAIL_OPERATION", language));
	
	i = 0;
	for (message_lookup_collect_begin(pcollection);
		!message_lookup_collect_done(pcollection);
		message_lookup_collect_forward(pcollection)) {
		pitem = message_lookup_collect_get_value(pcollection);
		strftime(temp_buff, 64, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
			language), localtime(&pitem->time));
		i ++;
		if (0 == i%2) {
			printf(HTML_TBITEM_EVEN, temp_buff, pitem->from, pitem->recipient,
				pitem->reason, pitem->file_name,
				lang_resource_get(g_lang_resource,"ACTIVE_LABEL", language),
				pitem->dir, pitem->file_name,
				lang_resource_get(g_lang_resource,"DOWNLOAD_LABEL", language));
		} else {
			printf(HTML_TBITEM_ODD, temp_buff, pitem->from, pitem->recipient,
				pitem->reason, pitem->file_name,
				lang_resource_get(g_lang_resource,"ACTIVE_LABEL", language),
				pitem->dir, pitem->file_name,
				lang_resource_get(g_lang_resource,"DOWNLOAD_LABEL", language));
		}
	}
	if (0 == message_lookup_collect_total(pcollection)) {
		printf(HTML_NORESULT_LABEL, lang_resource_get(g_lang_resource,
			"NORESULT_LABEL", language));
	}
	message_lookup_collect_free(pcollection);
	printf(HTML_RESULT_10);

}

static void admin_ui_activate_message(const char *temp_path)
{
	char *language;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET" ,language));
	if (TRUE == gateway_control_activate(temp_path)) {
		printf(HTML_ACTIVE_OK, lang_resource_get(g_lang_resource,"CHARSET", language),
			lang_resource_get(g_lang_resource,"MSGERR_ACTIVE", language));
	} else {
		printf(HTML_ACTIVE_OK, lang_resource_get(g_lang_resource,"CHARSET", language),
			lang_resource_get(g_lang_resource,"MSGERR_INACTIVE",language));
	}
}

static void admin_ui_activate_error(const char *error_string)
{
	char *language;
	
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET" ,language));
	printf(HTML_ACTIVE_OK, lang_resource_get(g_lang_resource,"CHARSET", language),
		error_string);
}

static void admin_ui_download_message(const char *temp_path)
{
	int fd;
	time_t cur_time;
	char *pbuff;
	char *language;
	struct stat node_stat;

	if (0 != stat(temp_path, &node_stat)) {
		goto FAIL_DOWNLOAD;
	}
	pbuff = (char*)malloc(node_stat.st_size + 1);
	if (NULL == pbuff) {
		goto FAIL_DOWNLOAD;
	}
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		goto FAIL_DOWNLOAD;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		goto FAIL_DOWNLOAD;
	}
	pbuff[node_stat.st_size] = '\0';
	close(fd);
	time(&cur_time);
	printf("Content-Type:application/x-download\n");
	printf("Content-Disposition:attachment;filename=\"%d.eml\"\n\n", cur_time);
	puts(pbuff);
	free(pbuff);
	return;

FAIL_DOWNLOAD:
	language = getenv("HTTP_ACCEPT_LANGUAGE");
	printf("Content-Type:text/html;charset=%s\n\n",
		lang_resource_get(g_lang_resource,"CHARSET" ,language));
	printf(HTML_ACTIVE_OK, lang_resource_get(g_lang_resource,"CHARSET", language),
		lang_resource_get(g_lang_resource,"MSGERR_FAILDOWN",language));
}

static void admin_ui_unencode(char *src, char *last, char *dest)
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

