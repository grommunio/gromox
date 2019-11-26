#include "item_sorter.h"
#include "domain_classifier.h"
#include "data_source.h"
#include "smtp_sender.h"
#include "lang_resource.h"
#include "int_hash.h"
#include "str_hash.h"
#include "list_file.h"
#include "config_file.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#define MAIL_HEAD_1		\
"Received: from unknown (helo localhost) (unkown@127.0.0.1)\r\n\
\tby herculiz with SMTP\r\nFrom: log-report@system.mail\r\n"

#define MAIL_HEAD_2		\
"Content-Type: multipart/related;\r\n\
\tboundary=\"----=_NextPart_000_0005_C248B87D.6AE33F9\"\r\n\r\n\
\tThis is a multi-part message in MIME format.\r\n\r\n"
		
	

#define MAIL_ATTACHMENT_DI1 \
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <001501c695cb$9bc2ea60$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/gif\r\n\r\n"

#define MAIL_ATTACHMENT_DI2	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <001601c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/gif\r\n\r\n"

#define MAIL_ATTACHMENT_KL	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <001701c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/gif\r\n\r\n"

#define MAIL_ATTACHMENT_KR	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <001801c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/gif\r\n\r\n"

#define MAIL_ATTACHMENT_LOGO	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <001901c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/gif\r\n\r\n"

#define MAIL_ATTACHMENT_VP	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <100001c695cb$9bc2ea60$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_VU	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <100003c695cb$9bc2ea60$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_VH	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <100002c695cb$9bc2ea60$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_BAR1	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <000501c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_BAR2	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <000601c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_BAR4	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <000701c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_BAR8	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <000801c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_BAR16	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <000901c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_BAR32	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-ID: <000001c695cb$9bc53450$6601a8c0@herculiz>\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Type: image/png\r\n\r\n"

#define MAIL_ATTACHMENT_END  "------=_NextPart_000_0005_C248B87D.6AE33F9--\r\n"

#define HTML_01	\
"------=_NextPart_000_0005_C248B87D.6AE33F9\r\n\
Content-Transfer-Encoding: 8bit\r\n\
Content-Type: text/html;\r\n\
\tcharset="

/* fill charset herer */

#define HTML_02 \
"\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\r\n\
<HTML><HEAD><STYLE TYPE=\"text/css\">\r\n\
<!--\r\n\
BODY {FONT-SIZE: 8pt; FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
TD {FONT-SIZE: 8pt; FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
A:active {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:link {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:visited {COLOR: #0000ff; TEXT-DECORATION: none}\r\n\
A:hover {COLOR: #0000ff; TEXT-DECORATION: underline}\r\n\
.TableTitle {FONT-WEIGHT: bold; FONT-SIZE: 10pt; FILTER:\r\n\
dropshadow(color=#000000,offx=2,offy=2); COLOR: #0b77d3; TEXT-ALIGN: center}\r\n\
.ItemRow {MARGIN-LEFT: 5px; MARGIN-RIGHT: 5px; BACKGROUND-COLOR: #ffffff}\r\n\
.SolidRow {FONT-WEIGHT: bold; MARGIN-LEFT: 5px; MARGIN-RIGHT:\r\n\
5px; BACKGROUND-COLOR: #d9d9d9}\r\n\
.ReportTitle {FONT-WEIGHT: bold; FONT-SIZE: 13pt; COLOR: #ffffff}\r\n\
-->\r\n\
</STYLE><TITLE>"

/* fill html title here */

#define HTML_03	\
"</TITLE>\r\n<META http-equiv=Content-Type content=\"text/html; charset=\""

#define HTML_04	\
"\">\r\n<META content=\"MSHTML 6.00.2900.2912\" name=GENERATOR></HEAD>\r\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\r\n\
marginheight=\"0\" marginwidth=\"0\">\r\n\
<CENTER><TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0><TBODY>\r\n\
<TR><TD noWrap align=middle background=\r\n\
\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\" height=55>\r\n\
<SPAN class=ReportTitle>"

/* fill content title here */

#define HTML_05	\
"</SPAN>\r\n<TD vAlign=bottom noWrap width=\"22%\"\r\n\
background=\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\"><A\r\n\
href=\"%s\" target=_blank><IMG height=48\r\n\
src=\"cid:001901c695cb$9bc53450$6601a8c0@herculiz\" width=195 align=right\r\n\
border=0></A></TD></TR></TBODY></TABLE><BR>\r\n"


#define HTML_TABLE_1	\
"<TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_LINK_NORMAL		"<a href=\"#table_normal\">"
#define HTML_LINK_OUTGOING		"<a href=\"#table_outgoing\">"
#define HTML_LINK_INSULATION	"<a href=\"#table_insulation\">"
#define HTML_LINK_RETRYING		"<a href=\"#table_retrying\">"
#define HTML_LINK_TIMEOUT		"<a href=\"#table_timeout\">"
#define HTML_LINK_NOUSER		"<a href=\"#table_nouser\">"
#define HTML_LINK_VIRUS			"<a href=\"#table_virus\">"
#define HTML_LINK_SPAM			"<a href=\"#table_spam\">"
#define HTML_LINK_END			"</a>"

#define HTML_TABLE_NORMAL	\
"<TABLE id=table_normal cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_TABLE_OUTGOING	\
"<TABLE id=table_outgoing cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_TABLE_INSULATION	\
"<TABLE id=table_insulation cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_TABLE_RETRYING	\
"<TABLE id=table_retrying cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_TABLE_TIMEOUT	\
"<TABLE id=table_timeout cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_TABLE_NOUSER	\
"<TABLE id=table_nouser cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_TABLE_VIRUS	\
"<TABLE id=table_virus cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_TABLE_SPAM	\
"<TABLE id=table_spam cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">"

/* fill table title here */

#define HTML_TABLE_2	\
"</TD>\r\n<TD align=right background=\"\
cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001801c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD></TR><TR bgColor=#bfbfbf><TD colSpan=4><TABLE cellSpacing=1\r\n\
cellPadding=2 width=\"100%\" border=0><TBODY>"

#define HTML_TABLE_2_END	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><BR>"

#define HTML_TABLE_PERCENTAGE	\
"<TABLE width=\"90%\" border=0 cellpadding=1 cellspacing=1><TR>\r\n\
<TD height=\"23\" align=\"left\" nowrap>"

#define HTML_TABLE_PERCENTAGE_END	\
"</TD></TR></TABLE><P></P><BR><P></P><BR>\r\n"

#define HTML_TABLE_END	\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR><P></P><BR>\r\n"

#define HTML_06	\
"<P></P><BR><P></P><BR></CENTER></BODY></HTML>\r\n"

#define HTML_TBITEM_FIRST	"<TR class=SolidRow><TD>&nbsp; "
#define HTML_TBITEM_1		"<TR class=ItemRow><TD>&nbsp; "
#define HTML_TBITEM_2		"&nbsp;</TD><TD>&nbsp; "
#define HTML_TBITEM_3		"&nbsp;</TD><TD>&nbsp; "
#define HTML_TBITEM_4		"&nbsp;</TD><TD>"
#define HTML_TBITEM_5		"</TD></TR>\r\n"

#define HTML_CHART_32   "<IMG src=\"cid:000001c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_16   "<IMG src=\"cid:000901c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_8    "<IMG src=\"cid:000801c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_4    "<IMG src=\"cid:000701c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_2    "<IMG src=\"cid:000601c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_1    "<IMG src=\"cid:000501c695cb$9bc53450$6601a8c0@herculiz\">"

#define HTML_STATISTIC_1		\
"<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0> <TBODY><TR>\r\n\
<TD noWrap align=left height=23></TD></TR></TBODY></TABLE><BR>\r\n\
<A name=General_Statistics></A>\r\n\
<TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0><TBODY>\r\n\
<TABLE class=ChartTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\r\n\
<TBODY><TR><TD align=middle><CENTER>\r\n\
<TABLE><TBODY><TR vAlign=bottom><TD>&nbsp;</TD>\r\n"

#define HTML_STATISTIC_2		\
"<TD>&nbsp;</TD></TR><TR vAlign=center><TD>&nbsp;</TD>\n"

#define HTML_STATISTIC_3     \
"<TD>&nbsp;</TD></TR></TBODY></TABLE><BR>\n\
<TABLE><TBODY><TR><TD width=80 bgColor=#ececec>%s</TD>\n\
<TD width=160 bgColor=#ffb055>%s</TD>\n\
<TD width=160 bgColor=#4477dd>%s</TD>\n\
<TD width=160 bgColor=#66f0ff>%s</TD>\n\
<TD width=160 bgColor=#ececec>%s</TD></TR>\n"

#define HTML_STATISTIC_4		\
"</TBODY></TABLE><BR></CENTER></TD></TR></TBODY></TABLE></TD></TR> \
</TBODY></TABLE></TD></TR><BR></CENTER></BODY></HTML>"

#define HTML_SUMMARY_LINE   "<TR><TD colspan=5><HR></TD>"

#define HTML_TBCELL_BEGIN   "<TD>"
#define HTML_TBCELL_END     "</TD>\r\n"
#define HTML_TBLINE_BEGIN   "<TR>"
#define HTML_TBLINE_END     "</TR>\r\n"

#define HTML_CHART_SPAM \
"<IMG title=\"%s: %d\" src=\"cid:100003c695cb$9bc2ea60$6601a8c0@herculiz\" \
height=%d width=12 align=bottom>"

#define HTML_CHART_NORMAL   \
"<IMG title=\"%s: %d\" src=\"cid:100001c695cb$9bc2ea60$6601a8c0@herculiz\" \
height=%d width=12 align=bottom>"

#define HTML_CHART_OUTGOING   \
"<IMG title=\"%s: %d\" src=\"cid:100002c695cb$9bc2ea60$6601a8c0@herculiz\" \
height=%d width=12 align=bottom>"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

enum {
	REPORT_NONE,
	REPORT_BRIEF,
	REPORT_DETAIL,
	REPORT_SIMPLE
};

typedef struct _SORT_DATA {
	unsigned int num;
	unsigned int pos;
} SORT_DATA;

typedef struct _STATISTIC_ITEM {
	char date[16];
	int spam;
	int normal;
	int outgoing_num;
} STATISTIC_ITEM;

static time_t g_now_time;
static char g_dest_path[256];
static char g_logo_link[256];
static char g_data_path[256];
static char g_resource_path[256];
static LANG_RESOURCE *g_lang_resource;
static char *g_d1_ptr;
static char *g_d2_ptr;
static char *g_kl_ptr;
static char *g_kr_ptr;
static char *g_logo_ptr;
static char *g_bar01_ptr;
static char *g_bar02_ptr;
static char *g_bar04_ptr;
static char *g_bar08_ptr;
static char *g_bar16_ptr;
static char *g_bar32_ptr;
static char *g_vp_ptr;
static char *g_vu_ptr;
static char *g_vh_ptr;
static int g_d1_len;
static int g_d2_len;
static int g_kl_len;
static int g_kr_len;
static int g_logo_len;
static int g_bar01_len;
static int g_bar02_len;
static int g_bar04_len;
static int g_bar08_len;
static int g_bar16_len;
static int g_bar32_len;
static int g_vp_len;
static int g_vu_len;
static int g_vh_len;
static BOOL g_bar1_hit;
static BOOL g_bar2_hit;
static BOOL g_bar4_hit;
static BOOL g_bar8_hit;
static BOOL g_bar16_hit;
static BOOL g_bar32_hit;

static char* item_sorter_draw_chart(char *ptr, int base_val, int num);

static void item_sorter_sort(SORT_DATA *parray, int size);

static void item_sorter_daily_statistics(ITEM_DATA *parray, int size,
	int normal_num, int out_going_num, int timeout_num, int nouser_num,
	int retrying_num, int virus_num, int spam_num, int insulated_num,
	int total_num, const char *domain, const char *padministrator,
	const char *language, int type);

static void item_sorter_mensual_statistics(char *path, const char *domain,
	const char *padministrator, const char *language);

static BOOL item_sorter_retrieve_image(const char *path, char **pptr,
	int *plen);

static int item_sorter_domain_query(const char* domain, char *domain_path,
	char *administrator, char *language);

void item_sorter_init(time_t now_time, const char *data_path,
	const char *url_link, const char *resource_path)
{
	g_d1_ptr = NULL;
	g_d2_ptr = NULL;
	g_kl_ptr = NULL;
	g_kr_ptr = NULL;
	g_logo_ptr = NULL;
	g_bar01_ptr = NULL;
	g_bar02_ptr = NULL;
	g_bar04_ptr = NULL;
	g_bar08_ptr = NULL;
	g_bar16_ptr = NULL;
	g_bar32_ptr = NULL;
	g_vp_ptr = NULL;
	g_vu_ptr = NULL;
	g_vh_ptr = NULL;
	g_now_time = now_time;
	strcpy(g_dest_path, "/tmp/posidon_cache");
	strcpy(g_logo_link, url_link);
	strcpy(g_data_path, data_path);
	strcpy(g_resource_path, resource_path);
}

int item_sorter_run()
{
	int fd, array_size, sorted_size;
	int i, j, *presult;
	int report_type;
	int sessions[8];
	int out_going_num, normal_num, insulated_num;
	int nouser_num, virus_num, spam_num;
	int retrying_num, timeout_num, total_num;
	ITEM_DATA *item_array;
	DIR *dirp1, *dirp2;
	INT_HASH_TABLE *phash;
	struct tm *ptime;
	struct stat node_stat;
	struct dirent *direntp1, *direntp2;
	char domain_path[256];
	char temp_path[256], time_str[32];
	char administrator[256], language[16];
	char statistic_path[256], temp_buff[256];
	SORT_DATA *sort_array;
	char *pbuff;


	sprintf(temp_path, "%s/picture/di1.gif", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_d1_ptr, &g_d1_len)) {
		return -1;
	}
	sprintf(temp_path, "%s/picture/di2.gif", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_d2_ptr, &g_d2_len)) {
		return -2;
	}
	sprintf(temp_path, "%s/picture/kl.gif", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_kl_ptr, &g_kl_len)) {
		return -3;
	}
	sprintf(temp_path, "%s/picture/kr.gif", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_kr_ptr, &g_kr_len)) {
		return -4;
	}
	sprintf(temp_path, "%s/picture/logo_bb.gif", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_logo_ptr,
		&g_logo_len)) {
		return -5;
	}
	sprintf(temp_path, "%s/picture/bar01.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_bar01_ptr,
		&g_bar01_len)) {
		return -6;
	}
	sprintf(temp_path, "%s/picture/bar02.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_bar02_ptr,
		&g_bar02_len)) {
		return -7;
	}
	sprintf(temp_path, "%s/picture/bar04.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_bar04_ptr,
		&g_bar04_len)) {
		return -8;
	}
	sprintf(temp_path, "%s/picture/bar08.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_bar08_ptr,
		&g_bar08_len)) {
		return -9;
	}
	sprintf(temp_path, "%s/picture/bar16.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_bar16_ptr,
		&g_bar16_len)) {
		return -10;
	}
	sprintf(temp_path, "%s/picture/bar32.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_bar32_ptr,
		&g_bar32_len)) {
		return -11;
	}
	sprintf(temp_path, "%s/picture/vp.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_vp_ptr, &g_vp_len)) {
		return -12;
	}
	sprintf(temp_path, "%s/picture/vu.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_vu_ptr, &g_vu_len)) {
		return -13;
	}
	sprintf(temp_path, "%s/picture/vh.png", g_data_path);
	if (FALSE == item_sorter_retrieve_image(temp_path, &g_vh_ptr, &g_vh_len)) {
		return -14;
	}
	g_lang_resource = lang_resource_init(g_resource_path);
	if (NULL == g_lang_resource) {
		return -15;
	}
	
	dirp1 = opendir(g_dest_path);
	if (NULL == dirp1) {
		return 0;
	}
	while (direntp1 = readdir(dirp1)) {
		if (0 == strcmp(direntp1->d_name, ".") ||
			0 == strcmp(direntp1->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", g_dest_path, direntp1->d_name);
		dirp2 = opendir(temp_path);
		if (NULL == dirp2) {
			continue;
		}
		while (direntp2 = readdir(dirp2)) {
			if (0 == strcmp(direntp2->d_name, ".") ||
				0 == strcmp(direntp2->d_name, "..")) {
				continue;
			}
			sprintf(temp_path, "%s/%s/%s/temp.dat", g_dest_path,
				direntp1->d_name, direntp2->d_name);
			if (0 != stat(temp_path, &node_stat)) {
				continue;
			}
			report_type = item_sorter_domain_query(direntp2->d_name,
							domain_path, administrator, language);
			if ('\0' == domain_path[0]) {
				continue;
			}
			pbuff = malloc(node_stat.st_size*2);
			if (NULL == pbuff) {
				continue;
			}
			array_size = node_stat.st_size / sizeof(ITEM_DATA);
			sort_array = malloc(sizeof(SORT_DATA)*array_size);
			if (NULL == sort_array) {
				free(pbuff);
				continue;
			}
			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				free(pbuff);
				free(sort_array);
				continue;
			}
			if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
				free(pbuff);
				free(sort_array);
				continue;
			}
			close(fd);
			remove(temp_path);
			item_array = (ITEM_DATA*)pbuff;
			
			phash = int_hash_init(array_size, 8*sizeof(int), NULL);
			if (NULL == phash) {
				free(pbuff);
				free(sort_array);
				continue;
			}
			for (i=0; i<array_size; i++) {
				if (0 == item_array[i].queue_id) {
					continue;
				}
				presult = (int*)int_hash_query(phash, item_array[i].queue_id);
				if (NULL == presult) {
					/* ignore items which haven't corresponding OK item */
					if (LOG_ITEM_SPAM_INSULATION == item_array[i].type ||
						LOG_ITEM_NO_USER == item_array[i].type) {
						continue;
					}
					memset(sessions, 0, 8*sizeof(int));
					sessions[0] = i + 1;
					int_hash_add(phash, item_array[i].queue_id, sessions);
				} else {
					if (LOG_ITEM_SPAM_INSULATION == item_array[i].type) {
						for (j=0; j<8; j++) {
							if (0 == presult[j]) {
								break;
							}
							item_array[presult[j] - 1].type = 
													LOG_ITEM_SPAM_INSULATION;
						}
						item_array[i].time = 0;
					} else if (LOG_ITEM_NO_USER == item_array[i].type) {
						for (j=0; j<8; j++) {
							if (0 == presult[j]) {
								break;
							}
							if (0 == strcmp(item_array[presult[j] - 1].to,
								item_array[i].to)) {
								item_array[presult[j] - 1].type = 
													LOG_ITEM_NO_USER;
								break;
							}
						}
						item_array[i].time = 0;
					} else {
						for (j=0; j<8; j++) {
							if (0 == presult[j]) {
								presult[j] = i + 1;
								break;
							}
						}
					}

				}
			}
			int_hash_free(phash);
			for (i=0; i<array_size; i++) {
				sort_array[i].num = item_array[i].time;
				sort_array[i].pos = i;
			}
			item_sorter_sort(sort_array, array_size);
			for (i=0,sorted_size=0; i<array_size; i++) {
				if (0 == sort_array[i].num) {
					continue;
				}
				memcpy(item_array + array_size + sorted_size,
					item_array + sort_array[i].pos, sizeof(ITEM_DATA));
				sorted_size ++;
			}
			memmove(item_array, item_array + array_size,
				sizeof(ITEM_DATA)*sorted_size);
			ptime = localtime(&g_now_time);
			strftime(time_str, 32, "%m%d", ptime);
			sprintf(statistic_path, "%s/log/statistic.txt", domain_path);
			sprintf(temp_path, "%s/log/log%s.dat", domain_path, time_str);
			fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
			write(fd, item_array, sizeof(ITEM_DATA)*sorted_size);
			close(fd);
			
			out_going_num = 0;
			normal_num = 0;
			insulated_num = 0;
			timeout_num = 0;
			nouser_num = 0;
			virus_num = 0;
			spam_num = 0;
			retrying_num = 0;

			for (i=0; i<sorted_size; i++) {
				switch (item_array[i].type) {
				case LOG_ITEM_OK:
					normal_num ++;
					break;
				case LOG_ITEM_SPAM_INSULATION:
					insulated_num ++;
					break;
				case LOG_ITEM_RETRYING:
					retrying_num ++;
					break;
				case LOG_ITEM_TIMEOUT:
					timeout_num ++;
					break;
				case LOG_ITEM_NO_USER:
					nouser_num ++;
					break;
				case LOG_ITEM_SPAM_VIRUS:
					virus_num ++;
					break;
				case LOG_ITEM_SPAM_MAIL:
					spam_num ++;
					break;
				case LOG_ITEM_OUTGOING_OK:
					out_going_num ++;
					break;
				}
			}
			total_num = insulated_num + spam_num + virus_num + retrying_num
						+ nouser_num + timeout_num + normal_num;
				
			fd = open(statistic_path, O_WRONLY|O_APPEND|O_CREAT, DEF_MODE);
			strftime(time_str, 32, "%Y-%m-%d", localtime(&g_now_time));
			sprintf(temp_buff, "%s\t%d\t%d\t%d\n", time_str,
					total_num - normal_num, normal_num, out_going_num);
			write(fd, temp_buff, strlen(temp_buff));
			close(fd);
				
			switch (report_type) {
			case REPORT_NONE:
				break;
			case REPORT_DETAIL:
				item_sorter_daily_statistics(item_array, sorted_size,
					normal_num, out_going_num, timeout_num, nouser_num,
					retrying_num, virus_num, spam_num, insulated_num,
					total_num, direntp2->d_name, administrator, language,
					REPORT_DETAIL);
				break;
			case REPORT_BRIEF:
				item_sorter_daily_statistics(item_array, sorted_size,
					normal_num, out_going_num, timeout_num, nouser_num,
					retrying_num, virus_num, spam_num, insulated_num,
					total_num, direntp2->d_name, administrator, language,
					REPORT_BRIEF);
				break;
			case REPORT_SIMPLE:
				item_sorter_mensual_statistics(statistic_path,
					direntp2->d_name, administrator, language);
				break;
			}	

			free(pbuff);
			free(sort_array);
			
		}
		closedir(dirp2);
	}
	closedir(dirp1);
	return 0;
}

int item_sorter_stop()
{
	if (NULL != g_lang_resource) {
		lang_resource_free(g_lang_resource);
		g_lang_resource = NULL;
	}
	if (NULL != g_d1_ptr) {
		free(g_d1_ptr);
		g_d1_ptr = NULL;
		g_d1_len = 0;
	}
	if (NULL != g_d2_ptr) {
		free(g_d2_ptr);
		g_d2_ptr = NULL;
		g_d2_len = 0;
	}
	if (NULL != g_kl_ptr) {
		free(g_kl_ptr);
		g_kl_ptr = NULL;
		g_kl_len = 0;
	}
	if (NULL != g_kr_ptr) {
		free(g_kr_ptr);
		g_kr_ptr = NULL;
		g_kr_len = 0;
	}
	if (NULL != g_logo_ptr) {
		free(g_logo_ptr);
		g_logo_ptr = NULL;
		g_logo_len = 0;
	}
	if (NULL != g_bar01_ptr) {
		free(g_bar01_ptr);
		g_bar01_ptr = NULL;
		g_bar01_len = 0;
	}
	if (NULL != g_bar02_ptr) {
		free(g_bar02_ptr);
		g_bar02_ptr = NULL;
		g_bar02_len = 0;
	}
	if (NULL != g_bar04_ptr) {
		free(g_bar04_ptr);
		g_bar04_ptr = NULL;
		g_bar04_len = 0;
	}
	if (NULL != g_bar08_ptr) {
		free(g_bar08_ptr);
		g_bar08_ptr = NULL;
		g_bar08_len = 0;
	}
	if (NULL != g_bar16_ptr) {
		free(g_bar16_ptr);
		g_bar16_ptr = NULL;
		g_bar16_len = 0;
	}
	if (NULL != g_bar32_ptr) {
		free(g_bar32_ptr);
		g_bar32_ptr = NULL;
		g_bar32_len = 0;
	}
	if (NULL != g_vp_ptr) {
		free(g_vp_ptr);
		g_vp_ptr = NULL;
		g_vp_len = 0;
	}
	if (NULL != g_vu_ptr) {
		free(g_vu_ptr);
		g_vu_ptr = NULL;
		g_vu_len = 0;
	}
	if (NULL != g_vh_ptr) {
		free(g_vh_ptr);
		g_vh_ptr = NULL;
		g_vh_len = 0;
	}
	return 0;
}

void item_sorter_free()
{
	g_dest_path[0] = '\0';

}

static void item_sorter_sort(SORT_DATA *parray, int size)
{
	int low, high;
	unsigned int list_separator;
	SORT_DATA temp;

	low = 0;
	high = size - 1;
	list_separator = parray[size/2].num;
	do {
		while (parray[low].num < list_separator) {
			low ++;
		}
		while (parray[high].num > list_separator) {
			high --;
		}
		if (low <= high) {
			temp = parray[low];
			parray[low] = parray[high];
			parray[high] = temp;
			low ++;
			high --;	
		}
	} while (low <= high);
	if (high > 0) {
		item_sorter_sort(parray, high + 1);
	}
	if (low < size - 1) {
		item_sorter_sort(parray + low, size - low);

	}
}

static void item_sorter_daily_statistics(ITEM_DATA *parray, int size,
	int normal_num, int out_going_num, int timeout_num, int nouser_num,
	int retrying_num, int virus_num, int spam_num, int insulated_num,
	int total_num, const char *domain, const char *padministrator,
	const char *language, int type)
{
	FILE *fp;
	char *pdomain;
	char *pbuff, *ptr;
	const char *str;
	time_t now_time;
	struct in_addr addr;
	char time_buff[128];
	char temp_buff[256];
	char temp_sender[256];
	int max_num, i, len;

	pbuff = malloc(size*256 + 1024*1024);
	if (NULL == pbuff) {
		return;
	}
	
	max_num = normal_num;
	if (out_going_num > max_num) {
		max_num = out_going_num;
	}
	if (insulated_num > max_num) {
		max_num = insulated_num;
	}
	if (retrying_num > max_num) {
		max_num = retrying_num;
	}
	if (timeout_num > max_num) {
		max_num = timeout_num;
	}
	if (nouser_num > max_num) {
		max_num = nouser_num;
	}
	if (virus_num > max_num) {
		max_num = virus_num;
	}
	if (spam_num > max_num) {
		max_num = spam_num;
	}
	max_num /= 64;
	
	g_bar1_hit = FALSE;
	g_bar2_hit = FALSE;
	g_bar4_hit = FALSE;
	g_bar8_hit = FALSE;
	g_bar16_hit = FALSE;
	g_bar32_hit = FALSE;
	
	ptr = pbuff;
	memcpy(ptr, MAIL_HEAD_1, sizeof(MAIL_HEAD_1) - 1);
	ptr += sizeof(MAIL_HEAD_1) - 1;
	strftime(time_buff, 128, lang_resource_get(g_lang_resource,"DAILY_TIME_FORMAT",
		language), localtime(&g_now_time));
	ptr += sprintf(ptr, "To: %s\r\nSubject: %s %s %s\r\n", padministrator, 
			lang_resource_get(g_lang_resource,"SUBJECT_DAILY", language), domain, time_buff);
	time(&now_time);
	strftime(time_buff, 128, "%a, %d %b %Y %H:%M:%S %z", localtime(&now_time));
	ptr += sprintf(ptr, "Date: %s\r\n", time_buff);
	memcpy(ptr, MAIL_HEAD_2, sizeof(MAIL_HEAD_2) - 1);
	ptr += sizeof(MAIL_HEAD_2) - 1;
	
	memcpy(ptr, HTML_01, sizeof(HTML_01) - 1);
	ptr += sizeof(HTML_01) - 1;
	
	str = lang_resource_get(g_lang_resource,"CHARSET", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	
	memcpy(ptr, HTML_02, sizeof(HTML_02) - 1);
	ptr += sizeof(HTML_02) - 1;

	str = lang_resource_get(g_lang_resource,"HTML_DAILY_TITLE", language);
	len = strlen(str);

	memcpy(ptr, str, len);
	ptr += len;
	
	memcpy(ptr, HTML_03, sizeof(HTML_03) - 1);
	ptr += sizeof(HTML_03) - 1;

	str = lang_resource_get(g_lang_resource,"CHARSET", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_04, sizeof(HTML_04) - 1);
	ptr += sizeof(HTML_04) - 1;
	
	str = lang_resource_get(g_lang_resource,"CONTENT_TITLE_DAILY", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	ptr += sprintf(ptr, HTML_05, g_logo_link);

	memcpy(ptr, HTML_TABLE_1, sizeof(HTML_TABLE_1) - 1);
	ptr += sizeof(HTML_TABLE_1) - 1;

	str = lang_resource_get(g_lang_resource,"SUM_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	
	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_NORMAL, sizeof(HTML_LINK_NORMAL) - 1);
	ptr += sizeof(HTML_LINK_NORMAL) - 1;
	
	str = lang_resource_get(g_lang_resource,"NORMAL_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;

	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", normal_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, normal_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_OUTGOING, sizeof(HTML_LINK_OUTGOING) - 1);
	ptr += sizeof(HTML_LINK_OUTGOING) - 1;
	
	str = lang_resource_get(g_lang_resource,"OUTGOING_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;

	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", out_going_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, out_going_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_INSULATION, sizeof(HTML_LINK_INSULATION) - 1);
	ptr += sizeof(HTML_LINK_INSULATION) - 1;
	
	str = lang_resource_get(g_lang_resource,"INSULATED_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	
	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;
	
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", insulated_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, insulated_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_RETRYING, sizeof(HTML_LINK_RETRYING) - 1);
	ptr += sizeof(HTML_LINK_RETRYING) - 1;
	
	str = lang_resource_get(g_lang_resource,"RETRYING_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;

	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", retrying_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, retrying_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_TIMEOUT, sizeof(HTML_LINK_TIMEOUT) - 1);
	ptr += sizeof(HTML_LINK_TIMEOUT) - 1;
	
	str = lang_resource_get(g_lang_resource,"TIMEOUT_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;
	
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", timeout_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, timeout_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_NOUSER, sizeof(HTML_LINK_NOUSER) - 1);
	ptr += sizeof(HTML_LINK_NOUSER) - 1;
	
	str = lang_resource_get(g_lang_resource,"NOUSER_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;
	
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", nouser_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, nouser_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_VIRUS, sizeof(HTML_LINK_VIRUS) - 1);
	ptr += sizeof(HTML_LINK_VIRUS) - 1;
	
	str = lang_resource_get(g_lang_resource,"VIRUS_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;
	
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", virus_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, virus_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
	ptr += sizeof(HTML_TBITEM_1) - 1;
	
	memcpy(ptr, HTML_LINK_SPAM, sizeof(HTML_LINK_SPAM) - 1);
	ptr += sizeof(HTML_LINK_SPAM) - 1;
	
	str = lang_resource_get(g_lang_resource,"SPAM_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_LINK_END, sizeof(HTML_LINK_END) - 1);
	ptr += sizeof(HTML_LINK_END) - 1;
	
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;

	ptr += sprintf(ptr, "%d", spam_num);

	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	
	ptr = item_sorter_draw_chart(ptr, max_num, spam_num);
	
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;

	memcpy(ptr, HTML_TABLE_2_END, sizeof(HTML_TABLE_2_END) - 1);
	ptr += sizeof(HTML_TABLE_2_END) - 1;

	memcpy(ptr, HTML_TABLE_PERCENTAGE, sizeof(HTML_TABLE_PERCENTAGE) - 1);
	ptr += sizeof(HTML_TABLE_PERCENTAGE) - 1;
	
	if (total_num > 0) {
		ptr += sprintf(ptr, "%s:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
			"&nbsp;&nbsp;%d%%",lang_resource_get(g_lang_resource,"SPAM_PERCENTAGE", language),
			(total_num - normal_num)*100/total_num);
	}
	
	memcpy(ptr, HTML_TABLE_PERCENTAGE_END, 
				sizeof(HTML_TABLE_PERCENTAGE_END) - 1);
	ptr += sizeof(HTML_TABLE_PERCENTAGE_END) - 1;
	
	if (REPORT_BRIEF == type) {
		goto FINAL_PART;
	}
	if (0 == normal_num) {
		goto OUTGOING_PART;
	}
	memcpy(ptr, HTML_TABLE_NORMAL, sizeof(HTML_TABLE_NORMAL) - 1);
	ptr += sizeof(HTML_TABLE_NORMAL) - 1;

	str = lang_resource_get(g_lang_resource,"NORMAL_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_OK != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;


OUTGOING_PART:
	if (0 == out_going_num) {
		goto INSULATED_PART;
	}
	memcpy(ptr, HTML_TABLE_OUTGOING, sizeof(HTML_TABLE_OUTGOING) - 1);
	ptr += sizeof(HTML_TABLE_OUTGOING) - 1;

	str = lang_resource_get(g_lang_resource,"OUTGOING_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_OUTGOING_OK != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;
	
	
INSULATED_PART:
	if (0 == insulated_num) {
		goto RETRYING_PART;
	}
	memcpy(ptr, HTML_TABLE_INSULATION, sizeof(HTML_TABLE_INSULATION) - 1);
	ptr += sizeof(HTML_TABLE_INSULATION) - 1;

	str = lang_resource_get(g_lang_resource,"INSULATED_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_SPAM_INSULATION != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;
RETRYING_PART:
	if (0 == retrying_num) {
		goto TIMEOUT_PART;
	}
	memcpy(ptr, HTML_TABLE_RETRYING, sizeof(HTML_TABLE_RETRYING) - 1);
	ptr += sizeof(HTML_TABLE_RETRYING) - 1;

	str = lang_resource_get(g_lang_resource,"RETRYING_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_RETRYING != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;
	
TIMEOUT_PART:
	if (0 == timeout_num) {
		goto NOUSER_PART;
	}
	memcpy(ptr, HTML_TABLE_TIMEOUT, sizeof(HTML_TABLE_TIMEOUT) - 1);
	ptr += sizeof(HTML_TABLE_TIMEOUT) - 1;

	str = lang_resource_get(g_lang_resource,"TIMEOUT_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_TIMEOUT != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;
	
NOUSER_PART:
	if (0 == nouser_num) {
		goto VIRUS_PART;
	}
	memcpy(ptr, HTML_TABLE_NOUSER, sizeof(HTML_TABLE_NOUSER) - 1);
	ptr += sizeof(HTML_TABLE_NOUSER) - 1;

	str = lang_resource_get(g_lang_resource,"NOUSER_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_NO_USER != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;
	
VIRUS_PART:
	if (0 == virus_num) {
		goto SPAM_PART;
	}
	memcpy(ptr, HTML_TABLE_VIRUS, sizeof(HTML_TABLE_VIRUS) - 1);
	ptr += sizeof(HTML_TABLE_VIRUS) - 1;

	str = lang_resource_get(g_lang_resource,"VIRUS_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_SPAM_VIRUS != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;
SPAM_PART:
	if (0 == spam_num) {
		goto FINAL_PART;
	}
	memcpy(ptr, HTML_TABLE_SPAM, sizeof(HTML_TABLE_SPAM) - 1);
	ptr += sizeof(HTML_TABLE_SPAM) - 1;

	str = lang_resource_get(g_lang_resource,"SPAM_TITLE", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;

	memcpy(ptr, HTML_TABLE_2, sizeof(HTML_TABLE_2) - 1);
	ptr += sizeof(HTML_TABLE_2) - 1;
	
	memcpy(ptr, HTML_TBITEM_FIRST, sizeof(HTML_TBITEM_FIRST) - 1);
	ptr += sizeof(HTML_TBITEM_FIRST) - 1;
	str = lang_resource_get(g_lang_resource,"TIME_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
	ptr += sizeof(HTML_TBITEM_2) - 1;
	str = lang_resource_get(g_lang_resource,"IP_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
	ptr += sizeof(HTML_TBITEM_3) - 1;
	str = lang_resource_get(g_lang_resource,"FROM_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
	ptr += sizeof(HTML_TBITEM_4) - 1;
	str = lang_resource_get(g_lang_resource,"TO_TAG", language);
	len = strlen(str);
	memcpy(ptr, str, len);
	ptr += len;
	memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
	ptr += sizeof(HTML_TBITEM_5) - 1;
	
	for (i=0; i<size; i++) {
		if (LOG_ITEM_SPAM_MAIL != parray[i].type) {
			continue;
		}
		memcpy(ptr, HTML_TBITEM_1, sizeof(HTML_TBITEM_1) - 1);
		ptr += sizeof(HTML_TBITEM_1) - 1;
		ptr += strftime(ptr, 128, lang_resource_get(g_lang_resource,"ITEM_TIME_FORMAT",
				language), localtime(&parray[i].time));
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		addr.s_addr = parray[i].ip;
		str = inet_ntoa(addr);
		len = strlen(str);
		memcpy(ptr, str, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
		len = strlen(parray[i].from);
		memcpy(ptr, parray[i].from, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
		len = strlen(parray[i].to);
		memcpy(ptr, parray[i].to, len);
		ptr += len;
		memcpy(ptr, HTML_TBITEM_5, sizeof(HTML_TBITEM_5) - 1);
		ptr += sizeof(HTML_TBITEM_5) - 1;
	}
	memcpy(ptr, HTML_TABLE_END, sizeof(HTML_TABLE_END) - 1);
	ptr += sizeof(HTML_TABLE_END) - 1;
	
FINAL_PART:
	memcpy(ptr, HTML_06, sizeof(HTML_06) - 1);
	ptr += sizeof(HTML_06) - 1;
	
	memcpy(ptr, MAIL_ATTACHMENT_DI1, sizeof(MAIL_ATTACHMENT_DI1) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_DI1) - 1;
	memcpy(ptr, g_d1_ptr, g_d1_len);
	ptr += g_d1_len;
	memcpy(ptr, MAIL_ATTACHMENT_DI2, sizeof(MAIL_ATTACHMENT_DI2) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_DI2) - 1;
	memcpy(ptr, g_d2_ptr, g_d2_len);
	ptr += g_d2_len;
	memcpy(ptr, MAIL_ATTACHMENT_KL, sizeof(MAIL_ATTACHMENT_KL) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_KL) - 1;
	memcpy(ptr, g_kl_ptr, g_kl_len);
	ptr += g_kl_len;
	memcpy(ptr, MAIL_ATTACHMENT_KR, sizeof(MAIL_ATTACHMENT_KR) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_KR) - 1;
	memcpy(ptr, g_kr_ptr, g_kr_len);
	ptr += g_kr_len;
	memcpy(ptr, MAIL_ATTACHMENT_LOGO, sizeof(MAIL_ATTACHMENT_LOGO) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_LOGO) - 1;
	memcpy(ptr, g_logo_ptr, g_logo_len);
	ptr += g_logo_len;
	
	if (TRUE == g_bar32_hit) {
		memcpy(ptr, MAIL_ATTACHMENT_BAR32, sizeof(MAIL_ATTACHMENT_BAR32) - 1);
		ptr += sizeof(MAIL_ATTACHMENT_BAR32) - 1;
		memcpy(ptr, g_bar32_ptr, g_bar32_len);
		ptr += g_bar32_len;
	}
	if (TRUE == g_bar16_hit) {
		memcpy(ptr, MAIL_ATTACHMENT_BAR16, sizeof(MAIL_ATTACHMENT_BAR16) - 1);
		ptr += sizeof(MAIL_ATTACHMENT_BAR16) - 1;
		memcpy(ptr, g_bar16_ptr, g_bar16_len);
		ptr += g_bar16_len;
	}
	if (TRUE == g_bar8_hit) {
		memcpy(ptr, MAIL_ATTACHMENT_BAR8, sizeof(MAIL_ATTACHMENT_BAR8) - 1);
		ptr += sizeof(MAIL_ATTACHMENT_BAR8) - 1;
		memcpy(ptr, g_bar08_ptr, g_bar08_len);
		ptr += g_bar08_len;
	}
	if (TRUE == g_bar4_hit) {
		memcpy(ptr, MAIL_ATTACHMENT_BAR4, sizeof(MAIL_ATTACHMENT_BAR4) - 1);
		ptr += sizeof(MAIL_ATTACHMENT_BAR4) - 1;
		memcpy(ptr, g_bar04_ptr, g_bar04_len);
		ptr += g_bar04_len;
	}
	if (TRUE == g_bar2_hit) {
		memcpy(ptr, MAIL_ATTACHMENT_BAR2, sizeof(MAIL_ATTACHMENT_BAR2) - 1);
		ptr += sizeof(MAIL_ATTACHMENT_BAR2) - 1;
		memcpy(ptr, g_bar02_ptr, g_bar02_len);
		ptr += g_bar02_len;
	}
	if (TRUE == g_bar1_hit) {
		memcpy(ptr, MAIL_ATTACHMENT_BAR1, sizeof(MAIL_ATTACHMENT_BAR1) - 1);
		ptr += sizeof(MAIL_ATTACHMENT_BAR1) - 1;
		memcpy(ptr, g_bar01_ptr, g_bar01_len);
		ptr += g_bar01_len;
	}
	memcpy(ptr, MAIL_ATTACHMENT_END, sizeof(MAIL_ATTACHMENT_END) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_END) - 1;

	pdomain = strchr(padministrator, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (0 == strcasecmp(pdomain, domain)) {
			smtp_sender_send("log-report@system.mail", padministrator,
				pbuff, ptr - pbuff);
		} else {
			sprintf(temp_sender, "log-report@%s", domain);
			smtp_sender_send(temp_sender, padministrator, pbuff, ptr - pbuff);
		}
	}
	free(pbuff);
}

static char* item_sorter_draw_chart(char *ptr, int base_val, int num)
{
	int temp_num;
	
	if (0 == base_val) {
		return ptr;
	}
	temp_num = num;
	if (1 == temp_num / (base_val*64)) {
		memcpy(ptr, HTML_CHART_32, sizeof(HTML_CHART_32) - 1);
		ptr += sizeof(HTML_CHART_32) - 1;
		memcpy(ptr, HTML_CHART_32, sizeof(HTML_CHART_32) - 1);
		ptr += sizeof(HTML_CHART_32) - 1;
		temp_num = 0;
		g_bar32_hit = TRUE;
	}
	if (1 == temp_num / (base_val*32)) {
		memcpy(ptr, HTML_CHART_32, sizeof(HTML_CHART_32) - 1);
		ptr += sizeof(HTML_CHART_32) - 1;
		temp_num = temp_num % (base_val*32);
		g_bar32_hit = TRUE;
	}
	if (1 == temp_num / (base_val*16)) {
		memcpy(ptr, HTML_CHART_16, sizeof(HTML_CHART_16) - 1);
		ptr += sizeof(HTML_CHART_16) - 1;
		temp_num = temp_num % (base_val*16);
		g_bar16_hit = TRUE;
	}
	if (1 == temp_num / (base_val*8)) {
		memcpy(ptr, HTML_CHART_8, sizeof(HTML_CHART_8) - 1);
		ptr += sizeof(HTML_CHART_8) - 1;
		temp_num = temp_num % (base_val*8);
		g_bar8_hit = TRUE;
	}
	if (1 == temp_num / (base_val*4)) {
		memcpy(ptr, HTML_CHART_4, sizeof(HTML_CHART_4) - 1);
		ptr += sizeof(HTML_CHART_4) - 1;
		temp_num = temp_num % (base_val*4);
		g_bar4_hit = TRUE;
	}
	if (1 == temp_num / (base_val*2)) {
		memcpy(ptr, HTML_CHART_2, sizeof(HTML_CHART_2) - 1);
		ptr += sizeof(HTML_CHART_2) - 1;
		temp_num = temp_num % (base_val*2);
		g_bar2_hit = TRUE;
	}
	if (1 == temp_num / base_val) {
		memcpy(ptr, HTML_CHART_1, sizeof(HTML_CHART_1) - 1);
		ptr += sizeof(HTML_CHART_1) - 1;
		g_bar1_hit = TRUE;
	}
	return ptr;
}

static void item_sorter_mensual_statistics(char *path, const char *domain,
	const char *padministrator, const char *language)
{
	int i, len;
	int height;
	int max_num;
	int item_num;
	int year, month;
	int total_spam;
	int total_normal;
	int total_outgoing;
	time_t tmp_time, now_time;
	LIST_FILE *pfile;
	char time_buff[128];
	char temp_sender[256];
	char *pbuff, *ptr, *pdomain;
	STATISTIC_ITEM *pitem;
	struct tm temp_tm, *ptm;
	
	tmp_time = g_now_time + 24*3600;
	ptm = localtime(&tmp_time);
	if (1 != ptm->tm_mday) {
		return;
	}
	
	ptm = localtime(&g_now_time);
	year = ptm->tm_year;
	month = ptm->tm_mon;
	
	pfile = list_file_init(path, "%s:16%d%d%d");
	if (NULL == pfile) {
		return;
	}
	pbuff = malloc(128*1024);
	if (NULL == pbuff) {
		list_file_free(pfile);
		return;
	}
	pitem = (STATISTIC_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	
	ptr = pbuff;
	memcpy(ptr, MAIL_HEAD_1, sizeof(MAIL_HEAD_1) - 1);
	ptr += sizeof(MAIL_HEAD_1) - 1;
	strftime(time_buff, 128, lang_resource_get(g_lang_resource,"MENSUAL_TIME_FORMAT",
			language), localtime(&g_now_time));
	ptr += sprintf(ptr, "To: %s\r\nSubject: %s %s %s\r\n", padministrator,
		lang_resource_get(g_lang_resource,"SUBJECT_MENSUAL", language), domain, time_buff);
	time(&now_time);
	strftime(time_buff, 128, "%a, %d %b %Y %H:%M:%S %z", localtime(&now_time));
	ptr += sprintf(ptr, "Date: %s\r\n", time_buff);
	memcpy(ptr, MAIL_HEAD_2, sizeof(MAIL_HEAD_2) - 1);
	ptr += sizeof(MAIL_HEAD_2) - 1;

	memcpy(ptr, HTML_01, sizeof(HTML_01) - 1);
	ptr += sizeof(HTML_01) - 1;

	ptr	+= sprintf(ptr, lang_resource_get(g_lang_resource,"CHARSET", language));

	memcpy(ptr, HTML_02, sizeof(HTML_02) - 1);
	ptr += sizeof(HTML_02) - 1;

	ptr += sprintf(ptr, lang_resource_get(g_lang_resource,"HTML_MENSUAL_TITLE", language));

	memcpy(ptr, HTML_03, sizeof(HTML_03) - 1);
	ptr += sizeof(HTML_03) - 1;

	ptr += sprintf(ptr, lang_resource_get(g_lang_resource,"CHARSET", language));

	memcpy(ptr, HTML_04, sizeof(HTML_04) - 1);
	ptr += sizeof(HTML_04) - 1;

	ptr += sprintf(ptr, lang_resource_get(g_lang_resource,"CONTENT_TITLE_MENSUAL", language));

	ptr += sprintf(ptr, HTML_05, g_logo_link);

	memcpy(ptr, HTML_STATISTIC_1, sizeof(HTML_STATISTIC_1) - 1);
	ptr += sizeof(HTML_STATISTIC_1) - 1;

	max_num = 0;
	for (i=0; i<item_num; i++) {
		strptime(pitem[i].date, "%Y-%m-%d", &temp_tm);
		if (temp_tm.tm_year != year || temp_tm.tm_mon != month) {
			continue;
		}
		if (pitem[i].spam > max_num) {
			max_num = pitem[i].spam;
		}
		if (pitem[i].normal > max_num) {
			max_num = pitem[i].normal;
		}
		if (pitem[i].outgoing_num > max_num) {
			max_num = pitem[i].outgoing_num;
		}
	}

	for (i=0; i<item_num; i++) {
		strptime(pitem[i].date, "%Y-%m-%d", &temp_tm);
		if (temp_tm.tm_year != year || temp_tm.tm_mon != month) {
			continue;
		}
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		if (0 == pitem[i].spam || 0 == max_num) {
			height = 1;
		} else {
			height = ((double)pitem[i].spam)/max_num*200;
		}
		ptr += sprintf(ptr, HTML_CHART_SPAM, lang_resource_get(g_lang_resource,"CHART_SPAM",
				language), pitem[i].spam, height);
		if (0 == pitem[i].normal || 0 == max_num) {
			height = 1;
		} else {
			height = ((double)pitem[i].normal)/max_num*200;
		}
		ptr += sprintf(ptr, HTML_CHART_NORMAL, lang_resource_get(g_lang_resource,
				"CHART_NORMAL", language), pitem[i].normal, height);
		if (0 == pitem[i].outgoing_num || 0 == max_num) {
			height = 1;
		} else {
			height = ((double)pitem[i].outgoing_num)/max_num*200;
		}
		ptr += sprintf(ptr, HTML_CHART_OUTGOING, lang_resource_get(g_lang_resource,
				"CHART_OUTGOING", language), pitem[i].outgoing_num, height);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
	}
	memcpy(ptr, HTML_STATISTIC_2, sizeof(HTML_STATISTIC_2) - 1);
	ptr += sizeof(HTML_STATISTIC_2) - 1;
	for (i=0; i<item_num; i++) {
		strptime(pitem[i].date, "%Y-%m-%d", &temp_tm);
		if (temp_tm.tm_year != year || temp_tm.tm_mon != month) {
			continue;
		}
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", temp_tm.tm_mday);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
	}

	ptr += sprintf(ptr, HTML_STATISTIC_3, lang_resource_get(g_lang_resource,"MENSUAL_DATE",
			language), lang_resource_get(g_lang_resource,"MENSUAL_SPAM", language),
			lang_resource_get(g_lang_resource,"MENSUAL_NORMAL", language),
			lang_resource_get(g_lang_resource,"MENSUAL_OUTGOING", language),
			lang_resource_get(g_lang_resource,"MENSUAL_PERCENTAGE", language));
	total_spam = 0;
	total_normal = 0;
	total_outgoing = 0;
	for (i=0; i<item_num; i++) {
		strptime(pitem[i].date, "%Y-%m-%d", &temp_tm);
		if (temp_tm.tm_year != year || temp_tm.tm_mon != month) {
			continue;
		}

		memcpy(ptr, HTML_TBLINE_BEGIN, sizeof(HTML_TBLINE_BEGIN) - 1);
		ptr += sizeof(HTML_TBLINE_BEGIN) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", temp_tm.tm_mday);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", pitem[i].spam);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", pitem[i].normal);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", pitem[i].outgoing_num);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		if (0 == pitem[i].spam + pitem[i].normal) {
			ptr += sprintf(ptr, "0%%");
		} else {
			ptr += sprintf(ptr, "%d%%",
					(100*pitem[i].spam)/(pitem[i].spam+pitem[i].normal));
		}
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBLINE_END, sizeof(HTML_TBLINE_END) - 1);
		ptr += sizeof(HTML_TBLINE_END) - 1;
		total_spam += pitem[i].spam;
		total_normal += pitem[i].normal;
		total_outgoing += pitem[i].outgoing_num;
	}
	
	if (0 != total_spam + total_normal + total_outgoing) {
		memcpy(ptr, HTML_SUMMARY_LINE, sizeof(HTML_SUMMARY_LINE) - 1);
		ptr += sizeof(HTML_SUMMARY_LINE) - 1;
		memcpy(ptr, HTML_TBLINE_BEGIN, sizeof(HTML_TBLINE_BEGIN) - 1);
		ptr += sizeof(HTML_TBLINE_BEGIN) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, lang_resource_get(g_lang_resource,"MENSUAL_TOTAL", language));
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", total_spam);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", total_normal);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", total_outgoing);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		if (total_spam + total_normal != 0) {
			ptr += sprintf(ptr, "%d%%",
					(int)(((double)total_spam)/(total_spam+total_normal)*100));
		} else {
			ptr += sprintf(ptr, "N/A");
		}
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBLINE_END, sizeof(HTML_TBLINE_END) - 1);
		ptr += sizeof(HTML_TBLINE_END) - 1;
	}
	list_file_free(pfile);

	memcpy(ptr, MAIL_ATTACHMENT_DI1, sizeof(MAIL_ATTACHMENT_DI1) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_DI1) - 1;
	memcpy(ptr, g_d1_ptr, g_d1_len);
	ptr += g_d1_len;
	
	memcpy(ptr, MAIL_ATTACHMENT_LOGO, sizeof(MAIL_ATTACHMENT_LOGO) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_LOGO) - 1;
	memcpy(ptr, g_logo_ptr, g_logo_len);
	ptr += g_logo_len;
	
	memcpy(ptr, MAIL_ATTACHMENT_VP, sizeof(MAIL_ATTACHMENT_VP) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_VP) - 1;
	memcpy(ptr, g_vp_ptr, g_vp_len);
	ptr += g_vp_len;

	memcpy(ptr, MAIL_ATTACHMENT_VU, sizeof(MAIL_ATTACHMENT_VU) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_VU) - 1;
	memcpy(ptr, g_vu_ptr, g_vu_len);
	ptr += g_vu_len;
	
	memcpy(ptr, MAIL_ATTACHMENT_VH, sizeof(MAIL_ATTACHMENT_VH) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_VH) - 1;
	memcpy(ptr, g_vh_ptr, g_vh_len);
	ptr += g_vh_len;
	
	memcpy(ptr, MAIL_ATTACHMENT_END, sizeof(MAIL_ATTACHMENT_END) - 1);
	ptr += sizeof(MAIL_ATTACHMENT_END) - 1;

	pdomain = strchr(padministrator, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (0 == strcasecmp(pdomain, domain)) {
			smtp_sender_send("log-report@system.mail", padministrator,
				pbuff, ptr - pbuff);
		} else {
			sprintf(temp_sender, "log-report@%s", domain);
			smtp_sender_send(temp_sender, padministrator, pbuff, ptr - pbuff);
		}
	}
	free(pbuff);
}

static BOOL item_sorter_retrieve_image(const char *path, char **pptr,
	int *plen)
{
	
	char *ptr;
	int fd, result;
	struct stat node_stat;
	
	if (0 != stat(path, &node_stat)) {
		printf("[item_sorter]: fail to stat %s\n", path);
		return FALSE;
	}
	ptr = malloc(3*node_stat.st_size);
	if (NULL == ptr) {
		printf("[item_sorter]: fail to allocte memory for %s\n", path);
		return FALSE;
	}
	
	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		printf("[item_sorter]: fail to open %s\n", path);
		free(ptr);
		return FALSE;
	}
	if (node_stat.st_size != read(fd, ptr + 2*node_stat.st_size,
		node_stat.st_size)) {
		printf("[item_sorter]: fail to read %s\n", path);
		close(fd);
		free(ptr);
		return FALSE;
	}
	close(fd);
	result = encode64_ex(ptr + 2*node_stat.st_size, node_stat.st_size, ptr,
				2*node_stat.st_size, plen);
	if (0 == result) {
		*pptr = ptr;
		return TRUE;
	} else {
		printf("[item_sorter]: fail to encoding %s into base64\n", path);
		free(ptr);
		return FALSE;
	}
}

static int item_sorter_domain_query(const char* domain, char *domain_path,
	char *administrator, char *language)
{
	int report_type;
	char *str_type;
	char *str_mailbox;
	char *str_language;
	char temp_path[256];
	char temp_string[256];
	CONFIG_FILE *pconfig;

	if (NULL == domain ||
		FALSE == data_source_get_homedir(domain, domain_path)) {
		domain_path[0] = '\0';
		return REPORT_NONE;
	}
	
	sprintf(temp_path, "%s/domain.cfg", domain_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		return REPORT_NONE;
	}
	str_mailbox = config_file_get_value(pconfig, "ADMIN_MAILBOX");
	str_language = config_file_get_value(pconfig, "REPORT_LANGUAGE");
	str_type = config_file_get_value(pconfig, "REPORT_TYPE");
	if (NULL == str_mailbox || NULL == str_language || NULL == str_type) {
		config_file_free(pconfig);
		return REPORT_NONE;
	}
	report_type = atoi(str_type);
	if (report_type > REPORT_SIMPLE || report_type < REPORT_NONE) {
		report_type = REPORT_NONE;
	}
	strcpy(administrator, str_mailbox);
	strcpy(language, str_language);
	config_file_free(pconfig);
	return report_type;
}



