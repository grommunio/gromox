#include "hook_common.h"
#include "util.h"
#include <stdio.h>
#include <pthread.h>

#define PIC01_CID	"<001501c695cb$9bc2ea60$6601a8c0@herculiz>"
#define PIC02_CID	"<001601c695cb$9bc53450$6601a8c0@herculiz>"
#define PIC03_CID	"<001701c695cb$9bc53450$6601a8c0@herculiz>"
#define PIC04_CID	"<001801c695cb$9bc53450$6601a8c0@herculiz>"
#define PIC05_CID	"<001901c695cb$9bc53450$6601a8c0@herculiz>"
#define BAR01_CID	"<000501c695cb$9bc53450$6601a8c0@herculiz>"
#define BAR02_CID	"<000601c695cb$9bc53450$6601a8c0@herculiz>"
#define BAR04_CID	"<000701c695cb$9bc53450$6601a8c0@herculiz>"
#define BAR08_CID	"<000801c695cb$9bc53450$6601a8c0@herculiz>"
#define BAR16_CID	"<000901c695cb$9bc53450$6601a8c0@herculiz>"
#define BAR32_CID	"<000001c695cb$9bc53450$6601a8c0@herculiz>"


#define PIC01_FILE	\
"R0lGODlhAwA3ANUAAHWQwX2XxV5+tGCAtnCMvmyJvE5xrFByrYKayICZx3+Yxlp6slFzrmaEuXqU\r\n\
xMjIyHOPwFV2sGSCuGmGunmUw3eSwld4sWuIu3uVxFt7s2KBt1N1r1h5slh5sVx8s26LvXmTxAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAAAAAAALAAAAAADADcAAAZSQINw\r\n\
eCgaGchkcsNsRp5Qi7RD5VgX2IzWwxV4v9+BeKwpS87ohno9aV/e8IL8Q68T7niIfr8H+CuAgSCD\r\n\
FIUOhxiJAYuMjAqPCZGSCJSVlQ+YQQA7\r\n"

#define PIC02_FILE	\
"R0lGODlhAQAeAMQAAOjo6L+/v/Ly8ubm5uvr6+zs7PDw8d7e3v39/ff39/z8/Pn5+fj4+Pr6+u7u\r\n\
7t3d3ePj4+Xm5uHh4eLi4tzc3ODg4PX19fT09O/v7+np6f7+/v///wAAAAAAAAAAAAAAACH5BAAA\r\n\
AAAALAAAAAABAB4AAAUYYLBpCKI0C5NYl2BgTkFkwBBBk1Qdz0OFADs=\r\n"

#define PIC03_FILE	\
"R0lGODlhAwAeAMQAAOjo6L+/v/Ly8ubm5uvr6+zs7PDw8d7e3v39/ff39/z8/Pn5+fj4+Pr6+u7u\r\n\
7t3d3ePj4+Xm5uHh4eLi4tzc3ODg4PX19fT09O/v7+np6f7+/tnZ2f///wAAAAAAAAAAACH5BAAA\r\n\
AAAALAAAAAADAB4AAAVJIMdtY7AFWoAgKqsoQdMEyxIwTJAkgWUFl0tAIAgYDAEMJuBwBAqFAIEQ\r\n\
yGQCAEBgMAhEIgEIJDCZBCSSQKUSOBwCjwdcTqGEAAA7\r\n"

#define PIC04_FILE	\
"R0lGODlhAwAeAMQAAOjo6L+/v/Ly8ubm5uvr6+zs7PDw8d7e3v39/ff39/z8/Pn5+fj4+Pr6+u7u\r\n\
7t3d3ePj4+Xm5uHh4eLi4tzc3ODg4PX19fT09O/v7+np6f7+/tnZ2f///wAAAAAAAAAAACH5BAAA\r\n\
AAAALAAAAAADAB4AAAVJ4MZxgaiVCBKkgaIETRMsS8AwQZIElhVcl4BAEDAYAhhMwOEIFAoBAiGQ\r\n\
yQQAgMBgEIhEAhBIYDIJSCSBSiVwOAQej3ecQgmEAAA7\r\n"

#define PIC05_FILE	\
"R0lGODlhwwAwAPcAAP5VKvyLb/xtThik/2yJvGWDuP/9mMrU6HWQwf75tKuUnvPMBPv8/XCMvl5+\r\n\
tOixBWGAttzj8Jer0Z6Obi+t/f780FCv9fL1+eeqBLTD3rrI4YyjzGmGu9Lb7ICZx6u72lp6svPY\r\n\
h+Xq9P+0plV2sJGnzn+Yxn2Wxf+kkoWdyXOOwDFPrpC3+P6DXOjt9e/ITfDNdqGz1v/sasSudEyR\r\n\
0e3w98iSjzOWx/6YgHqUxGyJv8WaKP/948+lJvN+E/zIwsLO5GR9q2S3+tWrIP/7kP/gA//DuZ63\r\n\
5qbD/5TJ/0Niuum4NXeSwruOKuDm8Zyv09GvkoWFi1+JwZt2WHmUw01su/fmlCx30c22zPb4+9q+\r\n\
brmtysenWnN+kOCMemCSzMOVRqS12PexAF96rPKrAKi52UFaseiwFa+/24ifymB+u3iSxVd4sVh5\r\n\
sVh5slx7s6a32Kut0XuVxHCBn2qk11x7r5OYuVme3YCLsMjIyFN1r1R1r4KayIKbyIGax////wAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAAwwAwAAAI/wD1CBxI\r\n\
sKDBgwgTKlzIsKHDhxAjSpxYcI/FixgzatzIsaPHjyBDihxJsqTJkxlJqFxJYkyXCTO0vJgxh6XN\r\n\
mzhz6tzJs6fPn0CDCh1KVOVLLSGIEDFghWbRp1CjSp1KdSibq1e7cAlhIIGBr0xpYh1LtqzZs2jT\r\n\
ql3Ltq3bt3Djpm1Dt00ULVa8ggVrRcucOnUDCx5MuLDhw4gTK17MuLHjx4XduGnTRUsCvUv3GiCi\r\n\
JUodyaBDix5NurTp06hTq17NurXr16JB1JnD5XJmzWA5R3kDorfv38CDCx9OvLjx48iTK1/OvLnv\r\n\
N2MmhKhwG/fezkHeaN/Ovbv37+DDi/8fT768+fPo06vfHqV2gurWv+rOvr6+/fv48+tXDwZGhfjx\r\n\
cTZBEA4UaOCBCCao4IIMNujggxBGKOGEFFboQA8w8ACgZkp9BYMCFoYo4ogklmhihUPIwMN7ASq1\r\n\
VAIV8FCBFjTU+MUXUkBw4o489uhjiRAM8UIFLO7l4lcwyphACC9wccMAA1BAwR1U5gjBlVhmqeWW\r\n\
XHbp5ZdghinmmGSWaaaXQyxAxB+bbdYhjDFWYAUML5xxhhg7PAnlnhRYcIeVZwYq6KCEFmpomGkW\r\n\
IeObcS4JwxJnYCApBnjquSefFnxx6KacduqpoQUkqmKMMloRwhJLTCrpA6xWeumrfX7/UcCstM6K\r\n\
Za245qrrrrz26uuvwAYr7LDEFtDDAkUUYQAPTEKqKqvQtprnq7BmquutxWar7bbcduttokXIEEKk\r\n\
q0Zr7gOuUntprL7+4e67wL77x67yemuvrvUKK++8987KwbHJygBDueeam666e1pgAQcMN0zrvvn2\r\n\
GjGuE/drb8US79tvwwCHGwLBBUN7MMJRZtowww/DqzG3GFvMMrzBtswtx8h6jEHI54rRhKUkD2CB\r\n\
ECc3HDHMs0I878RGHw1zvkNDnPLKBTjNa9NGFy111FALyzABHYsLMs4680wyBUJ8QcDZBDAsb9BB\r\n\
Q6z2u0In/ba7HKy99txu171v3Hmz/6033Xi7bXTgcPttOAdod/0xzgbv3DOfQtyBdtp//0EAxGjL\r\n\
O7nml7/bueefW64556SDzvnZpbs7+eagh4666a0nrfrqtNeu+Nchh/34nkJYQPvo+2beuuvEpy66\r\n\
56cLbzzrSddOfPGwzw699M7X3sAONXvNeLRkgEHH7iVL3sD4r0t/evLLPy/78LKXb7nyRjt/fvTv\r\n\
zz978tWjPX4Dt9+8/QPdg4MQdiclGuyvAe6DnwIXmL7QNc99x7sf+4aXP/vVj34MpGD+CLA/7AVs\r\n\
cf9jFRhYgAQWUKBnFrhBFVRwwPEBL3YTlKDqggfBGiZweu+rIf4WiMMbOpCGG9RfA/9U4EGb+W97\r\n\
3TtCEkp4QnVJSQlqUIEUWehC2e1PXgfEYhWNlsV3bfEPXUzaF1soxhZe0YtjbIAWtfhFNprxjUOU\r\n\
YhG1tz0M+AAAABAAC5ZoQmpJ6QpmiKMUybgvQrorjGA8I8TCyEhEFlKNaHRkIuHIxjWi0Y2QxCQc\r\n\
WyhFBMzxY0c0lx3viEc8CkCJJbTAuihwhRWYQQUIiCUCpkjLWtrylrjMpS53ycte+vKXwPylLD/5\r\n\
tVGW8pimjMESkaDKKLFyBStQAixlGcxqWvOa2MymNnEZSyZ8MlrGRKY48xiHZQ7wmdCUJhPWyQRq\r\n\
bvOd8IynPH3Jzm+Gc5ylFEAe8dj/gnIiAQlCaCU0o6kCdjJBDgZNqEIXytCGOvShEI2oRCdK0Yqu\r\n\
EwFNeEDAYEBKfArgoyANqQBasIUlHsEMA40mAqjA0pZSwaIwjalMZ0rTmbY0ClPAQLhQkM88ivSn\r\n\
LQhqAIRaUhagdKBKWKlLWVrTpjr1qVCdKEvXgAA8TKEJS2iBT4E60qC2IABgDWsAcDBWLLBACQM1\r\n\
QxWYkIO2ujUHcoirXOdK17ra9a54zate98rXvvr1r3hta1xfilOQtqCrQv2qWHHAWMai4LGPHcEW\r\n\
0ArNKiAAsJjNrGY3y9nO+vUEoD2BHPBgA68qdqxjbSwKcADZyI5gBEaILRYou9bQ/9oWtJ7NrW53\r\n\
y9vP3ha0dvCCaVML2dcaF7ax/YFyjTCCH5zVDGpYw29t29vqWve6nQWtCba73RNQwQ6lHe5YXZtc\r\n\
5f6AuasNgBfiUAUdcPe98MWufOdLX7vCF752UIBwTSvU1LJ2tWTlLxRU4IH73re+CE6wdbfrgQY7\r\n\
uMDbza8X9svfCntVvTawAx8ezOEHK/jDIOZshztsAj/YIb82mDBY+QvWCdtAAXYowYZHTGID2/jG\r\n\
OM6xjnfM4x77+Mc6brAfhkzkIhv5yEhOspKJ3IcmO/nJUI6ylKdM5Spb+cpYzrKWt0zlIfPhy2AO\r\n\
s5jHTOYymxnMXE6zmtfM5ja7GTvKX37zm1NA5zrb+c54zrOe98znPvv5z4AOtKD33OQ8GPrQiE60\r\n\
ohfN6EY7+tGQjrSkJ03pSlv60okOCAA7\r\n"

#define BAR01_FILE	\
"iVBORw0KGgoAAAANSUhEUgAAAAgAAAAGBAMAAAAMK8LIAAAAElBMVEXmeHjgWFjWRka/MzOwMDCJ\r\n\
JiZtfwd8AAAAFnRFWHRTb2Z0d2FyZQBnaWYycG5nIDIuNC4yo15HDgAAABxJREFUeNpjYAABQSBg\r\n\
UAICBmMgYHABAoZQIAAAJKQD/Y5bny4AAAAASUVORK5CYII=\r\n"

#define BAR02_FILE	\
"iVBORw0KGgoAAAANSUhEUgAAABAAAAAGBAMAAAA4UgPUAAAAElBMVEXmeHjgWFjWRka/MzOwMDCJ\r\n\
JiZtfwd8AAAAFnRFWHRTb2Z0d2FyZQBnaWYycG5nIDIuNC4yo15HDgAAABxJREFUeNpjYIABQShg\r\n\
UIICBmMoYHCBAoZQKAAAg7IH+ZQ6Hx4AAAAASUVORK5CYII=\r\n"

#define BAR04_FILE	\
"iVBORw0KGgoAAAANSUhEUgAAACAAAAAGBAMAAABQoYHsAAAAElBMVEXmeHjgWFjWRka/MzOwMDCJ\r\n\
JiZtfwd8AAAAFnRFWHRTb2Z0d2FyZQBnaWYycG5nIDIuNC4yo15HDgAAABxJREFUeNpjYEAHgmiA\r\n\
QQkNMBijAQYXNMAQigYA8S0P8cbwK3wAAAAASUVORK5CYII=\r\n"

#define BAR08_FILE	\
"iVBORw0KGgoAAAANSUhEUgAAAEAAAAAGBAMAAACBRoWcAAAAElBMVEXmeHjgWFjWRka/MzOwMDCJ\r\n\
JiZtfwd8AAAAFnRFWHRTb2Z0d2FyZQBnaWYycG5nIDIuNC4yo15HDgAAAB1JREFUeNpjYCAEBAkA\r\n\
BiUCgMGYAGBwIQAYQgkAAImfH+EUohS7AAAAAElFTkSuQmCC\r\n"

#define BAR16_FILE	\
"iVBORw0KGgoAAAANSUhEUgAAAIAAAAAGBAMAAAD5+Ys9AAAAElBMVEXmeHjgWFjWRka/MzOwMDCJ\r\n\
JiZtfwd8AAAAFnRFWHRTb2Z0d2FyZQBnaWYycG5nIDIuNC4yo15HDgAAAB5JREFUeNpjYKAUCFII\r\n\
GJQoBAzGFAIGFwoBQyiFAACwGT/BS2aTrwAAAABJRU5ErkJggg==\r\n"

#define BAR32_FILE	\
"iVBORw0KGgoAAAANSUhEUgAAAQAAAAAGBAMAAADecl38AAAAElBMVEXmeHjgWFjWRka/MzOwMDCJ\r\n\
JiZtfwd8AAAAFnRFWHRTb2Z0d2FyZQBnaWYycG5nIDIuNC4yo15HDgAAAB9JREFUeNpjYBhoIDjA\r\n\
gEFpgAGD8QADBpcBBgyhAwwA06F/gfmEzs8AAAAASUVORK5CYII=\r\n"


#define HTML_01	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\r\n\
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
.OddRow {MARGIN-LEFT: 5px; MARGIN-RIGHT: 5px; BACKGROUND-COLOR: #ffffff}\r\n\
.EvenRow {MARGIN-LEFT: 5px; MARGIN-RIGHT: 5px; BACKGROUND-COLOR: #f3f6f8}\r\n\
.SolidRow {FONT-WEIGHT: bold; MARGIN-LEFT: 5px; MARGIN-RIGHT:\r\n\
5px; BACKGROUND-COLOR: #d9d9d9}\r\n\
.ReportTitle {FONT-WEIGHT: bold; FONT-SIZE: 13pt; COLOR: #ffffff}\r\n\
-->\r\n\
</STYLE><TITLE>spam statistic</TITLE>\r\n\
<META http-equiv=Content-Type content=\"text/html; charset=us-ascii\">\r\n\
<META content=\"MSHTML 6.00.2900.2912\" name=GENERATOR></HEAD>\r\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\r\n\
marginheight=\"0\" marginwidth=\"0\">\r\n\
<CENTER><TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0><TBODY>\r\n\
<TR><TD noWrap align=middle background=\r\n\
\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\" height=55>\r\n\
<SPAN class=ReportTitle>Green Messenger General Report</SPAN>\r\n\
<TD vAlign=bottom noWrap width=\"22%\"\r\n\
background=\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\"><A\r\n\
href=\"http://www.gridware.com.cn\" target=_blank><IMG height=48\r\n\
src=\"cid:001901c695cb$9bc53450$6601a8c0@herculiz\" width=195 align=right\r\n\
border=0></A></TD></TR></TBODY></TABLE><BR>\r\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0> <TBODY><TR>\r\n\
<TD noWrap align=left height=23></TD></TR></TBODY></TABLE><BR>\r\n\
<A name=General_Statistics></A>\r\n\
<TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TD background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001701c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD><TD class=TableTitle noWrap align=middle background=\r\n\
\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">Spam Statistics</TD>\r\n\
<TD align=right background=\"cid:001601c695cb$9bc53450$6601a8c0@herculiz\">\r\n\
<IMG height=30 src=\"cid:001801c695cb$9bc53450$6601a8c0@herculiz\"\r\n\
width=3></TD></TR><TR bgColor=#bfbfbf><TD colSpan=3><TABLE cellSpacing=1\r\n\
cellPadding=2 width=\"100%\" border=0><TBODY>"

#define HTML_02		\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR>\r\n\
<TABLE width=\"90%\" border=0 cellpadding=1 cellspacing=1><TR>\r\n\
<TD height=\"23\" align=\"left\" nowrap>\r\n"

#define HTML_03		"</TD></TR></TABLE><P></P><BR></CENTER></BODY></HTML>"

#define HTML_TB_SMTP		"<TR class=SolidRow><TD colSpan=3>&nbsp; smtp forms (time range: "
#define HTML_TB_DELIVERY	"<TR class=SolidRow><TD colSpan=3>&nbsp; delivery forms (time range: "
#define HTML_TB_END			")</TD></TR>\r\n"
#define HTML_TBITEM_ODD_1	"<TR class=OddRow><TD width=\"25%\">&nbsp; "
#define HTML_TBITEM_EVEN_1	"<TR class=EvenRow><TD width=\"100%\">&nbsp; "
#define HTML_TBITEM_2		"&nbsp;</TD><TD noWrap width=\"0%\">&nbsp; "
#define HTML_TBITEM_3		"&nbsp;</TD><TD width=\"75%\">"
#define HTML_TBITEM_4		"</TD></TR>\r\n"
#define HTML_CHART_32	"<IMG src=\"cid:000001c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_16	"<IMG src=\"cid:000901c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_8	"<IMG src=\"cid:000801c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_4	"<IMG src=\"cid:000701c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_2	"<IMG src=\"cid:000601c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_1	"<IMG src=\"cid:000501c695cb$9bc53450$6601a8c0@herculiz\">"

#define SPAM_TAG_LEN        40
#define SPAM_TABLE_SIZE     4096

typedef BOOL (*CONSOLE_CONTROL)(char*, char*, int);

typedef struct _STATISTIC_ITEM {
	char	tag[SPAM_TAG_LEN];
	int		number;
} STATISTIC_ITEM;

DECLARE_API;

static CONSOLE_CONTROL smtp_console_control;
static CONSOLE_CONTROL delivery_console_control;
static void do_statistic();
static void* thread_work_func(void *arg);
static int buffer_extractor(char *buff_in, STATISTIC_ITEM *pitem);
static int time_extractor(char *buff_in, char *buff_out);
static char* html_reactor(STATISTIC_ITEM *pitem, int num, int max_val, char *buff_out);

static BOOL g_notify_stop;
static pthread_t g_thread_id;
static BOOL g_bar1_hit;
static BOOL g_bar2_hit;
static BOOL g_bar4_hit;
static BOOL g_bar8_hit;
static BOOL g_bar16_hit;
static BOOL g_bar32_hit;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	pthread_attr_t attr;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		g_notify_stop = TRUE;
		smtp_console_control = query_service("smtp_console_control");
		if (NULL == smtp_console_control) {
			printf("[report_forms]: fail to get service "
				"\"smtp_console_control\"\n");
			return FALSE;
		}
		delivery_console_control = query_service("delivery_console_control");
		if (NULL == delivery_console_control) {
			printf("[report_forms]: fail to get service "
				"\"delivery_console_control\"\n");
			return FALSE;
		}
		
		g_notify_stop = FALSE;
		pthread_attr_init(&attr);
		if (0 != pthread_create(&g_thread_id, &attr, thread_work_func, NULL)) {
			pthread_attr_destroy(&attr);
			g_notify_stop = TRUE;
			printf("[report_forms]: fail to create thread\n");
			return FALSE;
		}
		pthread_attr_destroy(&attr);
        return TRUE;
    case PLUGIN_FREE:
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_cancel(g_thread_id);
		}
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
}

static void* thread_work_func(void *arg)
{
	time_t cur_time;
	struct tm *ptime;
	struct tm time_buff;
	
	time(&cur_time);
	ptime = localtime_r(&cur_time, &time_buff);
	sleep(24*60*60 - ptime->tm_sec - 60*ptime->tm_min - 60*60*ptime->tm_hour);
	while (FALSE == g_notify_stop) {
		do_statistic();
		sleep(600);
		time(&cur_time);
		ptime = localtime_r(&cur_time, &time_buff);
		sleep(24*60*60 - ptime->tm_sec - 60*ptime->tm_min - 
			60*60*ptime->tm_hour);
	}

}

static int time_extractor(char *buff_in, char *buff_out)
{
	int i, j, buff_len;

	buff_len = strlen(buff_in);
	for (i=buff_len-1,j=0; i>=0; i--) {
		if (':' == buff_in[i]) {
			j++;
			if (3 == j) {
				break;
			}
		}
	}
	if (i < 0) {
		return 0;
	}
	memcpy(buff_out, buff_in + i + 2, buff_len - i - 4);
	return buff_len - i - 4;

}
	
static void do_statistic()
{
	time_t cur_time;
	struct tm time_buff;
	int i, max_num;
	int smtp_num, delivery_num;
	int total_num, normal_num, spam_num;
	char html_buff[128*1024];
	char *pdomain, *ptr;
	char temp_buff[16*1024];
	char temp_response[16*1024];
	MESSAGE_CONTEXT *pcontext;
	MIME *pmime, *pmime_child;
	STATISTIC_ITEM items[SPAM_TABLE_SIZE];
	
	
	g_bar1_hit = FALSE;
	g_bar2_hit = FALSE;
	g_bar4_hit = FALSE;
	g_bar8_hit = FALSE;
	g_bar16_hit = FALSE;
	g_bar32_hit = FALSE;

	ptr = html_buff;
	memcpy(ptr, HTML_01, sizeof(HTML_01) - 1);
	ptr += sizeof(HTML_01) - 1;
	if (FALSE == smtp_console_control("spam_statistic.svc report", temp_buff,
		16*1024) || 0 != strncmp(temp_buff, "250 ", 4)) {
		return;	
	}
	smtp_console_control("spam_statistic.svc clear", temp_response, 16*1024);
	memcpy(ptr, HTML_TB_SMTP, sizeof(HTML_TB_SMTP) - 1);
	ptr += sizeof(HTML_TB_SMTP) - 1;
	ptr += time_extractor(temp_buff, ptr);
	*ptr = '-';
	ptr ++;
	time(&cur_time);
	ptr += strftime(ptr, 128, "%Y/%m/%d %H:%M:%S",
			localtime_r(&cur_time, &time_buff));
	memcpy(ptr, HTML_TB_END, sizeof(HTML_TB_END) - 1);
	ptr += sizeof(HTML_TB_END) - 1;
	
	smtp_num = buffer_extractor(temp_buff, items);
	if (0 == smtp_num) {
		return;
	}
	
	if (FALSE == delivery_console_control("spam_statistic.svc report",
		temp_buff, 16*1024) || 0 != strncmp(temp_buff, "250 ", 4)) {
		return;
	}
	delivery_console_control("spam_statistic.svc clear", temp_response, 16*1024);
	delivery_num = buffer_extractor(temp_buff, items + smtp_num);
	if (0 == delivery_num) {
		return;
	}
	max_num = items[0].number;
	for (i=1; i<smtp_num+delivery_num; i++) {
		if (items[i].number > max_num) {
			max_num = items[i].number;
		}
	}
	ptr = html_reactor(items, smtp_num, max_num, ptr);
	if (NULL == ptr) {
		return;
	}
	
	memcpy(ptr, HTML_TB_DELIVERY, sizeof(HTML_TB_DELIVERY) - 1);
	ptr += sizeof(HTML_TB_DELIVERY) - 1;
	ptr += time_extractor(temp_buff, ptr);
	*ptr = '-';
	ptr ++;
	time(&cur_time);
	ptr += strftime(ptr, 128, "%Y/%m/%d %H:%M:%S",
			localtime_r(&cur_time, &time_buff));
	memcpy(ptr, HTML_TB_END, sizeof(HTML_TB_END) - 1);
	ptr += sizeof(HTML_TB_END) - 1;
	
	ptr = html_reactor(items + smtp_num, delivery_num, max_num, ptr);
	if (NULL == ptr) {
		return;
	}
	memcpy(ptr, HTML_02, sizeof(HTML_02) - 1);
	ptr += sizeof(HTML_02) - 1;

	for (i=1, total_num=0; i<smtp_num+delivery_num; i++) {
		total_num += items[i].number;
	}
	if (0 != total_num) {
		normal_num = items[smtp_num].number;
		spam_num = total_num - normal_num;
		ptr += sprintf(ptr, "total session: %d, normal session: %d, "
					"spam session: %d, spam percentage: %5.2f%%",
					total_num, normal_num, spam_num,
					(float)spam_num/total_num*100);
	}
	
	memcpy(ptr, HTML_03, sizeof(HTML_03) - 1);
	ptr += sizeof(HTML_03) - 1;
	
	pcontext =  get_context();
	if (NULL == pcontext) {
		return;
	}
	pdomain = strchr(get_admin_mailbox(), '@');
	if (NULL == pdomain) {
		put_context(pcontext);
		return;
	}
	pdomain ++;
	if (0 == strcasecmp(pdomain, get_default_domain())) {
		strcpy(pcontext->pcontrol->from, "report-forms@system.mail");
	} else {
		sprintf(pcontext->pcontrol->from, "report-forms@%s",
			get_default_domain());
	}
	mem_file_writeline(&pcontext->pcontrol->f_rcpt_to,(void*)get_admin_mailbox());
	pmime = mail_add_head(pcontext->pmail);
	if (NULL == pmime) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime, "multipart/related");
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "text/html");
	mime_set_content_param(pmime_child, "charset", "us-ascii");
	mime_write_content(pmime_child, html_buff, ptr - html_buff, 
		MIME_ENCODING_NONE);
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "image/gif");
	mime_write_content(pmime_child, PIC01_FILE, sizeof(PIC01_FILE) - 1,
		MIME_ENCODING_NONE);
	mime_set_field(pmime_child, "Content-ID", PIC01_CID);
	mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "image/gif");
	mime_write_content(pmime_child, PIC02_FILE, sizeof(PIC02_FILE) - 1,
		MIME_ENCODING_NONE);
	mime_set_field(pmime_child, "Content-ID", PIC02_CID);
	mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "image/gif");
	mime_write_content(pmime_child, PIC03_FILE, sizeof(PIC03_FILE) - 1,
		MIME_ENCODING_NONE);
	mime_set_field(pmime_child, "Content-ID", PIC03_CID);
	mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "image/gif");
	mime_write_content(pmime_child, PIC04_FILE, sizeof(PIC04_FILE) - 1,
		MIME_ENCODING_NONE);
	mime_set_field(pmime_child, "Content-ID", PIC04_CID);
	mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "image/gif");
	mime_write_content(pmime_child, PIC05_FILE, sizeof(PIC05_FILE) - 1,
		MIME_ENCODING_NONE);
	mime_set_field(pmime_child, "Content-ID", PIC05_CID);
	mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	if (TRUE == g_bar1_hit) {
		pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime_child) {
			put_context(pcontext);
			return;
		}
		mime_set_content_type(pmime_child, "image/png");
		mime_write_content(pmime_child, BAR01_FILE, sizeof(BAR01_FILE) - 1,
			MIME_ENCODING_NONE);
		mime_set_field(pmime_child, "Content-ID", BAR01_CID);
		mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	}
	if (TRUE == g_bar2_hit) {
		pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime_child) {
			put_context(pcontext);
			return;
		}
		mime_set_content_type(pmime_child, "image/png");
		mime_write_content(pmime_child, BAR02_FILE, sizeof(BAR02_FILE) - 1,
			MIME_ENCODING_NONE);
		mime_set_field(pmime_child, "Content-ID", BAR02_CID);
		mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	}
	if (TRUE == g_bar4_hit) {
		pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime_child) {
			put_context(pcontext);
			return;
		}
		mime_set_content_type(pmime_child, "image/png");
		mime_write_content(pmime_child, BAR04_FILE, sizeof(BAR04_FILE) - 1,
			MIME_ENCODING_NONE);
		mime_set_field(pmime_child, "Content-ID", BAR04_CID);
		mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	}
	if (TRUE == g_bar8_hit) {
		pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime_child) {
			put_context(pcontext);
			return;
		}
		mime_set_content_type(pmime_child, "image/png");
		mime_write_content(pmime_child, BAR08_FILE, sizeof(BAR08_FILE) - 1,
			MIME_ENCODING_NONE);
		mime_set_field(pmime_child, "Content-ID", BAR08_CID);
		mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	}
	if (TRUE == g_bar16_hit) {
		pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime_child) {
			put_context(pcontext);
			return;
		}
		mime_set_content_type(pmime_child, "image/png");
		mime_write_content(pmime_child, BAR16_FILE, sizeof(BAR16_FILE) - 1,
			MIME_ENCODING_NONE);
		mime_set_field(pmime_child, "Content-ID", BAR16_CID);
		mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	}
	if (TRUE == g_bar32_hit) {
		pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime_child) {
			put_context(pcontext);
			return;
		}
		mime_set_content_type(pmime_child, "image/png");
		mime_write_content(pmime_child, BAR32_FILE, sizeof(BAR32_FILE) - 1,
			MIME_ENCODING_NONE);
		mime_set_field(pmime_child, "Content-ID", BAR32_CID);
		mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	}
	
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
			                "(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
	mime_set_field(pmime, "From", pcontext->pcontrol->from);
	mime_set_field(pmime, "To", get_admin_mailbox());
	sprintf(temp_buff, "Anti-spam gateway report forms from %s", get_host_ID());
	mime_set_field(pmime, "Subject", temp_buff);
	time(&cur_time);
	strftime(temp_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
		localtime_r(&cur_time, &time_buff));
	mime_set_field(pmime, "Date", temp_buff);
	enqueue_context(pcontext);
}
		
static int buffer_extractor(char *buff_in, STATISTIC_ITEM *pitem)
{
	char temp_buff[64];
	int buff_len, last_crlf;
	int  start_pos, end_pos;
	int i, j, item_num, temp_len; 
	
	buff_len = strlen(buff_in);
	for (i=0; i<buff_len; i++) {
		if ('\n' == buff_in[i]) {
			break;
		}
	}
	if (i == buff_len) {
		return 0;
	}
	start_pos = i + 1;
	for (i=buff_len-3; i>start_pos; i--) {
		if ('\n' == buff_in[i]) {
			break;
		}
	}
	if (i <= start_pos) {
		return 0;
	}
	end_pos = i;
	
	for (i=start_pos,last_crlf=start_pos-1,item_num=0; i<end_pos; i++) {
		if ('\r' == buff_in[i]) {
			for (j=i; j>last_crlf; j--) {
				if (' ' == buff_in[j]) {
					break;
				}
			}
			if (j > last_crlf) {
				memcpy(pitem->tag, buff_in + last_crlf + 1, j - last_crlf);
				pitem->tag[j - last_crlf - 1] = '\0';
				rtrim_string(pitem->tag);
				if (i - j - 1 >= 64) {
					return 0;
				}
				memcpy(temp_buff, buff_in + j + 1, i - j - 1);
				temp_buff[i - j - 1] = '\0';
				pitem->number = atoi(temp_buff);
				item_num ++;
				pitem ++;
			}
			last_crlf = i + 1;
		}
	}
	return item_num;
}

static char* html_reactor(STATISTIC_ITEM *pitem, int num, int max_val, char *buff_out)
{ 
	int i, temp_len;
	int base_val, temp_num;
	char *ptr, temp_buff[1024];
	
	ptr = buff_out;
	base_val = max_val / 64;

	for (i=0; i<num; i++,pitem++) {
		if (i % 2 != 0) {
			memcpy(ptr, HTML_TBITEM_ODD_1, sizeof(HTML_TBITEM_ODD_1) - 1);
			ptr += sizeof(HTML_TBITEM_ODD_1) - 1;
		} else {
			memcpy(ptr, HTML_TBITEM_EVEN_1, sizeof(HTML_TBITEM_EVEN_1) - 1);
			ptr += sizeof(HTML_TBITEM_EVEN_1) - 1;
		} 
		temp_len = strlen(pitem->tag);
		memcpy(ptr, pitem->tag, temp_len);
		ptr += temp_len;
		
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		
		ptr += sprintf(ptr, "%d", pitem->number);
				
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
	
		if (0 == base_val) {
			memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
			ptr += sizeof(HTML_TBITEM_4) - 1;
			continue;
		}


		temp_num = pitem->number;
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
		
		memcpy(ptr, HTML_TBITEM_4, sizeof(HTML_TBITEM_4) - 1);
		ptr += sizeof(HTML_TBITEM_4) - 1;
	}
	return ptr;
}

