#include "net_failure.h"
#include "hook_common.h"
#include <stdio.h>
#include <time.h>
#include <time.h>
#include <pthread.h>


#define HTML_01 \
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\r\n\
<HTML><HEAD>\
<STYLE TYPE=\"text/css\"><!--\r\n\
BODY {FONT-SIZE: 10pt;FONT-WEIGHT: bold;COLOR: #ff0000;\r\n\
FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
TD {FONT-SIZE: 8pt; FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
A:active {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:link {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:visited {COLOR: #0000ff; TEXT-DECORATION: none}\r\n\
A:hover {COLOR: #0000ff; TEXT-DECORATION: underline}\r\n\
.AlarmTitle {FONT-WEIGHT: bold; FONT-SIZE: 13pt; COLOR: #ffffff}\r\n\
--></STYLE>\r\n\
<TITLE>Local Delivery Alarm</TITLE>\
<META http-equiv=Content-Type content=\"text/html; charset=us-ascii\">\r\n\
<META content=\"MSHTML 6.00.2900.2912\" name=GENERATOR></HEAD>\r\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\r\n\
marginheight=\"0\" marginwidth=\"0\">\r\n\
<CENTER><TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0><TBODY>\r\n\
<TR><TD noWrap align=middle background=\r\n\
\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\" height=55>\r\n\
<SPAN class=AlarmTitle>Green Messenger Dispatch Alarm</SPAN>\r\n\
<TD vAlign=bottom noWrap width=\"22%\"\r\n\
background=\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\"><A\r\n\
href=\"http://www.gridware.com.cn\" target=_blank><IMG height=48\r\n\
src=\"cid:001901c695cb$9bc53450$6601a8c0@herculiz\" width=195 align=right\r\n\
border=0></A></TD></TR></TBODY></TABLE><BR>\r\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0> <TBODY><TR>\r\n\
<P></P><BR><P></P><BR><P></P><BR><BR>\r\n"


#define HTML_02     \
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR>\
<P></P><BR></CENTER></BODY></HTML>"


#define PIC01_FILE  \
"R0lGODlhAwA3ANUAAHWQwX2XxV5+tGCAtnCMvmyJvE5xrFByrYKayICZx3+Yxlp6slFzrmaEuXqU\r\n\
xMjIyHOPwFV2sGSCuGmGunmUw3eSwld4sWuIu3uVxFt7s2KBt1N1r1h5slh5sVx8s26LvXmTxAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAAAAAAALAAAAAADADcAAAZSQINw\r\n\
eCgaGchkcsNsRp5Qi7RD5VgX2IzWwxV4v9+BeKwpS87ohno9aV/e8IL8Q68T7niIfr8H+CuAgSCD\r\n\
FIUOhxiJAYuMjAqPCZGSCJSVlQ+YQQA7\r\n"

#define PIC05_FILE  \
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


#define PIC01_CID   "<001501c695cb$9bc2ea60$6601a8c0@herculiz>"
#define PIC05_CID   "<001901c695cb$9bc53450$6601a8c0@herculiz>"


#define BOUND_ALARM				6

static int g_times;
static int g_interval;
static time_t g_last_check_point;
static time_t g_last_alarm_time;
static int g_alarm_interval;
static int g_fail_accumulating;
static int g_total_fail;
static int g_OK_num;
static int g_temp_fail_num;
static int g_permanent_fail_num;
static int g_nouser_num;
static BOOL g_turnoff_alarm;
static pthread_mutex_t g_lock;

void net_failure_init(int times, int interval, int alarm_interval)
{
	g_times = times;
	g_interval = interval;
	g_fail_accumulating = 0;
	g_total_fail = 0;
	g_OK_num = 0;
	g_temp_fail_num = 0;
	g_permanent_fail_num = 0;
	g_nouser_num = 0;
	g_turnoff_alarm = FALSE;
	g_last_alarm_time = 0;
	g_alarm_interval = alarm_interval;

}

int net_failure_run()
{
	time(&g_last_check_point);
	pthread_mutex_init(&g_lock, NULL);
	return 0;
}

int net_failure_stop()
{
	pthread_mutex_destroy(&g_lock);
	return 0;
}

void net_failure_free()
{
	g_times = 0;
    g_interval = 0;
    g_fail_accumulating = 0;
	g_total_fail = 0;
    g_OK_num = 0;
    g_temp_fail_num = 0;
    g_permanent_fail_num = 0;
    g_nouser_num = 0;
	g_last_alarm_time = 0;
	g_alarm_interval = 0;
}

void net_failure_statistic(int OK_num, int temp_fail, int permanent_fail,
    int nouser_num)
{
	BOOL need_alarm_one, need_alarm_two;
	MESSAGE_CONTEXT *pcontext;
	MIME *pmime, *pmime_child;
	struct tm *datetime;
	struct tm time_buff;
	char *pdomain;
	char tmp_buff[4096];
	time_t current_time;
	int offset;

	need_alarm_one = FALSE;
	need_alarm_two = FALSE;
    time(&current_time);
	pthread_mutex_lock(&g_lock);
	g_OK_num += OK_num;
	g_temp_fail_num += temp_fail;
	g_permanent_fail_num += permanent_fail;
	g_nouser_num += nouser_num;
	if (0 != OK_num) {
		g_total_fail = 0;
	} else {
		g_total_fail += temp_fail;
	}
	if (g_total_fail >= g_times && FALSE == g_turnoff_alarm) {
		need_alarm_one = TRUE;
	}
	g_fail_accumulating += temp_fail;
	if (current_time - g_last_check_point <= g_interval) {
		if (g_fail_accumulating > g_times) {
			if (FALSE == g_turnoff_alarm) {
				need_alarm_two = TRUE;
			}
			g_fail_accumulating = 0;
			g_last_check_point = current_time;
		}
	} else {
		g_fail_accumulating = 0;
        g_last_check_point = current_time;
	}
	pthread_mutex_unlock(&g_lock);
	
	if (TRUE == need_alarm_one || TRUE == need_alarm_two) {
		if (current_time - g_last_alarm_time < g_alarm_interval) {
			return;
		} else {
			g_last_alarm_time = current_time;
		}
		pcontext = get_context();
		if (NULL == pcontext) {
			return;
		}
		pcontext->pcontrol->bound_type = BOUND_ALARM;
		pcontext->pcontrol->need_bounce = FALSE;
		pdomain = strchr(get_admin_mailbox(), '@');
		if (NULL == pdomain) {
			put_context(pcontext);
			return;
		}
		if (0 == strcasecmp(pdomain, get_default_domain())) {
			strcpy(pcontext->pcontrol->from, "local-alarm@system.mail");
		} else {
			sprintf(pcontext->pcontrol->from, "local-alarm@%s",
				get_default_domain());
		}
		mem_file_writeline(&pcontext->pcontrol->f_rcpt_to,
			(char*)get_admin_mailbox());
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
		mime_set_content_param(pmime_child, "charset", "\"us-ascii\"");
		
		memcpy(tmp_buff, HTML_01, sizeof(HTML_01) - 1);
		offset = sizeof(HTML_01) - 1;
		
		if (TRUE == need_alarm_one) {
			offset += sprintf(tmp_buff + offset, "  The local delivery of %s "
						"has found %d times of failure and zero time of "
						"success, please check it as soon as possible!!!\r\n"
						"<P></P><BR><P></P><BR><P></P><BR>Alarm time: ",
						get_host_ID(), g_times);
		} else {
			offset += sprintf(tmp_buff + offset, "  The local delivery of %s "
						"has found %d times of failure within ", get_host_ID(),
						g_times);
			itvltoa(g_interval, tmp_buff + offset);
			offset += strlen(tmp_buff + offset);
			strcpy(tmp_buff + offset, ", please check it as soon as "
				"possible!!!\r\n<P></P><BR><P></P><BR><P></P><BR>Alarm time: ");
			offset += strlen(tmp_buff + offset);
		}
		datetime = localtime_r(&current_time, &time_buff);
        offset += strftime(tmp_buff + offset, 255, "%x %X", datetime);
		tmp_buff[offset] = '\r';
		offset ++;
		tmp_buff[offset] = '\n';
		offset ++;
		memcpy(tmp_buff + offset, HTML_02, sizeof(HTML_02) - 1);
		offset += sizeof(HTML_02) - 1;
		mime_write_content(pmime_child, tmp_buff, offset, MIME_ENCODING_NONE);
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
		mime_write_content(pmime_child, PIC05_FILE, sizeof(PIC05_FILE) - 1,
			MIME_ENCODING_NONE);
		mime_set_field(pmime_child, "Content-ID", PIC05_CID);
		mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
		
		mime_set_field(pmime, "Received", "from unknown (helo localhost) "
				"(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
		mime_set_field(pmime, "From", pcontext->pcontrol->from);
		mime_set_field(pmime, "To", get_admin_mailbox());
		strftime(tmp_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
				localtime_r(&current_time, &time_buff));
		mime_set_field(pmime, "Date", tmp_buff);
		sprintf(tmp_buff,"Local Delivery Alarm form %s!!!", get_host_ID());
		mime_set_field(pmime, "Subject", tmp_buff);
		enqueue_context(pcontext);
	}
}

int net_failure_get_param(int param)
{
	int ret_val;

	switch(param) {
	case NET_FAILURE_OK:
		pthread_mutex_lock(&g_lock);
		ret_val = g_OK_num;
		g_OK_num = 0;		
		pthread_mutex_unlock(&g_lock);
		return ret_val;
    case NET_FAILURE_TEMP:
		pthread_mutex_lock(&g_lock);
		ret_val = g_temp_fail_num;
		g_temp_fail_num = 0;
		pthread_mutex_unlock(&g_lock);
		return ret_val;
    case NET_FAILURE_PERMANENT:
		pthread_mutex_lock(&g_lock);
		ret_val = g_permanent_fail_num;
		g_permanent_fail_num = 0;
		pthread_mutex_unlock(&g_lock);
		return ret_val;
    case NET_FAILURE_NOUSER:
		pthread_mutex_lock(&g_lock);
		ret_val = g_nouser_num;
		g_nouser_num = 0;
		pthread_mutex_unlock(&g_lock);
		return ret_val;
	case NET_FAILURE_TURN_ALARM:
		return g_turnoff_alarm;
	case NET_FAILURE_STATISTIC_TIMES:
		return g_times;
	case NET_FAILURE_STATISTIC_INTERVAL:
		return g_interval;
	case NET_FAILURE_ALARM_INTERVAL:
		return g_alarm_interval;
	}
}

void net_failure_set_param(int param, int val)
{
	switch (param) {
	case NET_FAILURE_TURN_ALARM:
		g_turnoff_alarm = (BOOL)val;
		break;
	case NET_FAILURE_STATISTIC_TIMES:
		g_times = val;
		break;
	case NET_FAILURE_STATISTIC_INTERVAL:
		g_interval = val;
		break;
	case NET_FAILURE_ALARM_INTERVAL:
		g_alarm_interval = val;
		break;
	}
}
