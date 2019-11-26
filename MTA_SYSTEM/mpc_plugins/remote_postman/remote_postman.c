#include "remote_postman.h"
#include "files_allocator.h"
#include "smtp_deliverer.h"
#include "bounce_producer.h"
#include "sender_routing.h"
#include "net_failure.h"
#include "timer_queue.h"
#include "config_file.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <pthread.h>
#include <stdio.h>

typedef BOOL (*SINGLE_RCPT_QUERY)(char*);

static SINGLE_RCPT_QUERY single_rcpt_query;

static int g_max_rcpt;
static int g_max_thr;
static int g_concurrent_thr;
static char g_config_path[256];
static pthread_mutex_t g_concurrent_mutex;

typedef void (*STOP_FUNC)();

static STOP_FUNC g_running_modules[7];

static void remote_postman_clean_up();

static BOOL remote_postman_get_rcpt(MEM_FILE *psrc, MEM_FILE *pdst);

static BOOL remote_postman_check_address(MEM_FILE *psrc, MEM_FILE *presult);

/*
 *	remote postman's construct function
 */
void remote_postman_init(int max_thr, int files_num,
	int times, int interval, int alarm_interval, BOOL tls_switch,
	int trying_times, int max_rcpt, const char *resource_path,
	const char* separator, const char *timer_path, int timer_threads,
	int scan_interval, int fresh_interval, int retrying_interval,
	int final_interval, const char *routing_path, const char *config_path)
{
	int i;

	for (i=0; i<7; i++) {
		g_running_modules[i] = NULL;
	}
	g_max_thr = max_thr;
	g_max_rcpt = max_rcpt;
	g_concurrent_thr = 0;
	strcpy(g_config_path, config_path);
	files_allocator_init(files_num);
	net_failure_init(times, interval, alarm_interval);
	smtp_deliverer_init(trying_times, tls_switch);
	bounce_producer_init(resource_path, separator);
	timer_queue_init(timer_path, timer_threads, scan_interval,
		fresh_interval, retrying_interval, final_interval);
	sender_routing_init(routing_path);
	pthread_mutex_init(&g_concurrent_mutex, NULL);
}

/*
 *	run the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int remote_postman_run()
{
	single_rcpt_query = (SINGLE_RCPT_QUERY)query_service("single_rcpt_query");
	if (NULL == single_rcpt_query) {
		printf("[remote_postman]: fail to get \"single_rcpt_query\" service\n");
		return -1;
	}
	if (0 != files_allocator_run()) {
		printf("[remote_postman]: fail to init {files allocator} module\n");
		remote_postman_clean_up();
		return -2;
	}
	g_running_modules[1] = files_allocator_stop;
	if (0 != net_failure_run()) {
		printf("[remote_postman]: fail to init {net failure} module\n");
		remote_postman_clean_up();
        return -3;
	}
	g_running_modules[2] = net_failure_stop;
	if (0 != smtp_deliverer_run()) {
        printf("[remote_postman]: fail to init {smtp deliverer} module\n");
        remote_postman_clean_up();
        return -4;
    }
    g_running_modules[3] = smtp_deliverer_stop;
	if (0 != bounce_producer_run()) {
        printf("[remote_postman]: fail to init {bounce producer} module\n");
        remote_postman_clean_up();
        return -5;
    }
    g_running_modules[4] = bounce_producer_stop;
	if (0 != timer_queue_run()) {
        printf("[remote_postman]: fail to init {timer queue} module\n");
        remote_postman_clean_up();
        return -6;
    }
    g_running_modules[5] = timer_queue_stop;
	if (0 != sender_routing_run()) {
        printf("[remote_postman]: fail to init {sender routing} module\n");
        remote_postman_clean_up();
        return -7;
	}
    g_running_modules[6] = sender_routing_stop;
	return 0;
}

/*
 *	clean up run modules
 */
static void remote_postman_clean_up()
{
	int i;

	for (i=7; i>0; i--) {
		if (NULL != g_running_modules[i - 1]) {
			g_running_modules[i - 1]();
			g_running_modules[i - 1] = NULL;
		}
	}
}

/*
 *	stop the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
void remote_postman_stop()
{
	remote_postman_clean_up();
}

/*
 *	remote postman's destruct function
 */
void remote_postman_free()
{
	g_max_thr = 0;
	g_max_rcpt = 0;
	g_concurrent_thr = 0;
    files_allocator_free();
    net_failure_free();
    smtp_deliverer_free();
    bounce_producer_free();
    timer_queue_free();
	sender_routing_free();
	pthread_mutex_destroy(&g_concurrent_mutex);
}

/*
 *	hook processing function
 */
BOOL remote_postman_hook(MESSAGE_CONTEXT *pcontext)
{
	CONTROL_INFO control;
	time_t current_time;
	MESSAGE_CONTEXT fake_context;
	MESSAGE_CONTEXT *pbounce_context;
	char reason_buff[1024], ip_addr[16];
	int bounce_type, timer_ID;
	
	BOOL need_retry, need_bounce, is_untried, can_enter;
	int OK_num, permanent_fail, temp_fail, giveup_num;
	
	time(&current_time);
    mem_file_init(&control.f_rcpt_to, files_allocator_get_allocator());
	control.queue_ID = pcontext->pcontrol->queue_ID;
	control.bound_type = pcontext->pcontrol->bound_type;
	control.is_spam = pcontext->pcontrol->is_spam;
	control.need_bounce = pcontext->pcontrol->need_bounce;
	strcpy(control.from, pcontext->pcontrol->from);
	fake_context.pcontrol = &control;
	fake_context.pmail = pcontext->pmail;
	if (FALSE == remote_postman_check_address(&pcontext->pcontrol->f_rcpt_to,
				&control.f_rcpt_to)) {
		pbounce_context = get_context();
		if (NULL == pbounce_context) {
			smtp_deliverer_log_info(&fake_context, 8,
				"fail to get one context for bounce mail");
		} else {
			smtp_deliverer_log_info(&fake_context, 8, "rcpt address error");
			bounce_producer_make(&fake_context, current_time,
				BOUNCE_ADDRESS_ILLEGAL, NULL, NULL, pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from,
				"postmaster@%s", get_default_domain());
            mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
                pcontext->pcontrol->from);
			pbounce_context->pcontrol->bound_type = BOUND_REMOTE_BOUNCE;
			enqueue_context(pbounce_context);
			pbounce_context = NULL;
		}
	}
	pthread_mutex_lock(&g_concurrent_mutex);
	if (g_concurrent_thr >= g_max_thr) {
		can_enter = FALSE;
	} else { 
		g_concurrent_thr ++;
		can_enter = TRUE;
	}
	pthread_mutex_unlock(&g_concurrent_mutex);
	if (FALSE == can_enter) {
		net_failure_statistic(0, 0, 0, 1);
		while (TRUE == remote_postman_get_rcpt(
			&pcontext->pcontrol->f_rcpt_to,
			&control.f_rcpt_to)) {
			timer_queue_put(&fake_context, current_time, TRUE);
		}
		mem_file_free(&control.f_rcpt_to);
		return TRUE;
	}
	OK_num = 0;
	permanent_fail = 0;
	temp_fail = 0;
	giveup_num = 0;
	while (TRUE == remote_postman_get_rcpt(
		&pcontext->pcontrol->f_rcpt_to,
		&control.f_rcpt_to)) {
		is_untried = FALSE;
		switch (smtp_deliverer_process(&fake_context,
			ip_addr, reason_buff, 1024)) {
		case SMTP_DELIVERER_OK:
			need_retry = FALSE;
			need_bounce = FALSE;
			OK_num ++;
			break;
		case SMTP_DELIVERER_GIVE_UP:
			need_retry = TRUE;
			need_bounce = FALSE;
			is_untried = TRUE;
			giveup_num ++;
			break;
		case SMTP_DELIVERER_DNS_ERROR:
    	case SMTP_DELIVERER_CANNOT_CONNECT:
    	case SMTP_DELIVERER_TIME_OUT:
    	case SMTP_DELIVERER_TEMP_ERROR:
    	case SMTP_DELIVERER_UNKOWN_RESPONSE:
			need_retry = TRUE;
			need_bounce = FALSE;
			temp_fail ++;
			break;
    	case SMTP_DELIVERER_CONNECTION_REFUSED:
			bounce_type = BOUNCE_CONNECTION_REFUSED;
			need_retry = FALSE;
			need_bounce = TRUE;
			permanent_fail ++;
			break;
		case SMTP_DELIVERER_EXCEED_SIZE:
			bounce_type = BOUNCE_EXCEED_SIZE;
			need_retry = FALSE;
			need_bounce = TRUE;
			permanent_fail ++;
			break;
    	case SMTP_DELIVERER_NO_USER:
			bounce_type = BOUNCE_NO_USER;
			need_retry = FALSE;
			need_bounce = TRUE;
			permanent_fail ++;
			break;
		case SMTP_DELIVERER_PERMANENT_ERROR:
			bounce_type = BOUNCE_RESPONSE_ERROR;
			need_retry = FALSE;
			need_bounce = TRUE;
			permanent_fail ++;
			break;
		default:
			printf("[remote_postman]: fatal error of "
				"return value of smtp_deliverer_process\n");
			bounce_type = BOUNCE_CONNECTION_REFUSED;
			break;
		}
		if (TRUE == need_retry) {
			timer_ID = timer_queue_put(&fake_context, current_time, is_untried);
			if (timer_ID >= 0) {
				smtp_deliverer_log_info(&fake_context, 8, "message is put into "
					"timer queue with timer ID %d and wait to be delivered next"
					" time", timer_ID);
			} else {
				smtp_deliverer_log_info(&fake_context, 8,
					"fail to put message into timer queue!!!");
			}
		}
		need_bounce &= pcontext->pcontrol->need_bounce;
		if (TRUE == need_bounce) {
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				smtp_deliverer_log_info(&fake_context, 8,
					"fail to get one context for bounce mail");
			} else {
				bounce_producer_make(&fake_context, current_time, bounce_type,
					ip_addr, reason_buff, pbounce_context->pmail);
				pbounce_context->pcontrol->need_bounce = FALSE;
				sprintf(pbounce_context->pcontrol->from,
					"postmaster@%s", get_default_domain());
                mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
                	pcontext->pcontrol->from);
				pbounce_context->pcontrol->bound_type = BOUND_REMOTE_BOUNCE;
				enqueue_context(pbounce_context);
				pbounce_context = NULL;
			}	
		}
	}
	pthread_mutex_lock(&g_concurrent_mutex);
	g_concurrent_thr --;
	pthread_mutex_unlock(&g_concurrent_mutex);
	net_failure_statistic(OK_num, temp_fail, permanent_fail, giveup_num);
	mem_file_free(&control.f_rcpt_to);
	return TRUE;
}

/*
 *	console talk
 */
void remote_postman_console_talk(int argc,
	char **argv, char *result, int length)
{
	char *ptr;
	CONFIG_FILE *pfile;
	int max_rcpt, trying_times;
	int times, interval, alarm_interval;
	const char *tls_switch, *alarm_switch;
	int first_interval, second_interval, third_interval;
	char str_interval[64], str_alarm[64], str_scan[64];
	char str_first[64], str_second[64], str_third[64];
	char help_string[] = "250 remote postman help information:\r\n"
							 "\t%s status\r\n"
							 "\t    --print the running information\r\n"
							 "\t%s info\r\n"
							 "\t    --print the module information\r\n"
							 "\t%s routing reload\r\n"
							 "\t    --reload the sender routing list\r\n"
		                     "\t%s bounce reload\r\n"
							 "\t    --reload the bounce resource list\r\n"
							 "\t%s set alarm-frequncy <times/interval>\r\n"
							 "\t    --set alarm frequency\r\n"
							 "\t%s set alarm-interval <interval>\r\n"
							 "\t    --set alarm interval\r\n"
							 "\t%s set max-rcpts <number>\r\n"
							 "\t    --set maximum rcpt number on session\r\n"
							 "\t%s set trying-times <times>\r\n"
							 "\t    --set tring times when time out or "
							 "temporary failure\r\n"
							 "\t%s set timer-intervals <scan_interval> <1st> "
							 "<2nd> <3rd>\r\n"
							 "\t    --set the retrying delivery intervals\r\n"
							 "\t%s alarm [ON|OFF]\r\n"
							 "\t    --turn on or off the delivery alarm\r\n"
							 "\t%s starttls [ON|OFF]\r\n"
							 "\t    --turn on or off the starttls support";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0],
			argv[0], argv[0], argv[0], argv[0], argv[0],
			argv[0], argv[0], argv[0], argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}
	if (2 == argc && 0 == strcmp("status", argv[1])) {
		snprintf(result, length,
					"250 remote delivery running information:\r\n"
					"\tOK                       %d\r\n"
					"\ttemporary fail           %d\r\n"
					"\tpermanent fail           %d\r\n"
					"\tgive up                  %d",
					net_failure_get_param(NET_FAILURE_OK),
					net_failure_get_param(NET_FAILURE_TEMP),
					net_failure_get_param(NET_FAILURE_PERMANENT),
					net_failure_get_param(NET_FAILURE_GIVEUP));
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		itvltoa(net_failure_get_param(NET_FAILURE_STATISTIC_INTERVAL),
			str_interval);
		itvltoa(net_failure_get_param(NET_FAILURE_ALARM_INTERVAL), str_alarm);
		itvltoa(timer_queue_get_param(TIMER_QUEUE_SCAN_INTERVAL), str_scan);
		itvltoa(timer_queue_get_param(TIMER_QUEUE_FRESH), str_first);
		itvltoa(timer_queue_get_param(TIMER_QUEUE_RETRYING), str_second);
		itvltoa(timer_queue_get_param(TIMER_QUEUE_FINAL), str_third);
		tls_switch = smtp_deliverer_get_param(
			SMTP_DELIVERER_SSL_SWITCH)?"ON":"OFF",
		alarm_switch = net_failure_get_param(
			NET_FAILURE_TURN_ALARM)?"OFF":"ON",
		snprintf(result, length,
					"250 remote delivery module information:\r\n"
					"\tstarttls support         %s\r\n"
					"\tfailure alarm            %s\r\n"
					"\tstatistic times          %d\r\n"
					"\tstatistic interval       %s\r\n"
					"\talarm interval           %s\r\n"
					"\tmax rcpts                %d\r\n"
					"\ttrying times             %d\r\n"
					"\tscan interval            %s\r\n"
					"\tfirst interval           %s\r\n"
					"\tsecond interval          %s\r\n"
					"\tthird interval           %s\r\n"
					"\tmax timer threads        %d\r\n"
					"\tcurrent timer threads    %d",
					tls_switch, alarm_switch,
					net_failure_get_param(NET_FAILURE_STATISTIC_TIMES),
					str_interval, str_alarm, g_max_rcpt,
					smtp_deliverer_get_param(SMTP_DELIVERER_TRYING_TIMES),
					str_scan, str_first, str_second, str_third,
					timer_queue_get_param(TIMER_QUEUE_THREADS_MAX),
					timer_queue_get_param(TIMER_QUEUE_THREADS_NUM));
		return;
	}
	if (3 == argc && 0 == strcmp("routing", argv[1]) &&
		0 == strcmp("reload", argv[2])) {
		if (TRUE == sender_routing_refresh()) {
			strncpy(result, "250 sender routing list reload OK", length);
		} else {
			strncpy(result, "550 sender routing list reload error", length);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("bounce", argv[1]) &&
		0 == strcmp("reload", argv[2])) {
		if (TRUE == bounce_producer_refresh()) {
			strncpy(result, "250 bounce resource list reload OK", length);
		} else {
			strncpy(result, "550 bounce resource list reload error", length);
		}
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("alarm-frequncy", argv[2])) {
		ptr = strchr(argv[3], '/');
		if (NULL == ptr) {
			snprintf(result, length, "550 invalid argument"
					" %s should be times/interval", argv[3]);
			return;
		}
		*ptr = '\0';
		times = atoi(argv[3]);
		interval = atoitvl(ptr + 1);
		if (times <=0 || interval <=0) {
			snprintf(result, length, "550 times and "
					"interval should larger than 0");
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "FAILURE_TIMES_FOR_ALARM", argv[3]);
		config_file_set_value(pfile, "INTERVAL_FOR_FAILURE_STATISTIC", ptr + 1);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		net_failure_set_param(NET_FAILURE_STATISTIC_TIMES, times);
		net_failure_set_param(NET_FAILURE_STATISTIC_INTERVAL, interval);
		snprintf(result, length, "250 frequency set OK");
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("alarm-interval", argv[2])) {
		alarm_interval = atoitvl(argv[3]);
		if (alarm_interval <= 0) {
			snprintf(result, length, "550 invalid alram-interval %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "ALARM_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		net_failure_set_param(NET_FAILURE_ALARM_INTERVAL, alarm_interval);
		strncpy(result, "250 alarm-interval set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("max-rcpts", argv[2])) {
		max_rcpt = atoi(argv[3]);
		if (max_rcpt <= 0) {
			snprintf(result, length, "550 invalid max-rcpts %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "MAX_RCPT_NUM", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		g_max_rcpt = max_rcpt;
		strncpy(result, "250 max-rcpt set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("trying-times", argv[2])) {
		trying_times = atoi(argv[3]);
		if (trying_times <= 0) {
			snprintf(result, length, "550 invalid trying-times %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "SENDING_TRYING_TIMES", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		smtp_deliverer_set_param(SMTP_DELIVERER_TRYING_TIMES, trying_times);
		strncpy(result, "250 trying-times set OK", length);
		return;
	}
	if (7 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("timer-intervals", argv[2])) {
		interval = atoi(argv[3]);
		first_interval = atoitvl(argv[4]);
		second_interval = atoitvl(argv[5]);
		third_interval = atoitvl(argv[6]);
		if (interval <=0 ) {
			snprintf(result, length, "550 invalid interval %s", argv[3]);
			return;
		}
		if (first_interval < interval*2) {
			snprintf(result, length, "550 invalid interval %s", argv[4]);
			return;
		}
		if (second_interval < first_interval*2) {
			snprintf(result, length, "550 invalid interval %s", argv[5]);
			return;
		}
		if (third_interval < second_interval*2) {
			snprintf(result, length, "550 invalid interval %s", argv[6]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "TIMER_SCAN_INTERVAL", argv[3]);
		config_file_set_value(pfile, "FIRST_TRYING_INTERVAL", argv[4]);
		config_file_set_value(pfile, "SECOND_TRYING_INTERVAL", argv[5]);
		config_file_set_value(pfile, "FINAL_TRYING_INTERVAL", argv[6]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		timer_queue_set_param(TIMER_QUEUE_SCAN_INTERVAL, interval);
		timer_queue_set_param(TIMER_QUEUE_FRESH, first_interval);
		timer_queue_set_param(TIMER_QUEUE_RETRYING, second_interval);
		timer_queue_set_param(TIMER_QUEUE_FINAL, third_interval);
		strncpy(result, "250 timer-intervals set OK", length);
		return;
	}
	if (3 == argc && 0 == strcmp("alarm", argv[1])) {
		if (0 == strcasecmp("ON", argv[2])) {
			net_failure_set_param(NET_FAILURE_TURN_ALARM, FALSE);
			strncpy(result, "250 failure alarm is turned on", length);
		} else if (0 == strcasecmp("OFF", argv[2])) {
			net_failure_set_param(NET_FAILURE_TURN_ALARM, TRUE);
			strncpy(result, "250 failure alarm is turned off", length);
		} else {
			strncpy(result, "550 argument should be ON or OFF", length);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("starttls", argv[1])) {
		if (0 == strcasecmp("ON", argv[2])) {
			pfile = config_file_init2(NULL, g_config_path);
			if (NULL == pfile) {
				snprintf(result, length, "550 fail to open config file");
				return;
			}
			config_file_set_value(pfile, "STARTTLS_SUPPORT", "ON");
			if (FALSE == config_file_save(pfile)) {
				snprintf(result, length, "550 fail to save config file");
				config_file_free(pfile);
				return;
			}
			config_file_free(pfile);
			smtp_deliverer_set_param(SMTP_DELIVERER_SSL_SWITCH, TRUE);
			strncpy(result, "250 starttls support is on", length);
		} else if (0 == strcasecmp("OFF", argv[2])) {
			pfile = config_file_init2(NULL, g_config_path);
			if (NULL == pfile) {
				snprintf(result, length, "550 fail to open config file");
				return;
			}
			config_file_set_value(pfile, "STARTTLS_SUPPORT", "OFF");
			if (FALSE == config_file_save(pfile)) {
				snprintf(result, length, "550 fail to save config file");
				config_file_free(pfile);
				return;
			}
			config_file_free(pfile);
			smtp_deliverer_set_param(SMTP_DELIVERER_SSL_SWITCH, FALSE);
			strncpy(result, "250 starttls support is off", length);
		} else {
			strncpy(result, "550 argument should be ON or OFF", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

/*
 *	check addresses in psrc and arrange illegal ones into presult
 *	@param
 *		psrc [in, out]	source mem file pointer
 *		presult [in]	for saving illegal addresses
 *	@return
 *		TRUE			no illegal address
 *		FALSE			found illegal address
 */
static BOOL remote_postman_check_address(MEM_FILE *psrc, MEM_FILE *presult)
{
	MEM_FILE file_tmp;
	char rcpt_to[256];
	char *pdomain;
	BOOL ret_val;
	int  temp_len;

	mem_file_seek(psrc, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_init(&file_tmp, files_allocator_get_allocator());
	mem_file_clear(presult);
	ret_val = TRUE;
	while (MEM_END_OF_FILE != mem_file_readline(psrc, rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@');
		temp_len = strlen(rcpt_to);
		if (NULL == pdomain || '\'' == rcpt_to[temp_len - 1]) {
			ret_val = FALSE;
			mem_file_writeline(presult, rcpt_to);
		} else {
			mem_file_writeline(&file_tmp, rcpt_to);
		}
	}
	if (TRUE == ret_val) {
		mem_file_free(&file_tmp);
		return TRUE;
	} else {
		mem_file_copy(&file_tmp, psrc);
		mem_file_free(&file_tmp);
		return FALSE;
	}
}

/*
 *	copy same domain of rcpt address from psrc to pdst until maximum number 
 *	is reached!
 *	@param
 *		psrc [in, out]	source mem file pointer
 *		pdst [in]		destination mem file pointer
 *	@return
 *		TRUE			OK
 *		FALSE			empty
 */
static BOOL remote_postman_get_rcpt(MEM_FILE *psrc, MEM_FILE *pdst)
{
	MEM_FILE file_tmp;
	char rcpt_to[256];
	char domain[256], *pdomain;
	int rcpt_num;

	rcpt_num = 1;
	mem_file_seek(psrc, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	if (MEM_END_OF_FILE == mem_file_readline(psrc, rcpt_to, 256)) {
		return FALSE;
	}
	pdomain = strchr(rcpt_to, '@') + 1;
	mem_file_clear(pdst);
	mem_file_writeline(pdst, rcpt_to);
	/* if the destination domain only allow one rcpt, return immediately */
	if (TRUE == single_rcpt_query(pdomain)) {
		rcpt_num = g_max_rcpt;
	}
	mem_file_init(&file_tmp, files_allocator_get_allocator());
	strcpy(domain, pdomain);
	while (MEM_END_OF_FILE != mem_file_readline(psrc, rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@') + 1;
		if (0 == strcasecmp(domain, pdomain)) {
			if (rcpt_num >= g_max_rcpt) {
				mem_file_writeline(&file_tmp, rcpt_to);
			} else {
				mem_file_writeline(pdst, rcpt_to);
				rcpt_num ++;
			}
		} else {
			mem_file_writeline(&file_tmp, rcpt_to);
		}
	}
	mem_file_copy(&file_tmp, psrc);
	mem_file_free(&file_tmp);
	return TRUE;
}
