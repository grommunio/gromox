#include "gateway_dispatch.h"
#include "backend_list.h"
#include "files_allocator.h"
#include "smtp_dispatch.h"
#include "bounce_producer.h"
#include "net_failure.h"
#include "cache_queue.h"
#include "config_file.h"
#include "mail_func.h"
#include "vstack.h"
#include "util.h"
#include <time.h>
#include <pthread.h>
#include <stdio.h>

#define BACKEND_BUFFER_SIZE				4096


static char g_config_path[256];
static char g_backend_buffer[BACKEND_BUFFER_SIZE + 2];
static int  g_backend_buffer_size;
static int  g_block_interval;
static int  g_bounce_policy;
static LIB_BUFFER *g_stack_allocator;

typedef void (*STOP_FUNC)(void);
typedef BOOL (*DNS_QUERY)(char*, VSTACK*);
typedef BOOL (*CHECK_LOCAL)(const char*);
typedef BOOL (*GATEWAY_NOUSER_AUDIT)(char*);
typedef BOOL (*GATEWAY_NORCPT_AUDIT)(char*);
typedef BOOL (*CONSOLE_CONTROL)(const char *, char *, int);

static STOP_FUNC g_running_modules[7];

static DNS_QUERY dns_query_A;

static DNS_QUERY dns_query_MX;

static CHECK_LOCAL dns_check_local;

static GATEWAY_NOUSER_AUDIT gateway_nouser_audit;

static GATEWAY_NORCPT_AUDIT gateway_norcpt_audit;

SPAM_STATISTIC gateway_dispatch_spam_statistic;

static CONSOLE_CONTROL smtp_console_control;
static void gateway_dispatch_clean_up(void);
static void gateway_dispatch_dump_invalid(const char* ip, int port);

/*
 *	gateway dispatch's construct function
 */
void gateway_dispatch_init(const char *list_path, int backend_interval,
	int files_num, int times, int interval, int alarm_interval,
	int bounce_policy, const char *mash_string, const char *resource_path,
	const char* separator, const char *cache_path, int cache_interval,
	int retrying_times, int block_interval, const char *config_path)
{
	int i;

	for (i=0; i<7; i++) {
		g_running_modules[i] = NULL;
	}
	strcpy(g_config_path, config_path);
	g_block_interval = block_interval;
	g_bounce_policy = bounce_policy;
	backend_list_init(list_path, backend_interval);
	files_allocator_init(files_num);
	net_failure_init(times, interval, alarm_interval);
	smtp_dispatch_init(mash_string);
	bounce_producer_init(resource_path, separator);
	cache_queue_init(cache_path, cache_interval, retrying_times);
}

/*
 *	run the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int gateway_dispatch_run()
{
	gateway_dispatch_spam_statistic = (SPAM_STATISTIC)query_service(
										"spam_statistic");
	
	gateway_nouser_audit = (GATEWAY_NOUSER_AUDIT)query_service(
							"gateway_nouser_audit");
	gateway_norcpt_audit = (GATEWAY_NORCPT_AUDIT)query_service(
							"gateway_norcpt_audit");
	dns_query_A = (DNS_QUERY)query_service("dns_query_A");
	if (NULL == dns_query_A) {
		printf("[gateway_dispatch]: fail to get \"dns_query_A\" service\n");
		return -1;
	}
	
	dns_query_MX = (DNS_QUERY)query_service("dns_query_MX");
	if (NULL == dns_query_MX) {
		printf("[gateway_dispatch]: fail to get \"dns_query_MX\" service\n");
		return -2;
	}

	dns_check_local = (CHECK_LOCAL)query_service("dns_check_local");
	if (NULL == dns_check_local) {
		printf("[gateway_dispatch]: fail to get \"dns_check_local\" service\n");
		return -3;
	}
	
	if (NULL == gateway_nouser_audit) {
		printf("[gateway_dispatch]: fail to get \"gateway_nouser_audit\" "
				"service\n");
		return -4;
	}
	
	if (NULL == gateway_norcpt_audit) {
		printf("[gateway_dispatch]: fail to get \"gateway_norcpt_audit\" "
				"service\n");
		return -5;
	}
	
	smtp_console_control = (CONSOLE_CONTROL)query_service(
							"smtp_console_control");
	if (NULL == smtp_console_control) {
		printf("gateway_dispatch]: fail to get \"smtp_console_control\" "
				"service\n");
		return -6;
	}
	
	g_stack_allocator = vstack_allocator_init(16, 4096, TRUE);
	if (NULL == g_stack_allocator) {
		printf("[gateway_dispatch]: fail to init stack allocator\n");
		return -7;
	}
	
	if (0 != backend_list_run()) {
		printf("[gateway_dispatch]: fail to init {backend_list} module\n");
		return -8;
	}
	
	g_running_modules[1] = backend_list_stop;
	if (0 != files_allocator_run()) {
		printf("[gateway_dispatch]: fail to init {files allocator} module\n");
		gateway_dispatch_clean_up();
		return -9;
	}
	g_running_modules[2] = files_allocator_stop;

	if (0 != net_failure_run()) {
		printf("[gateway_dispatch]: fail to init {net failure} module\n");
		gateway_dispatch_clean_up();
        return -10;
	}
	g_running_modules[3] = net_failure_stop;

	if (0 != smtp_dispatch_run()) {
        printf("[gateway_dispatch]: fail to init {smtp deliverer} module\n");
        gateway_dispatch_clean_up();
        return -11;
    }
    g_running_modules[4] = smtp_dispatch_stop;

	if (0 != bounce_producer_run()) {
        printf("[gateway_dispatch]: fail to init {bounce producer} module\n");
        gateway_dispatch_clean_up();
        return -12;
    }
    g_running_modules[5] = bounce_producer_stop;

	if (0 != cache_queue_run()) {
        printf("[gateway_dispatch]: fail to init {cache queue} module\n");
        gateway_dispatch_clean_up();
        return -13;
    }
    g_running_modules[6] = cache_queue_stop;

	return 0;

}

/*
 *	clean up run modules
 */
static void gateway_dispatch_clean_up()
{
	int i;

	if (NULL != g_stack_allocator) {
		lib_buffer_free(g_stack_allocator);
		g_stack_allocator = NULL;
	}
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
void gateway_dispatch_stop()
{
	gateway_dispatch_clean_up();
}

/*
 *	gateway dispatch's destruct function
 */
void gateway_dispatch_free()
{
	backend_list_free();
    files_allocator_free();
    net_failure_free();
    smtp_dispatch_free();
    bounce_producer_free();
    cache_queue_free();
}

/*
 *	hook processing function
 */
BOOL gateway_dispatch_hook(MESSAGE_CONTEXT *pcontext)
{
	MIME *pmime;
	char ip_addr[16];
	time_t current_time;
	CONTROL_INFO control;
	MEM_FILE remote_file;
	int len;
	MESSAGE_CONTEXT fake_context;
	MESSAGE_CONTEXT *pbounce_context;
	int bounce_type, cache_ID;
	char reason_buff[1024], rcpt_buff[256];
	BOOL need_retry, need_bounce, local_found;
	char tmp_ip[16], host_ip[16];
	char *pdomain, *from_domain, add_command[64];
	
	if (BOUND_NOTLOCAL == pcontext->pcontrol->bound_type) {
		return FALSE;
	} else if (BOUND_IN == pcontext->pcontrol->bound_type) {
		mem_file_init(&control.f_rcpt_to, files_allocator_get_allocator());
		mem_file_copy(&pcontext->pcontrol->f_rcpt_to, &control.f_rcpt_to);
		mem_file_clear(&pcontext->pcontrol->f_rcpt_to);
	} else {
		local_found = FALSE;
		mem_file_init(&control.f_rcpt_to, files_allocator_get_allocator());
		mem_file_init(&remote_file, files_allocator_get_allocator());
		while (MEM_END_OF_FILE != mem_file_readline(
			&pcontext->pcontrol->f_rcpt_to, rcpt_buff, 256)) {
			pdomain = strchr(rcpt_buff, '@');
			if (NULL == pdomain) {
				mem_file_writeline(&remote_file, rcpt_buff);
				continue;
			}
			pdomain ++;
			if (TRUE == is_domainlist_valid()) {
				if (TRUE == check_domain(pdomain)) {
					mem_file_writeline(&control.f_rcpt_to, rcpt_buff);
					local_found = TRUE;
				} else {
					mem_file_writeline(&remote_file, rcpt_buff);
				}
			} else {
				if (TRUE == dns_check_local(pdomain)) {
					mem_file_writeline(&control.f_rcpt_to, rcpt_buff);
					local_found = TRUE;
				} else {
					mem_file_writeline(&remote_file, rcpt_buff);
				}
			}
		}
		if (FALSE == local_found) {
			mem_file_free(&control.f_rcpt_to);
			mem_file_free(&remote_file);
			return FALSE;
		}
		mem_file_copy(&remote_file, &pcontext->pcontrol->f_rcpt_to);
		mem_file_free(&remote_file);
	}
	time(&current_time);
	control.queue_ID = pcontext->pcontrol->queue_ID;
	control.bound_type = pcontext->pcontrol->bound_type;
	control.is_spam = pcontext->pcontrol->is_spam;
	control.need_bounce = pcontext->pcontrol->need_bounce;
	strcpy(control.from, pcontext->pcontrol->from);
	fake_context.pcontrol = &control;
	fake_context.pmail = pcontext->pmail;
	
	switch (smtp_dispatch_process(&fake_context,
		ip_addr, reason_buff, 1024)) {
	case SMTP_DISPATCH_OK:
		need_retry = FALSE;
		need_bounce = FALSE;
		net_failure_statistic(1, 0, 0, 0);
		if (NULL != gateway_dispatch_spam_statistic) {
			gateway_dispatch_spam_statistic(SPAM_STATISTIC_OK);
		}
		break;
    case SMTP_DISPATCH_TEMP_ERROR:
		need_retry = TRUE;
		need_bounce = FALSE;
		net_failure_statistic(0, 1, 0, 0);
		break;
    case SMTP_DISPATCH_NO_USER:
		bounce_type = BOUNCE_NO_USER;
		need_retry = FALSE;
		if (0 == strcmp(pcontext->pcontrol->from, "none@none")) {
			need_bounce = FALSE;
		} else {
			need_bounce = TRUE;
		}
		net_failure_statistic(0, 0, 0, 1);
		if (NULL != gateway_dispatch_spam_statistic) {
			gateway_dispatch_spam_statistic(SPAM_STATISTIC_NOUSER);
		}
		memset(tmp_ip, 0, 16);
		pmime = mail_get_head(pcontext->pmail);
		if (TRUE == mime_get_field(pmime,  "X-Lasthop", tmp_ip, 16) &&
			FALSE == gateway_nouser_audit(tmp_ip)) {
			len = sprintf(add_command, "ip_filter.svc temp-list add %s ",
					tmp_ip);
			itvltoa(g_block_interval, add_command + len);
			smtp_console_control(add_command, reason_buff, 1024);
			smtp_dispatch_log_info(&fake_context, 8, "ipaddr %s has sent too "
				"many mails of nouser, will be blocked for a while", tmp_ip);
		}
		if (FALSE == smtp_dispatch_has_maskstring()) {
			mem_file_seek(&fake_context.pcontrol->f_rcpt_to,
				MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
			while (MEM_END_OF_FILE != mem_file_readline(
				&fake_context.pcontrol->f_rcpt_to, rcpt_buff, 256)) {
				if (FALSE == gateway_norcpt_audit(rcpt_buff)) {
					sprintf(add_command, "invalid_user.svc add %s", rcpt_buff);
					smtp_console_control(add_command, reason_buff, 1024);
				}
			}
		}
		break;
	case SMTP_DISPATCH_PERMANENT_ERROR:
		bounce_type = BOUNCE_RESPONSE_ERROR;
		need_retry = FALSE;
		need_bounce = TRUE;
		net_failure_statistic(0, 0, 1, 0);
		break;
	}
	if (TRUE == need_retry) {
		cache_ID = cache_queue_put(&fake_context, current_time);
		if (cache_ID >= 0) {
			smtp_dispatch_log_info(&fake_context, 8, "message is put into "
				"cache queue with cache ID %d and wait to be delivered next"
				" time", cache_ID);
		} else {
			smtp_dispatch_log_info(&fake_context, 8, "failed to put message into "
				"cache queue");
		}
	}
	need_bounce &= pcontext->pcontrol->need_bounce;
	if (TRUE == need_bounce && BOUND_IN == pcontext->pcontrol->bound_type) {
		switch (g_bounce_policy) {
		case BOUNCE_POLICY_NONE:
			need_bounce = FALSE;
			break;
		case BOUNCE_POLICY_VERIFY:
			/* compare the B-class ip, if same, do not insulate the message */
			memset(host_ip, 0, 16);
			pmime = mail_get_head(pcontext->pmail);
			if (FALSE == mime_get_field(pmime, "X-Lasthop", host_ip, 16)) {
				need_bounce = FALSE;
			} else {
				from_domain = strchr(pcontext->pcontrol->from, '@') + 1;
				if (FALSE == gateway_dispatch_verify_ipdomain(from_domain,
					host_ip)) {
					need_bounce = FALSE;
					smtp_dispatch_log_info(&fake_context, 8,
						"original ipaddr is different from DNS result, "
						"will not bounce nouser mail");
				}
			}
			break;
		}
	}

	if (TRUE == need_bounce) {
		pbounce_context = get_context();
		if (NULL == pbounce_context) {
			smtp_dispatch_log_info(&fake_context, 8, "fail to get one context "
				"for bounce mail");
		} else {
			bounce_producer_make(&fake_context, current_time, bounce_type,
				ip_addr, reason_buff, pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from, "postmaster@%s",
					get_default_domain());
            mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
                pcontext->pcontrol->from);
			enqueue_context(pbounce_context);
			pbounce_context = NULL;
		}	
	}
	mem_file_free(&control.f_rcpt_to);
	if (0 == mem_file_get_total_length(&pcontext->pcontrol->f_rcpt_to)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

int gateway_dispatch_get_param(int param)
{
	switch (param) {
	case GATEWAY_DISPATCH_BOUNCE_POLICY:
		return g_bounce_policy;
	}
	return 0;
}

BOOL gateway_dispatch_verify_ipdomain(const char *domain, const char *ip)
{
	VSTACK stack;
	char *psearch;
	char *dest_ip;
	
	psearch = strrchr(ip, '.');
	if (NULL != psearch) {
		*psearch = '\0';
		psearch = strrchr(ip, '.');
		if (NULL != psearch) {
			*(psearch + 1) = '\0';
		}
	}
	vstack_init(&stack, g_stack_allocator, 16, 1024);
	if (TRUE == dns_query_MX((char*)domain, &stack)) {
		while (FALSE == vstack_is_empty(&stack)) {
			dest_ip = vstack_get_top(&stack);
			if (dest_ip == strstr(dest_ip, ip)) {
				vstack_free(&stack);
				return TRUE;
			}
			vstack_pop(&stack);
		}
	}
	if (TRUE == dns_query_A((char*)domain, &stack)) {
		while (FALSE == vstack_is_empty(&stack)) {
			dest_ip = vstack_get_top(&stack);
			if (dest_ip == strstr(dest_ip, ip)) {
				vstack_free(&stack);
				return TRUE;
			}
			vstack_pop(&stack);
		}
	}
	vstack_free(&stack);
	return FALSE;
}

static void gateway_dispatch_dump_invalid(const char *ip, int port)
{
	if (g_backend_buffer_size < BACKEND_BUFFER_SIZE - strlen(ip) - 7) {
		g_backend_buffer_size += 
			snprintf(g_backend_buffer + g_backend_buffer_size,
			BACKEND_BUFFER_SIZE - g_backend_buffer_size, "\t%s:%d\r\n",
			ip, port);
	}
}



/*
 *	console talk
 */
void gateway_dispatch_console_talk(int argc, char **argv, char *result,
	int length)
{
	char *ptr;
	CONFIG_FILE *pfile;
	int times, interval, alarm_interval;
	int scan_interval, retrying_times;
	int block_interval, bounce_policy;
	char str_block[64], str_policy[64];
	char str_interval[64], str_cache[64];
	char str_backend[64], str_alarm[64];
	char help_string[] = "250 gateway dispatch help information:\r\n"
							 "\t%s status\r\n"
							 "\t    --print the running information\r\n"
							 "\t%s info\r\n"
							 "\t    --print the module information\r\n"
							 "\t%s backends reload\r\n"
							 "\t    --reload back-end units from list file\r\n"
							 "\t%s echo invalid-backends\r\n"
							 "\t    --print the invalid backend server(s)\r\n"
		                     "\t%s bounce reload\r\n"
							 "\t    --reload the bounce resource list\r\n"
							 "\t%s set bounce-policy <0|1|2>\r\n"
							 "\t    --set bounce policy of in-bounce mail\r\n"
							 "\t%s set alarm-frequncy <times/interval>\r\n"
							 "\t    --set alarm frequency\r\n"
							 "\t%s set alarm-interval <interval>\r\n"
							 "\t    --set alarm interval\r\n"
							 "\t%s set backend-scan <interval>\r\n"
							 "\t    --set back-end invalid scanning interval\r\n"
							 "\t%s set cache-scan <interval>\r\n"
							 "\t    --set cache scanning interval\r\n"
							 "\t%s set retrying-times <times>\r\n"
							 "\t    --set the cache retrying times\r\n"
							 "\t%s set block-interval <interval>\r\n"
							 "\t    --set the nouser block interval";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], 
			argv[0], argv[0], argv[0], argv[0], argv[0], argv[0],
			argv[0], argv[0], argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}
	if (2 == argc && 0 == strcmp("status", argv[1])) {
		snprintf(result, length,
					"250 gateway dispatch running information:\r\n"
					"\tOK                       %d\r\n"
					"\ttemporary fail           %d\r\n"
					"\tpermanent fail           %d\r\n"
					"\tno user                  %d",
					net_failure_get_param(NET_FAILURE_OK),
					net_failure_get_param(NET_FAILURE_TEMP),
					net_failure_get_param(NET_FAILURE_PERMANENT),
					net_failure_get_param(NET_FAILURE_NOUSER));
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		itvltoa(net_failure_get_param(NET_FAILURE_STATISTIC_INTERVAL),
			str_interval);
		itvltoa(net_failure_get_param(NET_FAILURE_ALARM_INTERVAL), str_alarm);
		itvltoa(cache_queue_get_param(CACHE_QUEUE_SCAN_INTERVAL), str_cache);
		itvltoa(backend_list_get_param(BACKEND_LIST_SCAN_INTERVAL),str_backend);
		itvltoa(g_block_interval, str_block);
		switch (g_bounce_policy) {
		case BOUNCE_POLICY_NONE:
			strcpy(str_policy, "none");
			break;
		case BOUNCE_POLICY_VERIFY:
			strcpy(str_policy, "verify");
			break;
		case BOUNCE_POLICY_ALWAYS:
			strcpy(str_policy, "always");
			break;
		}
		snprintf(result, length,
					"250 gateway dispatch module information:\r\n"
					"\tstatistic times          %d\r\n"
					"\tstatistic interval       %s\r\n"
					"\talarm interval           %s\r\n"
					"\tbounce policy            %s\r\n"
					"\tback-end interval        %s\r\n"
					"\tcache interval           %s\r\n"
					"\tretrying times           %d\r\n"
					"\tnouser block interval    %s",
					net_failure_get_param(NET_FAILURE_STATISTIC_TIMES),
					str_interval,
					str_alarm,
					str_policy,
					str_backend,
					str_cache,
					cache_queue_get_param(CACHE_QUEUE_RETRYING_TIMES),
					str_block);
					
		return;
	}
	if (3 == argc && 0 == strcmp("backends", argv[1]) &&
		0 == strcmp("reload", argv[2])) {
		if (TRUE == backend_list_refresh()) {
			snprintf(result, length, "250 back-end list reload OK");
		} else {
			snprintf(result, length, "550 fail to reload back-end units from "
					"list file");
		}
		return;
	}
	if (3 == argc && 0 == strcmp("echo", argv[1]) &&
		0 == strcmp("invalid-backends", argv[2])) {
		g_backend_buffer_size = 0;
		backend_list_enum_invalid(gateway_dispatch_dump_invalid);
		if (0 == g_backend_buffer_size) {
			strncpy(result, "250 there's no invalid back-end unit", length);
		} else {
			g_backend_buffer[g_backend_buffer_size] = '\0';
			strncpy(result, g_backend_buffer, length);
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
		0 == strcmp("bounce-policy", argv[2])) {
		bounce_policy = atoi(argv[3]);
		if (bounce_policy > 2 || bounce_policy < 0) {
			snprintf(result, length, "550 bounce-policy should be 0, 1 or 2");
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "BOUNCE_POLICY", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		g_bounce_policy = bounce_policy;
		strncpy(result, "250 bounce-policy set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("alarm-frequncy", argv[2])) {
		ptr = strchr(argv[3], '/');
		if (NULL == ptr) {
			snprintf(result, length, "550 invalid argument %s should be "
					"times/interval", argv[3]);
			return;
		}
		*ptr = '\0';
		times = atoi(argv[3]);
		interval = atoitvl(ptr + 1);
		if (times <=0 || interval <=0) {
			snprintf(result, length, "550 times and interval should larger "
				"than 0");
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
		0 == strcmp("retrying-times", argv[2])) {
		retrying_times = atoi(argv[3]);
		if (retrying_times <= 0) {
			snprintf(result, length, "550 invalid retrying-times %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "RETRYING_TIMES", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		cache_queue_set_param(CACHE_QUEUE_RETRYING_TIMES, retrying_times);
		strncpy(result, "250 retrying-times set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("backend-scan", argv[2])) {
		scan_interval = atoitvl(argv[3]);
		if (scan_interval <=0 ) {
			snprintf(result, length, "550 invalid backend-scan %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "BACKEND_SCAN_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		backend_list_set_param(BACKEND_LIST_SCAN_INTERVAL, scan_interval);
		strncpy(result, "250 backend-scan set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("cache-scan", argv[2])) {
		scan_interval = atoitvl(argv[3]);
		if (scan_interval <=0 ) {
			snprintf(result, length, "550 invalid cache-scan %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "CACHE_SCAN_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		cache_queue_set_param(CACHE_QUEUE_SCAN_INTERVAL, scan_interval);
		strncpy(result, "250 cache-scan set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("block-interval", argv[2])) {
		block_interval = atoitvl(argv[3]);
		if (block_interval <=0 ) {
			snprintf(result, length, "550 invalid block-interval %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "NOUSER_BLOCK_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		g_block_interval = block_interval;
		strncpy(result, "250 block-interval set OK", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


