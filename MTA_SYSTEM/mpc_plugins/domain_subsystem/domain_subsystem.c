#include "domain_subsystem.h"
#include "smtp_clone.h"
#include "clone_queue.h"
#include "address_list.h"
#include "config_file.h"
#include "mail_func.h"
#include "util.h"
#include <time.h>
#include <pthread.h>
#include <stdio.h>


static char g_config_path[256];
static int g_max_thr;
static int g_concurrent_thr;
static pthread_mutex_t g_concurrent_mutex;


static BOOL domain_subsystem_get_rcpt(MEM_FILE *psrc, MEM_FILE *pdst, char *ip,
	int *pport);

void domain_subsystem_init(const char *config_path, const char *list_path,
	const char *queue_path, int times, int interval, int max_thr)
{
	strcpy(g_config_path, config_path);
	address_list_init(list_path);
	clone_queue_init(queue_path, interval, times);
	g_concurrent_thr = 0;
	g_max_thr = max_thr;
	pthread_mutex_init(&g_concurrent_mutex, NULL);
}

int domain_subsystem_run()
{
	
	if (0 != address_list_run()) {
		printf("[domain_subsystem]: failed to run address list\n");
		return -1;
	}
	if (0 != clone_queue_run()) {
		printf("[domain_subsystem]: Failed to init clone queue\n");
        return -3;
    }

	return 0;

}

int domain_subsystem_stop()
{
	clone_queue_stop();
	address_list_stop();
	return 0;
}

void domain_subsystem_free()
{
	clone_queue_free();
	address_list_free();
	g_concurrent_thr = 0;
	pthread_mutex_destroy(&g_concurrent_mutex);
}

BOOL domain_subsystem_hook(MESSAGE_CONTEXT *pcontext)
{
	char ip[16];
	BOOL can_enter;
	int queue_ID, port;
	time_t current_time;
	CONTROL_INFO control;
	MEM_FILE temp_file;
	MESSAGE_CONTEXT fake_context;
	
	mem_file_init(&control.f_rcpt_to, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_init(&temp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_copy(&pcontext->pcontrol->f_rcpt_to, &temp_file);

	time(&current_time);
	control.queue_ID = pcontext->pcontrol->queue_ID;
	control.bound_type = pcontext->pcontrol->bound_type;
	control.is_spam = pcontext->pcontrol->is_spam;
	control.need_bounce = pcontext->pcontrol->need_bounce;
	strcpy(control.from, pcontext->pcontrol->from);
	fake_context.pcontrol = &control;
	fake_context.pmail = pcontext->pmail;
	
	pthread_mutex_lock(&g_concurrent_mutex);
	if (g_concurrent_thr >= g_max_thr) {
		can_enter = FALSE;
	} else {
		g_concurrent_thr ++;
		can_enter = TRUE;
	}
	pthread_mutex_unlock(&g_concurrent_mutex);
	if (FALSE == can_enter) {
		while (TRUE == domain_subsystem_get_rcpt(&temp_file,
			&fake_context.pcontrol->f_rcpt_to, ip, &port)) {
			clone_queue_put(&fake_context, current_time);
		}
		mem_file_free(&control.f_rcpt_to);
		mem_file_free(&temp_file);
		return FALSE;	
	}

		
	while (TRUE == domain_subsystem_get_rcpt(&temp_file,
		&fake_context.pcontrol->f_rcpt_to, ip, &port)) {		
		if (SMTP_CLONE_TEMP_ERROR == smtp_clone_process(
			&fake_context, ip, port)) {
			queue_ID = clone_queue_put(&fake_context, current_time);
			if (queue_ID >= 0) {
				smtp_clone_log_info(&fake_context, 8, "message is put into "
					"clone queue with queue ID %d and wait to be delivered next"
					" time", queue_ID);
			} else {
				smtp_clone_log_info(&fake_context, 8, "failed to put message "
					"into clone queue");
			}
		}
	}
	
	mem_file_free(&control.f_rcpt_to);
	mem_file_free(&temp_file);
	
	pthread_mutex_lock(&g_concurrent_mutex);
	g_concurrent_thr --;
	pthread_mutex_unlock(&g_concurrent_mutex);
	return FALSE;
}


static BOOL domain_subsystem_get_rcpt(MEM_FILE *psrc, MEM_FILE *pdst, char *ip,
	int *pport)
{
	BOOL b_found;
    MEM_FILE file_tmp;
	char *pdomain;
    char domain[256];
    char rcpt_to[256];
	

	mem_file_init(&file_tmp, psrc->allocator);
    mem_file_seek(psrc, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
    mem_file_clear(pdst);
	
	b_found = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(psrc, rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@');
		if (NULL == pdomain) {
			continue;
		}
		pdomain ++;
		if (FALSE == b_found) {
			if (FALSE == address_list_query(pdomain, ip, pport)) {
				continue;
			}
			strcpy(domain, pdomain);
			b_found = TRUE;
			mem_file_writeline(pdst, rcpt_to);
		} else {
			if (0 == strcasecmp(pdomain, domain)) {
				mem_file_writeline(pdst, rcpt_to);
			} else {
				mem_file_writeline(&file_tmp, rcpt_to);
			}
		}
		
    }
	if (FALSE == b_found) {
		mem_file_free(&file_tmp);
		return FALSE;
	}
    mem_file_copy(&file_tmp, psrc);
	mem_file_free(&file_tmp);
    return TRUE;
}


void domain_subsystem_console_talk(int argc, char **argv, char *result,
	int length)
{
	CONFIG_FILE *pfile;
	int times, interval;
	char str_interval[64];
	char help_string[] = "250 domain subsystem help information:\r\n"
							 "\t%s info\r\n"
							 "\t    --print the module information\r\n"
							 "\t%s reload\r\n"
							 "\t    --reload address table from list file\r\n"
							 "\t%s set interval <interval>\r\n"
							 "\t    --set clone queue scanning interval\r\n"
							 "\t%s set times <times>\r\n"
							 "\t    --set the clone queue retrying times";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}
	
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		itvltoa(clone_queue_get_param(CLONE_QUEUE_SCAN_INTERVAL), str_interval);
		snprintf(result, length,
				"250 domain subsystem module information:\r\n"
				"\tretrying times               %d\r\n"
				"\tqueue canning interval       %s",
				clone_queue_get_param(CLONE_QUEUE_RETRYING_TIMES),
				str_interval);
		return;
	}
	
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("times", argv[2])) {
		times = atoi(argv[3]);
		if (times <= 0) {
			snprintf(result, length, "550 invalid times %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 Failed to open config file");
			return;
		}
		config_file_set_value(pfile, "RETRYING_TIMES", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		clone_queue_set_param(CLONE_QUEUE_RETRYING_TIMES, times);
		strncpy(result, "250 times set OK", length);
		return;
	}
	
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0 ) {
			snprintf(result, length, "550 invalid interval %s", argv[3]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 Failed to open config file");
			return;
		}
		config_file_set_value(pfile, "QUEUE_SCAN_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		clone_queue_set_param(CLONE_QUEUE_SCAN_INTERVAL, interval);
		strncpy(result, "250 interval set OK", length);
		return;
	}

	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		switch (address_list_refresh()) {
		case REFRESH_OK:
			strncpy(result, "250 address table reload OK", length);
			return;
		case REFRESH_FILE_ERROR:
			strncpy(result, "550 address list file error", length);
			return;
		case REFRESH_HASH_FAIL:
			strncpy(result, "550 hash map error for address table", length);
			return;
		}		
	}
	
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


