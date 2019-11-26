#include <stdbool.h>
#include "hook_common.h"
#include "remote_postman.h"
#include "config_file.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	int files_num;
	BOOL tls_switch;
	char tmp_path[256];
	CONFIG_FILE *pfile;
	 char separator[16];
	char temp_buff[256];
	char file_name[256];
	int times, interval;
	char timer_path[256];
	int max_thr, max_rcpt;
	char routing_path[256];
	int alarm_interval, len;
	char resource_path[256];
	char *str_value, *psearch;
	int trying_times, timer_threads;
	int scan_interval, fresh_interval;
	int retrying_interval, final_interval;

	/* path conatins the config files directory */
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(tmp_path);
		if (NULL == pfile) {
			printf("[remote_postman]: error to open config file!!!\n");
			return FALSE;
		}
		files_num = 256 * get_threads_num();
		
		str_value = config_file_get_value(pfile, "FAILURE_TIMES_FOR_ALARM");
		if (NULL == str_value) {
			times = 30;
			config_file_set_value(pfile, "FAILURE_TIMES_FOR_ALARM", "30");
		} else {
			times = atoi(str_value);
			if (times <= 0) {
				times = 30;
				config_file_set_value(pfile, "FAILURE_TIMES_FOR_ALARM", "30");
			}
		}
		printf("[remote_postman]: failure times for alarm is %d\n", times);

		str_value = config_file_get_value(pfile, 
				"INTERVAL_FOR_FAILURE_STATISTIC");
		if (NULL == str_value) {
			interval = 600;
			config_file_set_value(pfile, "INTERVAL_FOR_FAILURE_STATISTIC",
				"10minutes");
		} else {
			interval = atoitvl(str_value);
			if (interval <= 0) {
				interval = 600;
				config_file_set_value(pfile, "INTERVAL_FOR_FAILURE_STATISTIC",
					"10minutes");
			}
		}
		itvltoa(interval, temp_buff);
		printf("[remote_postman]: interval for failure alarm is %s\n",
			temp_buff);
		
		str_value = config_file_get_value(pfile, "ALARM_INTERVAL");
		if (NULL == str_value) {
			alarm_interval = 1800;
			config_file_set_value(pfile, "ALARM_INTERVAL", "30minutes");
		} else {
			alarm_interval = atoitvl(str_value);
			if (alarm_interval <= 0) {
				alarm_interval = 1800;
				config_file_set_value(pfile, "ALARM_INTERVAL", "30minutes");
			}
		}
		itvltoa(alarm_interval, temp_buff);
		printf("[remote_postman]: alarms interval is %s\n", temp_buff);
		
		if (get_threads_num() - 4 > 0) {
			max_thr = get_threads_num() - 4;
		} else {
			max_thr = get_threads_num();
		}
		
		sprintf(resource_path, "%s/remote_bounce", get_data_path());	

		sprintf(routing_path, "%s/remote_routing.txt", get_data_path());	
		
		str_value = config_file_get_value(pfile, "MAX_RCPT_NUM");
		if (NULL == str_value) {
			max_rcpt = 25;
			config_file_set_value(pfile, "MAX_RCPT_NUM", "25");
		} else {
			max_rcpt = atoi(str_value);
			if (max_rcpt <= 0) {
				max_rcpt = 25;
				config_file_set_value(pfile, "MAX_RCPT_NUM", "25");
			}
		}
		printf("[remote_postman]: maximum rcpt number is %d\n", max_rcpt);
		
		str_value = config_file_get_value(pfile, "SENDING_TRYING_TIMES");
		if (NULL == str_value) {
			trying_times = 3;
			config_file_set_value(pfile, "SENDING_TRYING_TIMES", "3");
		} else {
			trying_times = atoi(str_value);
			if (trying_times <= 0) {
				trying_times = 3;
				config_file_set_value(pfile, "SENDING_TRYING_TIMES", "3");
			}
		}
		printf("[remote_postman]: retring times on temporary failure is %d\n",
			trying_times);
		
		str_value = config_file_get_value(pfile, "SEPARATOR_FOR_BOUNCE");
		if (NULL == str_value) {
			strcpy(separator, " ");
		} else {
			strcpy(separator, str_value);
		}

		sprintf(timer_path, "%s/timer", get_queue_path());
		
		str_value = config_file_get_value(pfile, "TIMER_THREADS_MAX");
		if (NULL == str_value) {
			timer_threads = 8;
			config_file_set_value(pfile, "TIMER_THREADS_MAX", "8");
		} else {
			timer_threads = atoi(str_value);
			if (timer_threads <= 0) {
				timer_threads = 8;
				config_file_set_value(pfile, "TIMER_THREADS_MAX", "8");
			}
		}
		printf("[remote_postman]: maximum timer queue threads number is %d\n",
			timer_threads);
		
		str_value = config_file_get_value(pfile, "TIMER_SCAN_INTERVAL");
		if (NULL == str_value) {
			scan_interval = 60;
			config_file_set_value(pfile, "TIMER_SCAN_INTERVAL", "1minute");
		} else {
			scan_interval = atoitvl(str_value);
			if (scan_interval <= 0) {
				scan_interval = 60;
				config_file_set_value(pfile, "TIMER_SCAN_INTERVAL", "1minute");
			}
		}
		itvltoa(scan_interval, temp_buff);
		printf("[remote_postman]: timer queue scanning interval is %s\n",
			temp_buff);

		str_value = config_file_get_value(pfile, "FIRST_TRYING_INTERVAL");
		if (NULL == str_value) {
			fresh_interval = 900;
			config_file_set_value(pfile, "FIRST_TRYING_INTERVAL", "15minutes");
		} else {
			fresh_interval = atoitvl(str_value);
		}
		if (fresh_interval <= scan_interval*2) {
			fresh_interval = scan_interval * 2;
			itvltoa(fresh_interval, temp_buff);
			config_file_set_value(pfile, "FIRST_TRYING_INTERVAL", temp_buff);
		}
		itvltoa(fresh_interval, temp_buff);
		printf("[remote_postman]: first failure retring interval is %s\n",
			temp_buff);

		str_value = config_file_get_value(pfile, "SECOND_TRYING_INTERVAL");
		if (NULL == str_value) {
			retrying_interval = 3600;
			config_file_set_value(pfile, "SECOND_TRYING_INTERVAL", "1hour");
		} else {
			retrying_interval = atoitvl(str_value);
		}
		if (retrying_interval <= fresh_interval*2) {
			retrying_interval = fresh_interval * 2;
			itvltoa(retrying_interval, temp_buff);
			config_file_set_value(pfile, "SECOND_TRYING_INTERVAL", temp_buff);
		}
		itvltoa(retrying_interval, temp_buff);
		printf("[remote_postman]: second failure retring interval is %s\n",
			temp_buff);

		str_value = config_file_get_value(pfile, "FINAL_TRYING_INTERVAL");
		if (NULL == str_value) {
			final_interval = 3600 * 6;
			config_file_set_value(pfile, "FINAL_TRYING_INTERVAL", "6hours");
		} else {
			final_interval = atoitvl(str_value);
		}
		if (final_interval <= retrying_interval*2) {
			final_interval = retrying_interval * 2;
			itvltoa(final_interval, temp_buff);
			config_file_set_value(pfile, "FINAL_TRYING_INTERVAL", temp_buff);
		}
		itvltoa(final_interval, temp_buff);
		printf("[remote_postman]: last failure retrying interval is %s\n",
			temp_buff);
		
		str_value = config_file_get_value(pfile, "STARTTLS_SUPPORT");
		if (NULL == str_value) {
			tls_switch = TRUE;
			config_file_set_value(pfile, "STARTTLS_SUPPORT", "ON");
		} else {
			if (0 == strcasecmp(str_value, "ON") ||
				0 == strcasecmp(str_value, "TRUE")) {
				tls_switch = TRUE;
			} else if (0 == strcasecmp(str_value, "FALSE")
				|| 0 == strcasecmp(str_value, "OFF")) {
				tls_switch = FALSE;
			} else {
				tls_switch = TRUE;
				config_file_set_value(pfile, "STARTTLS_SUPPORT", "ON");
			}
		}
		if (TRUE == tls_switch) {
			printf("[remote_postman]: STARTTLS support is ON\n");
		} else {
			printf("[remote_postman]: STARTTLS support is OFF\n");
		}
		
		if (FALSE == config_file_save(pfile)) {
			printf("[remote_postman]: fail to save config file\n");
			config_file_free(pfile);
			return FALSE;
		}
		remote_postman_init(max_thr, files_num, times, interval,
			alarm_interval, tls_switch, trying_times, max_rcpt,
			resource_path, separator, timer_path, timer_threads,
			scan_interval, fresh_interval, retrying_interval,
			final_interval, routing_path, tmp_path);

		config_file_free(pfile);
		
		if (0 != remote_postman_run()) {
			printf("[remote_postman]: fail to run remote postman\n");
			return FALSE;
		}
		register_talk(remote_postman_console_talk);
		if (FALSE == register_remote(remote_postman_hook)) {
			printf("[remote_postman]: fail to register the hook function\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		remote_postman_stop();
		remote_postman_free();
		return TRUE;
	}
	return false;
}
