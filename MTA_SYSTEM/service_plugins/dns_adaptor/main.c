#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/mtasvc_common.h>
#include "dns_adaptor.h"
#include "inbound_ips.h"
#include "config_file.h"
#include "util.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256], tmp_path[256];
	char temp_buff[64];
	char *str_value, *psearch;
	int capacity, interval;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
       
		if (FALSE == register_talk(dns_adaptor_console_talk)) {
			printf("[dns_adaptor]: fail to register console talk\n");
			return FALSE;
		}
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, tmp_path);
		if (NULL == pfile) {
			printf("[dns_adaptor]: config_file_init %s: %s\n", tmp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "CACHE_CAPACITY");
		if (NULL == str_value) {
			capacity = 1000;
			config_file_set_value(pfile, "CACHE_CAPACITY", "1000");
		} else {
			capacity = atoi(str_value);
			if (capacity <= 0) {
				capacity = 1000;
				config_file_set_value(pfile, "CACHE_CAPACITY", "1000");
			}
		}
		printf("[dns_adaptor]: cahce capacity is %d\n", capacity);	
		str_value = config_file_get_value(pfile, "VALID_INTERVAL");
		if (NULL == str_value) {
			interval = 24*60*60;
			config_file_set_value(pfile, "VALID_INTERVAL", "1day");
		} else {
			interval = atoitvl(str_value);
			if (interval <= 0) {
				interval = 24*60*60;
				config_file_set_value(pfile, "VALID_INTERVAL", "1day");
			}
		}
		itvltoa(interval, temp_buff);
		printf("[dns_adaptor]: valid interval is %s\n", temp_buff);
		config_file_free(pfile);
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		dns_adaptor_init(tmp_path, capacity, interval);
		if (0 != dns_adaptor_run()) {
			printf("[dns_adaptor]: fail to run the dns-adaptor module\n");
			return FALSE;
		}
		sprintf(tmp_path, "%s/inbound_ips.txt", get_data_path());
		inbound_ips_init(tmp_path);
		if (0 != inbound_ips_run()) {
			printf("[dns_adaptor]: fail to run module inbound-ips\n");
			return FALSE;
		}
		if (FALSE == register_service("dns_query_A",
			dns_adaptor_query_A)) {
			printf("[dns_adaptor]: fail to register \"dns_query_A\""
					"service\n");
			return FALSE;

		}
		if (FALSE == register_service("dns_query_MX",
			dns_adaptor_query_MX)) {
			printf("[dns_adaptor]: fail to register \"dns_query_MX\""
					"service\n");
			return FALSE;
		}
		if (FALSE == register_service("dns_check_local",
			inbound_ips_check_local)) {
			printf("[dns_adaptor]: fail to register \"dns_check_local\""
					"service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		inbound_ips_stop();
		inbound_ips_free();
		dns_adaptor_stop();
		dns_adaptor_free();
		return TRUE;
	}
	return false;
}

