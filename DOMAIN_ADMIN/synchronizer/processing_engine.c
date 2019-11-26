#include <unistd.h>
#include "processing_engine.h"
#include "url_downloader.h"
#include "file_operation.h"
#include "list_file.h"
#include "config_file.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>


static BOOL g_noop;
static BOOL g_notify_stop;
static char g_master_host[256];
static char g_data_path[256];
static char g_config_path[256];
static pthread_t g_thread_id;

static void* thread_work_func(void *param);


void processing_engine_init(const char *master_host, const char *data_path,
	const char *config_path)
{
	if (NULL == master_host) {
		g_noop = TRUE;
	} else {
		strcpy(g_master_host, master_host);
		g_noop = FALSE;
	}
	strcpy(g_data_path, data_path);
	strcpy(g_config_path, config_path);
	g_notify_stop = TRUE;
}

int processing_engine_run()
{
	if (FALSE == g_noop) {
		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_thread_id, NULL, thread_work_func, NULL)) {
			g_notify_stop = TRUE;
			printf("[processing_engine]: fail to create fresh thread\n");
			return -1;
		}
	}
	return 0;
}

int processing_engine_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	return 0;
}

void processing_engine_free()
{
	g_master_host[0] = '\0';
}

static void* thread_work_func(void *param)
{
	char *str_master;
	char *str_slave;
	char temp_url[1024];
	char temp_path[256];
	char temp_path1[256];
	CONFIG_FILE *pconfig_master;
	CONFIG_FILE *pconfig_slave;
	
	while (FALSE == g_notify_stop) {
		sleep(3);
		sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?athena.cfg",
			g_master_host);
		sprintf(temp_path, "%s.tmp", g_config_path);
		if (FALSE == url_downloader_get(temp_url, temp_path)) {
			continue;
		}
		pconfig_master = config_file_init2(temp_path, NULL);
		if (NULL == pconfig_master) {
			continue;
		}
		pconfig_slave = config_file_init2(g_config_path, NULL);
		if (NULL == pconfig_slave) {
			continue;
		}
		if (NULL == pconfig_slave) {
			config_file_free(pconfig_master);
			continue;
		}
		
		str_master = config_file_get_value(pconfig_master, "DEFAULT_DOMAIN");
		str_slave = config_file_get_value(pconfig_slave, "DEFAULT_DOMAIN");
		if (NULL != str_master && (NULL == str_slave ||
			0 != strcasecmp(str_master, str_slave))) {
			config_file_set_value(pconfig_slave, "DEFAULT_DOMAIN", str_master);
		}
		
		str_master = config_file_get_value(pconfig_master, "LOG_VALID_DAYS");
		str_slave = config_file_get_value(pconfig_slave, "LOG_VALID_DAYS");
		if (NULL != str_master && (NULL == str_slave ||
			0 != strcmp(str_master, str_slave))) {
			config_file_set_value(pconfig_slave, "LOG_VALID_DAYS", str_master);
		}
		
		str_master = config_file_get_value(pconfig_master, "BACKUP_VALID_DAYS");
		str_slave = config_file_get_value(pconfig_slave, "BACKUP_VALID_DAYS");
		if (NULL != str_master && (NULL == str_slave ||
			0 != strcmp(str_master, str_slave))) {
			config_file_set_value(pconfig_slave, "BACKUP_VALID_DAYS", str_master);
		}

		config_file_save(pconfig_slave);
		config_file_free(pconfig_master);
		config_file_free(pconfig_slave);
		remove(temp_path);
		
		sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?area_list.txt",
			g_master_host);
		sprintf(temp_path, "%s/area_list.txt", g_data_path);
		sprintf(temp_path1, "%s/area_list.txt.tmp", g_data_path);
		if (TRUE == url_downloader_get(temp_url, temp_path1) &&
			FILE_COMPARE_DIFFERENT == file_operation_compare(
			temp_path, temp_path1)) {
			remove(temp_path);
			link(temp_path1, temp_path);
			remove(temp_path1);
		}
		
		sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?cidb_list.txt",
			g_master_host);
		sprintf(temp_path, "%s/cidb_list.txt", g_data_path);
		sprintf(temp_path1, "%s/cidb_list.txt.tmp", g_data_path);
		if (TRUE == url_downloader_get(temp_url, temp_path1) &&
			FILE_COMPARE_DIFFERENT == file_operation_compare(
			temp_path, temp_path1)) {
			remove(temp_path);
			link(temp_path1, temp_path);
			remove(temp_path1);
		}
	}
	return NULL;
}

