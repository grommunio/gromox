#include "domain_list.h"
#include "url_downloader.h"
#include "file_operation.h"
#include "gateway_control.h"
#include "list_file.h"
#include <stdio.h>
#include <pthread.h>

static BOOL g_noop;
static BOOL g_notify_stop;
static char g_url_path[1024];
static char g_list_path[256];
static char g_temp_path[256];
static pthread_t g_thread_id;

static void* thread_work_func(void *param);


void domain_list_init(const char *url, const char *list_path, BOOL b_noop)
{
	g_noop = b_noop;
	if (NULL == url) {
		g_noop = TRUE;
		g_url_path[0] = '\0';
	} else {
		strcpy(g_url_path, url);
	}
	strcpy(g_list_path, list_path);
	sprintf(g_temp_path, "%s.tmp", list_path);
	g_notify_stop = TRUE;
}

int domain_list_run()
{
	if (FALSE == g_noop) {
		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_thread_id, NULL, thread_work_func, NULL)) {
			g_notify_stop = TRUE;
			printf("[domain_list]: fail to create fresh thread\n");
			return -1;
		}
	}
	return 0;
}

int domain_list_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	return 0;
}

void domain_list_free()
{
	g_url_path[0] = '\0';
}

static void* thread_work_func(void *param)
{
	
	while (FALSE == g_notify_stop) {
		if (FALSE == url_downloader_get(g_url_path, g_temp_path)) {
			sleep(3);
			continue;
		}
		if (FILE_COMPARE_DIFFERENT != file_operation_compare(g_list_path,
			g_temp_path)) {
			sleep(3);
			continue;
		}
		remove(g_list_path);
		link(g_temp_path, g_list_path);
		remove(g_temp_path);
		file_operation_broadcast(g_list_path, "data/smtp/domain_list.txt");
		file_operation_broadcast(g_list_path, "data/delivery/domain_list.txt");
		gateway_control_notify("domain_list.svc reload",
			NOTIFY_SMTP|NOTIFY_DELIVERY);
		sleep(3);
	}
}

