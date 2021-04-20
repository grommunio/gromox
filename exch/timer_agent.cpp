// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#define DECLARE_API_STATIC
#include <atomic>
#include <cerrno>
#include <csignal>
#include <mutex>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/svc_common.h>
#include <libHX/string.h>
#include <gromox/double_list.hpp>
#include <gromox/config_file.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <unistd.h>
#include <csignal>
#include <pthread.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <poll.h>


#define SOCKET_TIMEOUT          60

#define MAX_CMD_LENGTH			64*1024

namespace {

struct BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
};

}

static std::atomic<bool> g_notify_stop{false};
static char g_timer_ip[40];
static int g_timer_port;
static pthread_t g_scan_id;
static std::mutex g_back_lock;
static DOUBLE_LIST g_back_list;
static DOUBLE_LIST g_lost_list;

static void *tmrag_scanwork(void *);

static int read_line(int sockd, char *buff, int length);
static int connect_timer();
static int add_timer(const char *command, int interval);

static BOOL cancel_timer(int timer_id);

static BOOL svc_timer_agent(int reason, void **ppdata)
{
	int i, conn_num;
    BACK_CONN *pback;
    DOUBLE_LIST_NODE *pnode;
	char file_name[256];
	char config_path[256], *psearch;
	
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		g_notify_stop = true;
		double_list_init(&g_back_list);
		double_list_init(&g_lost_list);
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		snprintf(config_path, GX_ARRAY_SIZE(config_path), "%s.cfg", file_name);
		auto pfile = config_file_initd(config_path, get_config_path());
		if (NULL == pfile) {
			printf("[timer_agent]: config_file_initd %s: %s\n",
			       config_path, strerror(errno));
			return FALSE;
		}

		auto str_value = config_file_get_value(pfile, "CONNECTION_NUM");
		if (NULL == str_value) {
			conn_num = 8;
			config_file_set_value(pfile, "CONNECTION_NUM", "8");
		} else {
			conn_num = atoi(str_value);
			if (conn_num < 0) {
				conn_num = 8;
				config_file_set_value(pfile, "CONNECTION_NUM", "8");
			}
		}
		printf("[timer_agent]: timer connection number is %d\n", conn_num);

		str_value = config_file_get_value(pfile, "TIMER_HOST");
		HX_strlcpy(g_timer_ip, str_value != nullptr ? str_value : "::1",
		           GX_ARRAY_SIZE(g_timer_ip));
		str_value = config_file_get_value(pfile, "TIMER_PORT");
		if (NULL == str_value) {
			g_timer_port = 6666;
			config_file_set_value(pfile, "TIMER_PORT", "6666");
		} else {
			g_timer_port = atoi(str_value);
			if (g_timer_port <= 0) {
				g_timer_port = 6666;
				config_file_set_value(pfile, "TIMER_PORT", "6666");
			}
		}
		printf("[timer_agent]: timer address is [%s]:%d\n",
		       *g_timer_ip == '\0' ? "*" : g_timer_ip, g_timer_port);

		for (i=0; i<conn_num; i++) {
			pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
			if (NULL != pback) {
		        pback->node.pdata = pback;
				pback->sockd = -1;
				double_list_append_as_tail(&g_lost_list, &pback->node);
			}
		}

		g_notify_stop = false;
		auto ret = pthread_create(&g_scan_id, nullptr, tmrag_scanwork, nullptr);
		if (ret != 0) {
			g_notify_stop = true;
			while ((pnode = double_list_pop_front(&g_back_list)) != nullptr)
				free(pnode->pdata);
			printf("[timer_agent]: failed to create scan thread: %s\n", strerror(ret));
			return FALSE;
		}
		pthread_setname_np(g_scan_id, "timer_agent");
		if (!register_service("add_timer", add_timer))
			printf("[timer_agent]: failed to register add_timer\n");
		if (!register_service("cancel_timer", cancel_timer))
			printf("[timer_agent]: failed to register cancel_timer\n");
		return TRUE;
	}
	case PLUGIN_FREE:
		if (!g_notify_stop) {
			g_notify_stop = true;
			pthread_kill(g_scan_id, SIGALRM);
			pthread_join(g_scan_id, NULL);

			while ((pnode = double_list_pop_front(&g_lost_list)) != nullptr)
				free(pnode->pdata);

			while ((pnode = double_list_pop_front(&g_back_list)) != nullptr) {
				pback = (BACK_CONN*)pnode->pdata;
				write(pback->sockd, "QUIT\r\n", 6);
				close(pback->sockd);
				free(pback);
			}
		}
		double_list_free(&g_lost_list);
		double_list_free(&g_back_list);

		return TRUE;
	}
	return TRUE;
}
SVC_ENTRY(svc_timer_agent);

static void *tmrag_scanwork(void *param)
{
	int tv_msec;
	BACK_CONN *pback;
	time_t now_time;
	char temp_buff[1024];
	struct pollfd pfd_read;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;


	double_list_init(&temp_list);
	while (!g_notify_stop) {
		std::unique_lock bk_hold(g_back_lock);
		time(&now_time);
		ptail = double_list_get_tail(&g_back_list);
		while ((pnode = double_list_pop_front(&g_back_list)) != nullptr) {
			pback = (BACK_CONN*)pnode->pdata;
			if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
				double_list_append_as_tail(&temp_list, &pback->node);
			} else {
				double_list_append_as_tail(&g_back_list, &pback->node);
			}

			if (pnode == ptail) {
				break;
			}
		}
		bk_hold.unlock();

		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "PING\r\n", 6);
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				bk_hold.lock();
				double_list_append_as_tail(&g_lost_list, &pback->node);
				bk_hold.unlock();
			} else {
				time(&pback->last_time);
				bk_hold.lock();
				double_list_append_as_tail(&g_back_list, &pback->node);
				bk_hold.unlock();
			}
		}

		bk_hold.lock();
		while ((pnode = double_list_pop_front(&g_lost_list)) != nullptr)
			double_list_append_as_tail(&temp_list, pnode);
		bk_hold.unlock();

		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_timer();
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				bk_hold.lock();
				double_list_append_as_tail(&g_back_list, &pback->node);
				bk_hold.unlock();
			} else {
				bk_hold.lock();
				double_list_append_as_tail(&g_lost_list, &pback->node);
				bk_hold.unlock();
			}
		}
		sleep(1);
	}
	return NULL;
}

static int add_timer(const char *command, int interval)
{
	int len;
	BACK_CONN *pback;
	DOUBLE_LIST_NODE *pnode;
	char temp_buff[MAX_CMD_LENGTH];

	std::unique_lock bk_hold(g_back_lock);
	pnode = double_list_pop_front(&g_back_list);
	if (NULL == pnode) {
		return 0;
	}
	bk_hold.unlock();
	pback = (BACK_CONN*)pnode->pdata;
	len = gx_snprintf(temp_buff, GX_ARRAY_SIZE(temp_buff), "ADD %d %s\r\n",
			interval, command);
	if (len != write(pback->sockd, temp_buff, len)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		double_list_append_as_tail(&g_lost_list, &pback->node);
		return 0;
	}
	if (0 != read_line(pback->sockd, temp_buff, 1024)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		double_list_append_as_tail(&g_lost_list, &pback->node);
		return 0;
	}
	time(&pback->last_time);
	bk_hold.lock();
	double_list_append_as_tail(&g_back_list, &pback->node);
	bk_hold.unlock();
	if (0 == strncasecmp(temp_buff, "TRUE ", 5)) {
		return atoi(temp_buff + 5);
	}
	return 0;
}

static BOOL cancel_timer(int timer_id)
{
	int len;
	BACK_CONN *pback;
	DOUBLE_LIST_NODE *pnode;
	char temp_buff[MAX_CMD_LENGTH];

	std::unique_lock bk_hold(g_back_lock);
	pnode = double_list_pop_front(&g_back_list);
	if (NULL == pnode) {
		return FALSE;
	}
	bk_hold.unlock();
	pback = (BACK_CONN*)pnode->pdata;
	len = gx_snprintf(temp_buff, GX_ARRAY_SIZE(temp_buff), "CANCEL %d\r\n", timer_id);
	if (len != write(pback->sockd, temp_buff, len)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		double_list_append_as_tail(&g_lost_list, &pback->node);
		return FALSE;
	}
	if (0 != read_line(pback->sockd, temp_buff, 1024)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		double_list_append_as_tail(&g_lost_list, &pback->node);
		return FALSE;
	}
	time(&pback->last_time);
	bk_hold.lock();
	double_list_append_as_tail(&g_back_list, &pback->node);
	bk_hold.unlock();
	if (0 == strcasecmp(temp_buff, "TRUE")) {
		return TRUE;
	}
	return FALSE;
}

static int read_line(int sockd, char *buff, int length)
{
	int offset;
	int tv_msec;
	int read_len;
	struct pollfd pfd_read;
	
	offset = 0;
	while (1) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return -1;
		}
		read_len = read(sockd, buff + offset, length - offset);
		if (read_len <= 0) {
			return -1;
		}
		offset += read_len;
		if (offset >= 2 &&
			'\r' == buff[offset - 2] && '\n' == buff[offset - 1]) {
			buff[offset - 2] = '\0';
			return 0;
		}
		if (length == offset) {
			return -1;
		}
	}
}


static int connect_timer()
{
    char temp_buff[1024];
	int sockd = gx_inet_connect(g_timer_ip, g_timer_port, 0);
	if (sockd < 0)
	        return -1;
	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "OK")) {
		close(sockd);
		return -1;
	}

	return sockd;
}
