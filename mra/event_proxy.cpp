// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#define DECLARE_SVC_API_STATIC
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#define MAX_CMD_LENGTH			64*1024

using namespace gromox;

namespace {

struct BACK_CONN {
	int sockd = -1;
	time_t last_time = 0;
};

}

static gromox::atomic_bool g_notify_stop;
static char g_event_ip[40];
static uint16_t g_event_port;
static pthread_t g_scan_id;
static std::mutex g_back_lock;
static std::list<BACK_CONN> g_back_list, g_lost_list;

static void *evpx_scanwork(void *);
static int read_line(int sockd, char *buff, int length);
static int connect_event();
static void broadcast_event(const char *event);

static void broadcast_select(const char *username, const char *folder);

static void broadcast_unselect(const char *username, const char *folder);

static BOOL svc_event_proxy(int reason, void **ppdata)
{
	int i, conn_num;
	
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		g_notify_stop = true;
		auto pfile = config_file_initd("event_proxy.cfg",
		             get_config_path(), nullptr);
		if (NULL == pfile) {
			mlog(LV_ERR, "event_proxy: config_file_initd event_proxy.cfg: %s\n",
				strerror(errno));
			return FALSE;
		}

		auto str_value = pfile->get_value("CONNECTION_NUM");
		if (NULL == str_value) {
			conn_num = 8;
		} else {
			conn_num = strtol(str_value, nullptr, 0);
			if (conn_num < 0)
				conn_num = 8;
		}
		printf("[event_proxy]: event connection number is %d\n", conn_num);

		str_value = pfile->get_value("EVENT_HOST");
		gx_strlcpy(g_event_ip, str_value != nullptr ? str_value : "::1",
		           arsizeof(g_event_ip));
		str_value = pfile->get_value("EVENT_PORT");
		if (NULL == str_value) {
			g_event_port = 33333;
		} else {
			g_event_port = strtoul(str_value, nullptr, 0);
			if (g_event_port == 0)
				g_event_port = 33333;
		}
		printf("[event_proxy]: event address is [%s]:%hu\n",
		       *g_event_ip == '\0' ? "*" : g_event_ip, g_event_port);

		for (i = 0; i < conn_num; ++i) try {
			g_lost_list.emplace_back();
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1657: ENOMEM");
		}

		g_notify_stop = false;
		auto ret = pthread_create4(&g_scan_id, nullptr, evpx_scanwork, nullptr);
		if (ret != 0) {
			g_notify_stop = true;
			g_back_list.clear();
			printf("[event_proxy]: failed to create scan thread: %s\n", strerror(ret));
			return FALSE;
		}
		pthread_setname_np(g_scan_id, "event_proxy");
		if (!register_service("broadcast_event", broadcast_event))
			printf("[event_proxy]: failed to register broadcast_event\n");
		if (!register_service("broadcast_select", broadcast_select))
			printf("[event_proxy]: failed to register broadcast_select\n");
		if (!register_service("broadcast_unselect", broadcast_unselect))
			printf("[event_proxy]: failed to register broadcast_unselect\n");
		return TRUE;
	}
	case PLUGIN_FREE:
		if (!g_notify_stop) {
			g_notify_stop = true;
			if (!pthread_equal(g_scan_id, {})) {
				pthread_kill(g_scan_id, SIGALRM);
				pthread_join(g_scan_id, NULL);
			}
			for (auto &c : g_back_list) {
				write(c.sockd, "QUIT\r\n", 6);
				close(c.sockd);
			}
		}
		g_lost_list.clear();
		g_back_list.clear();
		return TRUE;
	}
	return TRUE;
}
SVC_ENTRY(svc_event_proxy);

static void *evpx_scanwork(void *param)
{
	int tv_msec;
	time_t now_time;
	char temp_buff[1024];
	struct pollfd pfd_read;
	std::list<BACK_CONN> temp_list;
	
	while (!g_notify_stop) {
		std::unique_lock bl_hold(g_back_lock);
		time(&now_time);
		auto tail = g_back_list.size() > 0 ? &g_back_list.back() : nullptr;
		while (g_back_list.size() > 0) {
			auto pback = &g_back_list.front();
			if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
				temp_list.splice(temp_list.end(), g_back_list, g_back_list.begin());
			} else {
				g_back_list.splice(g_back_list.end(), g_back_list, g_back_list.begin());
			}
			if (pback == tail)
				break;
		}
		bl_hold.unlock();

		while (temp_list.size() > 0) {
			auto pback = &temp_list.front();
			write(pback->sockd, "PING\r\n", 6);
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				bl_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				bl_hold.unlock();
			} else {
				time(&pback->last_time);
				bl_hold.lock();
				g_back_list.splice(g_back_list.end(), temp_list, temp_list.begin());
				bl_hold.unlock();
			}
		}

		bl_hold.lock();
		temp_list = std::move(g_lost_list);
		g_lost_list.clear();
		bl_hold.unlock();

		while (temp_list.size() > 0) {
			auto pback = &temp_list.front();
			pback->sockd = connect_event();
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				bl_hold.lock();
				g_back_list.splice(g_back_list.end(), temp_list, temp_list.begin());
				bl_hold.unlock();
			} else {
				bl_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				bl_hold.unlock();
			}
		}
		sleep(1);
	}
	return NULL;
}

static void broadcast_select(const char *username, const char *folder)
{
	char buff[512];
	
	snprintf(buff, 512, "SELECT %s %s", username, folder);
	broadcast_event(buff);
}

static void broadcast_unselect(const char *username, const char *folder)
{
	char buff[512];
	
	snprintf(buff, 512, "UNSELECT %s %s", username, folder);
	broadcast_event(buff);
}

static void broadcast_event(const char *event)
{
	char temp_buff[MAX_CMD_LENGTH];
	std::list<BACK_CONN> hold;

	std::unique_lock bl_hold(g_back_lock);
	if (g_back_list.size() == 0)
		return;
	hold.splice(hold.end(), g_back_list, g_back_list.begin());
	bl_hold.unlock();
	auto pback = &hold.front();
	auto len = gx_snprintf(temp_buff, arsizeof(temp_buff), "%s\r\n", event);
	write(pback->sockd, temp_buff, len);
	if (0 != read_line(pback->sockd, temp_buff, 1024)) {
		close(pback->sockd);
		pback->sockd = -1;
		bl_hold.lock();
		g_lost_list.splice(g_lost_list.end(), std::move(hold));
		return;
	}
	time(&pback->last_time);
	bl_hold.lock();
	g_back_list.splice(g_back_list.end(), std::move(hold));
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


static int connect_event()
{
    char temp_buff[1024];
	int sockd = gx_inet_connect(g_event_ip, g_event_port, 0);
	if (sockd < 0) {
		static std::atomic<time_t> g_lastwarn_time;
		auto prev = g_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
			fprintf(stderr, "gx_inet_connect event_proxy@[%s]:%hu: %s\n",
			        g_event_ip, g_event_port, strerror(-sockd));
		return -1;
	}
	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "OK")) {
		close(sockd);
		return -1;
	}
	auto temp_len = gx_snprintf(temp_buff, arsizeof(temp_buff), "ID %s:%d\r\n",
				get_host_ID(), getpid());
	if (temp_len != write(sockd, temp_buff, temp_len)) {
		close(sockd);
		return -1;
	}

	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "TRUE")) {
		close(sockd);
		return -1;
	}

	return sockd;
}
