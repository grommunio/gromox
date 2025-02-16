// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
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
#include <fmt/core.h>
#include <libHX/io.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/process.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#define MAX_CMD_LENGTH			64*1024

using namespace gromox;
DECLARE_SVC_API(,);

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
static void broadcast_select(const char *username, const std::string &folder);
static void broadcast_unselect(const char *username, const std::string &folder);

BOOL SVC_event_proxy(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	int i, conn_num;
	
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		g_notify_stop = true;
		auto pfile = config_file_initd("event_proxy.cfg",
		             get_config_path(), nullptr);
		if (NULL == pfile) {
			mlog(LV_ERR, "event_proxy: config_file_initd event_proxy.cfg: %s",
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

		str_value = pfile->get_value("EVENT_HOST");
		gx_strlcpy(g_event_ip, str_value != nullptr ? str_value : "::1",
		           std::size(g_event_ip));
		str_value = pfile->get_value("EVENT_PORT");
		if (NULL == str_value) {
			g_event_port = 33333;
		} else {
			g_event_port = strtoul(str_value, nullptr, 0);
			if (g_event_port == 0)
				g_event_port = 33333;
		}
		mlog(LV_INFO, "event_proxy: sending events to nexus at [%s]:%hu, with up to %d connections",
		       *g_event_ip == '\0' ? "*" : g_event_ip, g_event_port,
		       conn_num);

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
				if (HXio_fullwrite(c.sockd, "QUIT\r\n", 6) < 0)
					/* ignore */;
				close(c.sockd);
			}
		}
		g_lost_list.clear();
		g_back_list.clear();
		return TRUE;
	default:
		return TRUE;
	}
}

static void *evpx_scanwork(void *param)
{
	int tv_msec;
	char temp_buff[1024];
	struct pollfd pfd_read;
	std::list<BACK_CONN> temp_list;
	
	while (!g_notify_stop) {
		std::unique_lock bl_hold(g_back_lock);
		auto now_time = time(nullptr);
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
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (HXio_fullwrite(pback->sockd, "PING\r\n", 6) != 6 ||
			    poll(&pfd_read, 1, tv_msec) != 1 ||
			    read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				bl_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				bl_hold.unlock();
			} else {
				pback->last_time = time(nullptr);
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
				pback->last_time = time(nullptr);
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

static void broadcast_select(const char *username, const std::string &folder) try
{
	broadcast_event(fmt::format("SELECT {} {}", username, folder).c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2415: ENOMEM");
}

static void broadcast_unselect(const char *username, const std::string &folder) try
{
	broadcast_event(fmt::format("UNSELECT {} {} ", username, folder).c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2416: ENOMEM");
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
	auto len = gx_snprintf(temp_buff, std::size(temp_buff), "%s\r\n", event);
	if (HXio_fullwrite(pback->sockd, temp_buff, len) != len ||
	    read_line(pback->sockd, temp_buff, 1024) != 0) {
		close(pback->sockd);
		pback->sockd = -1;
		bl_hold.lock();
		g_lost_list.splice(g_lost_list.end(), std::move(hold));
		return;
	}
	pback->last_time = time(nullptr);
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
	int sockd = HX_inet_connect(g_event_ip, g_event_port, 0);
	if (sockd < 0) {
		static std::atomic<time_t> g_lastwarn_time;
		auto prev = g_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
			fprintf(stderr, "HX_inet_connect event_proxy@[%s]:%hu: %s\n",
			        g_event_ip, g_event_port, strerror(-sockd));
		return -1;
	}
	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "OK")) {
		close(sockd);
		return -1;
	}
	auto temp_len = gx_snprintf(temp_buff, std::size(temp_buff), "ID %s:%d\r\n",
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
