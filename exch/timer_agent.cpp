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
#include <utility>
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
static char g_timer_ip[40];
static uint16_t g_timer_port;
static pthread_t g_scan_id;
static std::mutex g_back_lock;
static std::list<BACK_CONN> g_back_list, g_lost_list;

static constexpr cfg_directive timer_agent_cfg_defaults[] = {
	{"connection_num", "8", CFG_SIZE, "1"},
	{"timer_host", "::1"},
	{"timer_port", "6666"},
	CFG_TABLE_END,
};

static void *tmrag_scanwork(void *);

static int read_line(int sockd, char *buff, int length);
static int connect_timer();
static int add_timer(const char *command, int interval);

static BOOL cancel_timer(int timer_id);

BOOL SVC_timer_agent(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		g_notify_stop = true;
		auto pfile = config_file_initd("timer_agent.cfg",
		             get_config_path(), timer_agent_cfg_defaults);
		if (NULL == pfile) {
			mlog(LV_ERR, "timer_agent: config_file_initd timer_agent.cfg: %s",
				strerror(errno));
			return FALSE;
		}

		size_t conn_num = pfile->get_ll("connection_num");
		mlog(LV_INFO, "timer_agent: timer connection number is %zu", conn_num);

		gx_strlcpy(g_timer_ip, pfile->get_value("timer_host"), std::size(g_timer_ip));
		g_timer_port = pfile->get_ll("timer_port");
		mlog(LV_INFO, "timer_agent: timer address is [%s]:%hu",
		       *g_timer_ip == '\0' ? "*" : g_timer_ip, g_timer_port);

		std::unique_lock bk_hold(g_back_lock);
		for (size_t i = 0; i < conn_num; ++i) try {
			g_lost_list.emplace_back();
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1655: ENOMEM");
		}
		bk_hold.unlock();
		g_notify_stop = false;
		auto ret = pthread_create4(&g_scan_id, nullptr, tmrag_scanwork, nullptr);
		if (ret != 0) {
			g_notify_stop = true;
			g_back_list.clear();
			mlog(LV_ERR, "timer_agent: failed to create scan thread: %s",
				 strerror(ret));
			return FALSE;
		}
		pthread_setname_np(g_scan_id, "timer_agent");
		if (!register_service("add_timer", add_timer)) {
			mlog(LV_ERR, "timer_agent: failed to register add_timer");
			return false;
		}
		if (!register_service("cancel_timer", cancel_timer)) {
			mlog(LV_ERR, "timer_agent: failed to register cancel_timer");
			return false;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
	{
		std::unique_lock bk_hold(g_back_lock, std::defer_lock);
		if (!g_notify_stop) {
			g_notify_stop = true;
			if (!pthread_equal(g_scan_id, {})) {
				pthread_kill(g_scan_id, SIGALRM);
				pthread_join(g_scan_id, NULL);
			}
			bk_hold.lock();
			g_lost_list.clear();
			while (g_back_list.size() > 0) {
				auto pback = &g_back_list.front();
				if (HXio_fullwrite(pback->sockd, "QUIT\r\n", 6) != 6)
					/* ignore */;
				close(pback->sockd);
				g_back_list.pop_front();
			}
			bk_hold.unlock();
		}
		bk_hold.lock();
		g_back_list.clear();
		return TRUE;
	}
	default:
		return TRUE;
	}
}

static void *tmrag_scanwork(void *param)
{
	char temp_buff[1024];
	struct pollfd pfd_read;
	std::list<BACK_CONN> temp_list;

	while (!g_notify_stop) {
		std::unique_lock bk_hold(g_back_lock);
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
		bk_hold.unlock();

		while (temp_list.size() > 0) {
			auto pback = &temp_list.front();
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (HXio_fullwrite(pback->sockd, "PING\r\n", 6) != 6 ||
					poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1 ||
					read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				bk_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				bk_hold.unlock();
			} else {
				pback->last_time = time(nullptr);
				bk_hold.lock();
				g_back_list.splice(g_back_list.end(), temp_list, temp_list.begin());
				bk_hold.unlock();
			}
		}
		
		bk_hold.lock();
		temp_list = std::move(g_lost_list);
		g_lost_list.clear();
		bk_hold.unlock();
		
		while (temp_list.size() > 0) {
			auto pback = &temp_list.front();
			pback->sockd = connect_timer();
			if (-1 != pback->sockd) {
				pback->last_time = time(nullptr);
				bk_hold.lock();
				g_back_list.splice(g_back_list.end(), temp_list, temp_list.begin());
				bk_hold.unlock();
			} else {
				bk_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
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
	char temp_buff[MAX_CMD_LENGTH];
	std::list<BACK_CONN> hold;

	std::unique_lock bk_hold(g_back_lock);
	if (g_back_list.size() == 0)
		return 0;
	hold.splice(hold.end(), g_back_list, g_back_list.begin());
	bk_hold.unlock();
	auto pback = &hold.front();
	len = gx_snprintf(temp_buff, std::size(temp_buff), "ADD %d %s\r\n",
					  interval, command);
	if (len != write(pback->sockd, temp_buff, len)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		g_lost_list.splice(g_lost_list.end(), std::move(hold));
		return 0;
	}
	if (0 != read_line(pback->sockd, temp_buff, 1024)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		g_lost_list.splice(g_lost_list.end(), std::move(hold));
		return 0;
	}
	pback->last_time = time(nullptr);
	bk_hold.lock();
	g_back_list.splice(g_back_list.end(), std::move(hold));
	bk_hold.unlock();
	if (0 == strncasecmp(temp_buff, "TRUE ", 5)) {
		return strtol(temp_buff + 5, nullptr, 0);
	}
	return 0;
}

static BOOL cancel_timer(int timer_id)
{
	int len;
	char temp_buff[MAX_CMD_LENGTH];
	std::list<BACK_CONN> hold;
	
	std::unique_lock bk_hold(g_back_lock);
	if (g_back_list.size() == 0)
		return FALSE;
	hold.splice(hold.end(), g_back_list, g_back_list.begin());
	bk_hold.unlock();
	auto pback = &hold.front();
	len = gx_snprintf(temp_buff, std::size(temp_buff), "CANCEL %d\r\n", timer_id);
	if (len != write(pback->sockd, temp_buff, len)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		g_lost_list.splice(g_lost_list.end(), std::move(hold));
		return FALSE;
	}
	if (0 != read_line(pback->sockd, temp_buff, 1024)) {
		close(pback->sockd);
		pback->sockd = -1;
		bk_hold.lock();
		g_lost_list.splice(g_lost_list.end(), std::move(hold));
		return FALSE;
	}
	pback->last_time = time(nullptr);
	bk_hold.lock();
	g_back_list.splice(g_back_list.end(), std::move(hold));
	bk_hold.unlock();
	if (0 == strcasecmp(temp_buff, "TRUE")) {
		return TRUE;
	}
	return FALSE;
}

static int read_line(int sockd, char *buff, int length)
{
	int offset;
	int read_len;
	struct pollfd pfd_read;
	
	offset = 0;
	while (1) {
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
			return -1;
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
	int sockd = HX_inet_connect(g_timer_ip, g_timer_port, 0);
	if (sockd < 0) {
		static std::atomic<time_t> g_lastwarn_time;
		auto prev = g_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
			mlog(LV_ERR, "HX_inet_connect timer_agent@[%s]:%hu: %s",
				 g_timer_ip, g_timer_port, strerror(-sockd));
		return -1;
	}
	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "OK")) {
		close(sockd);
		return -1;
	}

	return sockd;
}
