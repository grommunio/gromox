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
#include <utility>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/svc_common.h>
#define MAX_CMD_LENGTH			64*1024

using namespace gromox;

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

static void *tmrag_scanwork(void *);

static int read_line(int sockd, char *buff, int length);
static int connect_timer();
static int add_timer(const char *command, int interval);

static BOOL cancel_timer(int timer_id);

static BOOL svc_timer_agent(int reason, void **ppdata) try
{
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		g_notify_stop = true;
		std::string plugname = get_plugin_name();
		auto pos = plugname.find('.');
		if (pos != plugname.npos)
			plugname.erase(pos);
		auto cfg_path = plugname + ".cfg";
		auto pfile = config_file_initd(cfg_path.c_str(), get_config_path());
		if (NULL == pfile) {
			printf("[timer_agent]: config_file_initd %s: %s\n",
			       cfg_path.c_str(), strerror(errno));
			return FALSE;
		}

		static constexpr cfg_directive timer_agent_cfg_defaults[] = {
			{"connection_num", "8", CFG_SIZE, "1"},
			{"timer_host", "::1"},
			{"timer_port", "6666"},
			CFG_TABLE_END,
		};
		config_file_apply(*pfile, timer_agent_cfg_defaults);

		size_t conn_num = pfile->get_ll("connection_num");
		printf("[timer_agent]: timer connection number is %zu\n", conn_num);

		gx_strlcpy(g_timer_ip, pfile->get_value("timer_host"), arsizeof(g_timer_ip));
		g_timer_port = pfile->get_ll("timer_port");
		printf("[timer_agent]: timer address is [%s]:%hu\n",
		       *g_timer_ip == '\0' ? "*" : g_timer_ip, g_timer_port);

		for (size_t i = 0; i < conn_num; ++i) try {
			g_lost_list.emplace_back();
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1655: ENOMEM\n");
		}

		g_notify_stop = false;
		auto ret = pthread_create(&g_scan_id, nullptr, tmrag_scanwork, nullptr);
		if (ret != 0) {
			g_notify_stop = true;
			g_back_list.clear();
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
			if (!pthread_equal(g_scan_id, {})) {
				pthread_kill(g_scan_id, SIGALRM);
				pthread_join(g_scan_id, NULL);
			}
			g_lost_list.clear();
			while (g_back_list.size() > 0) {
				auto pback = &g_back_list.front();
				write(pback->sockd, "QUIT\r\n", 6);
				close(pback->sockd);
				g_back_list.pop_front();
			}
		}
		g_back_list.clear();
		return TRUE;
	}
	return TRUE;
} catch (const cfg_error &) {
	return false;
}
SVC_ENTRY(svc_timer_agent);

static void *tmrag_scanwork(void *param)
{
	int tv_msec;
	time_t now_time;
	char temp_buff[1024];
	struct pollfd pfd_read;
	std::list<BACK_CONN> temp_list;

	while (!g_notify_stop) {
		std::unique_lock bk_hold(g_back_lock);
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
		bk_hold.unlock();

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
				bk_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				bk_hold.unlock();
			} else {
				time(&pback->last_time);
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
				time(&pback->last_time);
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
	len = gx_snprintf(temp_buff, GX_ARRAY_SIZE(temp_buff), "ADD %d %s\r\n",
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
	time(&pback->last_time);
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
	len = gx_snprintf(temp_buff, GX_ARRAY_SIZE(temp_buff), "CANCEL %d\r\n", timer_id);
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
	time(&pback->last_time);
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
	if (sockd < 0) {
		static std::atomic<time_t> g_lastwarn_time;
		auto prev = g_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
			fprintf(stderr, "gx_inet_connect timer_agent@[%s]:%hu: %s\n",
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
