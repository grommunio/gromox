// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2025 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <vector>
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
	BACK_CONN(unsigned int);
	NOMOVE(BACK_CONN); /* thread will have a pointer to BACK_CONN */
	~BACK_CONN();

	pthread_t thr_id{};
	int sockd = -1;
};

}

using EVENT_STUB_FUNC = void (*)(char *);

static gromox::atomic_bool g_eventstub_stop;
static char g_event_ip[40];
static uint16_t g_event_port;
static std::list<BACK_CONN> g_back_list;
static EVENT_STUB_FUNC g_event_stub_func;

static void *evst_thrwork(void *);
static int read_line(int sockd, char *buff, int length);
static int connect_event();
static void install_event_stub(EVENT_STUB_FUNC event_stub_func);

BACK_CONN::BACK_CONN(unsigned int i)
{
	auto ret = pthread_create4(&thr_id, nullptr, evst_thrwork, this);
	if (ret != 0)
		throw ret;
	char buf[32];
	snprintf(buf, std::size(buf), "evstub/%u", i);
	pthread_setname_np(thr_id, buf);
}

BACK_CONN::~BACK_CONN()
{
	if (sockd >= 0)
		close(sockd);
	if (!pthread_equal(thr_id, {})) {
		pthread_kill(thr_id, SIGALRM);
		pthread_join(thr_id, nullptr);
	}
}

BOOL SVC_event_stub(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	int i, conn_num;
	
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		g_eventstub_stop = true;
		g_event_stub_func = NULL;
		auto pfile = config_file_initd("event_stub.cfg",
		             get_config_path(), nullptr);
		if (NULL == pfile) {
			mlog(LV_ERR, "event_stub: config_file_initd event_stub.cfg: %s",
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
		mlog(LV_INFO, "event_stub: receiving events from nexus at [%s]:%hu, with up to %d connections",
		       *g_event_ip == '\0' ? "*" : g_event_ip, g_event_port,
		       conn_num);

		g_eventstub_stop = false;
		int ret = 0;
		for (i = 0; i < conn_num; ++i) try {
			g_back_list.emplace_back(i);
		} catch (int x) {
			ret = x;
			break;
		}

		if (i < conn_num) {
			g_eventstub_stop = true;
			g_back_list.clear();
			printf("[event_stub]: failed to create stub thread: %s\n", strerror(ret));
			return FALSE;
		}

		if (!register_service("install_event_stub", install_event_stub))
			printf("[event_stub]: failed to register install_event_stub\n");
		return TRUE;
	}
	case PLUGIN_FREE:
		g_eventstub_stop = true;
		g_back_list.clear();
		g_event_stub_func = NULL;
		return TRUE;
	default:
		return TRUE;
	}
}

static int read_line(int sockd, char *buff, int length)
{
	int offset;
	int tv_usec;
	int read_len;
	struct pollfd pfd_read;

	offset = 0;
	while (1) {
		tv_usec = SOCKET_TIMEOUT * 1000000;
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_usec)) {
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
		fprintf(stderr, "HX_inet_connect event_stub@[%s]:%hu: %s\n",
		        g_event_ip, g_event_port, strerror(-sockd));
		return -1;
	}
	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "OK")) {
        close(sockd);
        return -1;
	}
	
	auto temp_len = gx_snprintf(temp_buff, std::size(temp_buff), "LISTEN %s:%d\r\n",
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

static void *evst_thrwork(void *param)
{
	char buff[MAX_CMD_LENGTH];	
	auto pback = static_cast<BACK_CONN *>(param);

	while (!g_eventstub_stop) {
		pback->sockd = connect_event();
		if (pback->sockd < 0) {
			sleep(3);
			continue;
		}

		while (!g_eventstub_stop) {
			if (-1 == read_line(pback->sockd, buff, MAX_CMD_LENGTH)) {
				close(pback->sockd);
				pback->sockd = -1;
				break;
			}
		
			if (0 == strcasecmp(buff, "PING")) {
				if (HXio_fullwrite(pback->sockd, "TRUE\r\n", 6) != 6)
					goto out;
				continue;
			}

			if (NULL != g_event_stub_func) {
				g_event_stub_func(buff);
			}
			if (HXio_fullwrite(pback->sockd, "TRUE\r\n", 6) != 6)
				goto out;
		}
	}

 out:
	if (-1 != pback->sockd) {
		close(pback->sockd);
		pback->sockd = -1;
	}
	return nullptr;
}


static void install_event_stub(EVENT_STUB_FUNC event_stub_func)
{
	if (NULL == g_event_stub_func) {
		g_event_stub_func = event_stub_func;
	}
}

