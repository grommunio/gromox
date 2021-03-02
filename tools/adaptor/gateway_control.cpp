// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/gateway_control.h>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include <gromox/list_file.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

struct CONSOLE_PORT {
	char smtp_ip[40];
	int smtp_port;
	char delivery_ip[40];
	int delivery_port;
};

static char g_list_path[256];
static std::vector<CONSOLE_PORT> g_console_list;

static BOOL gateway_control_send(const char *ip, int port, const char *command);

void gateway_control_init(const char *path)
{
	if (NULL != path) {
		HX_strlcpy(g_list_path, path, GX_ARRAY_SIZE(g_list_path));
	} else {
		g_list_path[0] = '\0';
	}
}

int gateway_control_run()
{
	auto plist_file = list_file_initd(g_list_path, "/", /* CONSOLE_PORT */ "%s:40%d%s:40%d");
	if (NULL == plist_file) {
		printf("[gateway_control]: Failed to read console list from %s: %s\n",
			g_list_path, strerror(errno));
		return -1;
	}
	
	auto pitem = static_cast<const CONSOLE_PORT *>(plist_file->get_list());
	auto list_len = plist_file->get_size();
	for (decltype(list_len) i = 0; i < list_len; ++i) {
		try {
			g_console_list.push_back(pitem[i]);
		} catch (const std::bad_alloc &) {
		}
	}
	return 0;
}

void gateway_control_notify(const char *command, int control_mask)
{
	for (const auto &c : g_console_list) {
		if (NOTIFY_SMTP&control_mask) {
			gateway_control_send(c.smtp_ip, c.smtp_port, command);
		}
		if (NOTIFY_DELIVERY&control_mask) {
			gateway_control_send(c.delivery_ip, c.delivery_port, command);
		}
	}
}

static BOOL gateway_control_send(const char *ip, int port, const char *command)
{
	int cmd_len, read_len, offset;
	char temp_buff[1024];
	int sockd = gx_inet_connect(ip, port, 0);
	if (sockd < 0)
		return FALSE;
	offset = 0;
	memset(temp_buff, 0, 1024);
	/* read welcome information */
	do {
		read_len = read(sockd, temp_buff + offset, 1024 - offset);
		if (-1 == read_len || 0 == read_len) {
			close(sockd);
			return FALSE;
		}
		offset += read_len;
		if (NULL != search_string(temp_buff, "console> ", offset)) {
			break;
		}
	} while (offset < 1024);
	if (offset >= 1024) {
		close(sockd);
		return FALSE;
	}

	/* send command */
	cmd_len = sprintf(temp_buff, "%s\r\n", command);
	write(sockd, temp_buff, cmd_len);
	if (read(sockd, temp_buff, 1024))
		/* cov-ignore */;
	write(sockd, "quit\r\n", 6);
	close(sockd);
	return TRUE;
}

