// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <errno.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/gateway_control.h>
#include <gromox/socket.h>
#include "util.h"
#include "single_list.h"
#include "list_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef struct CONSOLE_PORT {
	char smtp_ip[32];
	int smtp_port;
	char delivery_ip[32];
	int delivery_port;
} CONSOLE_PORT;

typedef struct CONSOLE_PNODE {
	SINGLE_LIST_NODE node;
	CONSOLE_PORT u;
} CONSOLE_PNODE;

static char g_list_path[256];
static SINGLE_LIST g_console_list;

static BOOL gateway_control_send(const char *ip, int port, const char *command);

void gateway_control_init(const char *path)
{
	if (NULL != path) {
		strcpy(g_list_path, path);
	} else {
		g_list_path[0] = '\0';
	}
	single_list_init(&g_console_list);
}

int gateway_control_run()
{
	int i, list_len;
	LIST_FILE *plist_file = list_file_init3(g_list_path, /* CONSOLE_PORT */ "%s:32%d%s:32%d", false);
	if (NULL == plist_file) {
		printf("[gateway_control]: Failed to read console list from %s: %s\n",
			g_list_path, strerror(errno));
		return -1;
	}
	
	auto pitem = reinterpret_cast<const CONSOLE_PORT *>(list_file_get_list(plist_file));
	list_len = list_file_get_item_num(plist_file);
	for (i=0; i<list_len; i++) {
		auto pport = static_cast<CONSOLE_PNODE *>(malloc(sizeof(CONSOLE_PNODE)));
		if (NULL== pport) {
			continue;
		}
		pport->node.pdata = pport;
		memcpy(&pport->u, &pitem[i], sizeof(*pitem));
		single_list_append_as_tail(&g_console_list, &pport->node);
	}
	list_file_free(plist_file);
	return 0;
}

void gateway_control_notify(const char *command, int control_mask)
{
	SINGLE_LIST_NODE *pnode;
	
	for (pnode=single_list_get_head(&g_console_list); NULL!=pnode;
		pnode=single_list_get_after(&g_console_list, pnode)) {
		auto pconsole = &static_cast<const CONSOLE_PNODE *>(pnode->pdata)->u;
		if (NOTIFY_SMTP&control_mask) {
			gateway_control_send(pconsole->smtp_ip,
				pconsole->smtp_port, command);
		}
		if (NOTIFY_DELIVERY&control_mask) {
			gateway_control_send(pconsole->delivery_ip,
				pconsole->delivery_port, command);
		}
	}
}

int gateway_control_stop()
{
	SINGLE_LIST_NODE *pnode;

	while ((pnode = single_list_get_from_head(&g_console_list)) != NULL)
		free(pnode->pdata);
	return 0;
}

void gateway_control_free()
{
	single_list_free(&g_console_list);

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
	read(sockd, temp_buff, 1024);
	write(sockd, "quit\r\n", 6);
	close(sockd);
	return TRUE;
}

