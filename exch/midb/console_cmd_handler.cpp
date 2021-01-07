// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include "console_cmd_handler.h"
#include "console_server.h"
#include "exmdb_client.h"
#include "mail_engine.h"
#include "lib_buffer.h"
#include "service.h"
#include "util.h"
#include "guid.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536

static char g_server_help[] =
	"250 MIDB DAEMON server help information:\r\n"
	"\tmidb            --midb operating\r\n"
	"\tsystem         --control the MIDB DAEMON server\r\n"
	"\ttype \"<control-unit> --help\" for more information";

static char g_midb_help[] =
	"250 MIDB DAEMON midb control help information:\r\n"
	"\tmidb info\r\n"
	"\t    --print the http parser info";

static char g_system_help[] =
	"250 MIDB DAEMON system help information:\r\n"
	"\tsystem stop\r\n"
	"\t    --stop the server\r\n"
	"\tsystem version\r\n"
	"\t    --print the server version";

BOOL cmd_handler_help(int argc, char** argv)
{
	if (1 != argc) {
		console_server_reply_to_client("550 too many arguments");
		return TRUE;
	}
	console_server_reply_to_client(g_server_help);
	return TRUE;
}

BOOL cmd_handler_midb_control(int argc, char** argv)
{
	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_midb_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		console_server_reply_to_client(
			"table size:                %d\r\n"
			"allocated:                 %d\r\n"
			"alive proxy connections    %d\r\n"
			"lost proxy connections     %d",
			mail_engine_get_param(MIDB_TABLE_SIZE),
			mail_engine_get_param(MIDB_TABLE_USED),
			exmdb_client_get_param(ALIVE_PROXY_CONNECTIONS),
			exmdb_client_get_param(LOST_PROXY_CONNECTIONS));
		return TRUE;
	}
	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

BOOL cmd_handler_system_control(int argc, char** argv)
{
	if (1 == argc) {
		console_server_reply_to_client("550 too few auguments");
		return TRUE;
	}
	
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_system_help);
		return TRUE;
	}
	
	if (2 == argc && 0 == strcmp(argv[1], "stop")) {
		console_server_notify_main_stop();
		console_server_reply_to_client("250 stop OK");
		return TRUE;
	}
	
	if (2 == argc && 0 == strcmp(argv[1], "version")) {
		console_server_reply_to_client("250 MIDB DAEMON information:\r\n"
			"\tversion                     %s",
			PROJECT_VERSION);
									return TRUE;
	}
	
	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

BOOL cmd_handler_service_plugins(int argc, char** argv)
{
	char buf[TALK_BUFFER_LEN];
	
	memset(buf, 0, TALK_BUFFER_LEN);
	if (PLUGIN_TALK_OK == 
		service_console_talk(argc, argv, buf, TALK_BUFFER_LEN)) {
		if (strlen(buf) == 0) {
			strncpy(buf, "550 service plugin console talk is error "
					"implemented", sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = '\0';
		}
		console_server_reply_to_client("%s", buf);
		return TRUE;
	}
	return FALSE;
}
