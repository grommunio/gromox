#include "console_cmd_handler.h"
#include "console_server.h"
#include "zarafa_server.h"
#include "exmdb_client.h"
#include "common_util.h"
#include "service.h"
#include "util.h"
#include "guid.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536
#define ZCORE_BUILT_DATE		"2019-08-01"


static char g_plugname_buffer[PLUG_BUFFER_SIZE + 2];
static int  g_plugname_buffer_size = 0;
static FILE *g_file_ptr = NULL;

static char g_server_help[] =
	"250 ZCORE DAEMON server help information:\r\n"
	"\tservice        --control service plugins\r\n"
	"\tzcore          --zcore operating\r\n"
	"\tsystem         --control the ZCORE DAEMON server\r\n"
	"\ttype \"<control-unit> --help\" for more information";


static char g_service_help[] =
	"250 ZCORE DAEMON service plugins help information:\r\n"
	"\tservice info\r\n"
	"\t    --print the plug-in info";

static char g_zcore_help[] =
	"250 ZCORE DAEMON zcore control help information:\r\n"
	"\tzcore info\r\n"
	"\t    --print the http parser info";

static char g_system_help[] =
	"250 ZCORE DAEMON system help information:\r\n"
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
}

static void cmd_handler_dump_plugname(const char* plugname)
{
	if (g_plugname_buffer_size < PLUG_BUFFER_SIZE - strlen(plugname) - 3) {
		g_plugname_buffer_size += snprintf(g_plugname_buffer + 
			g_plugname_buffer_size, PLUG_BUFFER_SIZE - g_plugname_buffer_size,
			"\t%s\r\n", plugname);
	}
}

/*  
 *  service plug-in control, which can print all the plug-in 
 *  information, load and unload the specified plug-in dynamicly.
 *  the usage is as follows,
 *      service info                // print the plug-in info
 */
BOOL cmd_handler_service_control(int argc, char** argv)
{
	int result;

	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_service_help);
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		g_plugname_buffer_size = 0;
		service_enum_plugins(cmd_handler_dump_plugname);
		g_plugname_buffer[g_plugname_buffer_size] = '\0';
		console_server_reply_to_client("250 loaded service plugins:\r\n%s",
			g_plugname_buffer);
		return TRUE;
	}
	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

BOOL cmd_handler_zcore_control(int argc, char** argv)
{
	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_zcore_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		console_server_reply_to_client(
			"table size:                %d\r\n"
			"allocated:                 %d\r\n"
			"alive proxy connections    %d\r\n"
			"lost proxy connections     %d",
			zarafa_server_get_param(USER_TABLE_SIZE),
			zarafa_server_get_param(USER_TABLE_USED),
			exmdb_client_get_param(ALIVE_PROXY_CONNECTIONS),
			exmdb_client_get_param(LOST_PROXY_CONNECTIONS));
		return TRUE;
	}
	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

BOOL cmd_handler_system_control(int argc, char** argv)
{
	int current_thread_num;
	LIB_BUFFER* block_allocator;
	int max_context_num, parsing_context_num;
	size_t max_block_num, current_alloc_num, block_size;
	
	
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
		console_server_reply_to_client("250 ZCORE DAEMON information:\r\n"
									"\tversion                     %s\r\n"
									"\tbuilt in                    %s",
									ZCORE_VERSION, ZCORE_BUILT_DATE);
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
					"implemented!!!", sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = '\0';
		}
		console_server_reply_to_client("%s", buf);
		return TRUE;
	}
	return FALSE;
}
