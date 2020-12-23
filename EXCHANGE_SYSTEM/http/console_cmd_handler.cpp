#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <stdbool.h>
#include <gromox/fileio.h>
#include "console_cmd_handler.h"
#include "blocks_allocator.h"
#include "console_server.h"
#include "hpm_processor.h"
#include "pdu_processor.h"
#include "contexts_pool.h"
#include "threads_pool.h"
#include "http_parser.h"
#include "lib_buffer.h"
#include "resource.h"
#include "service.h"
#include "util.h"
#include "guid.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536

static char g_plugname_buffer[PLUG_BUFFER_SIZE + 2];
static int g_plugname_buffer_size;

static char g_server_help[] =
	"250 HTTP DAEMON server help information:\r\n"
	"\thttp           --http operating\r\n"
	"\trpc            --rpc operating\r\n"
	"\tsystem         --control the HTTP DAEMON server\r\n"
	"\ttype \"<control-unit> --help\" for more information";

static char g_http_help[] =
	"250 HTTP DAEMON http control help information:\r\n"
	"\thttp info\r\n"
	"\t    --print the http parser info\r\n"
	"\thttp set time-out <interval>\r\n"
	"\t    --set time-out of http connection\r\n"
	"\thttp set auth-times <number>\r\n"
	"\t    --set the maximum authentications if always fail\r\n"
	"\thttp set block-interval-auths <interval>\r\n"
	"\t    --how long a connection will be blocked if the failure of\r\n"
	"\t    authentication exceeds allowed times";

static char g_rpc_help[] = 
	"250 HTTP DAEMON rpc help information:\r\n"
	"\trpc info\r\n"
	"\t    --print all end-pointers of rpc";
	
static char g_system_help[] =
	"250 HTTP DAEMON system help information:\r\n"
	"\tsystem set default-domain <domain>\r\n"
	"\t    --set default domain of system\r\n"
	"\tsystem stop\r\n"
	"\t    --stop the server\r\n"
	"\tsystem status\r\n"
	"\t    --print the current system running status\r\n"
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

BOOL cmd_handler_http_control(int argc, char** argv)
{
	int  value;
	int  auth_times, time_out;
	int  block_interval_auths;
	char str_timeout[64];
	char str_authblock[64];
	BOOL support_ssl;

	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_http_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		time_out                = http_parser_get_param(HTTP_SESSION_TIMEOUT);
		block_interval_auths    = http_parser_get_param(BLOCK_AUTH_FAIL);
		auth_times              = http_parser_get_param(MAX_AUTH_TIMES);
		support_ssl             = http_parser_get_param(HTTP_SUPPORT_SSL);
		itvltoa(time_out, str_timeout);
		itvltoa(block_interval_auths, str_authblock);
		console_server_reply_to_client("250 http information of %s:\r\n"
			"\tsession time-out                     %s\r\n"
			"\tauthentication times                 %d\r\n"
			"\tauth failure block interval          %s\r\n"
			"\tsupport SSL?                         %s",
			resource_get_string("HOST_ID"),
			str_timeout,
			auth_times,
			str_authblock,
			support_ssl == FALSE ? "FALSE" : "TRUE");
		return TRUE;
	}
	if (argc < 4) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}
	if (argc > 4) {
		console_server_reply_to_client("550 too many arguments");
		return TRUE;
	}
	
	if (0 != strcmp(argv[1], "set")) {
		console_server_reply_to_client("550 invalid argument %s", argv[1]);
		return TRUE;
	}
	if (0 == strcmp(argv[2], "time-out")) {
		if ((value = atoitvl(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid time-out %s", argv[3]);
			return TRUE;
		}
		resource_set_string("HTTP_CONN_TIMEOUT", argv[3]);
		http_parser_set_param(HTTP_SESSION_TIMEOUT, value);
		console_server_reply_to_client("250 time-out set OK");
		return TRUE;                           
	}
	
	if (0 == strcmp(argv[2], "auth-times")) {
		if ((value = atoi(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid auth-times %s",
				argv[3]);
			return TRUE;
		}
		resource_set_integer("HTTP_AUTH_TIMES", value);
		http_parser_set_param(MAX_AUTH_TIMES, value);
		console_server_reply_to_client("250 auth-times set OK");
		return TRUE;
	}
	if (0 == strcmp(argv[2], "block-interval-auths")) {
		if ((value = atoitvl(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid "
				"block-interval-auths %s", argv[3]);
			return TRUE;
		}
		resource_set_string("BLOCK_INTERVAL_AUTHS", argv[3]);
		http_parser_set_param(BLOCK_AUTH_FAIL, value);
		console_server_reply_to_client("250 block-interval-auth set OK");
		return TRUE;
	}
	

	console_server_reply_to_client("550 no such argument %s", argv[2]);
	return TRUE;
}

static void cmd_handler_dump_interfaces(DCERPC_INTERFACE *pinterface)
{
	uint32_t version;
	const char *format_string;
	char uuid_string[64];
	
	if (g_plugname_buffer_size < PLUG_BUFFER_SIZE) {
		guid_to_string(&pinterface->uuid, uuid_string, 64);
		version = pinterface->version;
		if (0 == (version&0xFFFF0000)) {
			format_string = "\t\tinterface(%s) %s(%u.%u)\r\n";
		} else {
			format_string = "\t\tinterface(%s) %s(%u.%02u)\r\n";
		}
		g_plugname_buffer_size += gx_snprintf(g_plugname_buffer +
			g_plugname_buffer_size, PLUG_BUFFER_SIZE - g_plugname_buffer_size,
			format_string, pinterface->name, uuid_string,
			version&0xFFFF, (version&0xFFFF0000)>>16);
	}
}

static void cmd_handler_dump_endpoints(DCERPC_ENDPOINT *pendpoint)
{
	if (g_plugname_buffer_size < PLUG_BUFFER_SIZE) {
		g_plugname_buffer_size += gx_snprintf(g_plugname_buffer +
			g_plugname_buffer_size, PLUG_BUFFER_SIZE - g_plugname_buffer_size,
			"\tendpoint %s:%d:\r\n", pendpoint->host, pendpoint->tcp_port);
		pdu_processor_enum_interfaces(pendpoint, cmd_handler_dump_interfaces);
	}
}

BOOL cmd_handler_rpc_control(int argc, char** argv)
{	
	 if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_rpc_help);
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		g_plugname_buffer_size = 0;
		pdu_processor_enum_endpoints(cmd_handler_dump_endpoints);
		g_plugname_buffer[g_plugname_buffer_size] = '\0';
		console_server_reply_to_client("250 loaded proc plugins:\r\n%s",
			g_plugname_buffer);
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

	if (4 == argc && 0 == strcmp(argv[1], "set") &&
		0 == strcmp(argv[2], "default-domain")) {
		resource_set_string("DEFAULT_DOMAIN", argv[3]);
		console_server_reply_to_client("250 default domain set OK");
		return TRUE;
	}

	
	if (2 == argc && 0 == strcmp(argv[1], "stop")) {
		console_server_notify_main_stop();
		console_server_reply_to_client("250 stop OK");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "status")) {
		max_context_num      = contexts_pool_get_param(MAX_CONTEXTS_NUM);
		parsing_context_num  = contexts_pool_get_param(CUR_VALID_CONTEXTS);
		block_allocator      = blocks_allocator_get_allocator();
		max_block_num        = lib_buffer_get_param(block_allocator, MEM_ITEM_NUM);
		block_size           = lib_buffer_get_param(block_allocator, MEM_ITEM_SIZE);
		current_alloc_num    = lib_buffer_get_param(block_allocator, ALLOCATED_NUM);
		current_thread_num   = threads_pool_get_param(THREADS_POOL_CUR_THR_NUM);
		console_server_reply_to_client("250 http system running status of %s:\r\n"
			"\tmaximum contexts number      %d\r\n"
			"\tcurrent parsing contexts     %d\r\n"
			"\tmaximum memory blocks        %ld\r\n"
			"\tmemory block size            %ld * 64K\r\n"
			"\tcurrent allocated blocks     %ld\r\n"
			"\tcurrent threads number       %d",
			resource_get_string("HOST_ID"),
			max_context_num,
			parsing_context_num,
			max_block_num,
			block_size / (1024 * 64),
			current_alloc_num,
			current_thread_num);
		
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "version")) {
		console_server_reply_to_client("250 HTTP DAEMON information:\r\n"
			"\tversion                     %s",
			PROJECT_VERSION);
		return TRUE;
	}

	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

BOOL cmd_handler_proc_plugins(int argc, char** argv)
{
	char buf[TALK_BUFFER_LEN];
	
	memset(buf, 0, TALK_BUFFER_LEN);
	if (PLUGIN_TALK_OK == 
		pdu_processor_console_talk(argc, argv, buf, TALK_BUFFER_LEN)) {
		if (strlen(buf) == 0) {
			strncpy(buf, "550 proc plugin console talk is error "
					"implemented", sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = '\0';
		}
		console_server_reply_to_client("%s", buf);
		return TRUE;
	}
	return FALSE;
}

BOOL cmd_handler_hpm_plugins(int argc, char** argv)
{
	char buf[TALK_BUFFER_LEN];
	
	memset(buf, 0, TALK_BUFFER_LEN);
	if (PLUGIN_TALK_OK == 
		hpm_processor_console_talk(argc, argv, buf, TALK_BUFFER_LEN)) {
		if (strlen(buf) == 0) {
			strncpy(buf, "550 proc plugin console talk is error "
					"implemented", sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = '\0';
		}
		console_server_reply_to_client("%s", buf);
		return TRUE;
	}
	return FALSE;
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
