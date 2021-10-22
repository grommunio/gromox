// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include "console_cmd_handler.h"
#include "blocks_allocator.h"
#include <gromox/console_server.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/threads_pool.hpp>
#include "pop3_parser.h"
#include <gromox/lib_buffer.hpp>
#include "resource.h"
#include "service.h"
#include <gromox/util.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536

using namespace gromox;

static char g_server_help[] =
	"250 POP3 DAEMON server help information:\r\n"
	"\treturn-code    --return code operating\r\n"
	"\tpop3           --pop3 operating\r\n"
	"\tsystem         --control the POP3 DAEMON server\r\n"
	"\ttype \"<control-unit> --help\" for more information";

static char g_pop3_parser_help[] =
	"250 POP3 DAEMON pop3 control help information:\r\n"
	"\tpop3 info\r\n"
	"\t    --print the pop3 parser info\r\n"
	"\tpop3 set time-out <interval>\r\n"
	"\t    --set time-out of pop3 connection\r\n"
	"\tpop3 set auth-times <number>\r\n"
	"\t    --set the maximum authentications if always fail\r\n"
	"\tpop3 set block-interval-auths <interval>\r\n"
	"\t    --how long a connection will be blocked if the failure of\r\n"
	"\t    authentication exceeds allowed times\r\n"
	"\tpop3 set force-tls <TRUE|FALSE>\r\n"
	"\t    --set if TLS is necessary";

static char g_system_help[] =
	"250 POP3 DAEMON system help information:\r\n"
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

BOOL cmd_handler_pop3_control(int argc, char** argv)
{
	int  value;
	int  auth_times, time_out;
	int  block_interval_auths;
	char str_timeout[64];
	char str_authblock[64];
	BOOL support_tls, necessary_tls;

	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_pop3_parser_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		time_out    = pop3_parser_get_param(POP3_SESSION_TIMEOUT);
		block_interval_auths    = pop3_parser_get_param(BLOCK_AUTH_FAIL);
		auth_times              = pop3_parser_get_param(MAX_AUTH_TIMES);
		support_tls             = pop3_parser_get_param(POP3_SUPPORT_STLS);
		necessary_tls           = pop3_parser_get_param(POP3_FORCE_STLS);
		itvltoa(time_out, str_timeout);
		itvltoa(block_interval_auths, str_authblock);
		console_server_reply_to_client("250 pop3 information of %s:\r\n"
			"\tsession time-out                     %s\r\n"
			"\tauthentication times                 %d\r\n"
			"\tauth failure block interval          %s\r\n"
			"\tsupport TLS?                         %s\r\n"
			"\tforce TLS?                           %s",
			resource_get_string("HOST_ID"),
			str_timeout,
			auth_times,
			str_authblock,
			support_tls == FALSE ? "FALSE" : "TRUE",
			necessary_tls == FALSE ? "FALSE" : "TRUE");
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
		resource_set_string("POP3_CONN_TIMEOUT", argv[3]);
		pop3_parser_set_param(POP3_SESSION_TIMEOUT, value);
		console_server_reply_to_client("250 time-out set OK");
		return TRUE;                           
	}
	if (0 == strcmp(argv[2], "auth-times")) {
		value = strtol(argv[3], nullptr, 0);
		if (value <= 0) {
			console_server_reply_to_client("550 invalid auth-times %s",
				argv[3]);
			return TRUE;
		}
		resource_set_integer("POP3_AUTH_TIMES", value);
		pop3_parser_set_param(MAX_AUTH_TIMES, value);
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
		pop3_parser_set_param(BLOCK_AUTH_FAIL, value);
		console_server_reply_to_client("250 block-interval-auth set OK");
		return TRUE;
	}

	if (0 == strcmp(argv[2], "force-tls")) {
		if (FALSE == pop3_parser_get_param(POP3_SUPPORT_STLS)) {
			console_server_reply_to_client("550 STLS support must turn on");
			return TRUE;
		}
		if (0 == strcasecmp(argv[3], "FALSE")) {
			necessary_tls = FALSE;
		} else if (0 == strcasecmp(argv[3], "TRUE")) {
			necessary_tls = TRUE;
		} else {
			console_server_reply_to_client("550 invalid parameter, should be"
				"TRUE or FALSE");
			return TRUE;
		}
		resource_set_string("POP3_FORCE_STLS", argv[3]);
		pop3_parser_set_param(POP3_FORCE_STLS, necessary_tls);
		console_server_reply_to_client("250 force-tls set OK");
		return TRUE;
	}

	console_server_reply_to_client("550 no such argument %s", argv[2]);
	return TRUE;
}

BOOL cmd_handler_system_control(int argc, char** argv)
{
	LIB_BUFFER* block_allocator;
	size_t max_block_num, current_alloc_num, block_size;
	long max_context_num, parsing_context_num, current_thread_num;

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
		max_context_num     = contexts_pool_get_param(MAX_CONTEXTS_NUM);
		parsing_context_num = contexts_pool_get_param(CUR_VALID_CONTEXTS);
		block_allocator     = blocks_allocator_get_allocator();
		max_block_num       = lib_buffer_get_param(block_allocator, MEM_ITEM_NUM);
		block_size          = lib_buffer_get_param(block_allocator, MEM_ITEM_SIZE);
		current_alloc_num   = lib_buffer_get_param(block_allocator, ALLOCATED_NUM);
		current_thread_num  = threads_pool_get_param(THREADS_POOL_CUR_THR_NUM);
		console_server_reply_to_client("250 pop3 system running status of %s:\r\n"
			"\tmaximum contexts number      %ld\r\n"
			"\tcurrent parsing contexts     %ld\r\n"
			"\tmaximum memory blocks        %zu\r\n"
			"\tmemory block size            %zuK\r\n"
			"\tcurrent allocated blocks     %zu\r\n"
			"\tcurrent threads number       %ld",
			resource_get_string("HOST_ID"),
			max_context_num,
			parsing_context_num,
			max_block_num,
			block_size / 1024,
			current_alloc_num,
			current_thread_num);
		
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "version")) {
		console_server_reply_to_client("250 POP3 DAEMON information:\r\n"
			"\tversion                     %s", PACKAGE_VERSION);
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
