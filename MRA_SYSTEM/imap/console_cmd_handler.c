#include <stdbool.h>
#include "console_cmd_handler.h"
#include "blocks_allocator.h"
#include "console_server.h"
#include "contexts_pool.h"
#include "threads_pool.h"
#include "imap_parser.h"
#include "lib_buffer.h"
#include "resource.h"
#include "service.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536
#define IMAP_VERSION			"3.0"
#define IMAP_BUILT_DATE			"2015-6-20"


static char g_plugname_buffer[PLUG_BUFFER_SIZE + 2];
static int  g_plugname_buffer_size = 0;
static FILE *g_file_ptr = NULL;

static char g_server_help[] =
	"250 IMAP DAEMON server help information:\r\n"
	"\treturn-code    --return code operating\r\n"
	"\tservice        --control service plugins\r\n"
	"\timap           --imap operating\r\n"
	"\tsystem         --control the IMAP DAEMON server\r\n"
	"\ttype \"<control-unit> --help\" for more information";

static char g_imap_return_help[] =
	"250 IMAP DAEMON return code help information:\r\n"
	"\treturn-code reload\r\n"
	"\t    --reload imap error code table";

static char g_service_help[] =
	"250 IMAP DAEMON service plugins help information:\r\n"
	"\tservice info\r\n"
	"\t    --print the plug-in info\r\n"
	"\tservice load <name>\r\n"
	"\t    --load the specified plug-in\r\n"
	"\tservice unload <name>\r\n"
	"\t    --unload the specified plug-in\r\n"
	"\tservice reference <module>\r\n"
	"\t    --print the module's refering plug-ins\r\n"
	"\tservice depend <service>\r\n"
	"\t    --print modules depending the service plug-in";


static char g_imap_parser_help[] =
	"250 IMAP DAEMON imap control help information:\r\n"
	"\timap info\r\n"
	"\t    --print the imap parser info\r\n"
	"\timap set time-out <interval>\r\n"
	"\t    --set time-out of imap connection\r\n"
	"\timap set autologout-time <interval>\r\n"
	"\t    --set autologout-time of imap session\r\n"
	"\timap set auth-times <number>\r\n"
	"\t    --set the maximum authentications if always fail\r\n"
	"\timap set block-interval-auths <interval>\r\n"
	"\t    --how long a connection will be blocked if the failure of\r\n"
	"\t    authentication exceeds allowed times\r\n"
	"\timap set force-tls <TRUE|FALSE>\r\n"
	"\t    --set if TLS is necessary\r\n"
	"\timap wake <username> <folder>\r\n"
	"\t    --wake up idling imap sessions";

static char g_system_help[] =
	"250 IMAP DAEMON system help information:\r\n"
	"\tsystem set default-domain <domain>\r\n"
	"\t    --set default domain of system\r\n"
	"\tsystem stop\r\n"
	"\t    --stop the server\r\n"
	"\tsystem status\r\n"
	"\t    --print the current system running status\r\n"
	"\tsystem version\r\n"
	"\t    --print the server version";
	
static void cmd_handler_dump_plugname(const char* plugname);

BOOL cmd_handler_help(int argc, char** argv)
{
	if (1 != argc) {
		console_server_reply_to_client("550 too many arguments");
		return TRUE;
	}
	console_server_reply_to_client(g_server_help);
	return true;
}

/*
 *  imap error code control handler, the imap error code consists of
 *  imap standard code, native defined code, and the description of 
 *  this error. This function is used to reload this message if user
 *  has changed the imap error code file. we show how to use it,
 *
 *      return-code   reload// reload the error code msg
 */
BOOL cmd_handler_imap_return_code_control(int argc, char** argv)
{
	
	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_imap_return_help);
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		if (FALSE == resource_refresh_imap_code_table()) {
			console_server_reply_to_client("550 fail to reload return code"); 
			return TRUE;
		}
		console_server_reply_to_client("250 reload return code OK");
		return TRUE;
	}
	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

/*  
 *  service plug-in control, which can print all the plug-in 
 *  information, load and unload the specified plug-in dynamicly.
 *  the usage is as follows,
 *      service info                // print the plug-in info
 *      service load   <name>       // load the specified plug-in
 *      service unload <name>       // unload the specified plug-in
 *      service depend <name>       // print the modules depending plug-in
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
	if (3 == argc && 0 == strcmp(argv[1], "load")) {
		result = service_load_library(argv[2]);
		switch (result) {
		case PLUGIN_LOAD_OK:
			console_server_reply_to_client("250 load plug-in OK");
			return TRUE;
		case PLUGIN_ALREADY_LOADED:
			console_server_reply_to_client("550 the plug-in has already "
								"been loaded");
			break;
		case PLUGIN_FAIL_OPEN:
			console_server_reply_to_client("550 error to open the plug-in");
			break;
		case PLUGIN_NO_MAIN:
			console_server_reply_to_client("550 fail to find library function");
			break;
		case PLUGIN_FAIL_ALLOCNODE:
			console_server_reply_to_client("550 fail to plug-in alloc memory");
			break;
		case PLUGIN_FAIL_EXCUTEMAIN:
			console_server_reply_to_client("550 fail to execute plugin's "
						"init function");
			break;
		default:
			console_server_reply_to_client("550 unknown error");
		}
		return TRUE;
	}

	if (3 == argc && 0 == strcmp(argv[1], "unload")) {
		result = service_unload_library(argv[2]);
		switch (result) {
		case PLUGIN_UNLOAD_OK:
			console_server_reply_to_client("250 unload %s OK", argv[2]);
			return TRUE;
		case PLUGIN_UNABLE_UNLOAD:
			console_server_reply_to_client("550 unable to unload %s,"
					"there're some modules depending this plug-in", argv[2]);
			return TRUE;
		case PLUGIN_NOT_FOUND:
			console_server_reply_to_client("550 no such plug-in running");
			return TRUE;
		default:
			console_server_reply_to_client("550 unknown error");
			return TRUE;
		}
	}
	if (3 == argc && 0 == strcmp(argv[1], "reference")) {
		g_plugname_buffer_size = 0;
		service_enum_reference(argv[2], cmd_handler_dump_plugname);
		g_plugname_buffer[g_plugname_buffer_size] = '\0';
		console_server_reply_to_client("250 module %s depends on:\r\n%s",
				argv[2], g_plugname_buffer);
		return TRUE;
	}
	if (3 == argc && 0 == strcmp(argv[1], "depend")) {
		g_plugname_buffer_size = 0;
		service_enum_dependency(argv[2], cmd_handler_dump_plugname);
		g_plugname_buffer[g_plugname_buffer_size] = '\0';
		console_server_reply_to_client("250 plugin %s is referenced by:\r\n%s",
				argv[2], g_plugname_buffer);
		return TRUE;
	}

	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}


BOOL cmd_handler_imap_control(int argc, char** argv)
{
	int  value;
	int autologout_time;
	int  auth_times, time_out;
	int  block_interval_auths;
	char str_timeout[64];
	char str_authblock[64];
	char str_autologout[64];
	BOOL support_tls, necessary_tls;

	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_imap_parser_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		time_out                = imap_parser_get_param(IMAP_SESSION_TIMEOUT);
		autologout_time         = imap_parser_get_param(IMAP_AUTOLOGOUT_TIME);
		block_interval_auths    = imap_parser_get_param(BLOCK_AUTH_FAIL);
		auth_times              = imap_parser_get_param(MAX_AUTH_TIMES);
		support_tls             = imap_parser_get_param(IMAP_SUPPORT_STARTTLS);
		necessary_tls           = imap_parser_get_param(IMAP_FORCE_STARTTLS);
		itvltoa(time_out, str_timeout);
		itvltoa(autologout_time, str_autologout);
		itvltoa(block_interval_auths, str_authblock);
		console_server_reply_to_client("250 imap information of %s:\r\n"
			"\tsession time-out                     %s\r\n"
			"\tsession autologout-time              %s\r\n"
			"\tauthentication times                 %d\r\n"
			"\tauth failure block interval          %s\r\n"
			"\tsupport TLS?                         %s\r\n"
			"\tforce TLS?                           %s",
			resource_get_string(RES_HOST_ID),
			str_timeout,
			str_autologout,
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
	
	if (0 == strcmp(argv[1], "wake")) {
		imap_parser_touch_modify(NULL, argv[2], argv[3]);
		console_server_reply_to_client("250 sessions of %s idling "
			"within %s is waken up", argv[2], argv[3]);
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
		resource_set_string(RES_IMAP_CONN_TIMEOUT, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		imap_parser_set_param(IMAP_SESSION_TIMEOUT, value);
		console_server_reply_to_client("250 time-out set OK");
		return TRUE;                           
	}
	if (0 == strcmp(argv[2], "autologout-time")) {
		if ((value = atoitvl(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid autologout-time %s", argv[3]);
			return TRUE;
		}
		resource_set_string(RES_IMAP_AUTOLOGOUT_TIME, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		imap_parser_set_param(IMAP_AUTOLOGOUT_TIME, value);
		console_server_reply_to_client("250 autologout-time set OK");
		return TRUE;                           
	}
	if (0 == strcmp(argv[2], "auth-times")) {
		if ((value = atoi(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid auth-times %s",
				argv[3]);
			return TRUE;
		}
		resource_set_integer(RES_IMAP_AUTH_TIMES, value);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		imap_parser_set_param(MAX_AUTH_TIMES, value);
		console_server_reply_to_client("250 auth-times set OK");
		return TRUE;
	}
	if (0 == strcmp(argv[2], "block-interval-auths")) {
		if ((value = atoitvl(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid "
				"block-interval-auths %s", argv[3]);
			return TRUE;
		}
		resource_set_string(RES_BLOCK_INTERVAL_AUTHS, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		imap_parser_set_param(BLOCK_AUTH_FAIL, value);
		console_server_reply_to_client("250 block-interval-auth set OK");
		return TRUE;
	}

	if (0 == strcmp(argv[2], "force-tls")) {
		if (FALSE == imap_parser_get_param(IMAP_SUPPORT_STARTTLS)) {
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
		resource_set_string(RES_IMAP_FORCE_STARTTLS, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		imap_parser_set_param(IMAP_FORCE_STARTTLS, necessary_tls);
		console_server_reply_to_client("250 force-tls set OK");
		return TRUE;
	}
	

	console_server_reply_to_client("550 no such argument %s", argv[2]);
	return TRUE;
}


static void cmd_handler_dump_plugname(const char* plugname)
{
	if (g_plugname_buffer_size < PLUG_BUFFER_SIZE - strlen(plugname) - 3) {
		g_plugname_buffer_size += snprintf(g_plugname_buffer + 
			g_plugname_buffer_size, PLUG_BUFFER_SIZE - g_plugname_buffer_size,
			"\t%s\r\n", plugname);
	}
}

BOOL cmd_handler_system_control(int argc, char** argv)
{
	LIB_BUFFER* block_allocator;
	int max_context_num, parsing_context_num;
	int current_thread_num, sleeping_context_num;
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
		resource_set_string(RES_DEFAULT_DOMAIN, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
		} else {
			console_server_reply_to_client("250 default domain set OK");
		}
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
		sleeping_context_num = contexts_pool_get_param(CUR_SLEEPING_CONTEXTS);
		block_allocator      = blocks_allocator_get_allocator();
		max_block_num        = lib_buffer_get_param(block_allocator, MEM_ITEM_NUM);
		block_size           = lib_buffer_get_param(block_allocator, MEM_ITEM_SIZE);
		current_alloc_num    = lib_buffer_get_param(block_allocator, ALLOCATED_NUM);
		current_thread_num   = threads_pool_get_param(THREADS_POOL_CUR_THR_NUM);
		console_server_reply_to_client("250 imap system running status of %s:\r\n"
			"\tmaximum contexts number      %d\r\n"
			"\tcurrent parsing contexts     %d\r\n"
			"\tcurrent sleeping contexts    %d\r\n"
			"\tmaximum memory blocks        %ld\r\n"
			"\tmemory block size            %ldK\r\n"
			"\tcurrent allocated blocks     %ld\r\n"
			"\tcurrent threads number       %d",
			resource_get_string(RES_HOST_ID),
			max_context_num,
			parsing_context_num,
			sleeping_context_num,
			max_block_num,
			block_size / 1024,
			current_alloc_num,
			current_thread_num);
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "version")) {
		console_server_reply_to_client("250 IMAP DAEMON information:\r\n"
			"\tversion                     %s\r\n"
			"\tbuilt in                    %s",
			IMAP_VERSION, IMAP_BUILT_DATE);
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

