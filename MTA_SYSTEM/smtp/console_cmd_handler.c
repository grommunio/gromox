#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include "console_cmd_handler.h"
#include "blocks_allocator.h"
#include "console_server.h"
#include "anti_spamming.h"
#include "contexts_pool.h"
#include "threads_pool.h"
#include "lib_buffer.h"
#include "resource.h"
#include "flusher.h"
#include "service.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536
#define SMTP_BUILT_DATE			"2015-1-20"

static char g_plugname_buffer[PLUG_BUFFER_SIZE + 2];
static size_t g_plugname_buffer_size = 0;

static char g_server_help[] =
	"250 SMTP DAEMON server help information:\r\n"
	"\treturn-code    --return code operating\r\n"
	"\tservice        --control service plugins\r\n"
	"\tanti-spamming  --control anti-spamming plugins\r\n"
	"\tflusher        --control the flusher plgin\r\n"
	"\tsmtp           --smtp operating\r\n"
	"\tsystem         --control the SMTP DAEMON server\r\n"
	"\ttype \"<control-unit> --help\" for more information";

static char g_smtp_return_help[] =
	"250 SMTP DAEMON return code help information:\r\n"
	"\treturn-code reload\r\n"
	"\t    --reload smtp error code table";

static char g_service_help[] =
	"250 SMTP DAEMON service plugins help information:\r\n"
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

static char g_anti_spam_help[] =
	"250 SMTP DAEMON anti-spamming plugins help information:\r\n"
	"\tanti-spamming info\r\n"
	"\t    --print the plug-in info\r\n"
	"\tanti-spamming load <name>\r\n"
	"\t    --load the specified plug-in\r\n"
	"\tanti-spamming unload <name>\r\n"
	"\t    --unload the specified plug-in\r\n"
	"\tanti-spamming reload <name>\r\n"
	"\t    --reload the specified plug-in";

static char g_smtp_parser_help[] =
	"250 SMTP DAEMON smtp control help information:\r\n"
	"\tsmtp info\r\n"
	"\t    --print the smtp parser info\r\n"
	"\tsmtp set max-mails <number>\r\n"
	"\t    --set each connection can only send number of mails\r\n"
	"\tsmtp set mail-length <length>\r\n"
	"\t    --set maximume mail length system allowd\r\n"
	"\tsmtp set time-out <interval>\r\n"
	"\t    --set time-out of smtp connection\r\n"
	"\tsmtp set need-auth <TRUE|FALSE>\r\n"
	"\t    --set if authentication is needed\r\n"
	"\tsmtp set support-pipeline <TRUE|FALSE>\r\n"
	"\t    --set if pipeline mode is support\r\n"
	"\tsmtp set force-tls <TRUE|FALSE>\r\n"
	"\t    --set if TLS is necessary\r\n"
	"\tsmtp set auth-times <number>\r\n"
	"\t    --set the maximum authentications if always fail\r\n"
	"\tsmtp set block-interval-auths <interval>\r\n"
	"\t    --how long a connection will be blocked if the failure of\r\n"
	"\t    authentication exceeds allowed times\r\n"
	"\tsmtp set block-interval-sessions <interval>\r\n"
	"\t    --how long a connection will be blocked if the session exceed \r\n"
	"\t    the maximum allowed mails";

static char g_system_help[] =
	"250 SMTP DAEMON system help information:\r\n"
	"\tsystem set default-domain <domain>\r\n"
	"\t    --set default domain of system\r\n"
	"\tsystem set domain-list <TRUE|FALSE>\r\n"
	"\t    --validate or invalidate domain list in system\r\n"
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
	} else {
		console_server_reply_to_client(g_server_help);
	}
	return TRUE;
}

/*
 *  smtp error code control handler, the smtp error code consists of
 *  smtp standard code, native defined code, and the description of 
 *  this error. This function is used to reload this message if user
 *  has changed the smtp error code file. we show how to use it,
 *
 *      return-code   reload// reload the error code msg
 */
BOOL cmd_handler_smtp_error_code_control(int argc, char** argv)
{
	
	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_smtp_return_help);
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		if (FALSE == resource_refresh_smtp_code_table()) {
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

/*  
 *  anti-spamming plug-in control, which can print all the plug-in 
 *  information, load and unload the specified plug-in dynamicly.
 *  the usage is as follows,
 *      anti-spamming info          // print the plug-in info
 *      anti-spamming load   <name> // load the specified plug-in
 *      anti-spamming unload <name> // unload the specified plug-in
 *      anti-spamming reload <name> // reload the specified plug-in
 */
BOOL cmd_handler_anti_spamming_control(int argc, char** argv)
{
	int  result = 0;

	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_anti_spam_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		g_plugname_buffer_size = 0;
		anti_spamming_enum_plugins(cmd_handler_dump_plugname);
		g_plugname_buffer[g_plugname_buffer_size] = '\0';
		console_server_reply_to_client("250 loaded anti-spamming plugins\r\n%s",
				g_plugname_buffer);
		g_plugname_buffer_size = 0;
		return TRUE;
	}

	if (3 == argc && 0 == strcmp(argv[1], "load")) {
		result = anti_spamming_load_library(argv[2]);
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
		result = anti_spamming_unload_library(argv[2]);
		switch (result) {
		case PLUGIN_UNLOAD_OK:
			console_server_reply_to_client("250 unload %s OK", argv[2]);
			return TRUE;
		case PLUGIN_NOT_FOUND:
			console_server_reply_to_client("550 no such plug-in running");
			return TRUE;
		case PLUGIN_SYSTEM_ERROR:
			console_server_reply_to_client("550 information in "
				"anti-spamming module diff with the current plug-in");
			return TRUE;
		default:
			console_server_reply_to_client("550 unknown error");
			return TRUE;
		}
	}

	if (3 == argc && 0 == strcmp(argv[1], "reload")) {
		result = anti_spamming_reload_library(argv[2]);
		switch (result) {
		case PLUGIN_RELOAD_OK:
			console_server_reply_to_client("250 reload %s OK", argv[2]);
			return TRUE;
		case PLUGIN_RELOAD_NOT_FOUND:
			console_server_reply_to_client("550 no such plug-in running");
			return TRUE;
		case PLUGIN_RELOAD_ERROR:
			console_server_reply_to_client("550 reload error");
			return TRUE;
	 case PLUGIN_RELOAD_FAIL_OPEN:
		 console_server_reply_to_client("550 error to open the plug-in");
			return TRUE;
		case PLUGIN_RELOAD_NO_MAIN:
			console_server_reply_to_client("550 fail to find library function");
			return TRUE;
		case PLUGIN_RELOAD_FAIL_ALLOCNODE:
			console_server_reply_to_client("550 fail to plug-in alloc memory");
			return TRUE;
		case PLUGIN_RELOAD_FAIL_EXCUTEMAIN:
			console_server_reply_to_client("550 fail to execute plugin's "
				"init function");
			return TRUE;
		default:
			console_server_reply_to_client("550 unknown error");
			return TRUE;
		}
	}
	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

/*
 *  smtp control handler, which can reset some parameters in 
 *  smtp parser such as max-mails number, max mail length, 
 *  timeout and flushing size beyond which we will flush the
 *  data.
 *  Usage:
 *      smtp set max-mails       200 // set each context can
 *                                   // only send 200 mails
 *      smtp set mail-length     100 // set the max mail length
 *                                   // to be 100 bytes
 *      smtp set time-out        60  // set time-out to be one
 *                                   // minutes
 */
BOOL cmd_handler_smtp_control(int argc, char** argv)
{
	size_t  value;
	size_t  flushing_size, auth_times;
	size_t  max_mails, mail_length, time_out;
	size_t  block_interval_auths, block_interval_sessions;
	BOOL need_auth, support_pipeline;
	BOOL support_tls, necessary_tls;
	char str_mode[16];
	char str_flush[32];
	char str_length[32];
	char str_timeout[64];
	char str_authblock[64];
	char str_sessionblock[64];

	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_smtp_parser_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		max_mails   = smtp_parser_get_param(SMTP_MAX_MAILS);
		mail_length = smtp_parser_get_param(MAX_MAIL_LENGTH);
		time_out    = smtp_parser_get_param(SMTP_SESSION_TIMEOUT);
		need_auth   = smtp_parser_get_param(SMTP_NEED_AUTH);
		block_interval_auths    = smtp_parser_get_param(BLOCK_TIME_EXCEED_AUTHS);
		block_interval_sessions = smtp_parser_get_param(BLOCK_TIME_EXCEED_SESSIONS);
		flushing_size           = smtp_parser_get_param(MAX_FLUSHING_SIZE);
		auth_times              = smtp_parser_get_param(MAX_AUTH_TIMES);
		support_pipeline        = smtp_parser_get_param(SMTP_SUPPORT_PIPELINE);
		support_tls             = smtp_parser_get_param(SMTP_SUPPORT_STARTTLS);
		necessary_tls           = smtp_parser_get_param(SMTP_FORCE_STARTTLS);
		if (FALSE == support_tls) {
			necessary_tls = FALSE;
		}
		switch(smtp_parser_get_param(SMTP_RUNNING_MODE)) {
		case SMTP_MODE_OUTBOUND:
			strcpy(str_mode, "out-bound");
			break;
		case SMTP_MODE_INBOUND:
			strcpy(str_mode, "in-bound");
			break;
		case SMTP_MODE_MIXTURE:
			strcpy(str_mode, "mixture");
			break;
		}
		bytetoa(mail_length, str_length);
		bytetoa(flushing_size, str_flush);
		itvltoa(time_out, str_timeout);
		itvltoa(block_interval_auths, str_authblock);
		itvltoa(block_interval_sessions, str_sessionblock);
		console_server_reply_to_client("250 smtp information of %s:\r\n"
			"\tmaximum mail number per session      %ld\r\n"
			"\tmaximum mail length                  %s\r\n"
			"\tflushing size                        %s\r\n"
			"\tsession time-out                     %s\r\n"
			"\tneed authentication?                 %s\r\n"
			"\tsupport pipeline?                    %s\r\n"
			"\tsupport TLS?                         %s\r\n"
			"\tforce TLS?                           %s\r\n"
			"\tauthentication times                 %ld\r\n"
			"\trunning mode                         %s\r\n"
			"\tauth failure block interval          %s\r\n"
			"\tsession-exceed block interval        %s",
			resource_get_string(RES_HOST_ID),
			max_mails,
			str_length,
			str_flush,
			str_timeout,
			need_auth == FALSE ? "FALSE" : "TRUE",
			support_pipeline == FALSE ? "FALSE" : "TRUE",
			support_tls == FALSE ? "FALSE" : "TRUE",
			necessary_tls == FALSE ? "FALSE" : "TRUE",
			auth_times,
			str_mode,
			str_authblock,
			str_sessionblock);
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
	if (0 == strcmp(argv[2], "max-mails")) {
		if ((value = atol(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid max-mails %s", argv[3]);
			return TRUE;
		}
		resource_set_integer(RES_SMTP_MAX_MAIL_NUM, value);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(SMTP_MAX_MAILS, value);
		console_server_reply_to_client("250 max-mails set OK");
		return TRUE;
	}
	if (0 == strcmp(argv[2], "mail-length")) {
		if ((value = atobyte(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid mail-length %s",
				argv[3]);
			return TRUE;
		}
		resource_set_string(RES_MAIL_MAX_LENGTH, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(MAX_MAIL_LENGTH, value);
		console_server_reply_to_client("250 mail-length set OK");
		return TRUE;   
	}
	if (0 == strcmp(argv[2], "time-out")) {
		if ((value = atoitvl(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid time-out %s", argv[3]);
			return TRUE;
		}
		resource_set_string(RES_SMTP_CONN_TIMEOUT, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(SMTP_SESSION_TIMEOUT, value);
		console_server_reply_to_client("250 time-out set OK");
		return TRUE;                           
	}
	if (0 == strcmp(argv[2], "need-auth")) {
		if (0 == strcasecmp(argv[3], "FALSE")) {
			need_auth = FALSE;
		} else if (0 == strcasecmp(argv[3], "TRUE")) {
			need_auth = TRUE;
		} else {
			console_server_reply_to_client("550 invalid parameter, should be"
					"TRUE or FALSE");
			return TRUE;
		}
		resource_set_string(RES_SMTP_NEED_AUTH, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(SMTP_NEED_AUTH, need_auth);
		console_server_reply_to_client("250 need-auth set OK");
		return TRUE;
	}
	if (0 == strcmp(argv[2], "support-pipeline")) {
		if (0 == strcasecmp(argv[3], "FALSE")) {
			support_pipeline = FALSE;
		} else if (0 == strcasecmp(argv[3], "TRUE")) {
			support_pipeline = TRUE;
		} else {
			console_server_reply_to_client("550 invalid parameter, should be"
					"TRUE or FALSE");
			return TRUE;
		}
		resource_set_string(RES_SMTP_SUPPORT_PIPELINE, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(SMTP_SUPPORT_PIPELINE, support_pipeline);
		console_server_reply_to_client("250 support-pipeline set OK");
		return TRUE;
	}

	if (0 == strcmp(argv[2], "force-tls")) {
		if (FALSE == smtp_parser_get_param(SMTP_SUPPORT_STARTTLS)) {
			console_server_reply_to_client("550 STARTTLS support must turn on");
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
		resource_set_string(RES_SMTP_FORCE_STARTTLS, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(SMTP_FORCE_STARTTLS, necessary_tls);
		console_server_reply_to_client("250 force-tls set OK");
		return TRUE;
	}

	if (0 == strcmp(argv[2], "auth-times")) {
		if ((value = atol(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid auth-times %s",
				argv[3]);
			return TRUE;
		}
		resource_set_integer(RES_SMTP_AUTH_TIMES, value);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(MAX_AUTH_TIMES, value);
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
		smtp_parser_set_param(BLOCK_TIME_EXCEED_AUTHS, value);
		console_server_reply_to_client("250 block-interval-auth set OK");
		return TRUE;
	}
	if (0 == strcmp(argv[2], "block-interval-sessions")) {
		if ((value = atoitvl(argv[3])) <= 0) {
			console_server_reply_to_client("550 invalid "
				"block-interval-sessions %s", argv[3]);
			return TRUE;
		}
		resource_set_string(RES_BLOCK_INTERVAL_SESSIONS, argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
			return TRUE;
		}
		smtp_parser_set_param(BLOCK_TIME_EXCEED_SESSIONS, value);
		console_server_reply_to_client("250 block-interval-sessions set OK");
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
	int current_thread_num, flushing_context_num;
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
	if (4 == argc && 0 == strcmp(argv[1], "set") &&
		0 == strcmp(argv[2], "domain-list")) {
		if (0 == strcasecmp(argv[3], "TRUE")) {
			resource_set_string(RES_DOMAIN_LIST_VALID, "TRUE");
			if (FALSE == resource_save()) {
				console_server_reply_to_client("550 fail to save config file");
				return TRUE;
			}
			smtp_parser_validate_domainlist(TRUE);
			console_server_reply_to_client("250 domain-list valid set OK");
			return TRUE;
		} else if (0 == strcasecmp(argv[3], "FALSE")) {
			if (SMTP_MODE_MIXTURE == smtp_parser_get_param(SMTP_RUNNING_MODE)) {
				console_server_reply_to_client("550 fail to invalidate domain "
					"list under mixture mode");
				return TRUE;
			}
			resource_set_string(RES_DOMAIN_LIST_VALID, "FALSE");
			if (FALSE == resource_save()) {
				console_server_reply_to_client("550 fail to save config file");
				return TRUE;
			}
			smtp_parser_validate_domainlist(FALSE);
			console_server_reply_to_client("250 domain-list invalid set OK");
			return TRUE;
		} else {
			console_server_reply_to_client("550 invalid parameter, should be"
					"TRUE or FALSE");
			return TRUE;
		}
	}
	
	if (2 == argc && 0 == strcmp(argv[1], "stop")) {
		console_server_notify_main_stop();
		console_server_reply_to_client("250 stop OK");
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "status")) {
		max_context_num     = contexts_pool_get_param(MAX_CONTEXTS_NUM);
		parsing_context_num = contexts_pool_get_param(CUR_VALID_CONTEXTS);
		flushing_context_num= contexts_pool_get_param(CUR_SLEEPING_CONTEXTS);
		block_allocator     = blocks_allocator_get_allocator();
		max_block_num       = lib_buffer_get_param(block_allocator, MEM_ITEM_NUM);
		block_size          = lib_buffer_get_param(block_allocator, MEM_ITEM_SIZE);
		current_alloc_num   = lib_buffer_get_param(block_allocator, ALLOCATED_NUM);
		current_thread_num  = threads_pool_get_param(THREADS_POOL_CUR_THR_NUM);
		console_server_reply_to_client("250 smtp system running status of %s:\r\n"
			"\tmaximum contexts number      %d\r\n"
			"\tcurrent parsing contexts     %d\r\n"
			"\tcurrent flushing contexts    %d\r\n"
			"\tmaximum memory blocks        %ld\r\n"
			"\tmemory block size            %ldK\r\n"
			"\tcurrent allocated blocks     %ld\r\n"
			"\tcurrent threads number       %d\r\n"
			"\tdomain list valid            %s",
			resource_get_string(RES_HOST_ID),
			max_context_num,
			parsing_context_num,
			flushing_context_num,
			max_block_num,
			block_size / 1024,
			current_alloc_num,
			current_thread_num,
			smtp_parser_domainlist_valid() == FALSE ? "FALSE" : "TRUE");
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "version")) {
		console_server_reply_to_client("250 SMTP DAEMON information:\r\n"
			"\tversion                     %s\r\n"
			"\tbuilt in                    %s",
			PROJECT_VERSION, SMTP_BUILT_DATE);
			return TRUE;
	}

	console_server_reply_to_client("550 invalid argument %s", argv[1]);
	return TRUE;
}

BOOL cmd_handler_flusher_control(int argc, char** argv)
{

	static char result[TALK_BUFFER_LEN];

	memset(result, '\0', TALK_BUFFER_LEN);
	flusher_console_talk(argc, argv, result, TALK_BUFFER_LEN);
	if (0 == strlen(result)) {
		strncpy(result, "550 flusher plugin console talk is error "
				"implemented!!!", sizeof(result) - 1);
		result[sizeof(result) - 1] = '\0';
	}
	console_server_reply_to_client("%s", result);
	return TRUE;
}


BOOL cmd_handler_as_plugins(int argc, char** argv)
{
	char buf[TALK_BUFFER_LEN];
	
	memset(buf, 0, TALK_BUFFER_LEN);
	if (PLUGIN_TALK_OK == 
		anti_spamming_console_talk(argc, argv, buf, TALK_BUFFER_LEN)) {
		if (strlen(buf) == 0) {
			strncpy(buf, "550 anti-spamming plugin console talk is error "
					"implemented!!!", sizeof(buf) - 1);
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
					"implemented!!!", sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = '\0';
		}
		console_server_reply_to_client("%s", buf);
		return TRUE;
	}
	return FALSE;
}
