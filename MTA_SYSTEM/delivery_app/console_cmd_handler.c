#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include "console_cmd_handler.h"
#include "console_server.h"
#include "common_types.h"
#include "message_dequeue.h"
#include "transporter.h"
#include "resource.h"
#include "service.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536

static char g_plugname_buffer[PLUG_BUFFER_SIZE + 2];
static int g_plugname_buffer_size;

static char g_server_help[] =
	"250 DELIVERY APP server help information:\r\n"
	"\tservice        --control service plugins\r\n"
	"\tmpc            --control message process chain\r\n"
	"\tsystem         --control the DELIVERY APP server\r\n"
	"\ttype \"<control-unit> --help\" for more information";

static char g_service_help[] =
	"250 DELIVERY APP service plugins help information:\r\n"
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

static char g_mpc_help[] =
	"250 DELIVERY APP message process chain help information:\r\n"
	"\tmpc info\r\n"
	"\t    --print the plug-in info\r\n"
	"\tmpc load <name>\r\n"
	"\t    --load the specified plug-in\r\n"
	"\tmpc unload <name>\r\n"
	"\t    --unload the specified plug-in\r\n";

static char g_system_help[] =
	"250 DELIVERY APP system help information:\r\n"
	"\tsystem set default-domain <domain>\r\n"
	"\t    --set default domain of system\r\n"
	"\tsystem set admin-mailbox <mailbox>\r\n"
	"\t    --set administrator's mailbox address\r\n"
	"\tsystem set domain-list <TRUE|FALSE>\r\n"
	"\t    --validate or invalidate domain list in system\r\n"
	"\tsystem status\r\n"
	"\t    --printf the system running information\r\n"
    "\tsystem stop\r\n"
    "\t    --stop the server\r\n"
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
        case PLUGIN_FAIL_EXECUTEMAIN:
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


static void cmd_handler_dump_plugname(const char* plugname)
{
	if (g_plugname_buffer_size < PLUG_BUFFER_SIZE - strlen(plugname) - 3) {
    	g_plugname_buffer_size += snprintf(g_plugname_buffer + 
        	g_plugname_buffer_size, PLUG_BUFFER_SIZE - g_plugname_buffer_size,
			"\t%s\r\n", plugname);
	}
}

/*
 *  mpc plug-in control, which can print all the plug-in information,
 *  load and unload the specified plug-in dynamicly. usage:
 *      mpc info          // print the plug-in info
 *      mpc load   <name> // load the specified plug-in
 *      mpc unload <name> // unload the specified plug-in
 */
BOOL cmd_handler_mpc_control(int argc, char** argv)
{
	int result = 0;
	char *ptr;

	if (1 == argc) {
		console_server_reply_to_client("550 too few arguments");
		return TRUE;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		console_server_reply_to_client(g_mpc_help);
		return TRUE;
	}

	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		g_plugname_buffer_size = 0;
		transporter_enum_plugins(cmd_handler_dump_plugname);
		g_plugname_buffer[g_plugname_buffer_size] = '\0';
		console_server_reply_to_client("250 loaded message process chian "
				"plugins\r\n%s", g_plugname_buffer);
		g_plugname_buffer_size = 0;
		return TRUE;
	}
	if (3 == argc && 0 == strcmp(argv[1], "load")) {
		result = transporter_load_library(argv[2]);
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
		case PLUGIN_FAIL_EXECUTEMAIN:
		    console_server_reply_to_client("550 fail to execute plugin's "
					                    "init function");
			break;
		default:
			console_server_reply_to_client("550 unknown error");
		}
		return TRUE;
	}

	if (3 == argc && 0 == strcmp(argv[1], "unload")) {
		ptr = strchr(argv[2], '/');
		if (NULL == ptr) {
			ptr = argv[2];
		}
		if (0 == strcmp(ptr, transporter_get_local())) {
			console_server_reply_to_client("550 local hook plug-in can not be "
					"unloaded");
			return TRUE;
		}
		if (0 == strcmp(ptr, transporter_get_remote())) {
			console_server_reply_to_client("550 remote hook plug-in can not be"
					" unloaded");
			return TRUE;
		}
		result = transporter_unload_library(argv[2]);
		switch (result) {
		case PLUGIN_UNLOAD_OK:
			console_server_reply_to_client("250 unload %s OK", argv[2]);
			return TRUE;
		case PLUGIN_NOT_FOUND:
		    console_server_reply_to_client("550 no such plug-in running");
	        return TRUE;
	    case PLUGIN_SYSTEM_ERROR:
	        console_server_reply_to_client("550 information in message process"
					" chain module diff with the current plug-in");
	        return TRUE;
	    default:
	        console_server_reply_to_client("550 unknown error");
	        return TRUE;
	    }
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

	if (4 == argc && 0 == strcmp(argv[1], "set") &&
		0 == strcmp(argv[2], "default-domain")) {
		resource_set_string("DEFAULT_DOMAIN", argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
		} else {
			console_server_reply_to_client("250 default domain set OK");
		}
		return TRUE;
	}

	if (4 == argc && 0 == strcmp(argv[1], "set") &&
		0 == strcmp(argv[2], "admin-mailbox")) {
		resource_set_string("ADMIN_MAILBOX", argv[3]);
		if (FALSE == resource_save()) {
			console_server_reply_to_client("550 fail to save config file");
		} else {
			console_server_reply_to_client("250 administrator's mailbox set OK");
		}
		return TRUE;
	}

	if (4 == argc && 0 == strcmp(argv[1], "set") &&
		0 == strcmp(argv[2], "domain-list")) {
		if (0 == strcasecmp(argv[3], "TRUE")) {
			resource_set_string("DOMAIN_LIST_VALID", "TRUE");
			if (FALSE == resource_save()) {
				console_server_reply_to_client("550 fail to save config file");
				return TRUE;
			}
			transporter_validate_domainlist(TRUE);
			console_server_reply_to_client("250 domain-list valid set OK");
			return TRUE;
		} else if (0 == strcasecmp(argv[3], "FALSE")) {
			resource_set_string("DOMAIN_LIST_VALID", "FALSE");
			if (FALSE == resource_save()) {
				console_server_reply_to_client("550 fail to save config file");
				return TRUE;
			}
			transporter_validate_domainlist(FALSE);
			console_server_reply_to_client("250 domain-list invalid set OK");
			return TRUE;
		} else {
			 console_server_reply_to_client("550 invalid parameter, should be"
					"TRUE or FALSE");
			return TRUE;
		}
	}
	
	if (2 == argc && 0 == strcmp(argv[1], "status")) {
		console_server_reply_to_client("250 running information of %s:\r\n"
			"\tminimum threads number in pool       %d\r\n"
			"\tmaximum threads number in pool       %d\r\n"
			"\tcreated threads number in pool       %d\r\n"
			"\tprocessing threads number in pool    %d\r\n"
			"\tholding messages number in queue     %d\r\n"
			"\tdequeued messages number from queue  %d\r\n"
			"\tallocated message blocks number      %d\r\n"
			"\tdomain list valid                    %s",
			resource_get_string("HOST_ID"),
			transporter_get_param(TRANSPORTER_MIN_THREADS),
			transporter_get_param(TRANSPORTER_MAX_THREADS),
			transporter_get_param(TRANSPORTER_CREATED_THREADS),
			message_dequeue_get_param(MESSAGE_DEQUEUE_PROCESSING),
			message_dequeue_get_param(MESSAGE_DEQUEUE_HOLDING),
			message_dequeue_get_param(MESSAGE_DEQUEUE_DEQUEUED),
			message_dequeue_get_param(MESSAGE_DEQUEUE_ALLOCATED),
			transporter_domainlist_valid() == FALSE ? "FALSE" : "TRUE");
			return TRUE;	
	}
	
    if (2 == argc && 0 == strcmp(argv[1], "stop")) {
        console_server_notify_main_stop();
        console_server_reply_to_client("250 stop OK");
        return TRUE;
    }

    if (2 == argc && 0 == strcmp(argv[1], "version")) {
        console_server_reply_to_client("250 DELIVERY APP information:\r\n"
			"\tversion                     %s",
			PROJECT_VERSION);
            return TRUE;
    }
    console_server_reply_to_client("550 invalid argument %s", argv[1]);
    return TRUE;
}

BOOL cmd_handler_mpc_plugins(int argc, char** argv)
{
	char buf[TALK_BUFFER_LEN];

	memset(buf, 0, TALK_BUFFER_LEN);
	if (PLUGIN_TALK_OK ==
		transporter_console_talk(argc, argv, buf, TALK_BUFFER_LEN)) {
	    if (strlen(buf) == 0) {
		    strncpy(buf, "550 message process chain plugin console talk is "
					"error implemented!!!", sizeof(buf) - 1);
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
