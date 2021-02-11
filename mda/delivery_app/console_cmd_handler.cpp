// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include "console_cmd_handler.h"
#include <gromox/console_server.hpp>
#include <gromox/common_types.hpp>
#include "message_dequeue.h"
#include "transporter.h"
#include "resource.h"
#include "service.h"
#include <gromox/util.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#define PLUG_BUFFER_SIZE        4096*4
#define TALK_BUFFER_LEN         65536

static char g_server_help[] =
	"250 DELIVERY APP server help information:\r\n"
	"\tsystem         --control the DELIVERY APP server\r\n"
	"\ttype \"<control-unit> --help\" for more information";

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
	
BOOL cmd_handler_help(int argc, char** argv)
{
	if (1 != argc) {
		console_server_reply_to_client("550 too many arguments");
	} else {
		console_server_reply_to_client(g_server_help);
	}
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
		console_server_reply_to_client("250 default domain set OK");
		return TRUE;
	}

	if (4 == argc && 0 == strcmp(argv[1], "set") &&
		0 == strcmp(argv[2], "admin-mailbox")) {
		resource_set_string("ADMIN_MAILBOX", argv[3]);
		console_server_reply_to_client("250 administrator's mailbox set OK");
		return TRUE;
	}

	if (4 == argc && 0 == strcmp(argv[1], "set") &&
		0 == strcmp(argv[2], "domain-list")) {
		if (0 == strcasecmp(argv[3], "TRUE")) {
			resource_set_string("DOMAIN_LIST_VALID", "TRUE");
			transporter_validate_domainlist(TRUE);
			console_server_reply_to_client("250 domain-list valid set OK");
			return TRUE;
		} else if (0 == strcasecmp(argv[3], "FALSE")) {
			resource_set_string("DOMAIN_LIST_VALID", "FALSE");
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
				"error implemented", sizeof(buf) - 1);
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
