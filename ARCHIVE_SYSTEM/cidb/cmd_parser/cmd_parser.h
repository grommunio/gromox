#ifndef _H_CMD_PARSER_
#define _H_CMD_PARSER_

#include "double_list.h"
#include <pthread.h>


typedef struct _CONNECTION {
	DOUBLE_LIST_NODE node;
	int sockd;
	BOOL is_selecting;
	pthread_t thr_id;
} CONNECTION;

typedef int (*COMMAND_HANDLER)(int argc, char** argv, int sockd);

void cmd_parser_init(int threads_num, int timeout);

int cmd_parser_run();

int cmd_parser_stop();

void cmd_parser_free();

CONNECTION* cmd_parser_get_connection();

void cmd_parser_put_connection(CONNECTION *pconnection);

void cmd_parser_register_command(const char *command, COMMAND_HANDLER handler);

#endif
