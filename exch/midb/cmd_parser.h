#pragma once
#include <list>
#include <pthread.h>
#include <gromox/double_list.hpp>

struct midb_conn {
	~midb_conn();

	DOUBLE_LIST_NODE node{};
	int sockd = -1;
	BOOL is_selecting = false;
	pthread_t thr_id{};
};
using MIDB_CONNECTION = midb_conn;

using MIDB_CMD_HANDLER = int (*)(int argc, char **argv, int sockd);

extern void cmd_parser_init(unsigned int threads_num, int timeout, unsigned int debug);
extern int cmd_parser_run();
extern void cmd_parser_stop();
extern std::list<midb_conn> cmd_parser_get_connection();
extern void cmd_parser_put_connection(std::list<midb_conn> &&);
extern void cmd_parser_register_command(const char *command, MIDB_CMD_HANDLER);
extern int cmd_write(int fd, const char *buf, size_t size = -1) __attribute__((warn_unused_result));

extern unsigned int g_cmd_debug;
