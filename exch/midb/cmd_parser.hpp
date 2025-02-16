#pragma once
#include <list>
#include <pthread.h>
#include <gromox/double_list.hpp>
#include <gromox/generic_connection.hpp>

struct midb_conn : public generic_connection {
	DOUBLE_LIST_NODE node{};
	BOOL is_selecting = false;
	pthread_t thr_id{};
};
using MIDB_CONNECTION = midb_conn;

using MIDB_CMD_HANDLER = int (*)(int argc, char **argv, int sockd);

struct midb_cmd {
	MIDB_CMD_HANDLER func = nullptr;
	int min_args = 1, max_args = 0;
};

extern void cmd_parser_init(unsigned int threads_num, int timeout, unsigned int debug);
extern int cmd_parser_run();
extern void cmd_parser_stop();
extern std::list<midb_conn> cmd_parser_make_conn();
extern void cmd_parser_insert_conn(std::list<midb_conn> &&);
extern void cmd_parser_register_command(const char *command, const midb_cmd &);
extern int cmd_write(int fd, const char *buf, size_t size = -1) __attribute__((warn_unused_result));

extern unsigned int g_cmd_debug;
