#pragma once
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#include <pthread.h>


enum {
	ALIVE_ROUTER_CONNECTIONS
};

struct EXMDB_CONNECTION {
	DOUBLE_LIST_NODE node;
	BOOL b_stop;
	pthread_t thr_id;
	char remote_id[128];
	int sockd;
};

struct ROUTER_CONNECTION {
	DOUBLE_LIST_NODE node;
	BOOL b_stop;
	pthread_t thr_id;
	char remote_id[128];
	int sockd;
	time_t last_time;
	pthread_mutex_t lock;
	pthread_mutex_t cond_mutex;
	pthread_cond_t waken_cond;
	DOUBLE_LIST datagram_list;
};

int exmdb_parser_get_param(int param);
extern void exmdb_parser_init(int max_threads, int max_routers);
extern int exmdb_parser_run(const char *config_path);
extern int exmdb_parser_stop();
extern void exmdb_parser_free();
extern EXMDB_CONNECTION *exmdb_parser_get_connection();
void exmdb_parser_put_connection(EXMDB_CONNECTION *pconnection);

ROUTER_CONNECTION* exmdb_parser_get_router(const char *remote_id);

void exmdb_parser_put_router(ROUTER_CONNECTION *pconnection);

BOOL exmdb_parser_remove_router(ROUTER_CONNECTION *pconnection);
