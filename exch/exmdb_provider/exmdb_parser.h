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

#ifdef __cplusplus
extern "C" {
#endif

int exmdb_parser_get_param(int param);

void exmdb_parser_init(int max_threads,
	int max_routers, const char *list_path);
extern int exmdb_parser_run(void);
extern int exmdb_parser_stop(void);
extern void exmdb_parser_free(void);
extern EXMDB_CONNECTION *exmdb_parser_get_connection(void);
void exmdb_parser_put_connection(EXMDB_CONNECTION *pconnection);

ROUTER_CONNECTION* exmdb_parser_get_router(const char *remote_id);

void exmdb_parser_put_router(ROUTER_CONNECTION *pconnection);

BOOL exmdb_parser_remove_router(ROUTER_CONNECTION *pconnection);

#ifdef __cplusplus
} /* extern "C" */
#endif
