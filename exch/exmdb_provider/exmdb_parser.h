#pragma once
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
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
	ROUTER_CONNECTION();
	ROUTER_CONNECTION(ROUTER_CONNECTION &&) = delete;
	~ROUTER_CONNECTION();
	void operator=(ROUTER_CONNECTION &&) = delete;

	BOOL b_stop = false;
	pthread_t thr_id{};
	std::string remote_id;
	int sockd = -1;
	time_t last_time = 0;
	std::mutex lock, cond_mutex;
	std::condition_variable waken_cond;
	DOUBLE_LIST datagram_list{};
};

int exmdb_parser_get_param(int param);
extern void exmdb_parser_init(size_t max_threads, size_t max_routers);
extern int exmdb_parser_run(const char *config_path);
extern int exmdb_parser_stop();
extern void exmdb_parser_free();
extern EXMDB_CONNECTION *exmdb_parser_get_connection();
void exmdb_parser_put_connection(EXMDB_CONNECTION *pconnection);
extern std::shared_ptr<ROUTER_CONNECTION> exmdb_parser_get_router(const char *remote_id);
extern void exmdb_parser_put_router(std::shared_ptr<ROUTER_CONNECTION> &&);
extern BOOL exmdb_parser_remove_router(const std::shared_ptr<ROUTER_CONNECTION> &);
