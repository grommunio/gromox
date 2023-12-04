#pragma once
#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>

class EXMDB_CONNECTION : public std::enable_shared_from_this<EXMDB_CONNECTION> {
	public:
	EXMDB_CONNECTION() = default;
	~EXMDB_CONNECTION();
	NOMOVE(EXMDB_CONNECTION);

	gromox::atomic_bool b_stop{false};
	pthread_t thr_id{};
	std::string remote_id;
	int sockd = -1;
};

struct ROUTER_CONNECTION {
	ROUTER_CONNECTION() = default;
	NOMOVE(ROUTER_CONNECTION);
	~ROUTER_CONNECTION();

	gromox::atomic_bool b_stop{false};
	pthread_t thr_id{};
	std::string remote_id;
	int sockd = -1;
	time_t last_time = 0;
	std::mutex lock, cond_mutex;
	std::condition_variable waken_cond;
	std::list<BINARY> datagram_list; /* manual (de)allocation of .pb */
};

extern void exmdb_parser_init(size_t max_threads, size_t max_routers);
extern int exmdb_parser_run(const char *config_path);
extern void exmdb_parser_stop();
extern std::shared_ptr<EXMDB_CONNECTION> exmdb_parser_get_connection();
void exmdb_parser_put_connection(std::shared_ptr<EXMDB_CONNECTION> &&);
extern std::shared_ptr<ROUTER_CONNECTION> exmdb_parser_get_router(const char *remote_id);
extern void exmdb_parser_put_router(std::shared_ptr<ROUTER_CONNECTION> &&);
extern BOOL exmdb_parser_remove_router(const std::shared_ptr<ROUTER_CONNECTION> &);

extern unsigned int g_exrpc_debug, g_enable_dam;
extern unsigned int g_mbox_contention_warning, g_mbox_contention_reject;
