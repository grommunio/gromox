#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/generic_connection.hpp>

class config_file;

class EXMDB_CONNECTION : public GENERIC_CONNECTION {
	public:
	EXMDB_CONNECTION() = default;
	NOMOVE(EXMDB_CONNECTION);

	gromox::atomic_bool b_stop{false};
	pthread_t thr_id{};
	std::string remote_id;
};

struct ROUTER_CONNECTION {
	struct xbinary {
		std::unique_ptr<uint8_t[], gromox::stdlib_delete> pb;
		size_t cb = 0;
	};

	ROUTER_CONNECTION() = default;
	NOMOVE(ROUTER_CONNECTION);
	~ROUTER_CONNECTION();
	void push_and_wake(BINARY &&);

	gromox::atomic_bool b_stop{false};
	pthread_t thr_id{};
	std::string remote_id;
	int sockd = -1;
	time_t last_time = 0;
	std::mutex lock;
	std::condition_variable waken_cond;
	std::list<xbinary> datagram_list;
};
using router_connection = ROUTER_CONNECTION;

extern void exmdb_parser_init(size_t max_threads, size_t max_routers);
extern void exmdb_parser_stop();
extern bool exmdb_parser_insert_conn(generic_connection &&);
extern std::shared_ptr<router_connection> exmdb_parser_get_router(const char *remote_id);
extern void exmdb_parser_insert_router(std::shared_ptr<ROUTER_CONNECTION> &&);
extern BOOL exmdb_parser_erase_router(const std::shared_ptr<ROUTER_CONNECTION> &);
extern int exmdb_listener_init(const config_file &gxcfg, const config_file &oldcfg);
extern int exmdb_listener_run(const char *config_path, const config_file &gxcfg);
extern void exmdb_listener_stop();

extern std::atomic<unsigned int> g_exrpc_debug, g_enable_dam;
extern std::string g_host_id;
