#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <utility>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/generic_connection.hpp>

class config_file;

class parser_thread : public generic_connection {
	public:
	parser_thread(parser_thread &&);
	parser_thread(generic_connection &&);
	~parser_thread();
	void signal_stop();
	void close_fd();
	void join();

	gromox::atomic_bool b_stop{false};
	pthread_t thr_id{};
	std::mutex thr_lock; /* protects thr_id */
	std::mutex fd_lock; /* protects generic_connection::* */
	std::string remote_id;
};

/* Represents a connection from an exmdb_client */
class exmdb_connection final : public parser_thread {
	public:
	exmdb_connection(generic_connection &&co) : parser_thread(std::move(co)) {}
};
using EXMDB_CONNECTION = exmdb_connection;

/**
 * Represents a connection from an exmdb_client which has been switched to
 * notification listening mode.
 */
struct router_connection final : public parser_thread {
	struct xbinary {
		std::unique_ptr<uint8_t[], gromox::stdlib_delete> pb;
		size_t cb = 0;
	};

	router_connection(parser_thread &&, std::string_view);
	void push_and_wake(BINARY &&);
	void signal_stop();

	time_t last_time = 0;
	std::mutex dg_lock; /* protects datagram_list */
	std::condition_variable waken_cond;
	std::list<xbinary> datagram_list;
};
using ROUTER_CONNECTION = router_connection;

extern void exmdb_parser_init(size_t max_threads, size_t max_routers);
extern void exmdb_parser_stop();
extern bool exmdb_parser_insert_conn(generic_connection &&);
extern std::shared_ptr<router_connection> exmdb_parser_get_router(const char *remote_id);
extern void exmdb_parser_insert_router(std::shared_ptr<ROUTER_CONNECTION> &&);
extern BOOL exmdb_parser_erase_router(const std::shared_ptr<ROUTER_CONNECTION> &);
extern int exmdb_pickup(int control_fd);
extern int exmdb_listener_init(const config_file &gxcfg, const config_file &oldcfg);
extern int exmdb_listener_run(const char *config_path, const config_file &gxcfg);
extern void exmdb_listener_stop();
extern int exmdb_pickup_run(int fd);
extern bool exmdb_pickup_running();
extern void exmdb_pickup_stop();

extern std::atomic<unsigned int> g_exrpc_debug, g_enable_dam, g_istore_standalone;
extern std::string g_host_id;
