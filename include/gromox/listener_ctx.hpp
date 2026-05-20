#pragma once
#include <cstdint>
#include <memory>
#include <pthread.h>
#include <vector>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/poll_ctx.hpp>

struct generic_connection;

namespace gromox {

class GX_EXPORT listener_ctx {
	public:
	struct socket_desc {
		int fd = -1;
		unsigned int mark = 0;
	};

	listener_ctx() = default;
	NOMOVE(listener_ctx);
	~listener_ctx() { reset(); }
	void reset();
	errno_t add_inet(const char *addr, uint16_t port, unsigned int mark = 0);
	errno_t add_local(const char *path, unsigned int mark = 0);
	errno_t add_bunch(const char *line, unsigned int mark = 0);
	errno_t watch_start(atomic_bool &stop, int (*cb)(generic_connection &&));
	void watch_stop();
	bool empty() const { return m_sockets.size() == 0; }

	protected:
	static void *listener_thread(void *);

	atomic_bool *m_stop = nullptr;
	int (*m_callback)(generic_connection &&);
	poll_ctx m_poller;
	pthread_t m_thr_id{};
	public:
	unsigned int m_haproxy_level = 0;
	protected:
	std::vector<socket_desc> m_sockets;
	public:
	std::string m_thread_name;
};

}
