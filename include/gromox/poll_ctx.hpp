#pragma once
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <vector>
#include <gromox/defs.h>
#ifdef HAVE_SYS_EPOLL_H
#	include <sys/epoll.h>
#endif
#ifdef HAVE_SYS_EVENT_H
#	include <sys/event.h>
#endif

struct timespec;

namespace gromox {

class GX_EXPORT poll_ctx {
	public:
	poll_ctx() = default;
	~poll_ctx();
	NOMOVE(poll_ctx);
	void reset();
	errno_t init(int max_ev = 0);
	errno_t add(unsigned int mask, int fd, void *ctx = nullptr) { return addmod(mask, fd, ctx, true); }
	errno_t mod(unsigned int mask, int fd, void *ctx = nullptr) { return addmod(mask, fd, ctx, false); }
	errno_t del(int fd);
	int wait(const struct timespec * = nullptr, int max_ev = -1);
	void *data(unsigned int) const;

	static constexpr unsigned int polling_read = 0x1, polling_write = 0x2, level_trigger = 0x4;

	protected:
	errno_t addmod(unsigned int mask, int fd, void *ctx, bool am);

	int m_epfd = -1;
#ifdef HAVE_SYS_EPOLL_H
	std::vector<epoll_event> m_events;
#elif defined(HAVE_SYS_EVENT_H)
	std::vector<kevent> m_events;
#endif
};

}
