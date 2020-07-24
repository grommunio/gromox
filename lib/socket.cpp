/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cerrno>
#include <cstdio>
#include <memory>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <gromox/defs.h>
#include <gromox/socket.h>
#include <gromox/tie.hpp>

using namespace gromox;

int gx_inet_connect(const char *host, uint16_t port, unsigned int oflags)
{
	static constexpr struct addrinfo hints =
		{AI_V4MAPPED | AI_ADDRCONFIG, 0, SOCK_STREAM, IPPROTO_TCP};
	std::unique_ptr<addrinfo, gx_sock_free> aires;

	char portbuf[16];
	snprintf(portbuf, sizeof(portbuf), "%hu", port);
	int ret = getaddrinfo(host, port == 0 ? nullptr : portbuf, &hints, &unique_tie(aires));
	if (ret != 0) {
		printf("Could not resolve [%s]:%s: %s\n",
		       host, portbuf, gai_strerror(ret));
		return EHOSTUNREACH;
	}
	int saved_errno = 0, fd = -1;
	for (auto r = aires.get(); r != nullptr; r = r->ai_next) {
		fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (fd < 0) {
			saved_errno = errno;
			continue;
		}
		if (oflags & O_NONBLOCK) {
			int flags = 0;
			fcntl(fd, F_GETFL, 0);
			flags |= O_NONBLOCK;
			if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
				saved_errno = errno;
				close(fd);
				fd = -1;
				continue;
			}
		}
		ret = connect(fd, r->ai_addr, r->ai_addrlen);
		if (ret != 0) {
			if ((errno == EWOULDBLOCK || errno == EINPROGRESS) &&
			    (oflags & O_NONBLOCK))
				break;
			saved_errno = errno;
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}
	if (fd >= 0)
		return fd;
	return -(errno = saved_errno);
}
