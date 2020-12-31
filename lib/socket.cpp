// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <gromox/defs.h>
#include <gromox/socket.h>
#include <gromox/tie.hpp>

using namespace gromox;

/**
 * Return the pointer to the singular colon character, any other input
 * yields nullptr.
 */
static inline const char *has_exactly_one_colon(const char *s)
{
	s = strchr(s, ':');
	if (s == nullptr)
		return nullptr;
	return strchr(s + 1, ':') == nullptr ? s : nullptr;
}

/**
 * @spec:	"[" HOST-ANY "]" [ ":" PORT ]
 * 		HOST-NAME [ ":" PORT ]
 * 		HOST-IPV4 [ ":" PORT ]
 * 		HOST-IPV6
 * @host:	buffer for placing the extracted hostname
 * 		(can overlap @spec)
 * @hsize:	buffer size for @host
 * @port:	storage space for extracted port number
 * 		(can be nullptr)
 *
 * Returns <0 (error code) if unparsable or if the output buffer is too small.
 * Success if on >=0.
 */
int gx_addrport_split(const char *spec, char *host,
    size_t hbufsz, uint16_t *pport)
{
	if (*spec == '[') {
		/* We also happen to allow IPv4 addrs and hostnames in [] */
		++spec;
		auto end = strchr(spec, ']');
		if (end == nullptr)
			return -EINVAL;
		unsigned long hlen = end - spec;
		if (hlen >= hbufsz)
			return -E2BIG;
		if (*++end == '\0')
			return 1;
		if (*end++ != ':')
			return -EINVAL;
		char *nend = nullptr;
		uint16_t port = strtoul(end, &nend, 10);
		if (nend == nullptr || *nend != '\0')
			return -EINVAL;
		memmove(host, spec, hlen);
		host[hlen] = '\0';
		if (pport == nullptr)
			return 2;
		*pport = port;
		return 2;
	}
	auto onecolon = has_exactly_one_colon(spec);
	if (onecolon != nullptr) {
		unsigned long hlen = onecolon - spec;
		if (hlen >= hbufsz)
			return -E2BIG;
		char *nend = nullptr;
		uint16_t port = strtoul(onecolon + 1, &nend, 10);
		if (nend == nullptr || *nend != '\0')
			return -EINVAL;
		memmove(host, spec, hlen);
		host[hlen] = '\0';
		if (pport == nullptr)
			return 2;
		*pport = port;
		return 2;
	}
	auto hlen = strlen(spec) + 1;
	if (hlen >= hbufsz)
		return -E2BIG;
	memmove(host, spec, hlen);
	return 1;
}

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
