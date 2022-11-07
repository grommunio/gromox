// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#ifdef __linux__
#	include <linux/rtnetlink.h>
#endif
#include <libHX/socket.h>
#include <gromox/defs.h>
#include <gromox/socket.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>

using namespace gromox;

namespace {
struct sock_del {
	inline void operator()(struct addrinfo *a) const { freeaddrinfo(a); }
};
}

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

static std::unique_ptr<addrinfo, sock_del>
gx_inet_lookup(const char *host, uint16_t port, unsigned int xflags)
{
	struct addrinfo hints{};
#if defined(AI_V4MAPPED)
	hints.ai_flags    = AI_V4MAPPED | xflags;
#else
	hints.ai_flags    = xflags;
#endif
	hints.ai_family   = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	std::unique_ptr<addrinfo, sock_del> aires;

	char portbuf[16];
	snprintf(portbuf, sizeof(portbuf), "%hu", port);
	int ret = getaddrinfo(host, port == 0 ? nullptr : portbuf, &hints, &unique_tie(aires));
	if (ret != 0) {
		fprintf(stderr, "Could not resolve [%s]:%s: %s\n",
		       host, portbuf, gai_strerror(ret));
		return nullptr;
	}
	return aires;
}

int gx_inet_connect(const char *host, uint16_t port, unsigned int oflags)
{
	auto aires = gx_inet_lookup(host, port, AI_ADDRCONFIG);
	int saved_errno = 0;
	for (auto r = aires.get(); r != nullptr; r = r->ai_next) {
		int fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (fd < 0) {
			if (saved_errno == 0)
				saved_errno = errno;
			continue;
		}
		if (oflags & O_NONBLOCK) {
			int flags = fcntl(fd, F_GETFL, 0);
			if (flags < 0) {
				mlog(LV_WARN, "W-1391: fctnl: %s", strerror(errno));
				flags = 0;
			}
			flags |= O_NONBLOCK;
			if (fcntl(fd, F_SETFL, flags) != 0) {
				saved_errno = errno;
				close(fd);
				continue;
			}
		}
		auto ret = connect(fd, r->ai_addr, r->ai_addrlen);
		if (ret == 0)
			return fd;
		if ((errno == EWOULDBLOCK || errno == EINPROGRESS) &&
		    (oflags & O_NONBLOCK))
			return fd;
		saved_errno = errno;
		close(fd);
	}
	if (aires.get() == nullptr && saved_errno == 0)
		saved_errno = EHOSTUNREACH;
	return -(errno = saved_errno);
}

static int gx_gai_listen(const struct addrinfo *r)
{
	auto fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
	if (fd < 0)
		return -2;
	static const int y = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) < 0)
		mlog(LV_WARN, "W-1385: setsockopt: %s", strerror(errno));
	auto ret = bind(fd, r->ai_addr, r->ai_addrlen);
	if (ret != 0) {
		int se = errno;
		close(fd);
		errno = se;
		return -1;
	}
	ret = listen(fd, SOMAXCONN);
	if (ret != 0) {
		int se = errno;
		close(fd);
		errno = se;
		return -1;
	}
	return fd;
}

int gx_inet_listen(const char *host, uint16_t port)
{
	auto aires = gx_inet_lookup(host, port, AI_PASSIVE);
	int saved_errno = EHOSTUNREACH;
	auto use_env = getenv("HX_LISTEN_TOP_FD") != nullptr || getenv("LISTEN_FDS") != nullptr;
	for (auto r = aires.get(); r != nullptr; r = r->ai_next) {
		if (use_env) {
			auto fd = HX_socket_from_env(r, nullptr);
			if (fd >= 0)
				return fd;
		}
		auto fd = gx_gai_listen(r);
		if (fd >= 0)
			return fd;
		saved_errno = errno;
		if (fd == -2)
			continue;
		break;
	}
	return -(errno = saved_errno);
}

int gx_local_listen(const char *path, bool delete_on_create)
{
	struct sockaddr_un u;
	if (strlen(path) >= arsizeof(u.sun_path))
		return -EINVAL;
	u.sun_family = AF_LOCAL;
	strcpy(u.sun_path, path);
	struct addrinfo r{};
	r.ai_flags = AI_PASSIVE;
	r.ai_family = AF_LOCAL;
	r.ai_socktype = SOCK_STREAM;
	r.ai_addrlen = sizeof(u) - sizeof(u.sun_path) + strlen(u.sun_path) + 1;
	r.ai_addr = reinterpret_cast<struct sockaddr *>(&u);
	auto use_env = getenv("HX_LISTEN_TOP_FD") != nullptr || getenv("LISTEN_FDS") != nullptr;
	if (use_env) {
		auto fd = HX_socket_from_env(&r, nullptr);
		if (fd >= 0)
			return fd;
	}
	auto ret = gx_gai_listen(&r);
	if (ret >= 0)
		return ret; /* fd */
	if (ret == -2 || errno != EADDRINUSE)
		return -errno;
	int saved_errno = errno;
	struct stat sb;
	ret = stat(path, &sb);
	if (ret < 0 || !S_ISSOCK(sb.st_mode))
		return -saved_errno;
	/* There will be a TOCTOU report, but what can you do... */
	ret = unlink(path);
	if (ret < 0 && errno != ENOENT) {
		mlog(LV_ERR, "E-1400: unlink %s: %s", path, strerror(errno));
		return -errno;
	}
	ret = gx_gai_listen(&r);
	if (ret >= 0)
		return ret; /* fd */
	return -errno;
}

#ifdef __linux__
static int gx_peer_is_local3(int rsk, const void *buf, size_t bufsize)
{
	if (send(rsk, buf, bufsize, 0) < 0)
		return -errno;
	char rspbuf[4096];
	ssize_t ret = recv(rsk, rspbuf, sizeof(rspbuf), 0);
	if (ret < 0)
		return -errno;
	if (static_cast<size_t>(ret) < sizeof(struct nlmsghdr))
		return -ENODATA;
	auto nlh = reinterpret_cast<const struct nlmsghdr *>(rspbuf);
	if (!NLMSG_OK(nlh, nlh->nlmsg_len))
		return -EIO;
	auto rtm = reinterpret_cast<const struct rtmsg *>(NLMSG_DATA(nlh));
	return rtm->rtm_type == RTN_LOCAL;
}
#endif

int gx_peer_is_local2(const sockaddr *peer_sockaddr, socklen_t peer_socklen)
{
	if (peer_sockaddr->sa_family == AF_INET6) {
		if (peer_socklen < sizeof(sockaddr_in6))
			return -EIO;
	} else if (peer_sockaddr->sa_family == AF_INET) {
		if (peer_socklen < sizeof(sockaddr_in))
			return -EIO;
	} else {
		return -EPROTONOSUPPORT;
	}
#ifdef __linux__
	int rsk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (rsk < 0) {
		fprintf(stderr, "socket AF_NETLINK: %s\n", strerror(errno));
		return -errno;
	}
	struct {
		nlmsghdr nh;
		rtmsg rth;
		char attrbuf[4096];
	} req{};
	req.nh.nlmsg_len     = NLMSG_LENGTH(sizeof(req.rth));
	req.nh.nlmsg_flags   = NLM_F_REQUEST;
	req.nh.nlmsg_type    = RTM_GETROUTE;
	req.rth.rtm_family   = peer_sockaddr->sa_family;
	req.rth.rtm_protocol = RTPROT_UNSPEC;
	req.rth.rtm_type     = RTN_UNSPEC;
	req.rth.rtm_scope    = RT_SCOPE_UNIVERSE;
	req.rth.rtm_table    = RT_TABLE_UNSPEC;
	auto rta = reinterpret_cast<rtattr *>(reinterpret_cast<char *>(&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type        = RTA_DST;

	int ret = -ENODATA;
	if (peer_sockaddr->sa_family == AF_INET6) {
		auto &ad = reinterpret_cast<const sockaddr_in6 *>(peer_sockaddr)->sin6_addr;
		static constexpr uint8_t mappedv4[] =
			{0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
		req.rth.rtm_dst_len = sizeof(ad);
		if (memcmp(&ad, mappedv4, 12) == 0) {
			/* RTM_GETROUTE won't report RTN_LOCAL for ::ffff:127.0.0.1 */
			req.rth.rtm_family = AF_INET;
			rta->rta_len = RTA_LENGTH(sizeof(in_addr));
			req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;
			memcpy(RTA_DATA(rta), &ad.s6_addr[12], 4);
		} else {
			rta->rta_len = RTA_LENGTH(sizeof(ad));
			req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;
			memcpy(RTA_DATA(rta), &ad, sizeof(ad));
		}
	} else if (peer_sockaddr->sa_family == AF_INET) {
		auto &ad = reinterpret_cast<const sockaddr_in *>(peer_sockaddr)->sin_addr;
		req.rth.rtm_dst_len = sizeof(ad);
		rta->rta_len = RTA_LENGTH(sizeof(ad));
		req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;
		memcpy(RTA_DATA(rta), &ad, sizeof(ad));
	}
	ret = gx_peer_is_local3(rsk, &req, req.nh.nlmsg_len);
	close(rsk);
	return ret;
#endif
	return -EPROTONOSUPPORT;
}

bool gx_peer_is_local(const char *addr)
{
#if defined(AI_V4MAPPED)
	static constexpr struct addrinfo hints = {AI_V4MAPPED};
#else
	static constexpr struct addrinfo hints = {};
#endif
	std::unique_ptr<addrinfo, sock_del> aires;
	if (getaddrinfo(addr, nullptr, &hints, &unique_tie(aires)) < 0)
		return false;
	return gx_peer_is_local2(aires->ai_addr, aires->ai_addrlen) > 0;
}
