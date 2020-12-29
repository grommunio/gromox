#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include <netdb.h>
#include <sys/socket.h>
#include <gromox/defs.h>

#ifdef __cplusplus
struct gx_sock_free {
	void operator()(struct addrinfo *a) { freeaddrinfo(a); }
};

extern "C" {
#endif

extern int gx_addrport_split(const char *spec, char *host, size_t hsize, uint16_t *port);
extern int gx_inet_connect(const char *host, uint16_t port, unsigned int oflags);
extern GX_EXPORT int gx_inet_listen(const char *host, uint16_t port);
extern GX_EXPORT int gx_peer_is_local2(const sockaddr *, socklen_t);
extern GX_EXPORT bool gx_peer_is_local(const char *);

#ifdef __cplusplus
} /* extern "C" */
#endif
