#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include <netdb.h>

#ifdef __cplusplus
struct gx_sock_free {
	void operator()(struct addrinfo *a) { freeaddrinfo(a); }
};

extern "C" {
#endif

extern int gx_addrport_split(const char *spec, char *host, size_t hsize, uint16_t *port);
extern int gx_inet_connect(const char *host, uint16_t port, unsigned int oflags);

#ifdef __cplusplus
} /* extern "C" */
#endif
