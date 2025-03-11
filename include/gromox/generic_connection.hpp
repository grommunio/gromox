#pragma once
#include <unistd.h>
#include <openssl/ssl.h>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/defs.h>

struct GX_EXPORT generic_connection {
	generic_connection() = default;
	generic_connection(generic_connection &&);
	~generic_connection() { reset(); }
	generic_connection &operator=(generic_connection &&);

	static generic_connection accept(int listen_fd, int haproxy_level, gromox::atomic_bool *stop_accept);

	void reset(bool slp = 0) noexcept
	{
		if (ssl != nullptr) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
			ssl = nullptr;
		}
		if (sockd >= 0) {
			if (slp)
				::usleep(1000);
			::close(sockd);
			sockd = -1;
		}
	}

	ssize_t write(const void *buf, size_t z)
	{
		return ssl != nullptr ? SSL_write(ssl, buf, z) :
		       ::write(sockd, buf, z);
	}

	char client_addr[40]{}, server_addr[40]{};
	uint16_t client_port = 0, server_port = 0;
	int sockd = -1; /* context's socket file description */
	SSL *ssl = nullptr;
	gromox::time_point last_timestamp; /* last time when system got data from */
};
using GENERIC_CONNECTION = generic_connection;
