#pragma once
#include <unistd.h>
#include <openssl/ssl.h>
#include <gromox/clock.hpp>
#include <gromox/defs.h>

struct GX_EXPORT GENERIC_CONNECTION {
	GENERIC_CONNECTION() = default;
	~GENERIC_CONNECTION() { reset(); }
	NOMOVE(GENERIC_CONNECTION);

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

	char client_ip[40]{}; /* client ip address string */
	char server_ip[40]{}; /* server ip address */
	uint16_t client_port = 0, server_port = 0;
	int sockd = -1; /* context's socket file description */
	SSL *ssl = nullptr;
	gromox::time_point last_timestamp; /* last time when system got data from */
};
