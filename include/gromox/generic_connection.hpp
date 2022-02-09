#pragma once
#include <openssl/ssl.h>
#include <gromox/clock.hpp>
struct GENERIC_CONNECTION {
	char client_ip[40]{}; /* client ip address string */
	char server_ip[40]{}; /* server ip address */
	uint16_t client_port = 0, server_port = 0;
	int sockd{}; /* context's socket file description */
	SSL *ssl = nullptr;
	gromox::time_point last_timestamp; /* last time when system got data from */
};
