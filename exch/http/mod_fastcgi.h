#pragma once
#include <cstdint>
#include <ctime>
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>
#define RESPONSE_TIMEOUT				-1
#define RESPONSE_WAITING				0
#define RESPONSE_AVAILABLE				1

struct FASTCGI_NODE;

struct FASTCGI_CONTEXT {
	BOOL b_index = false, b_chunked = false, b_end = false;
	BOOL b_header = false; /* is response header met */
	uint32_t chunk_size = 0, chunk_offset = 0;
	uint64_t content_length = 0;
	const FASTCGI_NODE *pfnode = nullptr;
	uint64_t cache_size = 0;
	int cache_fd = -1, cli_sockd = -1;
	gromox::time_point last_time{};
	std::string tmpfile;
};

struct HTTP_CONTEXT;

extern void mod_fastcgi_init(int context_num, uint64_t cache_size, uint64_t max_size, gromox::time_duration exec_timeout);
extern int mod_fastcgi_run();
extern void mod_fastcgi_stop();
extern bool mod_fastcgi_take_request(HTTP_CONTEXT *);
BOOL mod_fastcgi_check_end_of_read(HTTP_CONTEXT *phttp);
BOOL mod_fastcgi_check_responded(HTTP_CONTEXT *phttp);
BOOL mod_fastcgi_relay_content(HTTP_CONTEXT *phttp);
void mod_fastcgi_put_context(HTTP_CONTEXT *phttp);
BOOL mod_fastcgi_write_request(HTTP_CONTEXT *phttp);
int mod_fastcgi_check_response(HTTP_CONTEXT *phttp);
BOOL mod_fastcgi_read_response(HTTP_CONTEXT *phttp);
