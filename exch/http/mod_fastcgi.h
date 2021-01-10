#pragma once
#ifdef __cplusplus
#	include <cstdint>
#	include <ctime>
#else
#	include <stdint.h>
#	include <time.h>
#endif
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#define RESPONSE_TIMEOUT				-1
#define RESPONSE_WAITING				0
#define RESPONSE_AVAILABLE				1

struct FASTCGI_NODE {
	DOUBLE_LIST_NODE node;
	char *domain;
	char *path;
	char *directory;
	char *suffix;
	char *index;
	DOUBLE_LIST header_list;
	char *sock_path;
};

struct FASTCGI_CONTEXT {
	BOOL b_index;
	BOOL b_chunked;
	uint32_t chunk_size;
	uint32_t chunk_offset; 
	BOOL b_end;
	uint64_t content_length;
	FASTCGI_NODE *pfnode;
	int cache_fd;
	uint64_t cache_size;
	int cli_sockd;
	BOOL b_header; /* is response header met */
	time_t last_time;
};

struct HTTP_CONTEXT;

void mod_fastcgi_init(int context_num, const char *list_path,
	uint64_t cache_size, uint64_t max_size, int exec_timeout);
extern int mod_fastcgi_run(void);
extern void mod_fastcgi_stop(void);
extern void mod_fastcgi_free(void);
BOOL mod_fastcgi_get_context(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_check_end_of_read(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_check_responded(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_relay_content(HTTP_CONTEXT *phttp);

void mod_fastcgi_put_context(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_write_request(HTTP_CONTEXT *phttp);

int mod_fastcgi_check_response(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_read_response(HTTP_CONTEXT *phttp);
