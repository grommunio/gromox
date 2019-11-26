#ifndef _H_MOD_FASTCGI_
#define _H_MOD_FASTCGI_
#include "common_types.h"
#include "double_list.h"
#include <stdint.h>
#include <time.h>

#define RESPONSE_TIMEOUT				-1
#define RESPONSE_WAITING				0
#define RESPONSE_AVAILABLE				1

typedef struct _FASTCGI_NODE {
	DOUBLE_LIST_NODE node;
	char *domain;
	char *path;
	char *directory;
	char *suffix;
	char *index;
	DOUBLE_LIST header_list;
	char *sock_path;
} FASTCGI_NODE;

typedef struct _FASTCGI_CONTEXT {
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
} FASTCGI_CONTEXT;

struct _HTTP_CONTEXT;

typedef struct _HTTP_CONTEXT HTTP_CONTEXT;

void mod_fastcgi_init(int context_num, const char *list_path,
	uint64_t cache_size, uint64_t max_size, int exec_timeout);

int mod_fastcgi_run();

int mod_fastcgi_stop();

void mod_fastcgi_free();

BOOL mod_fastcgi_get_context(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_check_end_of_read(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_check_responded(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_relay_content(HTTP_CONTEXT *phttp);

void mod_fastcgi_put_context(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_write_request(HTTP_CONTEXT *phttp);

int mod_fastcgi_check_response(HTTP_CONTEXT *phttp);

BOOL mod_fastcgi_read_response(HTTP_CONTEXT *phttp);

#endif /* _H_MOD_FASTCGI_ */
