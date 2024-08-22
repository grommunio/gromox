#pragma once
#include <gromox/common_types.hpp>
#include <gromox/http.hpp>

struct http_context;
using HTTP_CONTEXT = http_context;
extern void mod_cache_init(int context_num);
extern int mod_cache_run();
extern void mod_cache_stop();
extern bool mod_cache_is_in_charge(HTTP_CONTEXT *);
extern http_status mod_cache_take_request(http_context *);
extern void mod_cache_insert_ctx(http_context *);
BOOL mod_cache_check_responded(HTTP_CONTEXT *phttp);
BOOL mod_cache_read_response(HTTP_CONTEXT *phttp);
extern bool mod_cache_discard_content(http_context *);
