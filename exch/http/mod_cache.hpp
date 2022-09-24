#pragma once
#include <gromox/common_types.hpp>

struct http_context;
using HTTP_CONTEXT = http_context;
extern void mod_cache_init(int context_num);
extern int mod_cache_run();
extern void mod_cache_stop();
extern bool mod_cache_is_in_charge(HTTP_CONTEXT *);
extern bool mod_cache_take_request(HTTP_CONTEXT *);
void mod_cache_put_context(HTTP_CONTEXT *phttp);
BOOL mod_cache_check_responded(HTTP_CONTEXT *phttp);
BOOL mod_cache_read_response(HTTP_CONTEXT *phttp);
