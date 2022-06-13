#pragma once
#include <gromox/common_types.hpp>

struct HTTP_CONTEXT;
extern void mod_cache_init(int context_num);
extern int mod_cache_run();
extern void mod_cache_stop();
BOOL mod_cache_check_caching(HTTP_CONTEXT *phttp);
BOOL mod_cache_get_context(HTTP_CONTEXT *phttp);
void mod_cache_put_context(HTTP_CONTEXT *phttp);
BOOL mod_cache_check_responded(HTTP_CONTEXT *phttp);
BOOL mod_cache_read_response(HTTP_CONTEXT *phttp);
