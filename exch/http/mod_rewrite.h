#pragma once
#include <gromox/common_types.hpp>
#include <gromox/mem_file.hpp>

extern int mod_rewrite_run(const char *sdlist);
BOOL mod_rewrite_process(const char *uri_buff,
	int uri_len, MEM_FILE *pf_request_uri);
