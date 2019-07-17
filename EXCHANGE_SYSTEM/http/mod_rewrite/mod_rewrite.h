#ifndef _H_MOD_REWRITE_
#define _H_MOD_REWRITE_
#include "common_types.h"
#include "mem_file.h"

void mod_rewrite_init(const char *list_path);

int mod_rewrite_run();

int mod_rewrite_stop();

void mod_rewrite_free();

BOOL mod_rewrite_process(const char *uri_buff,
	int uri_len, MEM_FILE *pf_request_uri);

#endif /* _H_MOD_REWRITE_ */
