#pragma once
#include <gromox/common_types.hpp>
#include <gromox/mem_file.hpp>

extern int mod_rewrite_run(const char *sdlist);
extern BOOL mod_rewrite_process(const char *, size_t, MEM_FILE *);
