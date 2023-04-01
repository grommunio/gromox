#pragma once
#include <string>
extern int mod_rewrite_run(const char *sdlist);
extern bool mod_rewrite_process(const char *, size_t, std::string &);
