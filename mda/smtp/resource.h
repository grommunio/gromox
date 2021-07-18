#pragma once
#include <memory>
#include <gromox/config_file.hpp>
#include <gromox/common_types.hpp>

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_smtp_code(unsigned int code_type, unsigned int n, size_t *len);

extern std::shared_ptr<CONFIG_FILE> g_config_file;
