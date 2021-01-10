#pragma once
#include <gromox/config_file.hpp>
#include <gromox/common_types.hpp>
#define resource_get_string(k) config_file_get_value(g_config_file, (k))
#define resource_set_string(k, v) config_file_set_value(g_config_file, (k), (v))
#define resource_get_integer(k, vp) config_file_get_int(g_config_file, (k), (vp))
#define resource_set_integer(k, v) config_file_set_int(g_config_file, (k), (v))

extern CONFIG_FILE *g_config_file;

extern void resource_init(void);
extern void resource_free(void);
extern int resource_run(void);
extern int resource_stop(void);
