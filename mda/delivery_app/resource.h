#pragma once
#include <memory>
#include <gromox/config_file.hpp>
extern void resource_init();
extern void resource_free();
extern int resource_run();
extern int resource_stop();

extern std::shared_ptr<CONFIG_FILE> g_config_file;
