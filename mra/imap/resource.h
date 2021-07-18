#pragma once
#include <memory>
#include <gromox/config_file.hpp>
#include <gromox/common_types.hpp>

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_imap_code(unsigned int code_type, unsigned int n, size_t *len);
extern const char *const *resource_get_folder_strings(const char *lang);
const char* resource_get_default_charset(const char *lang);
extern const char *resource_get_error_string(unsigned int);

extern std::shared_ptr<CONFIG_FILE> g_config_file;
