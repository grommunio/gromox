#pragma once
#include <memory>
#include <gromox/config_file.hpp>
#include <gromox/common_types.hpp>
#define resource_get_string(k) config_file_get_value(g_config_file, (k))
#define resource_set_string(k, v) config_file_set_value(g_config_file, (k), (v))
#define resource_get_integer(k, vp) config_file_get_int(g_config_file, (k), (vp))
#define resource_set_integer(k, v) config_file_set_int(g_config_file, (k), (v))

struct POP3_ERROR_CODE {
    int     code;
    char    comment[512];
};

enum {
    POP3_CODE_2170000 = 0,
    POP3_CODE_2170001,
    POP3_CODE_2170002,
    POP3_CODE_2170003,
    POP3_CODE_2170004,
    POP3_CODE_2170005,
    POP3_CODE_2170006,
    POP3_CODE_2170007,
    POP3_CODE_2170008,
    POP3_CODE_2170009,
    POP3_CODE_2170010,
    POP3_CODE_2170011,
    POP3_CODE_2170012,
    POP3_CODE_2170013,
    POP3_CODE_2170014,
    POP3_CODE_2170015,
    POP3_CODE_2170016,
    POP3_CODE_2170017,
    POP3_CODE_2170018,
    POP3_CODE_2170019,
    POP3_CODE_2170020,
    POP3_CODE_2170021,
    POP3_CODE_2170022,
	POP3_CODE_2170023,
	POP3_CODE_2170024,
	POP3_CODE_2170025,
	POP3_CODE_2170026,
    POP3_CODE_COUNT
};

extern void resource_init();
extern void resource_free();
extern int resource_run();
extern int resource_stop();
char* resource_get_pop3_code(int code_type, int n, int *len);
extern BOOL resource_refresh_pop3_code_table();

extern std::shared_ptr<CONFIG_FILE> g_config_file;
