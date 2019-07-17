#ifndef _H_RESOURCE_
#define _H_RESOURCE_
#include "common_types.h"

enum {
    RES_LISTEN_PORT = 0,
	RES_LISTEN_SSL_PORT,
    RES_HOST_ID,
	RES_DEFAULT_DOMAIN,

    RES_CONTEXT_NUM,
    RES_CONTEXT_AVERAGE_MEM,
    RES_CONTEXT_MAX_MEM,
	RES_CONTEXT_AVERAGE_UNITS,

    RES_POP3_AUTH_TIMES,
    RES_POP3_CONN_TIMEOUT,
	RES_POP3_SUPPORT_STLS,
	RES_POP3_CERTIFICATE_PATH,
	RES_POP3_CERTIFICATE_PASSWD,
	RES_POP3_PRIVATE_KEY_PATH,
	RES_POP3_FORCE_STLS,

    RES_THREAD_INIT_NUM,
    RES_THREAD_CHARGE_NUM,

    RES_POP3_RETURN_CODE_PATH,

    RES_CONSOLE_SERVER_IP,
    RES_CONSOLE_SERVER_PORT,

	RES_CDN_CACHE_PATH,
    RES_SERVICE_PLUGIN_PATH,
    RES_RUNNING_IDENTITY,
    RES_BLOCK_INTERVAL_AUTHS,
    RES_CONFIG_FILE_PATH,
    RES_DATA_FILE_PATH,
    MAX_RES_CONFG_VAR_NUM
};

typedef struct _POP3_ERROR_CODE {
    int     code;
    char    comment[512];
} POP3_ERROR_CODE;

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

void resource_init(char* cfg_filename);

void resource_free();

int resource_run();

int resource_stop();

BOOL resource_save();

BOOL resource_get_integer(int key, int* value);

const char* resource_get_string(int key);

BOOL resource_set_integer(int key, int value);

BOOL resource_set_string(int key, char* value);

char* resource_get_pop3_code(int code_type, int n, int *len);

BOOL resource_refresh_pop3_code_table();


#endif /* _H_RESOURCE_ */
