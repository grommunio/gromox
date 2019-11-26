#ifndef _H_RESOURCE_
#define _H_RESOURCE_
#include "common_types.h"

enum {
	RES_LISTEN_PORT = 0,
	RES_LISTEN_SSL_PORT,
	RES_TCP_MAX_SEGMENT,
	RES_HOST_ID,
	RES_DEFAULT_DOMAIN,
	
	RES_CONTEXT_NUM,
	RES_CONTEXT_AVERAGE_MEM,
	
	RES_HTTP_AUTH_TIMES,
	RES_HTTP_CONN_TIMEOUT,
	RES_HTTP_SUPPORT_SSL,
	RES_HTTP_CERTIFICATE_PATH,
	RES_HTTP_CERTIFICATE_PASSWD,
	RES_HTTP_PRIVATE_KEY_PATH,
	
	RES_THREAD_INIT_NUM,
	RES_THREAD_CHARGE_NUM,
	
	RES_USER_DEFAULT_LANG,
	
	RES_CONSOLE_SERVER_IP,
	RES_CONSOLE_SERVER_PORT,
	
	RES_REQUEST_MAX_MEM,
	RES_PROC_PLUGIN_PATH,
	RES_HPM_PLUGIN_PATH,
	RES_SERVICE_PLUGIN_PATH,
	RES_RUNNING_IDENTITY,
	RES_BLOCK_INTERVAL_AUTHS,
	RES_CONFIG_FILE_PATH,
	RES_DATA_FILE_PATH,
	
	RES_FASTCGI_CACHE_SIZE,
	RES_FASTCGI_MAX_SIZE,
	RES_FASTCGI_EXEC_TIMEOUT,
	RES_HPM_CACHE_SIZE,
	RES_HPM_MAX_SIZE,
	MAX_RES_CONFG_VAR_NUM
};


void resource_init(char* cfg_filename);
extern void resource_free(void);
extern int resource_run(void);
extern int resource_stop(void);
extern BOOL resource_save(void);
BOOL resource_get_integer(int key, int* value);

const char* resource_get_string(int key);

BOOL resource_set_integer(int key, int value);

BOOL resource_set_string(int key, char* value);


#endif /* _H_RESOURCE_ */
