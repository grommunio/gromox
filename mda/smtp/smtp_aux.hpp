#pragma once
#include <gromox/common_types.hpp>
#define FLUSHING_INVALID_FD -1

enum {
    FLUSHER_MODE_DISK,
    FLUSHER_MODE_GATEWAY    
};

struct SMTP_CONTEXT;

extern void flusher_init(size_t queue_len);
extern int flusher_run();
extern void flusher_stop();
BOOL flusher_put_to_queue(SMTP_CONTEXT *pcontext);
void flusher_cancel(SMTP_CONTEXT *pcontext);
#pragma once
#include <cstdint>
extern void listener_init(uint16_t port, uint16_t ssl_port);
extern int listener_run();
extern int listener_trigger_accept();
extern void listener_stop_accept();
extern void listener_stop();

extern uint16_t g_listener_ssl_port;
#pragma once
#include <memory>

struct CONFIG_FILE;

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_smtp_code(unsigned int code_type, unsigned int n, size_t *len);

extern std::shared_ptr<CONFIG_FILE> g_config_file;
#pragma once
#include <gromox/common_types.hpp>

enum{
    SERVICE_AUTH_ERROR,       /* auth session fail  */
	SERVICE_AUTH_CONTINUE,    /* auth session processed OK, continue */
    SERVICE_AUTH_FINISH       /* auth session processed OK, finished */

};

extern int system_services_run();
extern void system_services_stop();

extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern bool (*system_services_check_user)(const char *, char *, size_t);
extern BOOL (*system_services_check_full)(const char*);
extern void (*system_services_log_info)(unsigned int, const char *, ...);
