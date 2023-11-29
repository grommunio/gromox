#pragma once
#include <cstdint>
#include <memory>
#include <gromox/common_types.hpp>
#define FLUSHING_INVALID_FD -1

enum {
    FLUSHER_MODE_DISK,
    FLUSHER_MODE_GATEWAY    
};

struct FLUSH_ENTITY;
struct smtp_context;
using CANCEL_FUNCTION = void (*)(FLUSH_ENTITY *);
using SMTP_CONTEXT = smtp_context;

extern void flusher_init(size_t queue_len);
extern int flusher_run();
extern void flusher_stop();
BOOL flusher_put_to_queue(SMTP_CONTEXT *pcontext);
void flusher_cancel(SMTP_CONTEXT *pcontext);
extern void message_enqueue_handle_workitem(FLUSH_ENTITY &);
extern BOOL flusher_register_cancel(CANCEL_FUNCTION);
extern void flusher_set_flush_ID(int);
extern BOOL FLH_LibMain(int);

extern uint16_t g_listener_ssl_port;

struct config_file;

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_smtp_code(unsigned int code_type, unsigned int n, size_t *len);

extern std::shared_ptr<config_file> g_config_file;

enum{
    SERVICE_AUTH_ERROR,       /* auth session fail  */
	SERVICE_AUTH_CONTINUE,    /* auth session processed OK, continue */
    SERVICE_AUTH_FINISH       /* auth session processed OK, finished */

};

extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern bool (*system_services_check_user)(const char *, const char *, char *, size_t);
