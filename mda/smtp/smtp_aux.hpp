#pragma once
#include <cstdint>
#include <memory>
#include <gromox/common_types.hpp>
#include <gromox/plugin.hpp>
#define FLUSHING_INVALID_FD -1

enum {
    FLUSHER_MODE_DISK,
    FLUSHER_MODE_GATEWAY    
};

class config_file;
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
extern BOOL FLH_LibMain(enum plugin_op);

extern uint16_t g_listener_ssl_port;

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_smtp_code(unsigned int code_type, unsigned int n, size_t *len);

extern std::shared_ptr<config_file> g_config_file;

enum{
    SERVICE_AUTH_ERROR,       /* auth session fail  */
	SERVICE_AUTH_CONTINUE,    /* auth session processed OK, continue */
    SERVICE_AUTH_FINISH       /* auth session processed OK, finished */

};
