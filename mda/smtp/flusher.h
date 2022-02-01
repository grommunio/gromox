#pragma once
#include <gromox/plugin.hpp>
#include "smtp_parser.h"
#define FLUSHING_INVALID_FD -1

enum {
    FLUSHER_MODE_DISK,
    FLUSHER_MODE_GATEWAY    
};

extern void flusher_init(size_t queue_len);
extern int flusher_run();
extern void flusher_stop();
BOOL flusher_put_to_queue(SMTP_CONTEXT *pcontext);
void flusher_cancel(SMTP_CONTEXT *pcontext);
