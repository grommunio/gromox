#pragma once
#include <gromox/plugin.hpp>
#include "smtp_parser.h"

#define FLUSHING_INVALID_FD -1

enum {
    FLUSHER_MODE_DISK,
    FLUSHER_MODE_GATEWAY    
};

/* enumeration for indicating the action of the flusher */
enum {
    FLUSH_WHOLE_MAIL,
    FLUSH_PART_MAIL
};

/* enumeration for indicating the result of the flushing */
enum {
    FLUSH_NONE,
    FLUSH_RESULT_OK,
    FLUSH_TEMP_FAIL,
	FLUSH_PERMANENT_FAIL
};

void flusher_init(const char* path, size_t queue_len);
extern void flusher_free();
extern int flusher_run();
extern int flusher_stop();
BOOL flusher_put_to_queue(SMTP_CONTEXT *pcontext);

void flusher_cancel(SMTP_CONTEXT *pcontext);
