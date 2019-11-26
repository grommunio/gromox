#ifndef _H_FLUSHER_
#define _H_FLUSHER_

#include "plugin.h"
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
extern void flusher_free(void);
extern int flusher_run(void);
extern int flusher_stop(void);
BOOL flusher_put_to_queue(SMTP_CONTEXT *pcontext);

void flusher_cancel(SMTP_CONTEXT *pcontext);

void flusher_console_talk(int argc, char** argv, char* reason, int len);

#endif
