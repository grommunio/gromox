#ifndef _H_LOG_FLUSHER_
#define _H_LOG_FLUSHER_

void log_flusher_init(const char *path);

int log_flusher_run();

int log_flusher_stop();

void log_flusher_free();

#endif
