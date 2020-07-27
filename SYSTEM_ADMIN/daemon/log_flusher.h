#pragma once

void log_flusher_init(const char *path);
extern int log_flusher_run(void);
extern int log_flusher_stop(void);
extern void log_flusher_free(void);
