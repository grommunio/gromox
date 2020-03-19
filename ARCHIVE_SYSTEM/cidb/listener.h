#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void listener_init(const char *ip, int port, const char *list_path);
extern int listener_run(void);
extern int listener_trigger_accept(void);
extern int listener_stop(void);
extern void listener_free(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
