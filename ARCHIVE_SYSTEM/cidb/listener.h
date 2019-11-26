#ifndef _H_LISTENER_
#define _H_LISTENER_

void listener_init(const char *ip, int port, const char *list_path);
extern int listener_run(void);
extern int listener_trigger_accept(void);
extern int listener_stop(void);
extern void listener_free(void);

#endif
