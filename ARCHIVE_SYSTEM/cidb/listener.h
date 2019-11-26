#ifndef _H_LISTENER_
#define _H_LISTENER_

void listener_init(const char *ip, int port, const char *list_path);

int listener_run();

int listener_trigger_accept();

int listener_stop();

void listener_free();


#endif
