#pragma once

void listener_init(int port, int port_ssl, int mss_size);
extern int listener_run(void);
extern int listerner_trigger_accept(void);
extern void listener_stop_accept(void);
extern void listener_free(void);
extern int listener_stop(void);
