#pragma once

void listener_init(int port, int port_ssl, int mss_size);
extern int listener_run();
extern int listerner_trigger_accept();
extern void listener_stop_accept();
extern void listener_free();
extern int listener_stop();
