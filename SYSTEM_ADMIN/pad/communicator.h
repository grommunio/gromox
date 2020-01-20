#pragma once

void communicator_init(const char *listen_ip, int listen_port,
	const char *list_path, int threads_num);
extern int communicator_run(void);
extern int communicator_stop(void);
extern void communicator_free(void);
