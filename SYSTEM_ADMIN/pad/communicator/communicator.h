#ifndef _H_COMMUNICATOR_
#define _H_COMMUNICATOR_

void communicator_init(const char *listen_ip, int listen_port,
	const char *list_path, int threads_num);

int communicator_run();

int communicator_stop();

void communicator_free();

#endif
