#ifndef _H_STUB_RETRYING_
#define _H_STUB_RETRYING_

enum {
	STUB_RETRYING_WAIT_INTERVAL
};

void stub_retrying_init(const char *list_path, int port, int time_out,
	int channel_num);

int stub_retrying_run();

int stub_retrying_stop();

void stub_retrying_free();

void stub_retrying_set_param(int param, int value);

#endif
