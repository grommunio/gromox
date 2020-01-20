#pragma once

enum {
	STUB_RETRYING_WAIT_INTERVAL
};

void stub_retrying_init(const char *list_path, int port, int time_out,
	int channel_num);
extern int stub_retrying_run(void);
extern int stub_retrying_stop(void);
extern void stub_retrying_free(void);
void stub_retrying_set_param(int param, int value);
