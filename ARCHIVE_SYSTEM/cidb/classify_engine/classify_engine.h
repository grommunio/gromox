#ifndef _H_CLASSIFY_ENGINE_
#define _H_CLASSIFY_ENGINE_
#include <time.h>

void classify_engine_init(char *storage_path, int valid_days,
	char *sphinx_host, int sphinx_port, long tmptbl_size);

int classify_engine_run();

void classify_engine_clean(time_t cut_time);

int classify_engine_stop();

void classify_engine_free();

#endif
