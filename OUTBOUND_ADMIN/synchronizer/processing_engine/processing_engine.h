#ifndef _H_PROCESSING_ENGINE_
#define _H_PROCESSING_ENGINE_
#include "common_types.h"

void processing_engine_init(const char *master_ip, const char *data_path,
	const char *config_path, const char *control_path, const char *shm_path,
	const char *mask_string, BOOL b_noop);

int processing_engine_run();

int processing_engine_stop();

void processing_engine_free();

#endif
