#ifndef _H_PROCESSING_ENGINE_
#define _H_PROCESSING_ENGINE_

void processing_engine_init(const char *master_host, const char *data_path,
	const char *config_path);

int processing_engine_run();

int processing_engine_stop();

void processing_engine_free();

#endif
