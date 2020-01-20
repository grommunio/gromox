#pragma once

void processing_engine_init(const char *master_host, const char *data_path,
	const char *config_path);
extern int processing_engine_run(void);
extern int processing_engine_stop(void);
extern void processing_engine_free(void);
