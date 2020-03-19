#pragma once
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

void classify_engine_init(char *storage_path, int valid_days,
	char *sphinx_host, int sphinx_port, long tmptbl_size);
extern int classify_engine_run(void);
void classify_engine_clean(time_t cut_time);
extern int classify_engine_stop(void);
extern void classify_engine_free(void);

#ifdef	__cplusplus
} /* extern "C" */
#endif
