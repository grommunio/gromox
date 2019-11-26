#ifndef _H_EXEC_SCHED_
#define _H_EXEC_SCHED_
#include "common_types.h"


void exec_sched_init(const char *list_path, int pop_interval, int threads_num);

void exec_sched_free();

int exec_sched_run();

int exec_sched_stop();

BOOL exec_sched_add(const char *username);

BOOL exec_sched_remove(const char *username);


#endif /* _H_EXEC_SCHED_ */
