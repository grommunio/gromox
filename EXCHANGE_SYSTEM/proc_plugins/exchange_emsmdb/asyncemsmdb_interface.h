#pragma once
#include "asyncemsmdb_ndr.h"

#ifdef __cplusplus
extern "C" {
#endif

void asyncemsmdb_interface_init(int threads_num);
extern int asyncemsmdb_interface_run(void);
extern int asyncemsmdb_interface_stop(void);
extern void asyncemsmdb_interface_free(void);
int asyncemsmdb_interface_async_wait(uint32_t async_id,
	ECDOASYNCWAITEX_IN *pin, ECDOASYNCWAITEX_OUT *pout);

void asyncemsmdb_interface_reclaim(uint32_t async_id);

void asyncemsmdb_interface_wakeup(const char *username, uint16_t cxr);

#ifdef __cplusplus
} /* extern "C" */
#endif
