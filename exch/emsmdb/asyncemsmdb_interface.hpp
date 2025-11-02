#pragma once
#include <cstdint>
#include <gromox/rpc_types.hpp>

struct ECDOASYNCWAITEX_IN;
struct ECDOASYNCWAITEX_OUT;

extern void asyncemsmdb_interface_register_active(void *);
extern void asyncemsmdb_interface_init(unsigned int threads_num);
extern int asyncemsmdb_interface_run();
extern void asyncemsmdb_interface_stop();
extern void asyncemsmdb_interface_free();
int asyncemsmdb_interface_async_wait(uint32_t async_id,
	ECDOASYNCWAITEX_IN *pin, ECDOASYNCWAITEX_OUT *pout);
void asyncemsmdb_interface_reclaim(uint32_t async_id);
extern void asyncemsmdb_interface_remove(ACXH *);
extern void asyncemsmdb_interface_wakeup(std::string &&username, uint16_t cxr);
