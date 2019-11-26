#include <stdbool.h>
#include "guid.h"
#include "proc_common.h"
#include <string.h>

DECLARE_API;


static int ndr_pull(int opnum, NDR_PULL* pndr, void **pin);

static int dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout);

static int ndr_push(int opnum, NDR_PUSH *pndr, void *pout);

BOOL PROC_LibMain(int reason, void **ppdata)
{
	void *pendpoint;
	DCERPC_INTERFACE interface;
	
	/* path conatins the config files directory */
	switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		/* host can include wildcard */
		pendpoint = register_endpoint("mail1.herculiz.com", 6004);
		if (NULL == pendpoint) {
			return FALSE;
		}
		strcpy(interface.name, "example1");
		guid_from_string(&interface.uuid, "1544f5e0-613c-11d1-93df-00c04fd7bd09");
		interface.version = 56;
		interface.ndr_pull = ndr_pull;
		interface.dispatch = dispatch;
		interface.ndr_push = ndr_push;
		interface.unbind = NULL;  /* can be null if we don't want use it */
		interface.reclaim = NULL; /* can be null if there's no async call */
		if (FALSE == register_interface(pendpoint, &interface)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return false;
}


static int ndr_pull(int opnum, NDR_PULL* pndr, void **pin)
{
	/* TODO add unmarshaling code for method parameters here */
	return NDR_ERR_FAILURE;
}

static int dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout)
{
	/* TODO add excution code of method parameters here */
	return DISPATCH_FAIL;
}

static int ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	/* TODO add marshaling code for method result here */
	return NDR_ERR_FAILURE;
}
