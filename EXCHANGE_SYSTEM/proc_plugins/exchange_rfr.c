#include "proc_common.h"
#include "util.h"
#include "guid.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

DECLARE_API;

typedef struct _RFRGETNEWDSA_IN {
	uint32_t flags;
	char puserdn[1024];
	char punused[256];
	char pserver[256];
} RFRGETNEWDSA_IN;

typedef struct _RFRGETNEWDSA_OUT {
	char punused[256];
	char pserver[256];
	uint32_t result;
} RFRGETNEWDSA_OUT;

typedef struct _RFRGETFQDNFROMLEGACYDN_IN {
	uint32_t flags;
	uint32_t cb;
	char mbserverdn[1024];
} RFRGETFQDNFROMLEGACYDN_IN;

typedef struct _RFRGETFQDNFROMLEGACYDN_OUT {
	char serverfqdn[256];
	uint32_t result;
} RFRGETFQDNFROMLEGACYDN_OUT;

static int exchange_rfr_ndr_pull(int opnum, NDR_PULL* pndr, void **pin);

static int exchange_rfr_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **pout);

static int exchange_rfr_ndr_push(int opnum, NDR_PUSH *pndr, void *pout);

static BOOL (*get_id_from_username)(const char *username, int *puser_id);

#define MAPI_E_SUCCESS 0x00000000


BOOL PROC_LibMain(int reason, void **ppdata)
{
	void *pendpoint1;
	void *pendpoint2;
	DCERPC_INTERFACE interface;
	
	/* path conatins the config files directory */
	switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		get_id_from_username = query_service("get_id_from_username");
		if (NULL == get_id_from_username) {
			printf("[exchange_rfr]: fail to get \"get_id_from_username\" service\n");
			return FALSE;
		}
		pendpoint1 = register_endpoint("*", 6001);
		if (NULL == pendpoint1) {
			printf("[exchange_rfr]: fail to register endpoint with port 6001\n");
			return FALSE;
		}
		pendpoint2 = register_endpoint("*", 6002);
		if (NULL == pendpoint2) {
			printf("[exchange_rfr]: fail to register endpoint with port 6002\n");
			return FALSE;
		}
		strcpy(interface.name, "exchangeRFR");
		guid_from_string(&interface.uuid, "1544f5e0-613c-11d1-93df-00c04fd7bd09");
		interface.version = 1;
		interface.ndr_pull = exchange_rfr_ndr_pull;
		interface.dispatch = exchange_rfr_dispatch;
		interface.ndr_push = exchange_rfr_ndr_push;
		interface.unbind = NULL;
		interface.reclaim = NULL;
		if (FALSE == register_interface(pendpoint1, &interface) ||
			FALSE == register_interface(pendpoint2, &interface)) {
			printf("[exchange_rfr]: fail to register interface\n");
			return FALSE;
		}
		printf("[exchange_rfr]: plugin is loaded into system\n");
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
}

static uint32_t rfr_get_newdsa(uint32_t flags, const char *puserdn,
	char *punused, char *pserver)
{
	int user_id;
	char *ptoken;
	char username[256];
	char hex_string[32];
	DCERPC_INFO rpc_info;
	
	*punused = '\0';
	rpc_info = get_rpc_info();
	get_id_from_username(rpc_info.username, &user_id);
	memset(username, 0, sizeof(username));
	strcpy(username, rpc_info.username);
	ptoken = strchr(username, '@');
	lower_string(username);
	if (NULL != ptoken) {
		ptoken ++;
	} else {
		ptoken = username;
	}
	encode_hex_int(user_id, hex_string);
	sprintf(pserver, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
			"-%02x%02x%s@%s", username[0], username[1], username[2],
			username[3], username[4], username[5], username[6],
			username[7], username[8], username[9], username[10],
			username[11], hex_string, ptoken);
	return MAPI_E_SUCCESS;
}

static uint32_t rfr_get_fqdnfromlegacydn(uint32_t flags,
	uint32_t cb, const char *mbserverdn, char *serverfqdn)
{
	char *ptoken;
	char tmp_unused[16];
	char tmp_buff[1024];
	
	strncpy(tmp_buff, mbserverdn, sizeof(tmp_buff));
	ptoken = strrchr(tmp_buff, '/');
	if (NULL == ptoken || 0 != strncasecmp(ptoken, "/cn=", 4)) {
		return rfr_get_newdsa(flags, NULL, tmp_unused, serverfqdn);
	}
	*ptoken = '\0';
	ptoken = strrchr(tmp_buff, '/');
	if (NULL == ptoken || 0 != strncasecmp(ptoken, "/cn=", 4)) {
		return rfr_get_newdsa(flags, NULL, tmp_unused, serverfqdn);
	}
	strncpy(serverfqdn, ptoken + 4, 1024);
	return MAPI_E_SUCCESS;
}

static int exchange_rfr_ndr_pull(int opnum, NDR_PULL* pndr, void **ppin)
{
	int status;
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	RFRGETNEWDSA_IN *prfr;
	RFRGETFQDNFROMLEGACYDN_IN *prfr_dn;

	
	switch (opnum) {
	case 0:
		prfr = ndr_stack_alloc(NDR_STACK_IN, sizeof(RFRGETNEWDSA_IN));
		if (NULL == prfr) {
			return NDR_ERR_ALLOC;
		}
		memset(prfr, 0, sizeof(RFRGETNEWDSA_IN));
		status = ndr_pull_uint32(pndr, &prfr->flags);
		if (NDR_ERR_SUCCESS!= status) {
			return status;
		}
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS!= status) {
			return status;
		}
		status = ndr_pull_ulong(pndr, &offset);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_ulong(pndr, &length);
		if (NDR_ERR_SUCCESS!= status) {
			return status;
		}
		if (0 != offset || length > size || length > 1024) {
			return NDR_ERR_ARRAY_SIZE;
		}
		
		status = ndr_pull_check_string(pndr, length, sizeof(uint8_t));
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		
		status = ndr_pull_string(pndr, prfr->puserdn, length);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (0 != ptr) {
				status = ndr_pull_ulong(pndr, &size);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length > size || length > 256) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length, sizeof(uint8_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_string(pndr, prfr->punused, length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			} else {
				prfr->punused[0] = '\0';
			}
		} else {
			prfr->punused[0] = '\0';
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (0 != ptr) {
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (0 != ptr) {
				status = ndr_pull_ulong(pndr, &size);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				size = ndr_pull_ulong(pndr, &length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length > size || length > 256) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length, sizeof(uint8_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				
				status = ndr_pull_string(pndr, prfr->pserver, length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			} else {
				prfr->pserver[0] = '\0';
			}
		} else {
			prfr->pserver[0] = '\0';
		}
		*ppin = prfr;
		return NDR_ERR_SUCCESS;
	case 1:
		prfr_dn = ndr_stack_alloc(NDR_STACK_IN, sizeof(RFRGETFQDNFROMLEGACYDN_IN));
		if (NULL == prfr_dn) {
			return NDR_ERR_ALLOC;
		}
		memset(prfr_dn, 0, sizeof(RFRGETFQDNFROMLEGACYDN_IN));
		status = ndr_pull_uint32(pndr, &prfr_dn->flags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &prfr_dn->cb);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (prfr_dn->cb < 10 || prfr_dn->cb > 1024) {
			return NDR_ERR_RANGE;
		}
		
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_ulong(pndr, &offset);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_ulong(pndr, &length);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != offset || length > size || length > 1024) {
			return NDR_ERR_ARRAY_SIZE;
		}
		status = ndr_pull_check_string(pndr, length, sizeof(uint8_t));
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_string(pndr, prfr_dn->mbserverdn, length);
		*ppin = prfr_dn;
		return NDR_ERR_SUCCESS;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static BOOL exchange_rfr_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout)
{
	RFRGETNEWDSA_IN *prfr_in;
	RFRGETNEWDSA_OUT *prfr_out;
	RFRGETFQDNFROMLEGACYDN_IN *prfr_dn_in;
	RFRGETFQDNFROMLEGACYDN_OUT *prfr_dn_out;
	
	switch (opnum) {
	case 0:	
		prfr_in = (RFRGETNEWDSA_IN*)pin;
		prfr_out = ndr_stack_alloc(NDR_STACK_OUT, sizeof(RFRGETNEWDSA_OUT));
		if (NULL == prfr_out) {
			return DISPATCH_FAIL;
		}
		prfr_out->result = rfr_get_newdsa(prfr_in->flags, prfr_in->puserdn,
							prfr_in->punused, prfr_in->pserver);
		strcpy(prfr_out->punused, prfr_in->punused);
		strcpy(prfr_out->pserver, prfr_in->pserver);
		*ppout = prfr_out;
		return DISPATCH_SUCCESS;
	case 1:
		prfr_dn_in = (RFRGETFQDNFROMLEGACYDN_IN*)pin;
		prfr_dn_out = ndr_stack_alloc(NDR_STACK_OUT, sizeof(RFRGETFQDNFROMLEGACYDN_OUT));
		if (NULL == prfr_dn_out) {
			return DISPATCH_FAIL;
		}
		prfr_dn_out->result = rfr_get_fqdnfromlegacydn(prfr_dn_in->flags,
								prfr_dn_in->cb, prfr_dn_in->mbserverdn,
								prfr_dn_out->serverfqdn);
		*ppout = prfr_dn_out;
		return DISPATCH_SUCCESS;
	default:
		return DISPATCH_FAIL;
	}
}

static int exchange_rfr_ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	int status;
	int length;
	RFRGETNEWDSA_OUT *prfr;
	RFRGETFQDNFROMLEGACYDN_OUT *prfr_dn;
	
	switch (opnum) {
	case 0:
		prfr = (RFRGETNEWDSA_OUT*)pout;
		if ('\0' == *prfr->punused) {
			status = ndr_push_unique_ptr(pndr, NULL);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		} else {
			status = ndr_push_unique_ptr(pndr, (void*)0x1);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			length = strlen(prfr->punused) + 1;
			status = ndr_push_unique_ptr(pndr, prfr->punused);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, 0);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_string(pndr, prfr->punused, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
		
		if ('\0' == *prfr->pserver) {
			status = ndr_push_unique_ptr(pndr, NULL);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		} else {
			status = ndr_push_unique_ptr(pndr, (void*)0x2);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			length = strlen(prfr->pserver) + 1;
			status = ndr_push_unique_ptr(pndr, prfr->pserver);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, 0);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_string(pndr, prfr->pserver, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
		return ndr_push_uint32(pndr, prfr->result);
	case 1:
		prfr_dn = (RFRGETFQDNFROMLEGACYDN_OUT*)pout;
		if ('\0' == *prfr_dn->serverfqdn) {
			status = ndr_push_unique_ptr(pndr, NULL);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		} else {
			length = strlen(prfr_dn->serverfqdn) + 1;
			status = ndr_push_unique_ptr(pndr, prfr_dn->serverfqdn);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, 0);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_ulong(pndr, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_string(pndr, prfr_dn->serverfqdn, length);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
		return ndr_push_uint32(pndr, prfr_dn->result);
	}
}
