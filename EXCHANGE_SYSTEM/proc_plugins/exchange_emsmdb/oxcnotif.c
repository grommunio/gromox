#include <gromox/defs.h>
#include "rops.h"
#include "common_util.h"
#include "exmdb_client.h"
#include "logon_object.h"
#include "rop_processor.h"
#include "subscription_object.h"


uint32_t rop_registernotification(
	uint8_t notification_types, uint8_t reserved,
	uint8_t want_whole_store, const uint64_t *pfolder_id,
	const uint64_t *pmessage_id, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_whole;
	int object_type;
	uint64_t folder_id;
	uint64_t message_id;
	LOGON_OBJECT *plogon;
	SUBSCRIPTION_OBJECT *psub;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_NULL_OBJECT;
	}
	if (NULL == rop_processor_get_object(
		plogmap, logon_id, hin, &object_type)) {
		return EC_NULL_OBJECT;
	}
	if (0 == want_whole_store) {
		b_whole = FALSE;
		folder_id = *pfolder_id;
		message_id = *pmessage_id;
	} else {
		b_whole = TRUE;
		folder_id = 0;
		message_id = 0;
	}
	psub = subscription_object_create(plogon, logon_id,
		notification_types, b_whole, folder_id, message_id);
	if (NULL == psub) {
		return EC_OUT_OF_MEMORY;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_SUBSCRIPTION, psub);
	if (*phout < 0) {
		subscription_object_free(psub);
		return ecError;
	}
	subscription_object_set_handle(psub, *phout);
	return ecSuccess;
}

void rop_release(void *plogmap, uint8_t logon_id, uint32_t hin)
{
	rop_processor_release_object_handle(plogmap, logon_id, hin);
}
