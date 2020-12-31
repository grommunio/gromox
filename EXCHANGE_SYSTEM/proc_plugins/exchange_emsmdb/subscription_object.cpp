#include "subscription_object.h"
#include "exmdb_client.h"

SUBSCRIPTION_OBJECT* subscription_object_create(
	LOGON_OBJECT *plogon, uint8_t logon_id,
	uint16_t notification_types, BOOL b_whole,
	uint64_t folder_id, uint64_t message_id)
{
	auto psub = static_cast<SUBSCRIPTION_OBJECT *>(malloc(sizeof(SUBSCRIPTION_OBJECT)));
	if (NULL == psub) {
		return NULL;
	}
	if (FALSE == emsmdb_interface_get_cxh(&psub->cxh)) {
		free(psub);
		return NULL;
	}
	psub->plogon = plogon;
	psub->logon_id = logon_id;
	if (FALSE == exmdb_client_subscribe_notification(
		logon_object_get_dir(plogon), notification_types,
		b_whole, folder_id, message_id, &psub->sub_id)) {
		free(psub);
		return NULL;
	}
	return psub;
}

void subscription_object_set_handle(
	SUBSCRIPTION_OBJECT *psub, uint32_t handle)
{
	psub->handle = handle;
	emsmdb_interface_add_subscription_notify(
		logon_object_get_dir(psub->plogon), psub->sub_id,
		psub->handle, psub->logon_id, &psub->cxh.guid);
}

void subscription_object_free(SUBSCRIPTION_OBJECT *psub)
{	
	exmdb_client_unsubscribe_notification(
		logon_object_get_dir(psub->plogon), psub->sub_id);
	emsmdb_interface_remove_subscription_notify(
		logon_object_get_dir(psub->plogon), psub->sub_id);
	free(psub);
}
