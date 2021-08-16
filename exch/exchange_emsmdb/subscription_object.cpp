// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "common_util.h"
#include "subscription_object.h"
#include "exmdb_client.h"

std::unique_ptr<SUBSCRIPTION_OBJECT> subscription_object_create(
	LOGON_OBJECT *plogon, uint8_t logon_id,
	uint16_t notification_types, BOOL b_whole,
	uint64_t folder_id, uint64_t message_id)
{
	std::unique_ptr<SUBSCRIPTION_OBJECT> psub;
	try {
		psub = std::make_unique<SUBSCRIPTION_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	if (FALSE == emsmdb_interface_get_cxh(&psub->cxh)) {
		return NULL;
	}
	psub->plogon = plogon;
	psub->logon_id = logon_id;
	if (!exmdb_client_subscribe_notification(plogon->get_dir(),
	    notification_types, b_whole, folder_id, message_id, &psub->sub_id))
		return NULL;
	return psub;
}

void SUBSCRIPTION_OBJECT::set_handle(uint32_t h)
{
	auto psub = this;
	psub->handle = h;
	emsmdb_interface_add_subscription_notify(psub->plogon->get_dir(),
		psub->sub_id, psub->handle, psub->logon_id, &psub->cxh.guid);
}

SUBSCRIPTION_OBJECT::~SUBSCRIPTION_OBJECT()
{	
	auto psub = this;
	exmdb_client_unsubscribe_notification(psub->plogon->get_dir(), psub->sub_id);
	emsmdb_interface_remove_subscription_notify(psub->plogon->get_dir(), psub->sub_id);
}
