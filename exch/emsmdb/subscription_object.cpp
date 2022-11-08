// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "logon_object.h"
#include "subscription_object.h"

std::unique_ptr<subscription_object>
subscription_object::create(logon_object *plogon, uint8_t logon_id,
    uint16_t notification_types, BOOL b_whole, uint64_t folder_id,
    uint64_t message_id)
{
	std::unique_ptr<subscription_object> psub;
	try {
		psub.reset(new subscription_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	if (!emsmdb_interface_get_cxh(&psub->cxh))
		return NULL;
	psub->plogon = plogon;
	psub->logon_id = logon_id;
	if (!exmdb_client::subscribe_notification(plogon->get_dir(),
	    notification_types, b_whole, folder_id, message_id, &psub->sub_id))
		return NULL;
	return psub;
}

void subscription_object::set_handle(uint32_t h)
{
	auto psub = this;
	psub->handle = h;
	emsmdb_interface_add_subscription_notify(psub->plogon->get_dir(),
		psub->sub_id, psub->handle, psub->logon_id, &psub->cxh.guid);
}

subscription_object::~subscription_object()
{	
	auto psub = this;
	exmdb_client::unsubscribe_notification(psub->plogon->get_dir(), psub->sub_id);
	emsmdb_interface_remove_subscription_notify(psub->plogon->get_dir(), psub->sub_id);
}
