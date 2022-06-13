// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <list>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include "common_util.h"
#include "exmdb_client.h"
#include "exmdb_ext.hpp"
#include "exmdb_server.h"

using namespace gromox;

static void buildenv(const remote_svr &s)
{
	auto flags = s.type == EXMDB_ITEM::EXMDB_PRIVATE ? EM_PRIVATE : 0;
	exmdb_server_build_env(flags, nullptr);
}

int exmdb_client_run_front(const char *dir)
{
	return exmdb_client_run(dir, EXMDB_CLIENT_ALLOW_DIRECT | EXMDB_CLIENT_ASYNC_CONNECT,
	       buildenv, exmdb_server_free_environment, exmdb_server_event_proc);
}

/* Caution. This function is not a common exmdb service,
	it only can be called by message_rule_new_message to
	pass a message to the delegate's mailbox. */
BOOL exmdb_client_relay_delivery(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (exmdb_client_check_local(dir, &b_private)) {
		auto original_dir = exmdb_server_get_dir();
		exmdb_server_set_dir(dir);
		b_result = exmdb_server_delivery_message(
					dir, from_address, account,
					cpid, pmsg, pdigest, presult);
		exmdb_server_set_dir(original_dir);
		return b_result;
	}
	request.call_id = exmdb_callid::delivery_message;
	request.dir = deconst(dir);
	request.payload.delivery_message.from_address = deconst(from_address);
	request.payload.delivery_message.account = deconst(account);
	request.payload.delivery_message.cpid = cpid;
	request.payload.delivery_message.pmsg = deconst(pmsg);
	request.payload.delivery_message.pdigest = deconst(pdigest);
	if (!exmdb_client_do_rpc(std::move(request), &response))
		return FALSE;
	*presult = response.payload.delivery_message.result;
	return TRUE;
}
