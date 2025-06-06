// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
/* Example program how to obtain notifications for mailbox changes */
#include <cstdint>
#include <cstdio>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>

using namespace gromox;
using LLU = unsigned long long;
static char *g_storedir;

static void event_proc(const char *dir, BOOL thing, uint32_t sub_id,
    const DB_NOTIFY *notify)
{
	printf("Event on %s (subscription %u):\n", dir, sub_id);
	// Slight inconsistency just turned up.
	// DB_NOTIFY structs carry the GCV (doc/glossary.rst) rather than the MID,
	// so no rop_util_get_gc_value call needed.
	switch (notify->type) {
	case db_notify_type::new_mail: {
		auto i = static_cast<const DB_NOTIFY_NEW_MAIL *>(notify->pdata);
		printf("\tnew mail... in folder %llu, msgid %llu\n",
			LLU{i->folder_id}, LLU{i->message_id});
			//LLU{rop_util_get_gc_value(i->folder_id)}
		break;
	}
	case db_notify_type::message_created: {
		auto i = static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(notify->pdata);
		printf("\tmsgcreated... folder %llu msgid %llu\n",
			LLU{i->folder_id}, LLU{i->message_id});
		break;
	}
	case db_notify_type::folder_modified:
		printf("\ta folder was modified...\n");
		break;
	default:
		printf("\tsomething else...\n");
		break;
	}
}

static int do_mbox()
{
	uint64_t folder_id, message_id;

	/* watch all objects */
	folder_id = message_id = 0;
	/* if watching just one folder */
	//folder_id = rop_util_make_eid_ex(1, PRIVATE_FID_INBOX);

	uint32_t event_mask = fnevNewMail | fnevObjectModified | fnevObjectCreated | fnevObjectMoved | fnevObjectDeleted;
	unsigned int sub_id = 0;
	if (!exmdb_client->subscribe_notification(g_storedir,
	    event_mask, TRUE, folder_id, message_id, &sub_id))
		return -1;

	while (1)
		sleep(1);

	exmdb_client->unsubscribe_notification(g_storedir, sub_id);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s MBOXDIR\n", argv[0]);
		return EXIT_FAILURE;
	}

	exmdb_client.emplace(1, 1);
	auto cleanup_0 = HX::make_scope_exit([]() { exmdb_client.reset(); });
	if (exmdb_client_run(PKGSYSCONFDIR, 0, nullptr, nullptr, event_proc) != 0)
		return EXIT_FAILURE;

	g_storedir = argv[1];
	return do_mbox() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
