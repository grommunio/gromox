// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <memory>
#include <gromox/element_data.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>

namespace gromox {

/*
 * The two per-mailbox settings which decide whether a message sent as, or on
 * behalf of, a mailbox is filed into that mailbox's Sent Items, and whether
 * that copy is then the only one.
 *
 * Spelled out here rather than at each use site because three subsystems read
 * them, and a typo in one would silently address a different property instead
 * of failing.
 *
 * msgcopy_exclusive has no effect of its own. It only says what happens to the
 * sender's copy once one of the other two has produced a copy here, which is
 * how Exchange's DelegateSentItemsStyle=1 plus MessageCopyForSentAsEnabled=0
 * combination comes out.
 */
static constexpr char msgcopy_np_sentas[] = "msgcopy_sentas";
static constexpr char msgcopy_np_sendonbehalf[] = "msgcopy_sendonbehalf";
static constexpr char msgcopy_np_exclusive[] = "msgcopy_exclusive";

/**
 * Named property resolvers, so that `sent_copy_prepare` can be called from
 * subsystems which each have their own exmdb client object of a distinct type.
 * emsmdb's `exmdb_client_shm` exposes function pointer members, while
 * `exmdb_client_remote` exposes static member functions. The signatures mirror
 * the EXMIDL prototypes verbatim, so both can be assigned without an adapter.
 *
 * @log_id:	free-form string used to identify the message in log messages
 */
struct GX_EXPORT sent_copy_ctx {
	BOOL (*get_named_propnames)(const char *dir, const PROPID_ARRAY &,
		PROPNAME_ARRAY *) = nullptr;
	BOOL (*get_named_propids)(const char *dir, BOOL b_create,
		const PROPNAME_ARRAY *, PROPID_ARRAY *) = nullptr;
	const char *log_id = "";
};

extern GX_EXPORT ec_error_t sent_copy_prepare(const sent_copy_ctx &,
	const MESSAGE_CONTENT &src, const char *srcdir, const char *dstdir,
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> &out);

}
