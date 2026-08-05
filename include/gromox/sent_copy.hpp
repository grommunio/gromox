// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <memory>
#include <gromox/element_data.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>

namespace gromox {

/**
 * Named-property resolvers, so that sent_copy_prepare can be called from
 * subsystems which each have their own exmdb client object of a distinct type
 * (emsmdb's exmdb_client_shm exposes function-pointer members, while
 * exmdb_client_remote exposes static member functions). The signatures mirror
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
