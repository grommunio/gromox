// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025–2026 grommunio GmbH
// This file is part of Gromox.
#include <gromox/defs.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_rpc.hpp>

using namespace gromox;

//#define EDEF(str, id) [static_cast<unsigned int>(exmdb_callid::str)] = #str
#define EDEF(str, id) (static_cast<void>(exmdb_callid::str), #str),
#define EOBSOL(str, id) #str,

static constexpr const char *exmdb_rpc_names[] = {
	#include <gromox/exmdb_allcalls.hpp>
};

#undef EDEF
#undef EOBSOL

namespace exmdb {

const char *exmdb_rpc_idtoname(exmdb_callid i)
{
	auto j = static_cast<uint8_t>(i);
	static_assert(std::size(exmdb_rpc_names) == static_cast<uint8_t>(exmdb_callid::write_delegates) + 1);
	auto s = j < std::size(exmdb_rpc_names) ? exmdb_rpc_names[j] : nullptr;
	return znul(s);
}

}
