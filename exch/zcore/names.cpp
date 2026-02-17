// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2026 grommunio GmbH
// This file is part of Gromox.
#include <gromox/defs.h>
#include <gromox/zcore_rpc.hpp>
#include "common_util.hpp"

using namespace gromox;

//#define EDEF(str, num) [static_cast<unsigned int>(zcore_callid::str)] = #str
//#define EOBSOL(num) [num] = (nullptr)
#define EDEF(str, id) (static_cast<void>(zcore_callid::str), #str),
#define EOBSOL(str, id) #str,
#define EUNDEF(id) nullptr,

static constexpr const char *zcore_rpc_names[] = {
#	include <gromox/zcore_allcalls.hpp>
};

#undef EDEF
#undef EOBSOL
#undef EUNDEF

const char *zcore_rpc_idtoname(zcore_callid i)
{
	auto j = static_cast<uint8_t>(i);
	static_assert(std::size(zcore_rpc_names) == static_cast<uint8_t>(zcore_callid::logon_np) + 1);
	auto s = j < std::size(zcore_rpc_names) ? zcore_rpc_names[j] : nullptr;
	return znul(s);
}
