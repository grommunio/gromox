#pragma once
#include <gromox/mapierr.hpp>
#include <gromox/mapidefs.h>
#include <gromox/plugin.hpp>

namespace gromox {

enum delivery_flags {
	DELIVERY_DO_RULES_SV = 0x1U,
	DELIVERY_DO_NOTIF_SV = 0x2U,
	DELIVERY_DO_MRAUTOPROC = 0x4U,
	DELIVERY_FORCE_JUNK = 0x8U,
	DELIVERY_DO_RULES_CL = 0x10U,
	DELIVERY_DO_NOTIF_CL = 0x20U,
};

extern GX_EXPORT ec_error_t exmdb_local_rules_execute(const char *dir, const char *ev_from, const char *ev_to, eid_t folder_id, eid_t msg_id, unsigned int flags);

}

extern "C" GX_EXPORT bool SVC_ruleproc(enum plugin_op, const struct dlfuncs &);
