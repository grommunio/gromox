#pragma once
#include <gromox/mapierr.hpp>
#include <gromox/mapidefs.h>
#include <gromox/plugin.hpp>

namespace gromox {

extern GX_EXPORT ec_error_t exmdb_local_rules_execute(const char *dir, const char *ev_from, const char *ev_to, eid_t folder_id, eid_t msg_id, unsigned int flags);

}

extern "C" GX_EXPORT bool SVC_ruleproc(enum plugin_op, const struct dlfuncs &);
