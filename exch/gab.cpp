#include <gromox/gab.hpp>

namespace gromox {

enum display_type dtypx_to_etyp(enum display_type dt)
{
	dt = static_cast<enum display_type>(dt & DTE_MASK_LOCAL);
	switch (dt) {
	case DT_MAILUSER:
	case DT_ROOM:
	case DT_EQUIPMENT:
	case DT_SEC_DISTLIST:
		return DT_MAILUSER;
	default:
		return dt;
	}
}

}
