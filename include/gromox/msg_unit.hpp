#pragma once
#include <gromox/common_types.hpp>

namespace gromox {

struct MSG_UNIT {
	size_t size = 0;
	char file_name[128]{};
	BOOL b_deleted = false;
};

}
