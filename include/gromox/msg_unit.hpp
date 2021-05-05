#pragma once
#include <gromox/common_types.hpp>
#include <gromox/single_list.hpp>

namespace gromox {

struct MSG_UNIT {
	SINGLE_LIST_NODE node{};
	size_t size = 0;
	char file_name[128]{};
	BOOL b_deleted = false;
};

}
