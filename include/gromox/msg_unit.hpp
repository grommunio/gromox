#pragma once
#include <string>
#include <gromox/common_types.hpp>

namespace gromox {

struct MSG_UNIT {
	std::string file_name;
	size_t size = 0;
	bool b_deleted = false;
};

}
