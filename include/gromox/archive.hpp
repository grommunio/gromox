#pragma once
#include <map>
#include <string>
#include <utility>
#include <gromox/defs.h>

namespace gromox {

class GX_EXPORT archive {
	public:
	~archive();
	errno_t open(const char *file);
	const std::string_view *find(const std::string &) const;

	protected:
	const char *mapped_area = nullptr;
	size_t mapped_size = 0;
	std::map<std::string, std::string_view> entries;
};

}
