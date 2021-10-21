#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/mapi_types.hpp>		

enum {
	PCL_CONFLICT = 0,
	PCL_INCLUDE = 1U << 0,
	PCL_INCLUDED = 1U << 1,
	PCL_IDENTICAL = PCL_INCLUDE | PCL_INCLUDED,
};

struct GX_EXPORT PCL {
	PCL() { double_list_init(&xl); }
	~PCL();
	bool append(const SIZED_XID &);
	bool merge(const PCL &);
	BINARY *serialize() const;
	bool deserialize(const BINARY *);
	uint32_t compare(const PCL &) const;
	void clear();

	DOUBLE_LIST xl;
};
