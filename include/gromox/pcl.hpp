#pragma once
#include <cstdint>
#include <list>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>		

enum {
	PCL_CONFLICT = 0,
	PCL_INCLUDE = 1U << 0,
	PCL_INCLUDED = 1U << 1,
	PCL_IDENTICAL = PCL_INCLUDE | PCL_INCLUDED,
};

struct GX_EXPORT PCL : private std::list<SIZED_XID> {
	bool append(const SIZED_XID &);
	bool merge(PCL &&);
	BINARY *serialize() const;
	bool deserialize(const BINARY *);
	uint32_t compare(const PCL &) const;

	using std::list<SIZED_XID>::clear;
	using std::list<SIZED_XID>::begin, std::list<SIZED_XID>::end;
	using std::list<SIZED_XID>::cbegin, std::list<SIZED_XID>::cend;
};
