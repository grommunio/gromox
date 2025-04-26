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

struct GX_EXPORT PCL : private std::list<XID> {
	bool append(const XID &x) { return subst(x, true); }
	bool replace(const XID &x) { return subst(x, false); }
	void delguid(GUID);
	bool merge(PCL &&);
	BINARY *serialize() const;
	bool deserialize(const BINARY *);
	uint32_t compare(const PCL &) const;

	using std::list<XID>::clear;
	using std::list<XID>::begin, std::list<XID>::end;
	using std::list<XID>::cbegin, std::list<XID>::cend;

	private:
	bool subst(const XID &, bool check_larger);
};
