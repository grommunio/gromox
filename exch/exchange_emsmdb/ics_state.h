#pragma once
#include <memory>
#include <gromox/mapi_types.hpp>

struct LOGON_OBJECT;

enum {
	ICS_STATE_CONTENTS_DOWN,
	ICS_STATE_CONTENTS_UP,
	ICS_STATE_HIERARCHY_DOWN,
	ICS_STATE_HIERARCHY_UP
};

struct ICS_STATE {
	protected:
	ICS_STATE() = default;

	public:
	~ICS_STATE();
	static std::unique_ptr<ICS_STATE> create(LOGON_OBJECT *, int type);
	BOOL append_idset(uint32_t state_property, IDSET *);
	TPROPVAL_ARRAY *serialize();

	int type = 0;
	IDSET *pgiven = nullptr, *pseen = nullptr, *pseen_fai = nullptr;
	IDSET *pread = nullptr;
};
using ics_state = ICS_STATE;
