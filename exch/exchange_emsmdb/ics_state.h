#pragma once
#include <memory>
#include <gromox/mapi_types.hpp>
#include "logon_object.h"

enum {
	ICS_STATE_CONTENTS_DOWN,
	ICS_STATE_CONTENTS_UP,
	ICS_STATE_HIERARCHY_DOWN,
	ICS_STATE_HIERARCHY_UP
};

struct ICS_STATE {
	~ICS_STATE();

	int type = 0;
	IDSET *pgiven = nullptr, *pseen = nullptr, *pseen_fai = nullptr;
	IDSET *pread = nullptr;
};

std::unique_ptr<ICS_STATE> ics_state_create(LOGON_OBJECT *, int type);
BOOL ics_state_append_idset(ICS_STATE *pstate,
	uint32_t state_property, IDSET *pset);
TPROPVAL_ARRAY* ics_state_serialize(ICS_STATE *pstate);
