#pragma once
#include <gromox/mapi_types.hpp>
#include "logon_object.h"


enum {
	ICS_STATE_CONTENTS_DOWN,
	ICS_STATE_CONTENTS_UP,
	ICS_STATE_HIERARCHY_DOWN,
	ICS_STATE_HIERARCHY_UP
};

struct ICS_STATE {
	int type;
	IDSET *pgiven;
	IDSET *pseen;
	IDSET *pseen_fai;
	IDSET *pread;
};

ICS_STATE* ics_state_create(LOGON_OBJECT *plogon, int type);

BOOL ics_state_append_idset(ICS_STATE *pstate,
	uint32_t state_property, IDSET *pset);

TPROPVAL_ARRAY* ics_state_serialize(ICS_STATE *pstate);

void ics_state_free(ICS_STATE *pstate);
