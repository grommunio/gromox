#pragma once
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include "ical.h"

#ifdef __cplusplus
extern "C" {
#endif

MESSAGE_CONTENT* oxcical_import(
	const char *str_zone, const ICAL *pical,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid);

BOOL oxcical_export(const MESSAGE_CONTENT *pmsg, ICAL *pical,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	ENTRYID_TO_USERNAME entryid_to_username,
	ESSDN_TO_USERNAME essdn_to_username,
	LCID_TO_LTAG lcid_to_ltag);

#ifdef __cplusplus
}
#endif
