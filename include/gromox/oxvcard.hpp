#pragma once
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/vcard.hpp>
#define VCARD_MAX_BUFFER_LEN				1024*1024

MESSAGE_CONTENT* oxvcard_import(
	const VCARD *pvcard, GET_PROPIDS get_propids);
extern GX_EXPORT BOOL oxvcard_export(MESSAGE_CONTENT *, vcard &, GET_PROPIDS);
extern GX_EXPORT unsigned int g_oxvcard_pedantic;
