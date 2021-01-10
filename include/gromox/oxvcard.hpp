#pragma once
#include <gromox/element_data.hpp>
#include <gromox/vcard.hpp>
#define VCARD_MAX_BUFFER_LEN				1024*1024

MESSAGE_CONTENT* oxvcard_import(
	const VCARD *pvcard, GET_PROPIDS get_propids);

BOOL oxvcard_export(const MESSAGE_CONTENT *pmsg,
	VCARD *pvcard, GET_PROPIDS get_propids);
