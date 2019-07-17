#ifndef _OXVCARD_H_
#define _OXVCARD_H_
#include "element_data.h"
#include "vcard.h"

#define VCARD_MAX_BUFFER_LEN				1024*1024

MESSAGE_CONTENT* oxvcard_import(
	const VCARD *pvcard, GET_PROPIDS get_propids);

BOOL oxvcard_export(const MESSAGE_CONTENT *pmsg,
	VCARD *pvcard, GET_PROPIDS get_propids);


#endif /* _OXVCARD_H_ */
