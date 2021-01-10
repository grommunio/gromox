#pragma once
#include <gromox/defs.h>
#include "ftstream_parser.h"
#include <gromox/element_data.hpp>
#define ROOT_ELEMENT_FOLDERCONTENT			1
#define ROOT_ELEMENT_MESSAGECONTENT			2
#define ROOT_ELEMENT_ATTACHMENTCONTENT		3
#define ROOT_ELEMENT_MESSAGELIST			4
#define ROOT_ELEMENT_TOPFOLDER				5

struct FASTUPCTX_OBJECT {
	FTSTREAM_PARSER *pstream;
	void *pobject;
	BOOL b_ended;
	int root_element;
	TPROPVAL_ARRAY *pproplist;
	MESSAGE_CONTENT *pmsgctnt;
	DOUBLE_LIST marker_stack;
};

#ifdef __cplusplus
extern "C" {
#endif

FASTUPCTX_OBJECT* fastupctx_object_create(
	LOGON_OBJECT *plogon, void *pobject, int root_element);

void fastupctx_object_free(FASTUPCTX_OBJECT *pctx);
extern gxerr_t fastupctx_object_write_buffer(FASTUPCTX_OBJECT *, const BINARY *transfer_data);

#ifdef __cplusplus
} /* extern "C" */
#endif
