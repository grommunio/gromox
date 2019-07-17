#ifndef _H_FASTUPCTX_OBJECT_
#define _H_FASTUPCTX_OBJECT_
#include "ftstream_parser.h"
#include "element_data.h"


#define ROOT_ELEMENT_FOLDERCONTENT			1
#define ROOT_ELEMENT_MESSAGECONTENT			2
#define ROOT_ELEMENT_ATTACHMENTCONTENT		3
#define ROOT_ELEMENT_MESSAGELIST			4
#define ROOT_ELEMENT_TOPFOLDER				5

typedef struct _FASTUPCTX_OBJECT {
	FTSTREAM_PARSER *pstream;
	void *pobject;
	BOOL b_ended;
	int root_element;
	TPROPVAL_ARRAY *pproplist;
	MESSAGE_CONTENT *pmsgctnt;
	DOUBLE_LIST marker_stack;
} FASTUPCTX_OBJECT;


FASTUPCTX_OBJECT* fastupctx_object_create(
	LOGON_OBJECT *plogon, void *pobject, int root_element);

void fastupctx_object_free(FASTUPCTX_OBJECT *pctx);

BOOL fastupctx_object_write_buffer(FASTUPCTX_OBJECT *pctx,
	const BINARY *ptransfer_data);

#endif /* _H_FASTUPCTX_OBJECT_ */
