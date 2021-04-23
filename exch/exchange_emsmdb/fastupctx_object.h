#pragma once
#include <memory>
#include <gromox/defs.h>
#include "ftstream_parser.h"
#include <gromox/element_data.hpp>
#define ROOT_ELEMENT_FOLDERCONTENT			1
#define ROOT_ELEMENT_MESSAGECONTENT			2
#define ROOT_ELEMENT_ATTACHMENTCONTENT		3
#define ROOT_ELEMENT_MESSAGELIST			4
#define ROOT_ELEMENT_TOPFOLDER				5

struct FASTUPCTX_OBJECT final {
	~FASTUPCTX_OBJECT();

	FTSTREAM_PARSER *pstream = nullptr;
	void *pobject = nullptr;
	BOOL b_ended = false;
	int root_element = 0;
	TPROPVAL_ARRAY *pproplist = nullptr;
	MESSAGE_CONTENT *pmsgctnt = nullptr;
	DOUBLE_LIST marker_stack{};
};

extern std::unique_ptr<FASTUPCTX_OBJECT> fastupctx_object_create(LOGON_OBJECT *, void *pobject, int root_element);
extern gxerr_t fastupctx_object_write_buffer(FASTUPCTX_OBJECT *, const BINARY *transfer_data);
