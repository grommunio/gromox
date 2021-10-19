#pragma once
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

#define ROOT_ELEMENT_FOLDERCONTENT			1
#define ROOT_ELEMENT_MESSAGECONTENT			2
#define ROOT_ELEMENT_ATTACHMENTCONTENT		3
#define ROOT_ELEMENT_MESSAGELIST			4
#define ROOT_ELEMENT_TOPFOLDER				5

struct FTSTREAM_PARSER;
struct logon_object;
struct MESSAGE_CONTENT;

struct fastupctx_object final {
	protected:
	fastupctx_object() = default;

	public:
	~fastupctx_object();
	static std::unique_ptr<fastupctx_object> create(logon_object *, void *pobject, int root_element);
	gxerr_t write_buffer(const BINARY *transfer_data);

	std::unique_ptr<FTSTREAM_PARSER> pstream;
	void *pobject = nullptr;
	BOOL b_ended = false;
	int root_element = 0;
	TPROPVAL_ARRAY *pproplist = nullptr;
	MESSAGE_CONTENT *pmsgctnt = nullptr;
	DOUBLE_LIST marker_stack{};
};
