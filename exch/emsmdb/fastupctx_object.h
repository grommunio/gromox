#pragma once
#include <cstdint>
#include <list>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

#define ROOT_ELEMENT_FOLDERCONTENT			1
#define ROOT_ELEMENT_MESSAGECONTENT			2
#define ROOT_ELEMENT_ATTACHMENTCONTENT		3
#define ROOT_ELEMENT_MESSAGELIST			4
#define ROOT_ELEMENT_TOPFOLDER				5

struct fxstream_parser;
struct logon_object;
struct ATTACHMENT_CONTENT;
struct MESSAGE_CONTENT;
struct TPROPVAL_ARRAY;

struct fxup_marker_node {
	uint32_t marker;
	union {
		MESSAGE_CONTENT *msg;
		ATTACHMENT_CONTENT *atx;
		TPROPVAL_ARRAY *props;
		uint32_t instance_id;
		uint64_t folder_id;
	};
};

struct fastupctx_object final {
	protected:
	fastupctx_object() = default;
	NOMOVE(fastupctx_object);

	public:
	~fastupctx_object();
	static std::unique_ptr<fastupctx_object> create(logon_object *, void *pobject, int root_element);
	gxerr_t write_buffer(const BINARY *transfer_data);
	gxerr_t record_marker(uint32_t marker);
	gxerr_t record_propval(const TAGGED_PROPVAL *);

	std::unique_ptr<fxstream_parser> pstream;
	void *pobject = nullptr;
	BOOL b_ended = false;
	int root_element = 0;
	TPROPVAL_ARRAY *pproplist = nullptr;
	MESSAGE_CONTENT *pmsgctnt = nullptr;
	std::list<fxup_marker_node> marker_stack;
};
