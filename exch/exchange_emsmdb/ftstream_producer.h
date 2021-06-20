#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <gromox/mapi_types.hpp>
#include <gromox/double_list.hpp>
#include "logon_object.h"
#include <sys/types.h>
#define FTSTREAM_PRODUCER_POINT_LENGTH			1024
#define FTSTREAM_PRODUCER_BUFFER_LENGTH			4*1024*1024
#define STRING_OPTION_NONE						0x00
#define STRING_OPTION_UNICODE					0x01
#define STRING_OPTION_CPID						0x02
#define STRING_OPTION_FORCE_UNICODE				0x08

struct FTSTREAM_PRODUCER {
	~FTSTREAM_PRODUCER();
	BOOL write_message(const MESSAGE_CONTENT *);
	BOOL write_progresstotal(const PROGRESS_INFORMATION *);
	BOOL write_progresspermessage(const PROGRESS_MESSAGE *);
	BOOL write_messagechangefull(const TPROPVAL_ARRAY *chgheader, MESSAGE_CONTENT *);
	BOOL write_messagechangepartial(const TPROPVAL_ARRAY *chgheader, const MSGCHG_PARTIAL *msg);
	BOOL write_readstatechanges(const TPROPVAL_ARRAY *);
	BOOL write_hierarchysync(const FOLDER_CHANGES *fldchgs, const TPROPVAL_ARRAY *del, const TPROPVAL_ARRAY *state);

	int type = 0, fd = -1;
	uint32_t offset = 0;
	std::string path;
	uint8_t buffer[FTSTREAM_PRODUCER_BUFFER_LENGTH]{};
	uint32_t buffer_offset = 0, read_offset = 0;
	uint8_t string_option = 0;
	LOGON_OBJECT *plogon = nullptr; /* plogon is a protected member */
	DOUBLE_LIST bp_list{};
	BOOL b_read = false;
};
using ftstream_producer = FTSTREAM_PRODUCER;

extern std::unique_ptr<FTSTREAM_PRODUCER> ftstream_producer_create(LOGON_OBJECT *, uint8_t string_option);
int ftstream_producer_total_length(FTSTREAM_PRODUCER *pstream);
BOOL ftstream_producer_read_buffer(FTSTREAM_PRODUCER *pstream,
	void *pbuff, uint16_t *plen, BOOL *pb_last);
BOOL ftstream_producer_write_uint32(
	FTSTREAM_PRODUCER *pstream, uint32_t v);
BOOL ftstream_producer_write_proplist(FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist);
BOOL ftstream_producer_write_attachmentcontent(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const ATTACHMENT_CONTENT *pattachment);
BOOL ftstream_producer_write_messagecontent(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const MESSAGE_CONTENT *pmessage);
BOOL ftstream_producer_write_deletions(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist);
BOOL ftstream_producer_write_state(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist);
