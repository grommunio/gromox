#pragma once
#include <cstdint>
#include <list>
#include <memory>
#include <sys/types.h>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#define FTSTREAM_PRODUCER_POINT_LENGTH			1024
#define FTSTREAM_PRODUCER_BUFFER_LENGTH			4*1024*1024
#define STRING_OPTION_NONE						0x00
#define STRING_OPTION_UNICODE					0x01
#define STRING_OPTION_CPID						0x02
#define STRING_OPTION_FORCE_UNICODE				0x08

struct attachment_content;
struct FOLDER_CHANGES;
struct logon_object;
struct message_content;
struct PROGRESS_INFORMATION;
struct PROGRESS_MESSAGE;

enum point_type {
	normal_break, long_var, wstring,
};

struct point_node {
	point_type type;
	uint32_t offset;
};

struct fxstream_producer {
	protected:
	fxstream_producer() = default;
	NOMOVE(fxstream_producer);

	public:
	static std::unique_ptr<fxstream_producer> create(logon_object *, uint8_t string_option);
	inline uint32_t total_length() const { return offset; }
	BOOL read_buffer(void *buf, uint16_t *len, BOOL *last);
	BOOL write_uint32(uint32_t);
	BOOL write_proplist(const TPROPVAL_ARRAY *);
	BOOL write_attachmentcontent(BOOL delprop, const attachment_content *);
	BOOL write_messagecontent(BOOL delprop, const message_content *);
	BOOL write_message(const message_content *);
	BOOL write_progresstotal(const PROGRESS_INFORMATION *);
	BOOL write_progresspermessage(const PROGRESS_MESSAGE *);
	BOOL write_messagechangefull(const TPROPVAL_ARRAY *chgheader, message_content *);
	BOOL write_deletions(const TPROPVAL_ARRAY *);
	BOOL write_readstatechanges(const TPROPVAL_ARRAY *);
	BOOL write_state(const TPROPVAL_ARRAY *);
	BOOL write_hierarchysync(const FOLDER_CHANGES *fldchgs, const TPROPVAL_ARRAY *del, const TPROPVAL_ARRAY *state);

	int type = 0;
	uint32_t offset = 0;
	gromox::tmpfile fd;
	uint8_t buffer[FTSTREAM_PRODUCER_BUFFER_LENGTH]{};
	uint32_t buffer_offset = 0, read_offset = 0;
	uint8_t string_option = 0;
	logon_object *plogon = nullptr; /* plogon is a protected member */
	std::list<point_node> bp_list;
	BOOL b_read = false;
};
