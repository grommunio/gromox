#ifndef _H_FTSTREAM_PRODUCER_
#define _H_FTSTREAM_PRODUCER_
#include "mapi_types.h"
#include "double_list.h"
#include "logon_object.h"
#include <sys/types.h>


#define FTSTREAM_PRODUCER_POINT_LENGTH			1024

#define FTSTREAM_PRODUCER_BUFFER_LENGTH			4*1024*1024

#define STRING_OPTION_NONE						0x00
#define STRING_OPTION_UNICODE					0x01
#define STRING_OPTION_CPID						0x02
#define STRING_OPTION_FORCE_UNICODE				0x08


typedef struct _FTSTREAM_PRODUCER {
	int type;
	int fd;
	uint32_t offset;
	char path[256];
	uint8_t buffer[FTSTREAM_PRODUCER_BUFFER_LENGTH];
	uint32_t buffer_offset;
	uint32_t read_offset;
	uint8_t string_option;
	LOGON_OBJECT *plogon;	/* plogon is a protected member */
	DOUBLE_LIST bp_list;
	BOOL b_read;
} FTSTREAM_PRODUCER;


FTSTREAM_PRODUCER* ftstream_producer_create(
	LOGON_OBJECT *plogon, uint8_t string_option);

void ftstream_producer_free(FTSTREAM_PRODUCER *pstream);

int ftstream_producer_total_length(FTSTREAM_PRODUCER *pstream);

BOOL ftstream_producer_read_buffer(FTSTREAM_PRODUCER *pstream,
	void *pbuff, uint16_t *plen, BOOL *pb_last);

BOOL ftstream_producer_write_uint32(
	FTSTREAM_PRODUCER *pstream, uint32_t v);

BOOL ftstream_producer_write_proplist(FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist);

BOOL ftstream_producer_write_errorinfo(
	FTSTREAM_PRODUCER *pstream, const EXTENDED_ERROR *perror);
	
BOOL ftstream_producer_write_attachmentcontent(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const ATTACHMENT_CONTENT *pattachment);
	
BOOL ftstream_producer_write_messagecontent(
	FTSTREAM_PRODUCER *pstream, BOOL b_delprop,
	const MESSAGE_CONTENT *pmessage);
	
BOOL ftstream_producer_write_message(
	FTSTREAM_PRODUCER *pstream,
	const MESSAGE_CONTENT *pmessage);

BOOL ftstream_producer_write_progresstotal(
	FTSTREAM_PRODUCER *pstream,
	const PROGRESS_INFORMATION *pprogtotal);

BOOL ftstream_producer_write_progresspermessage(
	FTSTREAM_PRODUCER *pstream,
	const PROGRESS_MESSAGE *pprogmsg);

BOOL ftstream_producer_write_messagechangefull(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pchgheader,
	MESSAGE_CONTENT *pmessage);

BOOL ftstream_producer_write_messagechangepartial(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pchgheader,
	const MSGCHG_PARTIAL *pmsg);	

BOOL ftstream_producer_write_deletions(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist);
	
BOOL ftstream_producer_write_readstatechanges(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist);

BOOL ftstream_producer_write_state(
	FTSTREAM_PRODUCER *pstream,
	const TPROPVAL_ARRAY *pproplist);

BOOL ftstream_producer_write_hierarchysync(
	FTSTREAM_PRODUCER *pstream,
	const FOLDER_CHANGES *pfldchgs,
	const TPROPVAL_ARRAY *pdels,
	const TPROPVAL_ARRAY *pstate);

#endif /* _H_FTSTREAM_PRODUCER_ */
