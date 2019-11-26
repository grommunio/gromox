#ifndef _H_ICSDOWNCTX_OBJECT_
#define _H_ICSDOWNCTX_OBJECT_
#include "mem_file.h"
#include "ics_state.h"
#include "mapi_types.h"
#include "folder_object.h"
#include "ftstream_producer.h"

typedef struct _ICSDOWNCTX_OBJECT {
	FTSTREAM_PRODUCER *pstream;
	uint8_t sync_type;
	FOLDER_OBJECT *pfolder;
	ICS_STATE *pstate;	/* public member */
	uint32_t state_property;
	MEM_FILE f_state_stream;
	BOOL b_started;
	DOUBLE_LIST flow_list;
	DOUBLE_LIST group_list;
	uint64_t last_readcn;
	uint64_t last_changenum;
	PROGRESS_INFORMATION *pprogtotal;
	EID_ARRAY *pmessages;
	EID_ARRAY *pdeleted_messages;
	EID_ARRAY *pnolonger_messages;
	EID_ARRAY *pread_messags;
	EID_ARRAY *punread_messags;
	uint8_t send_options;
	uint16_t sync_flags;
	uint32_t extra_flags;
	PROPTAG_ARRAY *pproptags;
	RESTRICTION *prestriction;
	uint64_t total_steps;
	uint64_t progress_steps;
	uint64_t next_progress_steps;
	uint64_t ratio;
	PROPERTY_GROUPINFO fake_gpinfo;
} ICSDOWNCTX_OBJECT;


ICSDOWNCTX_OBJECT* icsdownctx_object_create(LOGON_OBJECT *plogon,
	FOLDER_OBJECT *pfolder, uint8_t sync_type, uint8_t send_options,
	uint16_t sync_flags, const RESTRICTION *prestriction,
	uint32_t extra_flags, const PROPTAG_ARRAY *pproptags);

BOOL icsdownctx_object_begin_state_stream(ICSDOWNCTX_OBJECT *pctx,
	uint32_t state_property);

BOOL icsdownctx_object_continue_state_stream(ICSDOWNCTX_OBJECT *pctx,
	const BINARY *pstream_data);

BOOL icsdownctx_object_end_state_stream(ICSDOWNCTX_OBJECT *pctx);

BOOL icsdownctx_object_check_started(ICSDOWNCTX_OBJECT *pctx);
	
BOOL icsdownctx_object_make_sync(ICSDOWNCTX_OBJECT *pctx);

ICS_STATE* icsdownctx_object_get_state(ICSDOWNCTX_OBJECT *pctx);

void icsdownctx_object_free(ICSDOWNCTX_OBJECT *pctx);

BOOL icsdownctx_object_get_buffer(ICSDOWNCTX_OBJECT *pctx,
	void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal);

#endif /* _H_ICSDOWNCTX_OBJECT_ */
