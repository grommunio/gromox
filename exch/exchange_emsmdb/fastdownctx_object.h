#pragma once
#include <cstdint>
#include "ftstream_producer.h"
#include "ics_state.h"

struct FASTDOWNCTX_OBJECT {
	FTSTREAM_PRODUCER *pstream;
	BOOL b_back;
	BOOL b_last;
	BOOL b_chginfo;
	EID_ARRAY *pmsglst;
	FOLDER_CONTENT *pfldctnt;
	DOUBLE_LIST flow_list;
	uint32_t total_steps;
	uint32_t progress_steps;
};

/* make_xxx function can be invoked only once on the object */
FASTDOWNCTX_OBJECT* fastdownctx_object_create(
	LOGON_OBJECT *plogon, uint8_t string_option);
BOOL fastdownctx_object_make_messagecontent(
	FASTDOWNCTX_OBJECT *pctx, MESSAGE_CONTENT *pmsgctnt);
BOOL fastdownctx_object_make_attachmentcontent(
	FASTDOWNCTX_OBJECT *pctx,
	ATTACHMENT_CONTENT *pattachment);
BOOL fastdownctx_object_make_foldercontent(
	FASTDOWNCTX_OBJECT *pctx,
	BOOL b_subfolders, FOLDER_CONTENT *pfldctnt);
BOOL fastdownctx_object_make_topfolder(
	FASTDOWNCTX_OBJECT *pctx, FOLDER_CONTENT *pfldctnt);
BOOL fastdownctx_object_make_messagelist(
	FASTDOWNCTX_OBJECT *pctx,
	BOOL b_chginfo, EID_ARRAY *pmsglst);
BOOL fastdownctx_object_make_state(
	FASTDOWNCTX_OBJECT *pctx, ICS_STATE *pstate);
void fastdownctx_object_free(FASTDOWNCTX_OBJECT *pctx);
BOOL fastdownctx_object_get_buffer(FASTDOWNCTX_OBJECT *pctx,
	void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal);
