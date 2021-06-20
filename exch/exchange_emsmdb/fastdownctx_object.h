#pragma once
#include <cstdint>
#include <memory>
#include "ftstream_producer.h"
#include "ics_state.h"

struct FASTDOWNCTX_OBJECT final {
	~FASTDOWNCTX_OBJECT();

	std::unique_ptr<FTSTREAM_PRODUCER> pstream;
	BOOL b_back = false, b_last = false, b_chginfo = false;
	EID_ARRAY *pmsglst = nullptr;
	FOLDER_CONTENT *pfldctnt = nullptr;
	DOUBLE_LIST flow_list{};
	uint32_t total_steps = 0, progress_steps = 0;
};

/* make_xxx function can be invoked only once on the object */
extern std::unique_ptr<FASTDOWNCTX_OBJECT> fastdownctx_object_create(LOGON_OBJECT *, uint8_t string_option);
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
BOOL fastdownctx_object_get_buffer(FASTDOWNCTX_OBJECT *pctx,
	void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal);
