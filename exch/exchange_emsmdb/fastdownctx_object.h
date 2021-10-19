#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct ATTACHMENT_CONTENT;
struct FOLDER_CONTENT;
struct FTSTREAM_PRODUCER;
struct ICS_STATE;
struct logon_object;
struct MESSAGE_CONTENT;

struct fastdownctx_object final {
	protected:
	fastdownctx_object() = default;

	public:
	~fastdownctx_object();
	static std::unique_ptr<fastdownctx_object> create(logon_object *, uint8_t string_option);
	/* make_xxx function can be invoked only once on the object */
	BOOL make_messagecontent(MESSAGE_CONTENT *);
	BOOL make_attachmentcontent(ATTACHMENT_CONTENT *);
	BOOL make_foldercontent(BOOL subfolders, std::unique_ptr<FOLDER_CONTENT> &&);
	BOOL make_topfolder(std::unique_ptr<FOLDER_CONTENT> &&);
	BOOL make_messagelist(BOOL chginfo, EID_ARRAY *msglst);
	BOOL make_state(ICS_STATE *);
	BOOL get_buffer(void *buf, uint16_t *len, BOOL *last, uint16_t *progress, uint16_t *total);

	std::unique_ptr<FTSTREAM_PRODUCER> pstream;
	BOOL b_back = false, b_last = false, b_chginfo = false;
	EID_ARRAY *pmsglst = nullptr;
	std::unique_ptr<FOLDER_CONTENT> pfldctnt;
	DOUBLE_LIST flow_list{};
	uint32_t total_steps = 0, progress_steps = 0;
};
