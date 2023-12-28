#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/mapi_types.hpp>

struct attachment_content;
struct FOLDER_CONTENT;
struct FOLDER_MESSAGES;
struct fxstream_producer;
struct ics_state;
struct logon_object;
struct message_content;
using MESSAGE_CONTENT = message_content;

enum class fxdown_flow_func : uint8_t {
	immed32, proplist_ptr, msg_id,
};

using fxdown_flow_node = std::pair<fxdown_flow_func, uint64_t>;

struct fxdown_flow_list : public std::vector<fxdown_flow_node> {
	bool record_node(fxdown_flow_func, uint64_t = 0);
	bool record_node(fxdown_flow_func, const void *);
	bool record_tag(uint32_t t) { return record_node(fxdown_flow_func::immed32, t); }
	bool record_messagelist(EID_ARRAY *);
	bool record_foldermessages(const FOLDER_MESSAGES *);
	bool record_foldermessagesnodelprops(const FOLDER_MESSAGES *);
	bool record_foldercontent(const FOLDER_CONTENT *);
	bool record_foldercontentnodelprops(const FOLDER_CONTENT *);
	bool record_subfoldernodelprops(const FOLDER_CONTENT *);
	bool record_subfolder(const FOLDER_CONTENT *);
};

struct fastdownctx_object final {
	protected:
	fastdownctx_object() = default;
	NOMOVE(fastdownctx_object);

	public:
	~fastdownctx_object();
	static std::unique_ptr<fastdownctx_object> create(logon_object *, uint8_t string_option);
	/* make_xxx function can be invoked only once on the object */
	BOOL make_messagecontent(const message_content *);
	BOOL make_attachmentcontent(const attachment_content *);
	BOOL make_foldercontent(BOOL subfolders, std::unique_ptr<FOLDER_CONTENT> &&);
	BOOL make_topfolder(std::unique_ptr<FOLDER_CONTENT> &&);
	BOOL make_messagelist(BOOL chginfo, EID_ARRAY *msglst);
	BOOL make_state(ics_state *);
	BOOL get_buffer(void *buf, uint16_t *len, BOOL *last, uint16_t *progress, uint16_t *total);

	std::unique_ptr<fxstream_producer> pstream;
	BOOL b_back = false, b_last = false, b_chginfo = false;
	EID_ARRAY *pmsglst = nullptr;
	std::unique_ptr<FOLDER_CONTENT> pfldctnt;
	fxdown_flow_list flow_list;
	size_t total_steps = 0, progress_steps = 0, divisor = 1;
};
