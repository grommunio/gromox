#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/mapi_types.hpp>

struct ATTACHMENT_CONTENT;

struct GX_EXPORT property_groupinfo {
	property_groupinfo(uint32_t group_id);
	~property_groupinfo();
	property_groupinfo(property_groupinfo &&) noexcept;
	void operator=(property_groupinfo &&) noexcept = delete;
	bool append_internal(PROPTAG_ARRAY *);
	bool get_partial_index(uint32_t proptag, uint32_t *idx) const;

	uint32_t group_id = 0, reserved = 0, count = 0;
	PROPTAG_ARRAY *pgroups = nullptr;
};
using PROPERTY_GROUPINFO = property_groupinfo;

struct ATTACHMENT_LIST {
	uint16_t count;
	ATTACHMENT_CONTENT **pplist;
};

struct MESSAGE_CHILDREN {
	TARRAY_SET *prcpts;
	ATTACHMENT_LIST *pattachments;
};

struct CHANGE_PART {
	uint32_t index;
	TPROPVAL_ARRAY proplist;
};

struct MSGCHG_PARTIAL {
	const PROPERTY_GROUPINFO *pgpinfo; /* this memory is only a reference */
	uint32_t group_id;
	uint32_t count;
	CHANGE_PART *pchanges;
	MESSAGE_CHILDREN children;
};

struct PROGRESS_MESSAGE {
	uint32_t message_size;
	BOOL b_fai;
};

struct PROGRESS_INFORMATION {
	uint16_t version;
	uint16_t padding1;
	uint32_t fai_count;
	uint64_t fai_size;
	uint32_t normal_count;
	uint32_t padding2;
	uint64_t normal_size;
};

struct MESSAGE_CONTENT {
	TPROPVAL_ARRAY proplist;
	MESSAGE_CHILDREN children;
};

struct ATTACHMENT_CONTENT {
	TPROPVAL_ARRAY proplist; /* PR_ATTACH_NUM must be the first */
	MESSAGE_CONTENT *pembedded;
};

struct FOLDER_MESSAGES {
	EID_ARRAY *pfai_msglst;
	EID_ARRAY *pnormal_msglst;
};

struct GX_EXPORT FOLDER_CONTENT {
	FOLDER_CONTENT();
	FOLDER_CONTENT(FOLDER_CONTENT &&) noexcept;
	~FOLDER_CONTENT();
	void operator=(FOLDER_CONTENT &&) noexcept = delete;
	BOOL append_subfolder_internal(FOLDER_CONTENT &&);
	TPROPVAL_ARRAY *get_proplist() { return &proplist; }
	void append_failist_internal(EID_ARRAY *);
	void append_normallist_internal(EID_ARRAY *);

	TPROPVAL_ARRAY proplist{};
	FOLDER_MESSAGES fldmsgs{};
	std::vector<FOLDER_CONTENT> psubflds;
};

struct FOLDER_CHANGES {
	uint32_t count;
	TPROPVAL_ARRAY *pfldchgs;
};

extern ATTACHMENT_CONTENT *attachment_content_init();
extern void attachment_content_set_embedded_internal(ATTACHMENT_CONTENT *, MESSAGE_CONTENT *embed);
void attachment_content_free(ATTACHMENT_CONTENT *pattachment);
ATTACHMENT_CONTENT* attachment_content_dup(
	ATTACHMENT_CONTENT *pattachment);
extern ATTACHMENT_LIST *attachment_list_init();
void attachment_list_free(ATTACHMENT_LIST *plist);
void attachment_list_remove(ATTACHMENT_LIST *plist, uint16_t index);
BOOL attachment_list_append_internal(ATTACHMENT_LIST *plist,
	ATTACHMENT_CONTENT *pattachment);
ATTACHMENT_LIST* attachment_list_dup(ATTACHMENT_LIST *plist);
extern GX_EXPORT std::unique_ptr<FOLDER_CONTENT> folder_content_init();
extern MESSAGE_CONTENT *message_content_init();
BOOL message_content_init_internal(MESSAGE_CONTENT *pmsgctnt);
TPROPVAL_ARRAY* message_content_get_proplist(MESSAGE_CONTENT *pmsgctnt);
void message_content_set_rcpts_internal(
	MESSAGE_CONTENT *pmsgctnt, TARRAY_SET *prcpts);
void message_content_set_attachments_internal(
	MESSAGE_CONTENT *pmsgctnt, ATTACHMENT_LIST *pattachments);
void message_content_free_internal(MESSAGE_CONTENT *pmsgctnt);
void message_content_free(MESSAGE_CONTENT *pmsgctnt);
extern MESSAGE_CONTENT *message_content_dup(const MESSAGE_CONTENT *);
uint32_t message_content_get_size(const MESSAGE_CONTENT *pmsgctnt);
