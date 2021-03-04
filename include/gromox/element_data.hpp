#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

struct ATTACHMENT_CONTENT;

struct PROPERTY_GROUPINFO {
	uint32_t group_id;
	uint32_t reserved;
	uint32_t count;
	PROPTAG_ARRAY *pgroups;
};

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
	TPROPVAL_ARRAY proplist; /* PROP_TAG_ATTACHNUMBER must be the first */
	MESSAGE_CONTENT *pembedded;
};

struct FOLDER_MESSAGES {
	EID_ARRAY *pfai_msglst;
	EID_ARRAY *pnormal_msglst;
};

struct FOLDER_CONTENT {
	TPROPVAL_ARRAY proplist;
	FOLDER_MESSAGES fldmsgs;
	uint32_t count;
	struct FOLDER_CONTENT *psubflds;
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
extern FOLDER_CONTENT *folder_content_init();
void folder_content_free(FOLDER_CONTENT *pfldctnt);

BOOL folder_content_append_subfolder_internal(
	FOLDER_CONTENT *pfldctnt, FOLDER_CONTENT *psubfld);
	
TPROPVAL_ARRAY* folder_content_get_proplist(FOLDER_CONTENT *pfldctnt);

void folder_content_append_failist_internal(
	FOLDER_CONTENT *pfldctnt, EID_ARRAY *plist);

void folder_content_append_normallist_internal(
	FOLDER_CONTENT *pfldctnt, EID_ARRAY *plist);
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

PROPERTY_GROUPINFO* property_groupinfo_init(uint32_t group_id);

BOOL property_groupinfo_init_internal(
	PROPERTY_GROUPINFO *pgpinfo, uint32_t group_id);

BOOL property_groupinfo_append_internal(
	PROPERTY_GROUPINFO *pgpinfo, PROPTAG_ARRAY *pgroup);

BOOL property_groupinfo_get_partial_index(PROPERTY_GROUPINFO *pgpinfo,
	uint32_t proptag, uint32_t *pindex);

void property_groupinfo_free(PROPERTY_GROUPINFO *pgpinfo);

void property_groupinfo_free_internal(PROPERTY_GROUPINFO *pgpinfo);
