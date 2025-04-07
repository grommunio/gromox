#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/mapi_types.hpp>

struct attachment_content;
struct PROPERTY_XNAME;

struct GX_EXPORT property_groupinfo {
	property_groupinfo(uint32_t group_id);
	~property_groupinfo();
	property_groupinfo(property_groupinfo &&) noexcept;
	void operator=(property_groupinfo &&) noexcept = delete;
	bool append_internal(PROPTAG_ARRAY *);
	bool get_partial_index(gromox::proptag_t, uint32_t *idx) const;

	uint32_t group_id = 0, reserved = 0, count = 0;
	PROPTAG_ARRAY *pgroups = nullptr;
};
using PROPERTY_GROUPINFO = property_groupinfo;

struct GX_EXPORT attachment_list {
	void remove(uint16_t index);
	BOOL append_internal(attachment_content *);
	attachment_list *dup() const;
	gromox::deref_iterator<attachment_content> begin() { return pplist; }
	gromox::deref_iterator<attachment_content> end() { return pplist + count; }

	uint16_t count;
	attachment_content **pplist;
};
using ATTACHMENT_LIST = attachment_list;

struct GX_EXPORT MESSAGE_CHILDREN {
	TARRAY_SET *prcpts;
	ATTACHMENT_LIST *pattachments;
};

struct GX_EXPORT CHANGE_PART {
	uint32_t index;
	TPROPVAL_ARRAY proplist;
};

struct GX_EXPORT MSGCHG_PARTIAL {
	const PROPERTY_GROUPINFO *pgpinfo; /* this memory is only a reference */
	uint32_t group_id;
	uint32_t count;
	CHANGE_PART *pchanges;
	MESSAGE_CHILDREN children;
};

struct GX_EXPORT PROGRESS_MESSAGE {
	uint32_t message_size;
	BOOL b_fai;
};

struct GX_EXPORT PROGRESS_INFORMATION {
	uint16_t version;
	uint16_t padding1;
	uint32_t fai_count;
	uint64_t fai_size;
	uint32_t normal_count;
	uint32_t padding2;
	uint64_t normal_size;
};

struct GX_EXPORT message_content {
	TPROPVAL_ARRAY *get_proplist() { return &proplist; }
	void set_rcpts_internal(TARRAY_SET *);
	void set_attachments_internal(ATTACHMENT_LIST *);
	message_content *dup() const;

	TPROPVAL_ARRAY proplist;
	MESSAGE_CHILDREN children;
};
using MESSAGE_CONTENT = message_content;

struct GX_EXPORT attachment_content {
	void set_embedded_internal(message_content *);
	attachment_content *dup() const;

	TPROPVAL_ARRAY proplist; /* PR_ATTACH_NUM must be the first */
	MESSAGE_CONTENT *pembedded;
};
using ATTACHMENT_CONTENT = attachment_content;

struct GX_EXPORT FOLDER_MESSAGES {
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

struct GX_EXPORT FOLDER_CHANGES {
	uint32_t count;
	TPROPVAL_ARRAY *pfldchgs;
	I_BEGIN_END(pfldchgs, count);
};

extern GX_EXPORT attachment_content *attachment_content_init();
extern GX_EXPORT void attachment_content_free(attachment_content *);
extern GX_EXPORT attachment_list *attachment_list_init();
extern GX_EXPORT void attachment_list_free(attachment_list *);
extern GX_EXPORT std::unique_ptr<FOLDER_CONTENT> folder_content_init();
extern GX_EXPORT message_content *message_content_init();
extern GX_EXPORT BOOL message_content_init_internal(message_content *);
extern GX_EXPORT void message_content_free_internal(message_content *);
extern GX_EXPORT void message_content_free(message_content *);

namespace gromox {

struct GX_EXPORT mc_delete {
	inline void operator()(ATTACHMENT_LIST *x) { attachment_list_free(x); }
	inline void operator()(MESSAGE_CONTENT *x) { message_content_free(x); }
};

}

namespace gi_dump {

extern GX_EXPORT unsigned int g_show_tree, g_show_props;

extern GX_EXPORT void tree(unsigned int d);
extern GX_EXPORT void tlog(const char *f, ...) __attribute__((format(printf, 1, 2)));
extern GX_EXPORT void gi_print(unsigned int depth, const TAGGED_PROPVAL &, const PROPERTY_XNAME *(*gpn)(uint16_t) = nullptr);
extern GX_EXPORT void gi_print(unsigned int depth, const TPROPVAL_ARRAY &, const PROPERTY_XNAME *(*gpn)(uint16_t) = nullptr);
extern GX_EXPORT void gi_print(unsigned int depth, const tarray_set &, const PROPERTY_XNAME *(*gpn)(uint16_t) = nullptr);
extern GX_EXPORT void gi_print(unsigned int depth, const message_content &, const PROPERTY_XNAME *(*gpn)(uint16_t) = nullptr);

}
