#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/mapi_types.hpp>

struct attachment_content;
struct PROPERTY_XNAME;

struct GX_EXPORT attachment_list {
	void remove(uint16_t index);
	BOOL append_internal(attachment_content *);
	attachment_list *dup() const;
	gromox::deref_iterator<attachment_content> begin() { return pplist; }
	gromox::deref_iterator<attachment_content> end() { return pplist + count; }
	gromox::const_deref_iterator<attachment_content> begin() const { return pplist; }
	gromox::const_deref_iterator<attachment_content> end() const { return pplist + count; }
	gromox::const_deref_iterator<attachment_content> cbegin() const { return pplist; }
	gromox::const_deref_iterator<attachment_content> cend() const { return pplist + count; }

	uint16_t count;
	attachment_content **pplist;
};
using ATTACHMENT_LIST = attachment_list;

struct GX_EXPORT message_children {
	TARRAY_SET *prcpts;
	ATTACHMENT_LIST *pattachments;
};
using MESSAGE_CHILDREN = message_children;

struct GX_EXPORT change_part {
	uint32_t group;
	TPROPVAL_ARRAY proplist;
};
using CHANGE_PART = change_part;

struct GX_EXPORT progress_message {
	uint32_t message_size;
	BOOL b_fai;
};
using PROGRESS_MESSAGE = progress_message;

struct GX_EXPORT progress_information {
	uint16_t version;
	uint16_t padding1;
	uint32_t fai_count;
	uint64_t fai_size;
	uint32_t normal_count;
	uint32_t padding2;
	uint64_t normal_size;
};
using PROGRESS_INFORMATION = progress_information;

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

struct GX_EXPORT folder_messages {
	EID_ARRAY *pfai_msglst;
	EID_ARRAY *pnormal_msglst;
};
using FOLDER_MESSAGES = folder_messages;

struct GX_EXPORT folder_content {
	folder_content();
	folder_content(folder_content &&) noexcept;
	~folder_content();
	void operator=(folder_content &&) noexcept = delete;
	bool append_subfolder_internal(folder_content &&);
	TPROPVAL_ARRAY *get_proplist() { return &proplist; }
	void append_failist_internal(EID_ARRAY *);
	void append_normallist_internal(EID_ARRAY *);

	TPROPVAL_ARRAY proplist{};
	FOLDER_MESSAGES fldmsgs{};
	std::vector<folder_content> psubflds;
};
using FOLDER_CONTENT = folder_content;

struct GX_EXPORT folder_changes {
	uint32_t count;
	TPROPVAL_ARRAY *pfldchgs;
	I_BEGIN_END(pfldchgs, count);
};
using FOLDER_CHANGES = folder_changes;

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
