#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include "ics_state.hpp"

enum {
	SPECIAL_CONTAINER_ROOT = 0xc,
	SPECIAL_CONTAINER_EMPTY = 0xd,
	SPECIAL_CONTAINER_PROVIDER = 0xe,
	SPECIAL_CONTAINER_GAL = 0xf,
};

enum {
	CONTAINER_TYPE_FOLDER = 1,
	CONTAINER_TYPE_ABTREE = 2,
};

struct attachment_object;
struct store_object;
struct ics_state;
struct message_content;
struct store_object;

union CONTAINER_ID {
	struct {
		BOOL b_private;
		uint64_t folder_id;
	} exmdb_id;
	struct {
		int base_id;
		uint32_t minid;
	} abtree_id;
};

struct container_object {
	protected:
	container_object() = default;
	NOMOVE(container_object);

	public:
	~container_object() { clear(); }
	static std::unique_ptr<container_object> create(uint8_t type, CONTAINER_ID);
	void clear();
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL load_user_table(const RESTRICTION *);
	BOOL get_container_table_num(BOOL depth, uint32_t *num);
	BOOL query_container_table(const PROPTAG_ARRAY *, BOOL depth, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);
	BOOL get_user_table_num(uint32_t *);
	BOOL query_user_table(const PROPTAG_ARRAY *, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);

	uint8_t type = 0;
	CONTAINER_ID id{};
	union {
		TARRAY_SET *prow_set;
		LONG_ARRAY *pminid_array;
	} contents{};
};

struct folder_object {
	protected:
	folder_object() = default;

	public:
	static std::unique_ptr<folder_object> create(store_object *, uint64_t folder_id, uint8_t type, uint32_t tag_access);
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	bool is_readonly_prop(gromox::proptag_t) const;
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL get_permissions(PERMISSION_SET *);
	BOOL set_permissions(const PERMISSION_SET *);
	BOOL updaterules(uint32_t flags, RULE_LIST *);

	store_object *pstore = nullptr;
	uint64_t folder_id = 0;
	uint8_t type = 0;
	uint32_t tag_access = 0;
};

struct icsdownctx_object final {
	protected:
	icsdownctx_object() = default;
	NOMOVE(icsdownctx_object);

	public:
	~icsdownctx_object();
	static std::unique_ptr<icsdownctx_object> create(folder_object *, uint8_t sync_type);
	uint8_t get_type() const { return sync_type; }
	BOOL make_content(const BINARY &state, const RESTRICTION *, uint16_t sync_flags, BOOL *changed, uint32_t *msg_count);
	BOOL make_hierarchy(const BINARY &state, uint16_t sync_flags, BOOL *changed, uint32_t *fld_count);
	BINARY *get_state();
	BOOL sync_message_change(BOOL *found, BOOL *b_new, TPROPVAL_ARRAY *);
	BOOL sync_folder_change(BOOL *found, TPROPVAL_ARRAY *);
	BOOL sync_deletions(uint32_t flags, BINARY_ARRAY *);
	BOOL sync_readstates(STATE_ARRAY *);

	uint8_t sync_type = 0;
	store_object *pstore = nullptr;
	uint64_t folder_id = 0;
	std::unique_ptr<ics_state> pstate;
	BOOL b_started = false;
	uint64_t last_changenum = 0, last_readcn = 0;
	EID_ARRAY *pgiven_eids = nullptr, *pchg_eids = nullptr;
	EID_ARRAY *pupdated_eids = nullptr, *pdeleted_eids = nullptr;
	EID_ARRAY *pnolonger_messages = nullptr, *pread_messages = nullptr;
	EID_ARRAY *punread_messages = nullptr;
	uint32_t eid_pos = 0;
};

struct icsupctx_object final {
	protected:
	icsupctx_object() = default;

	public:
	static std::unique_ptr<icsupctx_object> create(folder_object *, uint8_t sync_type);
	BOOL upload_state(const BINARY &s) { return pstate->deserialize(s); }
	BINARY *get_state() { return pstate->serialize(); }
	store_object *get_store() const { return pstore; }
	uint8_t get_type() const { return sync_type; }
	uint64_t get_parent_folder_id() const { return folder_id; }

	store_object *pstore = nullptr;
	uint64_t folder_id = 0;
	std::shared_ptr<ics_state> pstate; /* public member */
	uint8_t sync_type = 0;
};

/* message_object and attachment_object are friend classes,
	so they can operate internal variables of each other */
struct message_object {
	protected:
	message_object() = default;
	NOMOVE(message_object);

	public:
	~message_object();
	static std::unique_ptr<message_object> create(store_object *, BOOL b_new, cpid_t cpid, uint64_t message_id, void *parent, uint32_t tag_access, BOOL b_writable, std::shared_ptr<ics_state>);
	uint32_t get_instance_id() const { return instance_id; }
	BOOL check_original_touched(BOOL *touched);
	bool importing() const { return message_id != 0 && pstate != nullptr; }
	bool writable() const { return b_writable; }
	gromox::errno_t init_message(bool fai, cpid_t);
	uint64_t get_id() const { return message_id; }
	store_object *get_store() const { return pstore; }
	ec_error_t save();
	BOOL reload();
	BOOL write_message(const message_content *);
	BOOL get_recipient_all_proptags(PROPTAG_ARRAY *);
	BOOL read_recipients(uint32_t row_id, uint16_t need_count, TARRAY_SET *);
	BOOL get_rowid_begin(uint32_t *begin_id);
	BOOL get_recipient_num(uint16_t *);
	BOOL set_rcpts(const TARRAY_SET *);
	BOOL empty_rcpts();
	BOOL get_attachments_num(uint16_t *);
	BOOL delete_attachment(uint32_t attachment_num);
	BOOL get_attachment_table_all_proptags(PROPTAG_ARRAY *);
	BOOL query_attachment_table(const PROPTAG_ARRAY *, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);
	BOOL clear_unsent();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL copy_to(message_object *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle);
	BOOL set_readflag(uint8_t read_flag, BOOL *changed);

	store_object *pstore = nullptr;
	BOOL b_new = false, b_writable = false, b_touched = false;
	uint64_t change_num = 0, message_id = 0, folder_id = 0;
	cpid_t cpid = CP_ACP;
	uint32_t instance_id = 0, tag_access = 0;
	attachment_object *pembedding = nullptr;
	std::shared_ptr<ics_state> pstate;
	PROPTAG_ARRAY *pchanged_proptags = nullptr, *premoved_proptags = nullptr;
};

/* message_object and attachment_object are friend classes,
	so they can operate internal variables of each other */
struct attachment_object {
	protected:
	attachment_object() = default;
	NOMOVE(attachment_object);

	public:
	~attachment_object();
	static std::unique_ptr<attachment_object> create(message_object *parent, uint32_t at_num);
	uint32_t get_instance_id() const { return instance_id; }
	BOOL init_attachment();
	uint32_t get_attachment_num() const { return attachment_num; }
	uint32_t get_tag_access() const { return pparent->tag_access; }
	ec_error_t save();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL copy_properties(attachment_object *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle);
	store_object *get_store() const { return pparent->pstore; }
	bool writable() const { return b_writable; }

	BOOL b_new = false, b_writable = false, b_touched = false;
	message_object *pparent = nullptr;
	uint32_t instance_id = 0, attachment_num = 0;
};

struct user_object {
	protected:
	user_object() = default;

	public:
	static std::unique_ptr<user_object> create(int base_id, uint32_t minid);
	bool valid();
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	ec_error_t load_list_members(const RESTRICTION *);
	ec_error_t query_member_table(const PROPTAG_ARRAY *, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);

	int base_id = 0;
	uint32_t minid = 0;
	std::vector<uint32_t> m_members;
};

struct oneoff_object {
	protected:
	oneoff_object(const ONEOFF_ENTRYID &);

	public:
	static std::unique_ptr<oneoff_object> create(const ONEOFF_ENTRYID &);
	ec_error_t get_props(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);

	static const uint32_t all_tags_raw[];
	static const PROPTAG_ARRAY all_tags;

	private:
	uint16_t m_flags = 0;
	std::string m_dispname, m_addrtype, m_emaddr;
};

extern BOOL container_object_fetch_special_property(uint8_t special_type, gromox::proptag_t, void **value);
extern void container_object_get_container_table_all_proptags(PROPTAG_ARRAY *);
extern void container_object_get_user_table_all_proptags(PROPTAG_ARRAY *);
