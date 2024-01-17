#pragma once
#include <cstdint>
#include <cstdlib>
#include <sqlite3.h>
#include <string>
#include <type_traits>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mysql_adaptor.hpp>
#define MAXIMUM_PROPNAME_NUMBER								0x7000
#define MAX_DIGLEN											256*1024
#define MAX_RULE_RECIPIENTS									256
#define MAX_DAMS_PER_RULE_FOLDER							128
#define STORE_OWNER_GRANTED nullptr

/*
 * These are used by exmdb internally; they never show up in the SQLite
 * database or the exmdb RPC interface.
 */
enum {
	ID_TAG_BODY = PROP_TAG(PT_GXI_STRING, 0x0001),
	ID_TAG_BODY_STRING8 = PROP_TAG(PT_GXI_STRING, 0x0002),
	ID_TAG_HTML = PROP_TAG(PT_GXI_STRING, 0x0004),
	ID_TAG_RTFCOMPRESSED = PROP_TAG(PT_GXI_STRING, 0x0005),
	ID_TAG_TRANSPORTMESSAGEHEADERS = PROP_TAG(PT_GXI_STRING, 0x0006),
	ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8 = PROP_TAG(PT_GXI_STRING, 0x0007),
	ID_TAG_ATTACHDATABINARY = PROP_TAG(PT_GXI_STRING, 0x000b),
	ID_TAG_ATTACHDATAOBJECT = PROP_TAG(PT_GXI_STRING, 0x000f),
};

enum {
	ADJ_INCREASE = false,
	ADJ_DECREASE = true,
};

struct MAIL;
#define E(s) extern decltype(mysql_adaptor_ ## s) *common_util_ ## s;
E(get_username_from_id)
E(check_mlist_include)
E(get_user_ids)
E(get_domain_ids)
E(get_homedir_by_id)
E(get_id_from_homedir)
E(get_id_from_maildir)
E(get_id_from_username)
E(get_maildir)
E(get_homedir)
E(get_timezone)
E(get_user_displayname)
E(get_user_lang)
#undef E
extern ec_error_t (*ems_send_mail)(MAIL *, const char *sender, const std::vector<std::string> &rcpts);
extern const GUID *(*common_util_get_handle)();

extern bool cu_rebuild_subjects(const char *&, const char *&, const char *&);
extern void cu_set_propval(TPROPVAL_ARRAY *, uint32_t tag, const void *data);
void common_util_remove_propvals(
	TPROPVAL_ARRAY *parray, uint32_t proptag);
extern BOOL common_util_username_to_essdn(const char *username, char *dn, size_t);
extern void common_util_pass_service(const char *name, void *func);
void common_util_init(const char *org_name, unsigned int max_msg,
	unsigned int max_rule_num, unsigned int max_ext_rule_num);
extern void common_util_build_tls();
extern unsigned int common_util_sequence_ID();
void* common_util_alloc(size_t size);
template<typename T> T *cu_alloc()
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(common_util_alloc(sizeof(T)));
}
template<typename T> T *cu_alloc(size_t elem)
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(common_util_alloc(sizeof(T) * elem));
}
char* common_util_dup(const char *pstr);
extern char *common_util_convert_copy(BOOL to_utf8, cpid_t, const char *s);
extern STRING_ARRAY *common_util_convert_copy_string_array(BOOL to_utf8, cpid_t, const STRING_ARRAY *);
BOOL common_util_allocate_eid(sqlite3 *psqlite, uint64_t *peid);
BOOL common_util_allocate_eid_from_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t *peid);
extern ec_error_t cu_allocate_cn(sqlite3 *, uint64_t *new_cn);
BOOL common_util_allocate_folder_art(sqlite3 *psqlite, uint32_t *part);
BOOL common_util_check_allocated_eid(sqlite3 *psqlite,
	uint64_t eid_val, BOOL *pb_result);
BOOL common_util_allocate_cid(sqlite3 *psqlite, uint64_t *pcid);
extern BOOL cu_get_proptags(mapi_object_type, uint64_t id, sqlite3 *, std::vector<uint32_t> &);
BOOL common_util_get_mapping_guid(sqlite3 *psqlite,
	uint16_t replid, BOOL *pb_found, GUID *pguid);
extern BOOL cu_get_property(mapi_object_type, uint64_t id, cpid_t, sqlite3 *, uint32_t proptag, void **out);
extern BOOL cu_get_properties(mapi_object_type, uint64_t id, cpid_t, sqlite3 *, const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
extern BOOL cu_set_property(mapi_object_type, uint64_t id, cpid_t, sqlite3 *, uint32_t tag, const void *data, BOOL *result);
extern BOOL cu_set_properties(mapi_object_type, uint64_t id, cpid_t, sqlite3 *, const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);
extern BOOL cu_remove_property(mapi_object_type, uint64_t id, sqlite3 *, uint32_t proptag);
extern BOOL cu_remove_properties(mapi_object_type, uint64_t id, sqlite3 *, const PROPTAG_ARRAY *);
BOOL common_util_get_rule_property(uint64_t rule_id,
	sqlite3 *psqlite, uint32_t proptag, void **ppvalue);
BOOL common_util_get_permission_property(uint64_t member_id,
	sqlite3 *psqlite, uint32_t proptag, void **ppvalue);
BOOL common_util_check_msgcnt_overflow(sqlite3 *psqlite);
extern BOOL cu_check_msgsize_overflow(sqlite3 *psqlite, uint32_t qtag);
extern uint32_t cu_folder_unread_count(sqlite3 *psqlite, uint64_t folder_id, unsigned int flags = 0);
extern BOOL common_util_get_folder_type(sqlite3 *, uint64_t folder_id, uint32_t *type, const char *dir = nullptr);
uint64_t common_util_get_folder_parent_fid(
	sqlite3 *psqlite, uint64_t folder_id);
BOOL common_util_get_folder_by_name(
	sqlite3 *psqlite, uint64_t parent_id,
	const char *str_name, uint64_t *pfolder_id);
BOOL common_util_check_message_associated(
	sqlite3 *psqlite, uint64_t message_id);
BOOL common_util_get_message_flags(sqlite3 *psqlite,
	uint64_t message_id, BOOL b_native,
	uint32_t **ppmessage_flags);
extern std::string cu_cid_path(const char *dir, const char *cid, unsigned int type);
void common_util_set_message_read(sqlite3 *psqlite,
	uint64_t message_id, uint8_t is_read);
BINARY* common_util_username_to_addressbook_entryid(
	const char *username);
extern BOOL common_util_parse_addressbook_entryid(const BINARY *, char *address_type, size_t atsize, char *email_address, size_t emsize);
BINARY* common_util_to_private_folder_entryid(
	sqlite3 *psqlite, const char *username,
	uint64_t folder_id);
BINARY* common_util_to_private_message_entryid(
	sqlite3 *psqlite, const char *username,
	uint64_t folder_id, uint64_t message_id);
extern BOOL cu_get_folder_permission(sqlite3 *, uint64_t folder_id, const char *username, uint32_t *perms);
extern BOOL common_util_check_descendant(sqlite3 *, uint64_t inner_fid, uint64_t outer_fid, BOOL *pb_included);
BOOL common_util_get_message_parent_folder(sqlite3 *psqlite,
	uint64_t message_id, uint64_t *pfolder_id);
BOOL common_util_load_search_scopes(sqlite3 *psqlite,
	uint64_t folder_id, LONGLONG_ARRAY *pfolder_ids);
extern bool cu_eval_folder_restriction(sqlite3 *, uint64_t folder_id, const RESTRICTION *);
extern bool cu_eval_msg_restriction(sqlite3 *, cpid_t, uint64_t msgid, const RESTRICTION *);
BOOL common_util_check_search_result(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist);
BOOL common_util_get_mid_string(sqlite3 *psqlite,
	uint64_t message_id, char **ppmid_string);
BOOL common_util_set_mid_string(sqlite3 *psqlite,
	uint64_t message_id, const char *pmid_string);
BOOL common_util_check_message_owner(sqlite3 *psqlite,
	uint64_t message_id, const char *username, BOOL *pb_owner);
BOOL common_util_copy_message(sqlite3 *psqlite, int account_id,
	uint64_t message_id, uint64_t folder_id, uint64_t *pdst_mid,
	BOOL *pb_result, uint32_t *pmessage_size);
BOOL common_util_get_named_propids(sqlite3 *psqlite,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids);
BOOL common_util_get_named_propnames(sqlite3 *psqlite,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);
BOOL common_util_check_folder_id(sqlite3 *psqlite,
	uint64_t folder_id, BOOL *pb_exist);
BOOL common_util_increase_deleted_count(sqlite3 *psqlite,
	uint64_t folder_id, uint32_t del_count);
extern BOOL cu_adjust_store_size(sqlite3 *psqlite, bool sub, uint64_t normal_size, uint64_t fai_size);
extern BINARY *cu_xid_to_bin(const XID &);
BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid);
BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key);
BOOL common_util_bind_sqlite_statement(sqlite3_stmt *pstmt,
	int bind_index, uint16_t proptype, void *pvalue);
void* common_util_column_sqlite_statement(sqlite3_stmt *pstmt,
	int column_index, uint16_t proptype);
BOOL common_util_indexing_sub_contents(
	uint32_t step, sqlite3_stmt *pstmt,
	sqlite3_stmt *pstmt1, uint32_t *pidx);
extern uint32_t common_util_calculate_message_size(const message_content *);
extern uint32_t common_util_calculate_attachment_size(const attachment_content *);
extern const char *exmdb_rpc_idtoname(exmdb_callid);
extern int need_msg_perm_check(sqlite3 *, const char *user, uint64_t fid);
extern int have_delete_perm(sqlite3 *, const char *user, uint64_t fid, uint64_t mid = 0);
extern ec_error_t cu_id2user(int, std::string &);

extern unsigned int g_max_rule_num, g_max_extrule_num, g_cid_compression;
extern thread_local unsigned int g_inside_flush_instance;
extern thread_local sqlite3 *g_sqlite_for_oxcmail;
extern char g_exmdb_org_name[];
