#pragma once
#include <cstdint>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/zcore_rpc.hpp>

#define STORE_OWNER_GRANTED nullptr
#define HOOK_INBOUND								0x00000200
#define HOOK_OUTBOUND								0x00000400
#define SYNC_NEW_MESSAGE							0x800
#define SYNC_SOFT_DELETE							0x01

#define EC_SUPPORTMASK_OWNER	\
	(STORE_ENTRYID_UNIQUE | STORE_SEARCH_OK | STORE_MODIFY_OK | \
	STORE_CREATE_OK | STORE_ATTACH_OK | STORE_OLE_OK | \
	STORE_NOTIFY_OK | STORE_MV_PROPS_OK | STORE_CATEGORIZE_OK | \
	STORE_RTF_OK | STORE_RESTRICTION_OK | STORE_SORT_OK | \
	STORE_UNCOMPRESSED_RTF | \
	STORE_HTML_OK | STORE_UNICODE_OK | STORE_LOCALSTORE | \
	STORE_SUBMIT_OK)
													
#define EC_SUPPORTMASK_OTHER \
	(STORE_ENTRYID_UNIQUE | STORE_SEARCH_OK | STORE_MODIFY_OK | \
	STORE_CREATE_OK | STORE_ATTACH_OK | STORE_OLE_OK | \
	STORE_NOTIFY_OK | STORE_MV_PROPS_OK | STORE_CATEGORIZE_OK | \
	STORE_RTF_OK | STORE_RESTRICTION_OK | STORE_SORT_OK | \
	STORE_UNCOMPRESSED_RTF | STORE_HTML_OK | STORE_UNICODE_OK)

#define EC_SUPPORTMASK_PUBLIC \
	(STORE_ENTRYID_UNIQUE | STORE_SEARCH_OK | STORE_MODIFY_OK | \
	STORE_CREATE_OK | STORE_ATTACH_OK | STORE_OLE_OK | \
	STORE_NOTIFY_OK | STORE_MV_PROPS_OK | STORE_CATEGORIZE_OK | \
	STORE_RTF_OK | STORE_RESTRICTION_OK | STORE_SORT_OK | \
	STORE_UNCOMPRESSED_RTF | \
	STORE_HTML_OK | STORE_UNICODE_OK | STORE_PUBLIC_FOLDERS)

/* end of zarafa defs */

#define NOTIFY_RECEIPT_READ							1
#define NOTIFY_RECEIPT_NON_READ						2

#define LOC_TYPE_PRIVATE_FOLDER						1
#define LOC_TYPE_PUBLIC_FOLDER						2
#define LOC_TYPE_PRIVATE_MESSAGE					3
#define LOC_TYPE_PUBLIC_MESSAGE						4

enum {
	RES_ID_IPM,
	RES_ID_INBOX,
	RES_ID_DRAFT,
	RES_ID_OUTBOX,
	RES_ID_SENT,
	RES_ID_DELETED,
	RES_ID_CONTACTS,
	RES_ID_CALENDAR,
	RES_ID_JOURNAL,
	RES_ID_NOTES,
	RES_ID_TASKS,
	RES_ID_JUNK,
	RES_ID_SYNC,
	RES_ID_CONFLICT,
	RES_ID_LOCAL,
	RES_ID_SERVER,
	RES_TOTAL_NUM
};

enum class repr_grant {
	error = -1, no_impersonation, send_on_behalf, send_as,
};

struct MAIL;
struct message_content;
struct message_object;
struct store_object;

extern void common_util_init(const char *org_name, unsigned int max_rcpt, size_t max_mail_len, unsigned int max_rule_len, std::string &&smtp_url, const char *submit_cmd);
extern int common_util_run(const char *data_path);
extern bool cu_verify_columns_and_sorts(proptag_cspan, const SORTORDER_SET *);
extern bool cu_extract_delegator(message_object *, std::string &);
extern repr_grant cu_get_delegate_perm_MD(const char *account, const char *maildir);
extern repr_grant cu_get_delegate_perm_AA(const char *account, const char *account_representing);
extern ec_error_t cu_set_propval(TPROPVAL_ARRAY *parray, gromox::proptag_t, const void *);
extern void common_util_remove_propvals(TPROPVAL_ARRAY *, gromox::proptag_t);
extern void cu_reduce_proptags(PROPTAG_ARRAY *, proptag_cspan);
BOOL common_util_essdn_to_uid(const char *pessdn, int *puid);
BOOL common_util_essdn_to_ids(const char *pessdn,
	int *pdomain_id, int *puser_id);
BINARY* common_util_username_to_addressbook_entryid(
	const char *username);
extern BOOL common_util_essdn_to_entryid(const char *essdn, BINARY *pbin, unsigned int etyp = DT_MAILUSER);
extern bool common_util_exmdb_locinfo_from_string(const char *loc_string, uint8_t *ptype, int *pdb_id, eid_t *);
extern BOOL common_util_build_environment();
extern void common_util_free_environment();
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
void common_util_set_clifd(int clifd);
extern int common_util_get_clifd();
extern char *common_util_dup(std::string_view);
extern bool cu_parse_abkeid(BINARY, uint32_t *type, std::string &essdn);
uint16_t common_util_get_messaging_entryid_type(BINARY bin);
extern bool cu_entryid_to_fid(BINARY bin, BOOL *pb_private, int *pdb_id, eid_t *folder_id);
extern bool cu_entryid_to_mid(BINARY bin, BOOL *pb_private, int *pdb_id, eid_t *folder_id, eid_t *msg_id);
extern BINARY *cu_to_store_entryid(const store_object &);
extern std::string cu_to_store_entryid_s(const store_object &);
extern BINARY *cu_fid_to_entryid(const store_object &, uint64_t folder_id);
extern std::string cu_fid_to_entryid_s(const store_object &, uint64_t folder_id);
extern BINARY *cu_fid_to_sk(const store_object &, uint64_t folder_id);
extern std::string cu_fid_to_sk_s(const store_object &, uint64_t folder_id);
extern BINARY *cu_mid_to_entryid(const store_object &, uint64_t folder_id, uint64_t msg_id);
extern std::string cu_mid_to_entryid_s(const store_object &, uint64_t folder_id, uint64_t msg_id);
extern ec_error_t cu_calc_msg_access(const store_object &, const char *user, uint64_t folder_id, uint64_t msg_id, uint32_t &access);
extern BINARY *cu_mid_to_sk(const store_object &, uint64_t msg_id);
extern std::string cu_mid_to_sk_s(const store_object &, uint64_t msg_id);
extern BINARY *cu_xid_to_bin(const XID &);
extern std::string cu_xid_to_bin_s(const XID &);
BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid);
extern BINARY *common_util_guid_to_binary(FLATUID);
BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key);
extern void common_util_notify_receipt(const char *username, int type, message_content *brief);
BOOL common_util_convert_from_zrule(TPROPVAL_ARRAY *ppropvals);
BOOL common_util_load_file(const char *path, BINARY *pbin);
extern BOOL common_util_convert_to_zrule_data(store_object *, TPROPVAL_ARRAY *);
extern ec_error_t cu_remote_copy_message(store_object *s0, uint64_t message_id, store_object *s1, uint64_t folder_id1);
extern ec_error_t cu_remote_copy_folder(store_object *s0, uint64_t folder_id, store_object *s1, uint64_t folder_id1, const char *new_name);
extern ec_error_t cu_send_message(store_object *, message_object *, const char *ev_from);
extern BOOL common_util_message_to_rfc822(store_object *, uint64_t inst_id, BINARY *eml);
extern message_content *cu_rfc822_to_message(store_object *, unsigned int mxf_flags, BINARY *eml);
extern BOOL common_util_message_to_ical(store_object *, uint64_t msg_id, BINARY *ical);
extern std::unique_ptr<message_content, gromox::mc_delete> cu_ical_to_message(store_object *, const BINARY *ical);
extern ec_error_t cu_ical_to_message2(store_object *, char *ical_data, std::vector<std::unique_ptr<message_content, gromox::mc_delete>> &);
extern BOOL common_util_message_to_vcf(message_object *, BINARY *vcfout);
extern message_content *common_util_vcf_to_message(store_object *, const BINARY *vcf);
extern ec_error_t cu_vcf_to_message2(store_object *, char *vcf_data, std::vector<std::unique_ptr<message_content, gromox::mc_delete>> &);
extern const char *common_util_get_default_timezone();
extern const char *common_util_get_submit_command();
void common_util_get_folder_lang(const char *lang, char **ppfolder_lang);
extern const char *zcore_rpc_idtoname(zcore_callid);
extern bool bounce_producer_make(bool (*)(const char *, char *, size_t), bool (*)(const char *, char *, size_t), bool (*)(const char *, char *, size_t), const char *user, message_content *, const char *bounce_type, MAIL *);
extern void *cu_read_storenamedprop(const char *, const GUID &, const char *, gromox::proptype_t);
extern gromox::errno_t cu_write_storenamedprop(const char *, const GUID &, const char *, gromox::proptype_t, const void *buf, size_t);
extern ec_error_t cu_fbdata_to_ical(const char *, const char *, time_t, time_t, const std::vector<freebusy_event> &, BINARY *);
extern bool permrow_entryids_equal(const PERMISSION_ROW &, const uint32_t *, const BINARY *);

extern size_t g_max_mail_len;
extern unsigned int g_max_rcpt;
extern unsigned int g_max_rule_len, g_max_extrule_len;
extern unsigned int zcore_backfill_transporthdr;
extern char g_org_name[256];
