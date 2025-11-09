#pragma once
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>
#include <vmime/message.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#define NOTIFY_RECEIPT_READ							1
#define NOTIFY_RECEIPT_NON_READ						2
#define STORE_OWNER_GRANTED nullptr

DECLARE_PROC_API(emsmdb, extern);
using namespace emsmdb;

struct logon_object;
struct MAIL;
struct message_content;
struct message_object;

namespace emsmdb {

void* common_util_alloc(size_t size);
extern char *cu_strdup(std::string_view);
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
extern std::string cu_cvt_str(std::string_view, cpid_t, bool dir);
static inline std::string cu_mb_to_utf8(cpid_t cpid, std::string_view sv) { return cu_cvt_str(std::move(sv), cpid, true); }
static inline std::string cu_utf8_to_mb(cpid_t cpid, std::string_view sv) { return cu_cvt_str(std::move(sv), cpid, false); }
extern char *cu_mb_to_utf8_dup(cpid_t, std::string_view);
extern char *cu_utf8_to_mb_dup(cpid_t, std::string_view);
void common_util_obfuscate_data(uint8_t *data, uint32_t size);
BOOL common_util_essdn_to_public(const char *pessdn, char *domainname);
extern BINARY *cu_username_to_oneoff(const char *username, const char *dispname);
extern std::string cu_username_to_oneoff_s(const char *username, const char *dispname);
BINARY* common_util_username_to_addressbook_entryid(const char *username);
extern BINARY *cu_fid_to_entryid(const logon_object &, uint64_t folder_id);
extern std::string cu_fid_to_entryid_s(const logon_object &, uint64_t folder_id);
extern BINARY *cu_fid_to_sk(const logon_object &, uint64_t folder_id);
extern std::string cu_fid_to_sk_s(const logon_object &, uint64_t folder_id);
extern BINARY *cu_mid_to_entryid(const logon_object &, uint64_t folder_id, uint64_t msg_id);
extern std::string cu_mid_to_entryid_s(const logon_object &, uint64_t folder_id, uint64_t msg_id);
extern BOOL cu_entryid_to_fid(const logon_object &, const BINARY *, uint64_t *folder_id);
extern BOOL cu_entryid_to_mid(const logon_object &, const BINARY *, uint64_t *folder_id, uint64_t *msg_id);
extern BINARY *cu_mid_to_sk(const logon_object &, uint64_t msg_id);
extern std::string cu_mid_to_sk_s(const logon_object &, uint64_t msg_id);
extern BINARY *cu_xid_to_bin(const XID &);
extern std::string cu_xid_to_bin_s(const XID &);
BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid);
BINARY* common_util_guid_to_binary(GUID guid);
BOOL common_util_pcl_compare(const BINARY *pbin_pcl1,
	const BINARY *pbin_pcl2, uint32_t *presult);
BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key);
BINARY* common_util_pcl_merge(const BINARY *pbin_pcl1,
	const BINARY *pbin_pcl2);
BOOL common_util_mapping_replica(BOOL to_guid,
	void *pparam, uint16_t *preplid, GUID *pguid);
extern ec_error_t cu_set_propval(TPROPVAL_ARRAY *, gromox::proptag_t, const void *data);
extern void common_util_remove_propvals(TPROPVAL_ARRAY *, gromox::proptag_t);
extern BOOL common_util_retag_propvals(TPROPVAL_ARRAY *, gromox::proptag_t orig_tag, gromox::proptag_t new_tag);
extern void cu_reduce_proptags(PROPTAG_ARRAY *minuend, proptag_cspan subtractor);
extern PROPTAG_ARRAY *cu_trim_proptags(proptag_cspan tags);
extern bool cu_propvals_to_row(const TPROPVAL_ARRAY *, proptag_cspan cols, PROPERTY_ROW *row);
extern bool cu_propvals_to_row_ex(cpid_t, bool unicode, const TPROPVAL_ARRAY *, proptag_cspan cols, PROPERTY_ROW *row);
extern BOOL common_util_convert_unspecified(cpid_t, BOOL unicode, TYPED_PROPVAL *);
extern bool cu_propvals_to_openrecipient(cpid_t, TPROPVAL_ARRAY *vals, proptag_cspan cols, OPENRECIPIENT_ROW *row);
extern bool cu_propvals_to_readrecipient(cpid_t, TPROPVAL_ARRAY *vals, proptag_cspan cols, READRECIPIENT_ROW *row);
extern bool cu_modifyrecipient_to_propvals(cpid_t, const MODIFYRECIPIENT_ROW *, proptag_cspan cols, TPROPVAL_ARRAY *vals);
BOOL common_util_convert_tagged_propval(
	BOOL to_unicode, TAGGED_PROPVAL *ppropval);
BOOL common_util_convert_restriction(BOOL to_unicode, RESTRICTION *pres);
BOOL common_util_convert_rule_actions(BOOL to_unicode, RULE_ACTIONS *pactions);
extern void common_util_notify_receipt(const char *username, int type, message_content *brief);
extern ec_error_t ems_send_mail(MAIL *, const char *sender, const std::vector<std::string> &rcpts);
extern ec_error_t ems_send_vmail(vmime::shared_ptr<vmime::message>, const char *sender, const std::vector<std::string> &rcpts);
extern ec_error_t cu_send_message(logon_object *, message_object *, const char *ev_from);
extern bool bounce_producer_make(bool (*)(const char *, char *, size_t), bool (*)(const char *, char *, size_t), bool (*)(const char *, char *, size_t), const char *user, message_content *, const char *bounce_type, MAIL *);

extern int (*common_util_add_timer)(const char *command, int interval);
extern BOOL (*common_util_cancel_timer)(int timer_id);

extern void common_util_init(const char *org_name, unsigned int max_rcpt, size_t max_mail_len, unsigned int max_rule_len, std::string &&smtp_url, const char *submit_cmd);
extern int common_util_run();
extern const char *common_util_get_submit_command();
extern uint32_t common_util_get_ftstream_id();
extern void fxs_propsort(message_content &);
extern ec_error_t replid_to_replguid(const logon_object &, uint16_t, GUID &);
extern ec_error_t replguid_to_replid(const logon_object &, const GUID &, uint16_t &);

extern size_t g_max_mail_len;
extern unsigned int g_max_rcpt;
extern unsigned int g_max_rule_len, g_max_extrule_len;
extern char g_emsmdb_org_name[256];

}

static inline size_t fx_divisor(size_t total)
{
	size_t r = total / 0xFFFF;
	return r > 0 ? r : 1;
}
