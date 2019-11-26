#ifndef _H_COMMON_UTIL_
#define _H_COMMON_UTIL_
#include "common_types.h"
#include "store_object.h"
#include "message_object.h"

#define ZCORE_VERSION								"steep zcore 1.0"

#define SOCKET_TIMEOUT								60

#define CALL_ID_LOGON								0x00
#define CALL_ID_UNLOADOBJECT						0x01
#define CALL_ID_OPENENTRY							0x02
#define CALL_ID_OPENSTOREENTRY						0x03
#define CALL_ID_OPENABENTRY							0x04
#define CALL_ID_RESOLVENAME							0x05
#define CALL_ID_GETPERMISSIONS						0x07
#define CALL_ID_MODIFYPERMISSIONS					0x08
#define CALL_ID_MODIFYRULES							0x09
#define CALL_ID_GETABGAL							0x0a
#define CALL_ID_LOADSTORETABLE						0x0b
#define CALL_ID_OPENSTORE							0x0c
#define CALL_ID_OPENPROPFILESEC						0x0d
#define CALL_ID_LOADHIERARCHYTABLE					0x0e
#define CALL_ID_LOADCONTENTTABLE					0x0f
#define CALL_ID_LOADRECIPIENTTABLE					0x10
#define CALL_ID_LOADRULETABLE						0x12
#define CALL_ID_CREATEMESSAGE						0x13
#define CALL_ID_DELETEMESSAGES						0x14
#define CALL_ID_COPYMESSAGES						0x15
#define CALL_ID_SETREADFLAGS						0x16
#define CALL_ID_CREATEFOLDER						0x17
#define CALL_ID_DELETEFOLDER						0x18
#define CALL_ID_EMPTYFOLDER							0x19
#define CALL_ID_COPYFOLDER							0x1a
#define CALL_ID_GETSTOREENTRYID						0x1b
#define CALL_ID_ENTRYIDFROMSOURCEKEY				0x1c
#define CALL_ID_STOREADVISE							0x1d
#define CALL_ID_UNADVISE							0x1e
#define CALL_ID_NOTIFDEQUEUE						0x1f
#define CALL_ID_QUERYROWS							0x20
#define CALL_ID_SETCOLUMNS							0x21
#define CALL_ID_SEEKROW								0x22
#define CALL_ID_SORTTABLE							0x23
#define CALL_ID_GETROWCOUNT							0x24
#define CALL_ID_RESTRICTTABLE						0x25
#define CALL_ID_FINDROW								0x26
#define CALL_ID_CREATEBOOKMARK						0x27
#define CALL_ID_FREEBOOKMARK						0x28
#define CALL_ID_GETRECEIVEFOLDER					0x29
#define CALL_ID_MODIFYRECIPIENTS					0x2a
#define CALL_ID_SUBMITMESSAGE						0x2b
#define CALL_ID_LOADATTACHMENTTABLE					0x2c
#define CALL_ID_OPENATTACHMENT						0x2d
#define CALL_ID_CREATEATTACHMENT					0x2e
#define CALL_ID_DELETEATTACHMENT					0x2f
#define CALL_ID_SETPROPVALS							0x30
#define CALL_ID_GETPROPVALS							0x31
#define CALL_ID_DELETEPROPVALS						0x32
#define CALL_ID_SETMESSAGEREADFLAG					0x33
#define CALL_ID_OPENEMBEDDED						0x34
#define CALL_ID_GETNAMEDPROPIDS						0x35
#define CALL_ID_GETPROPNAMES						0x36
#define CALL_ID_COPYTO								0x37
#define CALL_ID_SAVECHANGES							0x38
#define CALL_ID_HIERARCHYSYNC						0x39
#define CALL_ID_CONTENTSYNC							0x3a
#define CALL_ID_CONFIGSYNC							0x3b
#define CALL_ID_STATESYNC							0x3c
#define CALL_ID_SYNCMESSAGECHANGE					0x3d
#define CALL_ID_SYNCFOLDERCHANGE					0x3e
#define CALL_ID_SYNCREADSTATECHANGES				0x3f
#define CALL_ID_SYNCDELETIONS						0x40
#define CALL_ID_HIERARCHYIMPORT						0x41
#define CALL_ID_CONTENTIMPORT						0x42
#define CALL_ID_CONFIGIMPORT						0x43
#define CALL_ID_STATEIMPORT							0x44
#define CALL_ID_IMPORTMESSAGE						0x45
#define CALL_ID_IMPORTFOLDER						0x46
#define CALL_ID_IMPORTDELETION						0x47
#define CALL_ID_IMPORTREADSTATES					0x48
#define CALL_ID_GETSEARCHCRITERIA					0x49
#define CALL_ID_SETSEARCHCRITERIA					0x4a
#define CALL_ID_MESSAGETORFC822						0x4b
#define CALL_ID_RFC822TOMESSAGE						0x4c
#define CALL_ID_MESSAGETOICAL						0x4d
#define CALL_ID_ICALTOMESSAGE						0x4e
#define CALL_ID_MESSAGETOVCF						0x4f
#define CALL_ID_VCFTOMESSAGE						0x50
#define CALL_ID_UINFO								0x51
#define CALL_ID_CHECKSESSION						0x52
#define CALL_ID_GETUSERAVAILABILITY					0x53
#define CALL_ID_SETPASSWD							0x54
#define CALL_ID_LINKMESSAGE							0x55

/* ---------------------- defined by zarafa ---------------------- */

#define MAPI_STORE_PROVIDER							33
#define MAPI_AB										34
#define MAPI_AB_PROVIDER							35
#define MAPI_TRANSPORT_PROVIDER						36
#define MAPI_SPOOLER								37
#define MAPI_PROFILE_PROVIDER						38
#define MAPI_SUBSYSTEM								39
#define MAPI_HOOK_PROVIDER							40

#define STATUS_DEFAULT_OUTBOUND						0x00000001
#define STATUS_DEFAULT_STORE						0x00000002
#define STATUS_PRIMARY_IDENTITY						0x00000004
#define STATUS_SIMPLE_STORE							0x00000008
#define STATUS_XP_PREFER_LAST						0x00000010
#define STATUS_NO_PRIMARY_IDENTITY					0x00000020
#define STATUS_NO_DEFAULT_STORE						0x00000040
#define STATUS_TEMP_SECTION							0x00000080
#define STATUS_OWN_STORE							0x00000100
#define HOOK_INBOUND								0x00000200
#define HOOK_OUTBOUND								0x00000400
#define STATUS_NEED_IPM_TREE						0x00000800
#define STATUS_PRIMARY_STORE						0x00001000
#define STATUS_SECONDARY_STORE						0x00002000

typedef struct _FLATUID {
	uint8_t ab[16];
} FLATUID;

typedef struct _ZMOVECOPY_ACTION {
	BINARY store_eid;
	BINARY folder_eid;
} ZMOVECOPY_ACTION;

typedef struct _ZREPLY_ACTION {
	BINARY message_eid;
	GUID template_guid;
} ZREPLY_ACTION;

typedef struct _ADVISE_INFO {
	uint32_t hstore;
	uint32_t sub_id;
} ADVISE_INFO;

typedef struct _NOTIF_SINK {
	GUID hsession;
	uint16_t count;
	ADVISE_INFO *padvise;
} NOTIF_SINK;

#define ACCESS_TYPE_DENIED							1
#define ACCESS_TYPE_GRANT							2
#define ACCESS_TYPE_BOTH							3

#define RIGHT_NORMAL								0x00
#define RIGHT_NEW									0x01
#define RIGHT_MODIFY								0x02
#define RIGHT_DELETED								0x04
#define RIGHT_AUTOUPDATE_DENIED						0x08

#define STREAM_SEEK_SET								0
#define STREAM_SEEK_CUR								1
#define STREAM_SEEK_END								2

#define BOOKMARK_BEGINNING							0
#define BOOKMARK_CURRENT							1
#define BOOKMARK_END								2

#define MODRECIP_ADD								0x00000002
#define MODRECIP_MODIFY								0x00000004
#define MODRECIP_REMOVE								0x00000008

#define MAPI_ROOT									0
#define MAPI_TABLE									1
#define MAPI_MESSAGE								2
#define MAPI_ATTACHMENT								3
#define MAPI_ABCONT									4
#define MAPI_FOLDER									5
#define MAPI_SESSION								6
#define MAPI_ADDRESSBOOK							7
#define MAPI_STORE									8
#define MAPI_MAILUSER								9
#define MAPI_DISTLIST								10
#define MAPI_PROFPROPERTY							11
#define MAPI_ICSDOWNCTX								13
#define MAPI_ICSUPCTX								14
#define MAPI_INVALID								255

typedef struct _NEWMAIL_ZNOTIFICATION {
	BINARY entryid;
	BINARY parentid;
	uint32_t flags; /* unicode or not */
	char *message_class;
	uint32_t message_flags;
} NEWMAIL_ZNOTIFICATION;

typedef struct _OBJECT_ZNOTIFICATION {
	uint32_t object_type;
	BINARY *pentryid;
	BINARY *pparentid;
	BINARY *pold_entryid;
	BINARY *pold_parentid;
	PROPTAG_ARRAY *pproptags;
} OBJECT_ZNOTIFICATION;

#define EVENT_TYPE_NEWMAIL							0x00000002
#define EVENT_TYPE_OBJECTCREATED					0x00000004
#define EVENT_TYPE_OBJECTDELETED					0x00000008
#define EVENT_TYPE_OBJECTMODIFIED					0x00000010
#define EVENT_TYPE_OBJECTMOVED						0x00000020
#define EVENT_TYPE_OBJECTCOPIED						0x00000040
#define EVENT_TYPE_SEARCHCOMPLETE					0x00000080

typedef struct _ZNOTIFICATION {
	uint32_t event_type;
	void *pnotification_data; /* NEWMAIL_ZNOTIFICATION or OBJECT_ZNOTIFICATION */
} ZNOTIFICATION;

typedef struct _ZNOTIFICATION_ARRAY {
	uint16_t count;
	ZNOTIFICATION **ppnotification;
} ZNOTIFICATION_ARRAY;

typedef struct _PERMISSION_ROW {
	uint32_t flags;
	BINARY entryid;
	uint32_t member_rights;
} PERMISSION_ROW;

typedef struct _PERMISSION_SET {
	uint16_t count;
	PERMISSION_ROW *prows;
} PERMISSION_SET;

typedef struct _RULE_LIST {
	uint16_t count;
	RULE_DATA *prule;
} RULE_LIST;

#define SYNC_NEW_MESSAGE							0x800
#define SYNC_SOFT_DELETE							0x01

typedef struct _MESSAGE_STATE {
	BINARY source_key;
	uint32_t message_flags;
} MESSAGE_STATE;

typedef struct _STATE_ARRAY {
	uint32_t count;
	MESSAGE_STATE *pstate;
} STATE_ARRAY;

#define ICS_TYPE_CONTENTS							1
#define ICS_TYPE_HIERARCHY							2

#define FLAG_SOFT_DELETE            				0x00000002
#define FLAG_ASSOCIATED								0x00000040
#define FLAG_HARD_DELETE							0x00000010
#define FLAG_MOVE		            				0x00000001
#define FLAG_CLEAR_READ								0x00000004
#define FLAG_UNICODE            					0x80000000
#define FLAG_OPEN_IF_EXISTS							0x00000001
#define FLAG_DEL_ASSOCIATED							0x00000008
#define FLAG_COPY_SUBFOLDERS						0x00000010
#define FLAG_CREATE									0x00000002
#define FLAG_CONVENIENT_DEPTH						0x00000001


#define STORE_ENTRYID_UNIQUE						0x00000001
#define STORE_READONLY								0x00000002
#define STORE_SEARCH_OK								0x00000004
#define STORE_MODIFY_OK								0x00000008
#define STORE_CREATE_OK								0x00000010
#define STORE_ATTACH_OK								0x00000020
#define STORE_OLE_OK								0x00000040
#define STORE_SUBMIT_OK								0x00000080
#define STORE_NOTIFY_OK								0x00000100
#define STORE_MV_PROPS_OK							0x00000200
#define STORE_CATEGORIZE_OK							0x00000400
#define STORE_RTF_OK								0x00000800
#define STORE_RESTRICTION_OK						0x00001000
#define STORE_SORT_OK								0x00002000
#define STORE_PUBLIC_FOLDERS						0x00004000
#define STORE_UNCOMPRESSED_RTF						0x00008000
#define STORE_HTML_OK								0x00010000
#define STORE_UNICODE_OK							0x00040000
#define STORE_LOCALSTORE							0x00080000
#define STORE_PUSHER_OK								0x00800000
#define STORE_HAS_SEARCHES							0x01000000

#define EC_SUPPORTMASK_OWNER	\
	STORE_ENTRYID_UNIQUE | STORE_SEARCH_OK | STORE_MODIFY_OK | \
	STORE_CREATE_OK | STORE_ATTACH_OK | STORE_OLE_OK | \
	STORE_NOTIFY_OK | STORE_MV_PROPS_OK | STORE_CATEGORIZE_OK | \
	STORE_RTF_OK | STORE_RESTRICTION_OK | STORE_SORT_OK | \
	STORE_HTML_OK | STORE_UNICODE_OK | STORE_LOCALSTORE | \
	STORE_SUBMIT_OK
													
#define EC_SUPPORTMASK_OTHER \
	STORE_ENTRYID_UNIQUE | STORE_SEARCH_OK | STORE_MODIFY_OK | \
	STORE_CREATE_OK | STORE_ATTACH_OK | STORE_OLE_OK | \
	STORE_NOTIFY_OK | STORE_MV_PROPS_OK | STORE_CATEGORIZE_OK | \
	STORE_RTF_OK | STORE_RESTRICTION_OK | STORE_SORT_OK | \
	STORE_HTML_OK | STORE_UNICODE_OK

#define EC_SUPPORTMASK_PUBLIC \
	STORE_ENTRYID_UNIQUE | STORE_SEARCH_OK | STORE_MODIFY_OK | \
	STORE_CREATE_OK | STORE_ATTACH_OK | STORE_OLE_OK | \
	STORE_NOTIFY_OK | STORE_MV_PROPS_OK | STORE_CATEGORIZE_OK | \
	STORE_RTF_OK | STORE_RESTRICTION_OK | STORE_SORT_OK | \
	STORE_HTML_OK | STORE_UNICODE_OK | STORE_PUBLIC_FOLDERS

/* ------------------------ end of zarafa ------------------------ */

#define NOTIFY_RECEIPT_READ							1
#define NOTIFY_RECEIPT_NON_READ						2

#define LOC_TYPE_PRIVATE_FOLDER						1
#define LOC_TYPE_PUBLIC_FOLDER						2
#define LOC_TYPE_PRIVATE_MESSAGE					3
#define LOC_TYPE_PUBLIC_MESSAGE						4

enum {
	COMMON_UTIL_MAX_RCPT,
	COMMON_UTIL_MAX_MESSAGE,
	COMMON_UTIL_MAX_MAIL_LENGTH,
	COMMON_UTIL_MAX_EXTRULE_LENGTH
};

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

void common_util_init(const char *org_name, const char *hostname,
	const char *default_charset, const char *default_zone, int mime_num,
	int max_rcpt, int max_message, unsigned int max_mail_len,
	unsigned int max_rule_len, const char *smtp_ip, int smtp_port,
	const char *freebusy_path, const char *langmap_path,
	const char *folderlang_path, const char *submit_command);

int common_util_run();

int common_util_stop();

void common_util_free();

unsigned int common_util_get_param(int param);

void common_util_set_param(int param, unsigned int value);

const char* common_util_get_hostname();

const char* common_util_get_freebusy_path();

BOOL common_util_verify_columns_and_sorts(
	const PROPTAG_ARRAY *pcolumns,
	const SORTORDER_SET *psort_criteria);

BOOL common_util_check_message_class(const char *str_class);

BOOL common_util_check_delegate(
	MESSAGE_OBJECT *pmessage, char *username);

BOOL common_util_check_delegate_permission(
	const char *account, const char *maildir);

BOOL common_util_check_delegate_permission_ex(
	const char *account, const char *account_representing);

BOOL common_util_rectify_message(MESSAGE_OBJECT *pmessage,
	const char *representing_username);

void common_util_set_propvals(TPROPVAL_ARRAY *parray,
	const TAGGED_PROPVAL *ppropval);

void common_util_remove_propvals(
	TPROPVAL_ARRAY *parray, uint32_t proptag);
	
void* common_util_get_propvals(
	const TPROPVAL_ARRAY *parray, uint32_t proptag);

int common_util_index_proptags(
	const PROPTAG_ARRAY *pproptags, uint32_t proptag);

void common_util_reduce_proptags(PROPTAG_ARRAY *pproptags_minuend,
	const PROPTAG_ARRAY *pproptags_subtractor);

BOOL common_util_mapping_replica(BOOL to_guid,
	void *pparam, uint16_t *preplid, GUID *pguid);
	
BOOL common_util_essdn_to_username(const char *pessdn, char *username);

BOOL common_util_essdn_to_uid(const char *pessdn, int *puid);

BOOL common_util_essdn_to_ids(const char *pessdn,
	int *pdomain_id, int *puser_id);

BOOL common_util_entryid_to_username(
	const BINARY *pbin, char *username);

BINARY* common_util_username_to_addressbook_entryid(
	const char *username);

BOOL common_util_essdn_to_entryid(const char *essdn, BINARY *pbin);

BOOL common_util_username_to_entryid(const char *username,
	const char *pdisplay_name, BINARY *pbin, int *paddress_type);

BINARY* common_util_public_to_addressbook_entryid(const char *domainname);

BOOL common_util_username_to_essdn(const char *username, char *pessdn);

BOOL common_util_essdn_to_public(const char *pessdn, char *domainname);

BOOL common_util_public_to_essdn(const char *username, char *pessdn);

void common_util_exmdb_locinfo_to_string(
	uint8_t type, int db_id, uint64_t eid,
	char *loc_string);

BOOL common_util_exmdb_locinfo_from_string(
	const char *loc_string, uint8_t *ptype,
	int *pdb_id, uint64_t *peid);

BOOL common_util_build_environment();

void common_util_free_environment();

void* common_util_alloc(size_t size);

void common_util_set_clifd(int clifd);

int common_util_get_clifd();

char* common_util_dup(const char *pstr);

ZNOTIFICATION* common_util_dup_znotification(
	ZNOTIFICATION *pnotification, BOOL b_temp);

void common_util_free_znotification(ZNOTIFICATION *pnotification);

int common_util_mb_from_utf8(uint32_t cpid,
	const char *src, char *dst, size_t len);
	
int common_util_mb_to_utf8(uint32_t cpid,
	const char *src, char *dst, size_t len);
	
int common_util_convert_string(BOOL to_utf8,
	const char *src, char *dst, size_t len);

BOOL common_util_check_local_ip(const char *ip_addr);

BOOL common_util_addressbook_entryid_to_username(
	BINARY entryid_bin, char *username);

BOOL common_util_parse_addressbook_entryid(
	BINARY entryid_bin, uint32_t *ptype, char *pessdn);

uint16_t common_util_get_messaging_entryid_type(BINARY bin);

BOOL common_util_from_folder_entryid(BINARY bin,
	BOOL *pb_private, int *pdb_id, uint64_t *pfolder_id);

BOOL common_util_from_message_entryid(BINARY bin, BOOL *pb_private,
	int *pdb_id, uint64_t *pfolder_id, uint64_t *pmessage_id);

BINARY* common_util_to_store_entryid(STORE_OBJECT *pstore);

BINARY* common_util_to_folder_entryid(
	STORE_OBJECT *pstore, uint64_t folder_id);

BINARY* common_util_calculate_folder_sourcekey(
	STORE_OBJECT *pstore, uint64_t folder_id);

BINARY* common_util_to_message_entryid(STORE_OBJECT *pstore,
	uint64_t folder_id, uint64_t message_id);
	
BINARY* common_util_calculate_message_sourcekey(
	STORE_OBJECT *pstore, uint64_t message_id);

BOOL common_util_recipients_to_list(
	TARRAY_SET *prcpts, DOUBLE_LIST *plist);

BINARY* common_util_xid_to_binary(uint8_t size, const XID *pxid);

BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid);

BINARY* common_util_guid_to_binary(GUID guid);

BOOL common_util_pcl_compare(const BINARY *pbin_pcl1,
	const BINARY *pbin_pcl2, uint32_t *presult);

BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key);

BINARY* common_util_pcl_merge(const BINARY *pbin_pcl1,
	const BINARY *pbin_pcl2);

void common_util_notify_receipt(const char *username,
	int type, MESSAGE_CONTENT *pbrief);

BOOL common_util_convert_from_zrule(TPROPVAL_ARRAY *ppropvals);

BOOL common_util_convert_to_zrule(
	STORE_OBJECT *pstore, TPROPVAL_ARRAY *ppropvals);

BOOL common_util_load_file(const char *path, BINARY *pbin);

BOOL common_util_remote_copy_message(
	STORE_OBJECT *pstore, uint64_t message_id,
	STORE_OBJECT *pstore1, uint64_t folder_id1);

BOOL common_util_remote_copy_folder(
	STORE_OBJECT *pstore, uint64_t folder_id,
	STORE_OBJECT *pstore1, uint64_t folder_id1,
	const char *new_name);
	
uint8_t* common_util_get_muidecsab();

uint8_t* common_util_get_muidzcsab();

uint64_t common_util_convert_notification_folder_id(uint64_t folder_id);

BOOL common_util_send_message(STORE_OBJECT *pstore,
	uint64_t message_id, BOOL b_submit);

BOOL common_util_message_to_rfc822(STORE_OBJECT *pstore,
	uint64_t message_id, BINARY *peml_bin);

MESSAGE_CONTENT* common_util_rfc822_to_message(
	STORE_OBJECT *pstore, const BINARY *peml_bin);

BOOL common_util_message_to_ical(STORE_OBJECT *pstore,
	uint64_t message_id, BINARY *pical_bin);

MESSAGE_CONTENT* common_util_ical_to_message(
	STORE_OBJECT *pstore, const BINARY *pical_bin);

BOOL common_util_message_to_vcf(STORE_OBJECT *pstore,
	uint64_t message_id, BINARY *pvcf_bin);
	
MESSAGE_CONTENT* common_util_vcf_to_message(
	STORE_OBJECT *pstore, const BINARY *pvcf_bin);

uint64_t common_util_tm_to_nttime(struct tm unix_tm);

BOOL common_util_nttime_to_tm(uint64_t nt_time, struct tm *ptm);

const char* common_util_lang_to_i18n(const char *lang);

const char* common_util_i18n_to_lang(const char *i18n);

const char* common_util_get_default_timezone();

const char* common_util_get_submit_command();

void common_util_get_folder_lang(const char *lang, char **ppfolder_lang);

#endif /* _H_COMMON_UTIL_ */
