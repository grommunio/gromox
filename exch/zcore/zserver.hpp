#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unordered_map>
#include <gromox/mapi_types.hpp>

struct OBJECT_TREE;

struct sink_node {
	sink_node() = default;
	~sink_node();
	NOMOVE(sink_node);

	int clifd = -1;
	time_t until_time = 0;
	NOTIF_SINK sink{};
};
using SINK_NODE = sink_node;

struct USER_INFO {
	USER_INFO() = default;
	USER_INFO(USER_INFO &&) noexcept;
	void operator=(USER_INFO &&) = delete;
	~USER_INFO();
	inline const char *get_username() const { return username.c_str(); }
	inline const char *get_lang() const { return lang.c_str(); }
	inline const char *get_maildir() const { return maildir.c_str(); }
	inline const char *get_homedir() const { return homedir.c_str(); }

	GUID hsession{};
	std::atomic<int> reference{0};
	int user_id = 0, domain_id = 0, org_id = 0;
	std::string username, lang, maildir, homedir;
	uint32_t cpid = 0, flags = 0;
	time_t last_time = 0, reload_time = 0;
	std::unique_ptr<OBJECT_TREE> ptree;
	std::list<sink_node> sink_list;
	std::unordered_map<int, long> extra_owner;
	std::mutex eowner_lock;
	std::recursive_mutex lock;
};

extern void zserver_init(size_t table_size, int cache_interval, int ping_interval);
extern int zserver_run();
extern void zserver_stop();
extern USER_INFO *zs_get_info();
extern ec_error_t zs_logon(const char *username, const char *password, uint32_t flags, GUID *ses);
extern ec_error_t zs_checksession(GUID ses);
extern ec_error_t zs_uinfo(const char *username, BINARY *entryid, char **dispname, char **x500dn, uint32_t *priv_bits);
extern ec_error_t zs_unloadobject(GUID ses, uint32_t obj_handle);
extern ec_error_t zs_openentry(GUID ses, BINARY entryid, uint32_t flags, uint8_t *mapi_type, uint32_t *obj_handle);
extern ec_error_t zs_openstoreentry(GUID ses, uint32_t obj_handle, BINARY entryid, uint32_t flags, uint8_t *mapi_type, uint32_t *out_handle);
extern ec_error_t zs_openabentry(GUID ses, BINARY entryid, uint8_t *mapi_type, uint32_t *obj_handle);
extern ec_error_t zs_resolvename(GUID ses, const TARRAY_SET *cond, TARRAY_SET *);
extern ec_error_t zs_getpermissions(GUID ses, uint32_t obj_handle, PERMISSION_SET *);
extern ec_error_t zs_modifypermissions(GUID ses, uint32_t fld_handle, const PERMISSION_SET *);
extern ec_error_t zs_modifyrules(GUID ses, uint32_t fld_handle, uint32_t flags, const RULE_LIST *);
extern ec_error_t zs_getabgal(GUID ses, BINARY *entryid);
extern ec_error_t zs_loadstoretable(GUID ses, uint32_t *obj_handle);
extern ec_error_t zs_openstore(GUID ses, BINARY entryid, uint32_t *obj_handle);
extern ec_error_t zs_openprofilesec(GUID sess, const FLATUID *, uint32_t *obj);
extern ec_error_t zs_loadhierarchytable(GUID ses, uint32_t fld_handle, uint32_t flags, uint32_t *obj_handle);
extern ec_error_t zs_loadcontenttable(GUID ses, uint32_t fld_handle, uint32_t flags, uint32_t *obj_handle);
extern ec_error_t zs_loadrecipienttable(GUID ses, uint32_t msg_handle, uint32_t *obj_handle);
extern ec_error_t zs_loadruletable(GUID ses, uint32_t fld_handle, uint32_t *obj_handle);
extern ec_error_t zs_createmessage(GUID ses, uint32_t fld_handle,  uint32_t flags, uint32_t *obj_handle);
extern ec_error_t zs_deletemessages(GUID ses, uint32_t fld_handle, const BINARY_ARRAY *entryids, uint32_t flags);
extern ec_error_t zs_copymessages(GUID ses, uint32_t srcfld_handle, uint32_t dstfld_handle, const BINARY_ARRAY *entryids, uint32_t flags);
extern ec_error_t zs_setreadflags(GUID ses, uint32_t fld_handle, const BINARY_ARRAY *entryids, uint32_t flags);
extern ec_error_t zs_createfolder(GUID ses, uint32_t parent_fld_handle, uint32_t folder_type, const char *folder_name, const char *folder_comment, uint32_t flags, uint32_t *obj_handle);
extern ec_error_t zs_deletefolder(GUID ses, uint32_t parent_fld_handle, BINARY entryid, uint32_t flags);
extern ec_error_t zs_emptyfolder(GUID ses, uint32_t fld_handle, uint32_t flags);
extern ec_error_t zs_copyfolder(GUID ses, uint32_t srcfld_handle, BINARY entryid, uint32_t dstfld_handle, const char *new_name, uint32_t flags);
extern ec_error_t zs_getstoreentryid(const char *mailbox_dn, BINARY *entryid);
extern ec_error_t zs_entryidfromsourcekey(GUID ses, uint32_t store_handle, BINARY folder_key, const BINARY *msg_key, BINARY *entryid);
extern ec_error_t zs_storeadvise(GUID ses, uint32_t store_handle, const BINARY *entryid, uint32_t event_mask, uint32_t *sub_id);
extern ec_error_t zs_unadvise(GUID ses, uint32_t store_handle, uint32_t sub_id);
extern ec_error_t zs_notifdequeue(const NOTIF_SINK *, uint32_t timeval, ZNOTIFICATION_ARRAY *);
extern ec_error_t zs_queryrows(GUID ses, uint32_t tbl_handle, uint32_t start, uint32_t count, const RESTRICTION *, const PROPTAG_ARRAY *, TARRAY_SET *);
extern ec_error_t zs_setcolumns(GUID ses, uint32_t tbl_handle, const PROPTAG_ARRAY *, uint32_t flags);
extern ec_error_t zs_seekrow(GUID ses, uint32_t tbl_handle, uint32_t bookmark, int32_t seek_rows, int32_t *sought);
extern ec_error_t zs_sorttable(GUID ses, uint32_t tbl_handle, const SORTORDER_SET *);
extern ec_error_t zs_getrowcount(GUID ses, uint32_t tbl_handle, uint32_t *count);
extern ec_error_t zs_restricttable(GUID ses, uint32_t tbl_handle, const RESTRICTION *, uint32_t flags);
extern ec_error_t zs_findrow(GUID ses, uint32_t tbl_handle, uint32_t bookmark, const RESTRICTION *, uint32_t flags, uint32_t *row_idx);
extern ec_error_t zs_createbookmark(GUID ses, uint32_t tbl_handle, uint32_t *bookmark);
extern ec_error_t zs_freebookmark(GUID ses, uint32_t tbl_handle, uint32_t bookmark);
extern ec_error_t zs_getreceivefolder(GUID ses, uint32_t store_handle, const char *xclass, BINARY *entryid);
extern ec_error_t zs_modifyrecipients(GUID ses, uint32_t msg_handle, uint32_t flags, const TARRAY_SET *rcpts);
extern ec_error_t zs_submitmessage(GUID ses, uint32_t msg_handle);
extern ec_error_t zs_loadattachmenttable(GUID ses, uint32_t msg_handle, uint32_t *obj_handle);
extern ec_error_t zs_openattachment(GUID ses, uint32_t msg_handle, uint32_t attach_id, uint32_t *obj_handle);
extern ec_error_t zs_createattachment(GUID ses, uint32_t msg_handle, uint32_t *obj_handle);
extern ec_error_t zs_deleteattachment(GUID ses, uint32_t msg_handle, uint32_t attach_id);
extern ec_error_t zs_setpropvals(GUID ses, uint32_t obj, TPROPVAL_ARRAY *);
extern ec_error_t zs_getpropvals(GUID ses, uint32_t obj_handle, const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
extern ec_error_t zs_deletepropvals(GUID ses, uint32_t obj_handle, const PROPTAG_ARRAY *);
extern ec_error_t zs_setmessagereadflag(GUID ses, uint32_t msg_handle, uint32_t flags);
extern ec_error_t zs_openembedded(GUID ses, uint32_t atx_handle, uint32_t flags, uint32_t *obj_handle);
extern ec_error_t zs_getnamedpropids(GUID ses, uint32_t store_handle, const PROPNAME_ARRAY *, PROPID_ARRAY *);
extern ec_error_t zs_getpropnames(GUID ses, uint32_t store_handle, const PROPID_ARRAY *, PROPNAME_ARRAY *);
extern ec_error_t zs_copyto(GUID ses, uint32_t srcobj_handle, const PROPTAG_ARRAY *exclprop, uint32_t dstobj_handle, uint32_t flags);
extern ec_error_t zs_savechanges(GUID ses, uint32_t obj_handle);
extern ec_error_t zs_hierarchysync(GUID ses, uint32_t fld_handle, uint32_t *obj_handle);
extern ec_error_t zs_contentsync(GUID ses, uint32_t fld_handle, uint32_t *obj_handle);
extern ec_error_t zs_configsync(GUID, uint32_t, uint32_t, const BINARY *, const RESTRICTION *, uint8_t *, uint32_t *);
extern ec_error_t zs_statesync(GUID ses, uint32_t ctx_handle, BINARY *state);
extern ec_error_t zs_syncmessagechange(GUID, uint32_t, uint8_t *, TPROPVAL_ARRAY *);
extern ec_error_t zs_syncfolderchange(GUID ses, uint32_t ctx_handle, TPROPVAL_ARRAY *);
extern ec_error_t zs_syncreadstatechanges(GUID ses, uint32_t ctx_handle, STATE_ARRAY *);
extern ec_error_t zs_syncdeletions(GUID ses, uint32_t ctx_handle, uint32_t flags, BINARY_ARRAY *);
extern ec_error_t zs_hierarchyimport(GUID ses, uint32_t fld_handle, uint32_t *obj_handle);
extern ec_error_t zs_contentimport(GUID ses, uint32_t fld_handle, uint32_t *obj_handle);
extern ec_error_t zs_configimport(GUID ses, uint32_t ctx_handle, uint8_t sync_type, const BINARY *state);
extern ec_error_t zs_stateimport(GUID ses, uint32_t ctx_handle, BINARY *state);
extern ec_error_t zs_importmessage(GUID ses, uint32_t ctx_handle, uint32_t flags, const TPROPVAL_ARRAY *, uint32_t *obj_handle);
extern ec_error_t zs_importfolder(GUID ses, uint32_t ctx_handle, const TPROPVAL_ARRAY *);
extern ec_error_t zs_importdeletion(GUID ses, uint32_t ctx_handle, uint32_t flags, const BINARY_ARRAY *);
extern ec_error_t zs_importreadstates(GUID ses, uint32_t ctx_handle, const STATE_ARRAY *);
extern ec_error_t zs_getsearchcriteria(GUID ses, uint32_t fld_handle, BINARY_ARRAY *folders, RESTRICTION **, uint32_t *srch_stat);
extern ec_error_t zs_setsearchcriteria(GUID ses, uint32_t fld_handle, uint32_t flags, const BINARY_ARRAY *folders, const RESTRICTION *);
extern ec_error_t zs_messagetorfc822(GUID ses, uint32_t msg_handle, BINARY *eml);
extern ec_error_t zs_rfc822tomessage(GUID ses, uint32_t msg_handle, uint32_t mxf_flags, const BINARY *eml);
extern ec_error_t zs_messagetoical(GUID ses, uint32_t msg_handle, BINARY *ical);
extern ec_error_t zs_icaltomessage(GUID ses, uint32_t msg_handle, const BINARY *ical);
extern ec_error_t zs_imtomessage2(GUID session, uint32_t folder_handle, uint32_t data_type, char *im_data, LONG_ARRAY *outhandles);
extern ec_error_t zs_messagetovcf(GUID ses, uint32_t msg_handle, BINARY *vcf);
extern ec_error_t zs_vcftomessage(GUID ses, uint32_t msg_handle, const BINARY *vcf);
extern ec_error_t zs_getuseravailability(GUID ses, BINARY entryid, uint64_t starttime, uint64_t endtime, char **result);
extern ec_error_t zs_setpasswd(const char *username, const char *passwd, const char *new_passwd);
extern ec_error_t zs_linkmessage(GUID ses, BINARY search_eid, BINARY msg_eid);
