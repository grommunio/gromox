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

extern void zarafa_server_init(size_t table_size, int cache_interval, int ping_interval);
extern int zarafa_server_run();
extern void zarafa_server_stop();
extern USER_INFO *zarafa_server_get_info();
uint32_t zarafa_server_logon(const char *username,
	const char *password, uint32_t flags, GUID *phsession);
uint32_t zarafa_server_checksession(GUID hsession);
uint32_t zarafa_server_uinfo(const char *username, BINARY *pentryid,
	char **ppdisplay_name, char **ppx500dn, uint32_t *pprivilege_bits);
uint32_t zarafa_server_unloadobject(GUID hsession, uint32_t hobject);
uint32_t zarafa_server_openentry(GUID hsession, BINARY entryid,
	uint32_t flags, uint8_t *pmapi_type, uint32_t *phobject);
uint32_t zarafa_server_openstoreentry(GUID hsession,
	uint32_t hobject, BINARY entryid, uint32_t flags,
	uint8_t *pmapi_type, uint32_t *phobject);
uint32_t zarafa_server_openabentry(GUID hsession,
	BINARY entryid, uint8_t *pmapi_type, uint32_t *phobject);
uint32_t zarafa_server_resolvename(GUID hsession,
	const TARRAY_SET *pcond_set, TARRAY_SET *presult_set);
uint32_t zarafa_server_getpermissions(GUID hsession,
	uint32_t hobject, PERMISSION_SET *pperm_set);
uint32_t zarafa_server_modifypermissions(GUID hsession,
	uint32_t hfolder, const PERMISSION_SET *pset);
uint32_t zarafa_server_modifyrules(GUID hsession,
	uint32_t hfolder, uint32_t flags, const RULE_LIST *plist);
uint32_t zarafa_server_getabgal(GUID hsession, BINARY *pentryid);
uint32_t zarafa_server_loadstoretable(
	GUID hsession, uint32_t *phobject);
uint32_t zarafa_server_openstore(GUID hsession,
	BINARY entryid, uint32_t *phobject);
extern uint32_t zarafa_server_openprofilesec(GUID sess, const FLATUID *, uint32_t *obj);
uint32_t zarafa_server_loadhierarchytable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject);
uint32_t zarafa_server_loadcontenttable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject);
uint32_t zarafa_server_loadrecipienttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject);
uint32_t zarafa_server_loadruletable(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);
uint32_t zarafa_server_createmessage(GUID hsession,
	uint32_t hfolder,  uint32_t flags, uint32_t *phobject);
uint32_t zarafa_server_deletemessages(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags);
uint32_t zarafa_server_copymessages(GUID hsession,
	uint32_t hsrcfolder, uint32_t hdstfolder,
	const BINARY_ARRAY *pentryids, uint32_t flags);
uint32_t zarafa_server_setreadflags(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags);
uint32_t zarafa_server_createfolder(GUID hsession,
	uint32_t hparent_folder, uint32_t folder_type,
	const char *folder_name, const char *folder_comment,
	uint32_t flags, uint32_t *phobject);
uint32_t zarafa_server_deletefolder(GUID hsession,
	uint32_t hparent_folder, BINARY entryid, uint32_t flags);
uint32_t zarafa_server_emptyfolder(GUID hsession,
	uint32_t hfolder, uint32_t flags);
uint32_t zarafa_server_copyfolder(GUID hsession,
	uint32_t hsrc_folder, BINARY entryid, uint32_t hdst_folder,
	const char *new_name, uint32_t flags);
uint32_t zarafa_server_getstoreentryid(
	const char *mailbox_dn, BINARY *pentryid);
uint32_t zarafa_server_entryidfromsourcekey(
	GUID hsession, uint32_t hstore, BINARY folder_key,
	const BINARY *pmessage_key, BINARY *pentryid);
uint32_t zarafa_server_storeadvise(GUID hsession,
	uint32_t hstore, const BINARY *pentryid,
	uint32_t event_mask, uint32_t *psub_id);
uint32_t zarafa_server_unadvise(GUID hsession,
	uint32_t hstore, uint32_t sub_id);
uint32_t zarafa_server_notifdequeue(const NOTIF_SINK *psink,
	uint32_t timeval, ZNOTIFICATION_ARRAY *pnotifications);
uint32_t zarafa_server_queryrows(
	GUID hsession, uint32_t htable, uint32_t start,
	uint32_t count, const RESTRICTION *prestriction,
	const PROPTAG_ARRAY *pproptags, TARRAY_SET *prowset);
uint32_t zarafa_server_setcolumns(GUID hsession, uint32_t htable,
	const PROPTAG_ARRAY *pproptags, uint32_t flags);
uint32_t zarafa_server_seekrow(GUID hsession,
	uint32_t htable, uint32_t bookmark, int32_t seek_rows,
	int32_t *psought_rows);
uint32_t zarafa_server_sorttable(GUID hsession,
	uint32_t htable, const SORTORDER_SET *psortset);
uint32_t zarafa_server_getrowcount(GUID hsession,
	uint32_t htable, uint32_t *pcount);
uint32_t zarafa_server_restricttable(GUID hsession, uint32_t htable,
	const RESTRICTION *prestriction, uint32_t flags);
uint32_t zarafa_server_findrow(GUID hsession, uint32_t htable,
	uint32_t bookmark, const RESTRICTION *prestriction,
	uint32_t flags, uint32_t *prow_idx);
uint32_t zarafa_server_createbookmark(GUID hsession,
	uint32_t htable, uint32_t *pbookmark);
uint32_t zarafa_server_freebookmark(GUID hsession,
	uint32_t htable, uint32_t bookmark);
uint32_t zarafa_server_getreceivefolder(GUID hsession,
	uint32_t hstore, const char *pstrclass, BINARY *pentryid);
uint32_t zarafa_server_modifyrecipients(GUID hsession,
	uint32_t hmessage, uint32_t flags, const TARRAY_SET *prcpt_list);
uint32_t zarafa_server_submitmessage(GUID hsession, uint32_t hmessage);
uint32_t zarafa_server_loadattachmenttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject);
uint32_t zarafa_server_openattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id, uint32_t *phobject);
uint32_t zarafa_server_createattachment(GUID hsession,
	uint32_t hmessage, uint32_t *phobject);
uint32_t zarafa_server_deleteattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id);
extern uint32_t zarafa_server_setpropvals(GUID ses, uint32_t obj, TPROPVAL_ARRAY *);
uint32_t zarafa_server_getpropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);
uint32_t zarafa_server_deletepropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags);
uint32_t zarafa_server_setmessagereadflag(
	GUID hsession, uint32_t hmessage, uint32_t flags);
uint32_t zarafa_server_openembedded(GUID hsession,
	uint32_t hattachment, uint32_t flags, uint32_t *phobject);
uint32_t zarafa_server_getnamedpropids(GUID hsession, uint32_t hstore,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids);
uint32_t zarafa_server_getpropnames(GUID hsession, uint32_t hstore,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);
uint32_t zarafa_server_copyto(GUID hsession, uint32_t hsrcobject,
	const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject,
	uint32_t flags);
uint32_t zarafa_server_savechanges(GUID hsession, uint32_t hobject);
uint32_t zarafa_server_hierarchysync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);
uint32_t zarafa_server_contentsync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);
extern uint32_t zarafa_server_configsync(GUID, uint32_t, uint32_t, const BINARY *, const RESTRICTION *, uint8_t *, uint32_t *);
uint32_t zarafa_server_statesync(GUID hsession,
	uint32_t hctx, BINARY *pstate);
extern uint32_t zarafa_server_syncmessagechange(GUID, uint32_t, uint8_t *, TPROPVAL_ARRAY *);
uint32_t zarafa_server_syncfolderchange(GUID hsession,
	uint32_t hctx, TPROPVAL_ARRAY *pproplist);
uint32_t zarafa_server_syncreadstatechanges(
	GUID hsession, uint32_t hctx, STATE_ARRAY *pstates);
uint32_t zarafa_server_syncdeletions(GUID hsession,
	uint32_t hctx, uint32_t flags, BINARY_ARRAY *pbins);
uint32_t zarafa_server_hierarchyimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);
uint32_t zarafa_server_contentimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);
uint32_t zarafa_server_configimport(GUID hsession,
	uint32_t hctx, uint8_t sync_type, const BINARY *pstate);
uint32_t zarafa_server_stateimport(GUID hsession,
	uint32_t hctx, BINARY *pstate);
uint32_t zarafa_server_importmessage(GUID hsession, uint32_t hctx,
	uint32_t flags, const TPROPVAL_ARRAY *pproplist, uint32_t *phobject);
uint32_t zarafa_server_importfolder(GUID hsession,
	uint32_t hctx, const TPROPVAL_ARRAY *pproplist);
uint32_t zarafa_server_importdeletion(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY_ARRAY *pbins);
uint32_t zarafa_server_importreadstates(GUID hsession,
	uint32_t hctx, const STATE_ARRAY *pstates);
uint32_t zarafa_server_getsearchcriteria(GUID hsession,
	uint32_t hfolder, BINARY_ARRAY *pfolder_array,
	RESTRICTION **pprestriction, uint32_t *psearch_stat);
uint32_t zarafa_server_setsearchcriteria(
	GUID hsession, uint32_t hfolder, uint32_t flags,
	const BINARY_ARRAY *pfolder_array,
	const RESTRICTION *prestriction);
uint32_t zarafa_server_messagetorfc822(GUID hsession,
	uint32_t hmessage, BINARY *peml_bin);
extern uint32_t zarafa_server_rfc822tomessage(GUID hsession, uint32_t hmessage, uint32_t mxf_flags, const BINARY *peml_bin);
uint32_t zarafa_server_messagetoical(GUID hsession,
	uint32_t hmessage, BINARY *pical_bin);
uint32_t zarafa_server_icaltomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pical_bin);
extern uint32_t zarafa_server_imtomessage2(GUID session, uint32_t folder, uint32_t data_type, char *im_data, LONG_ARRAY *outhandles);
uint32_t zarafa_server_messagetovcf(GUID hsession,
	uint32_t hmessage, BINARY *pvcf_bin);
uint32_t zarafa_server_vcftomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pvcf_bin);
uint32_t zarafa_server_getuseravailability(GUID hsession,
	BINARY entryid, uint64_t starttime, uint64_t endtime,
	char **ppresult_string);
uint32_t zarafa_server_setpasswd(const char *username,
	const char *passwd, const char *new_passwd);
uint32_t zarafa_server_linkmessage(GUID hsession,
	BINARY search_entryid, BINARY message_entryid);
