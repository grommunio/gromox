#ifndef _H_ZARAFA_SERVER_
#define _H_ZARAFA_SERVER_
#include "mapi_types.h"
#include "common_util.h"
#include "object_tree.h"
#include <pthread.h>
#include <time.h>

enum {
	USER_TABLE_SIZE,
	USER_TABLE_USED
};

typedef struct _USER_INFO {
	volatile int reference;
	GUID hsession;
	int user_id;
	int domain_id;
	int org_id;
	char username[256];
	char lang[32];
	uint32_t cpid;
	char maildir[256];
	char homedir[256];
	char *password;
	time_t last_time;
	OBJECT_TREE *ptree;
	pthread_mutex_t lock;
	DOUBLE_LIST sink_list;
} USER_INFO;

void zarafa_server_init(int table_size,
	int cache_interval, int ping_interval);

int zarafa_server_run();

int zarafa_server_stop();

void zarafa_server_free();

int zarafa_server_get_param(int param);

USER_INFO* zarafa_server_get_info();

uint32_t zarafa_server_logon(const char *username,
	const char *password, uint32_t flags, GUID *phsession);

uint32_t zarafa_server_checksession(GUID hsession);
	
uint32_t zarafa_server_uinfo(const char *username,
	BINARY *pentryid, char **ppdisplay_name, char **ppx500dn);

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

uint32_t zarafa_server_openrules(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);

uint32_t zarafa_server_getpermissions(GUID hsession,
	uint32_t hobject, PERMISSION_SET *pperm_set);

uint32_t zarafa_server_modifypermissions(GUID hsession,
	uint32_t hfolder, const PERMISSION_SET *pset);

uint32_t zarafa_server_modifyrules(GUID hsession,
	uint32_t hrules, uint32_t flags, const RULE_LIST *plist);

uint32_t zarafa_server_getabgal(GUID hsession, BINARY *pentryid);

uint32_t zarafa_server_loadstoretable(
	GUID hsession, uint32_t *phobject);

uint32_t zarafa_server_openstore(GUID hsession,
	BINARY entryid, uint32_t *phobject);

uint32_t zarafa_server_openpropfilesec(GUID hsession,
	const FLATUID *puid, uint32_t *phobject);

uint32_t zarafa_server_loadhierarchytable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject);

uint32_t zarafa_server_loadcontenttable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject);

uint32_t zarafa_server_loadrecipienttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject);

uint32_t zarafa_server_loadruletable(GUID hsession,
	uint32_t hrules, uint32_t *phobject);

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

uint32_t zarafa_server_setpropvals(GUID hsession,
	uint32_t hobject, const TPROPVAL_ARRAY *ppropvals);

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

uint32_t zarafa_server_configsync(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY *pstate,
	const RESTRICTION *prestriction, BOOL *pb_changed,
	uint32_t *pcount);

uint32_t zarafa_server_statesync(GUID hsession,
	uint32_t hctx, BINARY *pstate);

uint32_t zarafa_server_syncmessagechange(GUID hsession,
	uint32_t hctx, BOOL *pb_new, TPROPVAL_ARRAY *pproplist);

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

uint32_t zarafa_server_openfreebusydata(GUID hsession,
	uint32_t hsupport, const BINARY_ARRAY *pentryids,
	LONG_ARRAY *phobject_array);

uint32_t zarafa_server_enumfreebusyblocks(GUID hsession,
	uint32_t hfbdata, uint64_t nttime_start, uint64_t nttime_end,
	uint32_t *phobject);

uint32_t zarafa_server_fbenumreset(GUID hsession, uint32_t hfbenum);

uint32_t zarafa_server_fbenumskip(GUID hsession,
	uint32_t hfbenum, uint32_t num);

uint32_t zarafa_server_fbenumrestrict(GUID hsession,
	uint32_t hfbenum, uint64_t nttime_start, uint64_t nttime_end);

uint32_t zarafa_server_fbenumexport(GUID hsession,
	uint32_t hfbenum, uint32_t count, uint64_t nttime_start,
	uint64_t nttime_end, const char *organizer_name,
	const char *username, const char *uid_string,
	BINARY *pbin_ical);

uint32_t zarafa_server_fetchfreebusyblocks(GUID hsession,
	uint32_t hfbenum, uint32_t celt, FBBLOCK_ARRAY *pblocks);

uint32_t zarafa_server_getfreebusyrange(GUID hsession,
	uint32_t hfbdata, uint64_t *pnttime_start, uint64_t *pnttime_end);
	
uint32_t zarafa_server_messagetorfc822(GUID hsession,
	uint32_t hmessage, BINARY *peml_bin);

uint32_t zarafa_server_rfc822tomessage(GUID hsession,
	uint32_t hmessage, const BINARY *peml_bin);

uint32_t zarafa_server_messagetoical(GUID hsession,
	uint32_t hmessage, BINARY *pical_bin);

uint32_t zarafa_server_icaltomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pical_bin);

uint32_t zarafa_server_messagetovcf(GUID hsession,
	uint32_t hmessage, BINARY *pvcf_bin);

uint32_t zarafa_server_vcftomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pvcf_bin);

#endif /* _H_ZARAFA_CLIENT_ */
