#include "idset.h"
#include "rpc_ext.h"
#include "rpc_parser.h"
#include "common_util.h"
#include "zarafa_server.h"
#include "mapi_types.h"
#include <sys/socket.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>

enum {
	DISPATCH_TRUE,
	DISPATCH_FALSE,
	DISPATCH_CONTINUE
};

typedef struct _CLIENT_NODE {
	DOUBLE_LIST_NODE node;
	int clifd;
} CLIENT_NODE;

static int g_thread_num;
static BOOL g_notify_stop;
static pthread_t *g_thread_ids;
static DOUBLE_LIST g_conn_list;
static pthread_cond_t g_waken_cond;
static pthread_mutex_t g_conn_lock;
static pthread_mutex_t g_cond_mutex;


void rpc_parser_init(int thread_num)
{
	g_notify_stop = TRUE;
	g_thread_num = thread_num;
	pthread_mutex_init(&g_conn_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);
}

void rpc_parser_free()
{
	pthread_mutex_destroy(&g_conn_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);
}

BOOL rpc_parser_activate_connection(int clifd)
{
	CLIENT_NODE *pclient;
	
	pclient = malloc(sizeof(CLIENT_NODE));
	if (NULL == pclient) {
		return FALSE;
	}
	pclient->node.pdata = pclient;
	pclient->clifd = clifd;
	pthread_mutex_lock(&g_conn_lock);
	double_list_append_as_tail(&g_conn_list, &pclient->node);
	pthread_mutex_unlock(&g_conn_lock);
	pthread_cond_signal(&g_waken_cond);
	return TRUE;
}

static int rpc_parser_dispatch(const RPC_REQUEST *prequest,
	RPC_RESPONSE *presponse)
{
	presponse->call_id = prequest->call_id;
	switch (prequest->call_id) {
	case CALL_ID_LOGON:
		presponse->result = zarafa_server_logon(
			prequest->payload.logon.username,
			prequest->payload.logon.password,
			prequest->payload.logon.flags,
			&presponse->payload.logon.hsession);
		break;
	case CALL_ID_CHECKSESSION:
		presponse->result = zarafa_server_checksession(
			prequest->payload.checksession.hsession);
		break;
	case CALL_ID_UINFO:
		presponse->result = zarafa_server_uinfo(
			prequest->payload.uinfo.username,
			&presponse->payload.uinfo.entryid,
			&presponse->payload.uinfo.pdisplay_name,
			&presponse->payload.uinfo.px500dn);
		break;
	case CALL_ID_UNLOADOBJECT:
		presponse->result = zarafa_server_unloadobject(
			prequest->payload.unloadobject.hsession,
			prequest->payload.unloadobject.hobject);
		break;
	case CALL_ID_OPENENTRY:
		presponse->result = zarafa_server_openentry(
			prequest->payload.openentry.hsession,
			prequest->payload.openentry.entryid,
			prequest->payload.openentry.flags,
			&presponse->payload.openentry.mapi_type,
			&presponse->payload.openentry.hobject);
		break;
	case CALL_ID_OPENSTOREENTRY:
		presponse->result = zarafa_server_openstoreentry(
			prequest->payload.openstoreentry.hsession,
			prequest->payload.openstoreentry.hobject,
			prequest->payload.openstoreentry.entryid,
			prequest->payload.openstoreentry.flags,
			&presponse->payload.openstoreentry.mapi_type,
			&presponse->payload.openstoreentry.hobject);
		break;
	case CALL_ID_OPENABENTRY:
		presponse->result = zarafa_server_openabentry(
			prequest->payload.openabentry.hsession,
			prequest->payload.openabentry.entryid,
			&presponse->payload.openabentry.mapi_type,
			&presponse->payload.openabentry.hobject);
		break;
	case CALL_ID_RESOLVENAME:
		presponse->result = zarafa_server_resolvename(
			prequest->payload.resolvename.hsession,
			prequest->payload.resolvename.pcond_set,
			&presponse->payload.resolvename.result_set);
		break;
	case CALL_ID_OPENRULES:
		presponse->result = zarafa_server_openrules(
			prequest->payload.openrules.hsession,
			prequest->payload.openrules.hfolder,
			&presponse->payload.openrules.hobject);
		break;
	case CALL_ID_GETPERMISSIONS:
		presponse->result = zarafa_server_getpermissions(
			prequest->payload.getpermissions.hsession,
			prequest->payload.getpermissions.hobject,
			&presponse->payload.getpermissions.perm_set);
		break;
	case CALL_ID_MODIFYPERMISSIONS:
		presponse->result = zarafa_server_modifypermissions(
			prequest->payload.modifypermissions.hsession,
			prequest->payload.modifypermissions.hfolder,
			prequest->payload.modifypermissions.pset);
		break;
	case CALL_ID_MODIFYRULES:
		presponse->result = zarafa_server_modifyrules(
			prequest->payload.modifyrules.hsession,
			prequest->payload.modifyrules.hrules,
			prequest->payload.modifyrules.flags,
			prequest->payload.modifyrules.plist);
		break;
	case CALL_ID_GETABGAL:
		presponse->result = zarafa_server_getabgal(
			prequest->payload.getabgal.hsession,
			&presponse->payload.getabgal.entryid);
		break;
	case CALL_ID_LOADSTORETABLE:
		presponse->result = zarafa_server_loadstoretable(
			prequest->payload.loadstoretable.hsession,
			&presponse->payload.loadstoretable.hobject);
		break;
	case CALL_ID_OPENSTORE:
		presponse->result = zarafa_server_openstore(
			prequest->payload.openstore.hsession,
			prequest->payload.openstore.entryid,
			&presponse->payload.openstore.hobject);
		break;
	case CALL_ID_OPENPROPFILESEC:
		presponse->result = zarafa_server_openpropfilesec(
			prequest->payload.openpropfilesec.hsession,
			prequest->payload.openpropfilesec.puid,
			&presponse->payload.openpropfilesec.hobject);
		break;
	case CALL_ID_LOADHIERARCHYTABLE:
		presponse->result = zarafa_server_loadhierarchytable(
			prequest->payload.loadhierarchytable.hsession,
			prequest->payload.loadhierarchytable.hfolder,
			prequest->payload.loadhierarchytable.flags,
			&presponse->payload.loadhierarchytable.hobject);
		break;
	case CALL_ID_LOADCONTENTTABLE:
		presponse->result = zarafa_server_loadcontenttable(
			prequest->payload.loadcontenttable.hsession,
			prequest->payload.loadcontenttable.hfolder,
			prequest->payload.loadcontenttable.flags,
			&presponse->payload.loadcontenttable.hobject);
		break;
	case CALL_ID_LOADRECIPIENTTABLE:
		presponse->result = zarafa_server_loadrecipienttable(
			prequest->payload.loadrecipienttable.hsession,
			prequest->payload.loadrecipienttable.hmessage,
			&presponse->payload.loadrecipienttable.hobject);
		break;
	case CALL_ID_LOADRULETABLE:
		presponse->result = zarafa_server_loadruletable(
			prequest->payload.loadruletable.hsession,
			prequest->payload.loadruletable.hrules,
			&presponse->payload.loadruletable.hobject);
		break;
	case CALL_ID_CREATEMESSAGE:
		presponse->result = zarafa_server_createmessage(
			prequest->payload.createmessage.hsession,
			prequest->payload.createmessage.hfolder,
			prequest->payload.createmessage.flags,
			&presponse->payload.createmessage.hobject);
		break;
	case CALL_ID_DELETEMESSAGES:
		presponse->result = zarafa_server_deletemessages(
			prequest->payload.deletemessages.hsession,
			prequest->payload.deletemessages.hfolder,
			prequest->payload.deletemessages.pentryids,
			prequest->payload.deletemessages.flags);
		break;
	case CALL_ID_COPYMESSAGES:
		presponse->result = zarafa_server_copymessages(
			prequest->payload.copymessages.hsession,
			prequest->payload.copymessages.hsrcfolder,
			prequest->payload.copymessages.hdstfolder,
			prequest->payload.copymessages.pentryids,
			prequest->payload.copymessages.flags);
		break;
	case CALL_ID_SETREADFLAGS:
		presponse->result = zarafa_server_setreadflags(
			prequest->payload.setreadflags.hsession,
			prequest->payload.setreadflags.hfolder,
			prequest->payload.setreadflags.pentryids,
			prequest->payload.setreadflags.flags);
		break;
	case CALL_ID_CREATEFOLDER:
		presponse->result = zarafa_server_createfolder(
			prequest->payload.createfolder.hsession,
			prequest->payload.createfolder.hparent_folder,
			prequest->payload.createfolder.folder_type,
			prequest->payload.createfolder.folder_name,
			prequest->payload.createfolder.folder_comment,
			prequest->payload.createfolder.flags,
			&presponse->payload.createfolder.hobject);
		break;
	case CALL_ID_DELETEFOLDER:
		presponse->result = zarafa_server_deletefolder(
			prequest->payload.deletefolder.hsession,
			prequest->payload.deletefolder.hparent_folder,
			prequest->payload.deletefolder.entryid,
			prequest->payload.deletefolder.flags);
		break;
	case CALL_ID_EMPTYFOLDER:
		presponse->result = zarafa_server_emptyfolder(
			prequest->payload.emptyfolder.hsession,
			prequest->payload.emptyfolder.hfolder,
			prequest->payload.emptyfolder.flags);
		break;
	case CALL_ID_COPYFOLDER:
		presponse->result = zarafa_server_copyfolder(
			prequest->payload.copyfolder.hsession,
			prequest->payload.copyfolder.hsrc_folder,
			prequest->payload.copyfolder.entryid,
			prequest->payload.copyfolder.hdst_folder,
			prequest->payload.copyfolder.new_name,
			prequest->payload.copyfolder.flags);
		break;
	case CALL_ID_GETSTOREENTRYID:
		presponse->result = zarafa_server_getstoreentryid(
			prequest->payload.getstoreentryid.mailbox_dn,
			&presponse->payload.getstoreentryid.entryid);
		break;
	case CALL_ID_ENTRYIDFROMSOURCEKEY:
		presponse->result = zarafa_server_entryidfromsourcekey(
			prequest->payload.entryidfromsourcekey.hsession,
			prequest->payload.entryidfromsourcekey.hstore,
			prequest->payload.entryidfromsourcekey.folder_key,
			prequest->payload.entryidfromsourcekey.pmessage_key,
			&presponse->payload.entryidfromsourcekey.entryid);
		break;
	case CALL_ID_STOREADVISE:
		presponse->result = zarafa_server_storeadvise(
			prequest->payload.storeadvise.hsession,
			prequest->payload.storeadvise.hstore,
			prequest->payload.storeadvise.pentryid,
			prequest->payload.storeadvise.event_mask,
			&presponse->payload.storeadvise.sub_id);
		break;
	case CALL_ID_UNADVISE:
		presponse->result = zarafa_server_unadvise(
			prequest->payload.unadvise.hsession,
			prequest->payload.unadvise.hstore,
			prequest->payload.unadvise.sub_id);
		break;
	case CALL_ID_NOTIFDEQUEUE:
		presponse->result = zarafa_server_notifdequeue(
			prequest->payload.notifdequeue.psink,
			prequest->payload.notifdequeue.timeval,
			&presponse->payload.notifdequeue.notifications);
		if (EC_NOT_FOUND == presponse->result) {
			return DISPATCH_CONTINUE;
		}
		break;
	case CALL_ID_QUERYROWS:
		presponse->result = zarafa_server_queryrows(
			prequest->payload.queryrows.hsession,
			prequest->payload.queryrows.htable,
			prequest->payload.queryrows.start,
			prequest->payload.queryrows.count,
			prequest->payload.queryrows.prestriction,
			prequest->payload.queryrows.pproptags,
			&presponse->payload.queryrows.rowset);
		break;
	case CALL_ID_SETCOLUMNS:
		presponse->result = zarafa_server_setcolumns(
			prequest->payload.setcolumns.hsession,
			prequest->payload.setcolumns.htable,
			prequest->payload.setcolumns.pproptags,
			prequest->payload.setcolumns.flags);
		break;
	case CALL_ID_SEEKROW:
		presponse->result = zarafa_server_seekrow(
			prequest->payload.seekrow.hsession,
			prequest->payload.seekrow.htable,
			prequest->payload.seekrow.bookmark,
			prequest->payload.seekrow.seek_rows,
			&presponse->payload.seekrow.sought_rows);
		break;
	case CALL_ID_SORTTABLE:
		presponse->result = zarafa_server_sorttable(
			prequest->payload.sorttable.hsession,
			prequest->payload.sorttable.htable,
			prequest->payload.sorttable.psortset);
		break;
	case CALL_ID_GETROWCOUNT:
		presponse->result = zarafa_server_getrowcount(
			prequest->payload.getrowcount.hsession,
			prequest->payload.getrowcount.htable,
			&presponse->payload.getrowcount.count);
		break;
	case CALL_ID_RESTRICTTABLE:
		presponse->result = zarafa_server_restricttable(
			prequest->payload.restricttable.hsession,
			prequest->payload.restricttable.htable,
			prequest->payload.restricttable.prestriction,
			prequest->payload.restricttable.flags);
		break;
	case CALL_ID_FINDROW:
		presponse->result = zarafa_server_findrow(
			prequest->payload.findrow.hsession,
			prequest->payload.findrow.htable,
			prequest->payload.findrow.bookmark,
			prequest->payload.findrow.prestriction,
			prequest->payload.findrow.flags,
			&presponse->payload.findrow.row_idx);
		break;
	case CALL_ID_CREATEBOOKMARK:
		presponse->result = zarafa_server_createbookmark(
			prequest->payload.createbookmark.hsession,
			prequest->payload.createbookmark.htable,
			&presponse->payload.createbookmark.bookmark);
		break;
	case CALL_ID_FREEBOOKMARK:
		presponse->result = zarafa_server_freebookmark(
			prequest->payload.freebookmark.hsession,
			prequest->payload.freebookmark.htable,
			prequest->payload.freebookmark.bookmark);
		break;
	case CALL_ID_GETRECEIVEFOLDER:
		presponse->result = zarafa_server_getreceivefolder(
			prequest->payload.getreceivefolder.hsession,
			prequest->payload.getreceivefolder.hstore,
			prequest->payload.getreceivefolder.pstrclass,
			&presponse->payload.getreceivefolder.entryid);
		break;
	case CALL_ID_MODIFYRECIPIENTS:
		presponse->result = zarafa_server_modifyrecipients(
			prequest->payload.modifyrecipients.hsession,
			prequest->payload.modifyrecipients.hmessage,
			prequest->payload.modifyrecipients.flags,
			prequest->payload.modifyrecipients.prcpt_list);
		break;
	case CALL_ID_SUBMITMESSAGE:
		presponse->result = zarafa_server_submitmessage(
			prequest->payload.submitmessage.hsession,
			prequest->payload.submitmessage.hmessage);
		break;
	case CALL_ID_LOADATTACHMENTTABLE:
		presponse->result = zarafa_server_loadattachmenttable(
			prequest->payload.loadattachmenttable.hsession,
			prequest->payload.loadattachmenttable.hmessage,
			&presponse->payload.loadattachmenttable.hobject);
		break;
	case CALL_ID_OPENATTACHMENT:
		presponse->result = zarafa_server_openattachment(
			prequest->payload.openattachment.hsession,
			prequest->payload.openattachment.hmessage,
			prequest->payload.openattachment.attach_id,
			&presponse->payload.openattachment.hobject);
		break;
	case CALL_ID_CREATEATTACHMENT:
		presponse->result = zarafa_server_createattachment(
			prequest->payload.createattachment.hsession,
			prequest->payload.createattachment.hmessage,
			&presponse->payload.createattachment.hobject);
		break;
	case CALL_ID_DELETEATTACHMENT:
		presponse->result = zarafa_server_deleteattachment(
			prequest->payload.deleteattachment.hsession,
			prequest->payload.deleteattachment.hmessage,
			prequest->payload.deleteattachment.attach_id);
		break;
	case CALL_ID_SETPROPVALS:
		presponse->result = zarafa_server_setpropvals(
			prequest->payload.setpropvals.hsession,
			prequest->payload.setpropvals.hobject,
			prequest->payload.setpropvals.ppropvals);
		break;
	case CALL_ID_GETPROPVALS:
		presponse->result = zarafa_server_getpropvals(
			prequest->payload.getpropvals.hsession,
			prequest->payload.getpropvals.hobject,
			prequest->payload.getpropvals.pproptags,
			&presponse->payload.getpropvals.propvals);
		break;
	case CALL_ID_DELETEPROPVALS:
		presponse->result = zarafa_server_deletepropvals(
			prequest->payload.deletepropvals.hsession,
			prequest->payload.deletepropvals.hobject,
			prequest->payload.deletepropvals.pproptags);
		break;
	case CALL_ID_SETMESSAGEREADFLAG:
		presponse->result = zarafa_server_setmessagereadflag(
			prequest->payload.setmessagereadflag.hsession,
			prequest->payload.setmessagereadflag.hmessage,
			prequest->payload.setmessagereadflag.flags);
		break;
	case CALL_ID_OPENEMBEDDED:
		presponse->result = zarafa_server_openembedded(
			prequest->payload.openembedded.hsession,
			prequest->payload.openembedded.hattachment,
			prequest->payload.openembedded.flags,
			&presponse->payload.openembedded.hobject);
		break;
	case CALL_ID_GETNAMEDPROPIDS:
		presponse->result = zarafa_server_getnamedpropids(
			prequest->payload.getnamedpropids.hsession,
			prequest->payload.getnamedpropids.hstore,
			prequest->payload.getnamedpropids.ppropnames,
			&presponse->payload.getnamedpropids.propids);
		break;
	case CALL_ID_GETPROPNAMES:
		presponse->result = zarafa_server_getpropnames(
			prequest->payload.getpropnames.hsession,
			prequest->payload.getpropnames.hstore,
			prequest->payload.getpropnames.ppropids,
			&presponse->payload.getpropnames.propnames);
		break;
	case CALL_ID_COPYTO:
		presponse->result = zarafa_server_copyto(
			prequest->payload.copyto.hsession,
			prequest->payload.copyto.hsrcobject,
			prequest->payload.copyto.pexclude_proptags,
			prequest->payload.copyto.hdstobject,
			prequest->payload.copyto.flags);
		break;
	case CALL_ID_SAVECHANGES:
		presponse->result = zarafa_server_savechanges(
			prequest->payload.savechanges.hsession,
			prequest->payload.savechanges.hobject);
		break;
	case CALL_ID_HIERARCHYSYNC:
		presponse->result = zarafa_server_hierarchysync(
			prequest->payload.hierarchysync.hsession,
			prequest->payload.hierarchysync.hfolder,
			&presponse->payload.hierarchysync.hobject);
		break;
	case CALL_ID_CONTENTSYNC:
		presponse->result = zarafa_server_contentsync(
			prequest->payload.contentsync.hsession,
			prequest->payload.contentsync.hfolder,
			&presponse->payload.contentsync.hobject);
		break;
	case CALL_ID_CONFIGSYNC:
		presponse->result = zarafa_server_configsync(
			prequest->payload.configsync.hsession,
			prequest->payload.configsync.hctx,
			prequest->payload.configsync.flags,
			prequest->payload.configsync.pstate,
			prequest->payload.configsync.prestriction,
			&presponse->payload.configsync.b_changed,
			&presponse->payload.configsync.count);
		break;
	case CALL_ID_STATESYNC:
		presponse->result = zarafa_server_statesync(
			prequest->payload.statesync.hsession,
			prequest->payload.statesync.hctx,
			&presponse->payload.statesync.state);
		break;
	case CALL_ID_SYNCMESSAGECHANGE:
		presponse->result = zarafa_server_syncmessagechange(
			prequest->payload.syncmessagechange.hsession,
			prequest->payload.syncmessagechange.hctx,
			&presponse->payload.syncmessagechange.b_new,
			&presponse->payload.syncmessagechange.proplist);
		break;
	case CALL_ID_SYNCFOLDERCHANGE:
		presponse->result = zarafa_server_syncfolderchange(
			prequest->payload.syncfolderchange.hsession,
			prequest->payload.syncfolderchange.hctx,
			&presponse->payload.syncfolderchange.proplist);
		break;
	case CALL_ID_SYNCREADSTATECHANGES:
		presponse->result = zarafa_server_syncreadstatechanges(
			prequest->payload.syncreadstatechanges.hsession,
			prequest->payload.syncreadstatechanges.hctx,
			&presponse->payload.syncreadstatechanges.states);
		break;
	case CALL_ID_SYNCDELETIONS:
		presponse->result = zarafa_server_syncdeletions(
			prequest->payload.syncdeletions.hsession,
			prequest->payload.syncdeletions.hctx,
			prequest->payload.syncdeletions.flags,
			&presponse->payload.syncdeletions.bins);
		break;
	case CALL_ID_HIERARCHYIMPORT:
		presponse->result = zarafa_server_hierarchyimport(
			prequest->payload.hierarchyimport.hsession,
			prequest->payload.hierarchyimport.hfolder,
			&presponse->payload.hierarchyimport.hobject);
		break;
	case CALL_ID_CONTENTIMPORT:
		presponse->result = zarafa_server_contentimport(
			prequest->payload.contentimport.hsession,
			prequest->payload.contentimport.hfolder,
			&presponse->payload.contentimport.hobject);
		break;
	case CALL_ID_CONFIGIMPORT:
		presponse->result = zarafa_server_configimport(
			prequest->payload.configimport.hsession,
			prequest->payload.configimport.hctx,
			prequest->payload.configimport.sync_type,
			prequest->payload.configimport.pstate);
		break;
	case CALL_ID_STATEIMPORT:
		presponse->result = zarafa_server_stateimport(
			prequest->payload.stateimport.hsession,
			prequest->payload.stateimport.hctx,
			&presponse->payload.stateimport.state);
		break;
	case CALL_ID_IMPORTMESSAGE:
		presponse->result = zarafa_server_importmessage(
			prequest->payload.importmessage.hsession,
			prequest->payload.importmessage.hctx,
			prequest->payload.importmessage.flags,
			prequest->payload.importmessage.pproplist,
			&presponse->payload.importmessage.hobject);
		break;
	case CALL_ID_IMPORTFOLDER:
		presponse->result = zarafa_server_importfolder(
			prequest->payload.importfolder.hsession,
			prequest->payload.importfolder.hctx,
			prequest->payload.importfolder.pproplist);
		break;
	case CALL_ID_IMPORTDELETION:
		presponse->result = zarafa_server_importdeletion(
			prequest->payload.importdeletion.hsession,
			prequest->payload.importdeletion.hctx,
			prequest->payload.importdeletion.flags,
			prequest->payload.importdeletion.pbins);
		break;
	case CALL_ID_IMPORTREADSTATES:
		presponse->result = zarafa_server_importreadstates(
			prequest->payload.importreadstates.hsession,
			prequest->payload.importreadstates.hctx,
			prequest->payload.importreadstates.pstates);
		break;
	case CALL_ID_GETSEARCHCRITERIA:
		presponse->result = zarafa_server_getsearchcriteria(
			prequest->payload.getsearchcriteria.hsession,
			prequest->payload.getsearchcriteria.hfolder,
			&presponse->payload.getsearchcriteria.folder_array,
			&presponse->payload.getsearchcriteria.prestriction,
			&presponse->payload.getsearchcriteria.search_stat);
		break;
	case CALL_ID_SETSEARCHCRITERIA:
		presponse->result = zarafa_server_setsearchcriteria(
			prequest->payload.setsearchcriteria.hsession,
			prequest->payload.setsearchcriteria.hfolder,
			prequest->payload.setsearchcriteria.flags,
			prequest->payload.setsearchcriteria.pfolder_array,
			prequest->payload.setsearchcriteria.prestriction);
		break;
	case CALL_ID_OPENFREEBUSYDATA:
		presponse->result = zarafa_server_openfreebusydata(
			prequest->payload.openfreebusydata.hsession,
			prequest->payload.openfreebusydata.hsupport,
			prequest->payload.openfreebusydata.pentryids,
			&presponse->payload.openfreebusydata.hobject_array);
		break;
	case CALL_ID_ENUMFREEBUSYBLOCKS:
		presponse->result = zarafa_server_enumfreebusyblocks(
			prequest->payload.enumfreebusyblocks.hsession,
			prequest->payload.enumfreebusyblocks.hfbdata,
			prequest->payload.enumfreebusyblocks.nttime_start,
			prequest->payload.enumfreebusyblocks.nttime_end,
			&presponse->payload.enumfreebusyblocks.hobject);
		break;
	case CALL_ID_FBENUMRESET:
		presponse->result = zarafa_server_fbenumreset(
			prequest->payload.fbenumreset.hsession,
			prequest->payload.fbenumreset.hfbenum);
		break;
	case CALL_ID_FBENUMSKIP:
		presponse->result = zarafa_server_fbenumskip(
			prequest->payload.fbenumskip.hsession,
			prequest->payload.fbenumskip.hfbenum,
			prequest->payload.fbenumskip.num);
		break;
	case CALL_ID_FBENUMRESTRICT:
		presponse->result = zarafa_server_fbenumrestrict(
			prequest->payload.fbenumrestrict.hsession,
			prequest->payload.fbenumrestrict.hfbenum,
			prequest->payload.fbenumrestrict.nttime_start,
			prequest->payload.fbenumrestrict.nttime_end);
		break;
	case CALL_ID_FBENUMEXPORT:
		presponse->result = zarafa_server_fbenumexport(
			prequest->payload.fbenumexport.hsession,
			prequest->payload.fbenumexport.hfbenum,
			prequest->payload.fbenumexport.count,
			prequest->payload.fbenumexport.nttime_start,
			prequest->payload.fbenumexport.nttime_end,
			prequest->payload.fbenumexport.organizer_name,
			prequest->payload.fbenumexport.username,
			prequest->payload.fbenumexport.uid_string,
			&presponse->payload.fbenumexport.bin_ical);
		break;
	case CALL_ID_FETCHFREEBUSYBLOCKS:
		presponse->result = zarafa_server_fetchfreebusyblocks(
			prequest->payload.fetchfreebusyblocks.hsession,
			prequest->payload.fetchfreebusyblocks.hfbenum,
			prequest->payload.fetchfreebusyblocks.celt,
			&presponse->payload.fetchfreebusyblocks.blocks);
		break;
	case CALL_ID_GETFREEBUSYRANGE:
		presponse->result = zarafa_server_getfreebusyrange(
			prequest->payload.getfreebusyrange.hsession,
			prequest->payload.getfreebusyrange.hfbdata,
			&presponse->payload.getfreebusyrange.nttime_start,
			&presponse->payload.getfreebusyrange.nttime_end);
		break;
	case CALL_ID_MESSAGETORFC822:
		presponse->result = zarafa_server_messagetorfc822(
			prequest->payload.messagetorfc822.hsession,
			prequest->payload.messagetorfc822.hmessage,
			&presponse->payload.messagetorfc822.eml_bin);
		break;
	case CALL_ID_RFC822TOMESSAGE:
		presponse->result = zarafa_server_rfc822tomessage(
			prequest->payload.rfc822tomessage.hsession,
			prequest->payload.rfc822tomessage.hmessage,
			prequest->payload.rfc822tomessage.peml_bin);
		break;
	case CALL_ID_MESSAGETOICAL:
		presponse->result = zarafa_server_messagetoical(
			prequest->payload.messagetoical.hsession,
			prequest->payload.messagetoical.hmessage,
			&presponse->payload.messagetoical.ical_bin);
		break;
	case CALL_ID_ICALTOMESSAGE:
		presponse->result = zarafa_server_icaltomessage(
			prequest->payload.icaltomessage.hsession,
			prequest->payload.icaltomessage.hmessage,
			prequest->payload.icaltomessage.pical_bin);
		break;
	case CALL_ID_MESSAGETOVCF:
		presponse->result = zarafa_server_messagetovcf(
			prequest->payload.messagetovcf.hsession,
			prequest->payload.messagetovcf.hmessage,
			&presponse->payload.messagetovcf.vcf_bin);
		break;
	case CALL_ID_VCFTOMESSAGE:
		presponse->result = zarafa_server_vcftomessage(
			prequest->payload.vcftomessage.hsession,
			prequest->payload.vcftomessage.hmessage,
			prequest->payload.vcftomessage.pvcf_bin);
		break;
	default:
		return DISPATCH_FALSE;
	}
	return DISPATCH_TRUE;
}

static void *thread_work_func(void *param)
{
	int clifd;
	void *pbuff;
	int tv_msec;
	int read_len;
	BINARY tmp_bin;
	uint32_t offset;
	uint8_t tmp_byte;
	uint32_t buff_len;
	RPC_REQUEST request;
	struct pollfd fdpoll;
	RPC_RESPONSE response;
	DOUBLE_LIST_NODE *pnode;


WAIT_CLIFD:
	pthread_mutex_lock(&g_cond_mutex);
	pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
	pthread_mutex_unlock(&g_cond_mutex);
NEXT_CLIFD:
	pthread_mutex_lock(&g_conn_lock);
	pnode = double_list_get_from_head(&g_conn_list);
	pthread_mutex_unlock(&g_conn_lock);

	if (NULL == pnode) {
		if (TRUE == g_notify_stop) {
			pthread_exit(0);
		}
		goto WAIT_CLIFD;
	}
	clifd = ((CLIENT_NODE*)pnode->pdata)->clifd;
	free(pnode->pdata);
	
	offset = 0;
	buff_len = 0;
	
	tv_msec = SOCKET_TIMEOUT * 1000;
	fdpoll.fd = clifd;
	fdpoll.events = POLLIN|POLLPRI;
	if (1 != poll(&fdpoll, 1, tv_msec)) {
		close(clifd);
		goto NEXT_CLIFD;
	}
	read_len = read(clifd, &buff_len, sizeof(uint32_t));
	if (read_len != sizeof(uint32_t)) {
		close(clifd);
		goto NEXT_CLIFD;
	}
	pbuff = malloc(buff_len);
	if (NULL == pbuff) {
		tmp_byte = RESPONSE_CODE_LACK_MEMORY;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	while (TRUE) {
		if (1 != poll(&fdpoll, 1, tv_msec)) {
			close(clifd);
			free(pbuff);
			goto NEXT_CLIFD;
		}
		read_len = read(clifd, pbuff + offset, buff_len - offset);
		if (read_len <= 0) {
			close(clifd);
			free(pbuff);
			goto NEXT_CLIFD;
		}
		offset += read_len;
		if (offset == buff_len) {
			break;
		}
	}
	common_util_build_environment();
	tmp_bin.pb = pbuff;
	tmp_bin.cb = buff_len;
	if (FALSE == rpc_ext_pull_request(&tmp_bin, &request)) {
		free(pbuff);
		common_util_free_environment();
		tmp_byte = RESPONSE_CODE_PULL_ERROR;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	free(pbuff);
	if (CALL_ID_NOTIFDEQUEUE == request.call_id) {
		common_util_set_clifd(clifd);
	}
	switch (rpc_parser_dispatch(&request, &response)) {
	case DISPATCH_FALSE:
		common_util_free_environment();
		tmp_byte = RESPONSE_CODE_DISPATCH_ERROR;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	case DISPATCH_CONTINUE:
		/* clifd will be maintained by zarafa_server */
		goto NEXT_CLIFD;
	}
	if (FALSE == rpc_ext_push_response(
		&response, &tmp_bin)) {
		common_util_free_environment();
		tmp_byte = RESPONSE_CODE_PUSH_ERROR;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	common_util_free_environment();
	offset = 0;
	fdpoll.events = POLLOUT|POLLWRBAND;
	if (1 == poll(&fdpoll, 1, tv_msec)) {
		write(clifd, tmp_bin.pb, tmp_bin.cb);
	}
	shutdown(clifd, SHUT_WR);
	read(clifd, &tmp_byte, 1);
	close(clifd);
	free(tmp_bin.pb);
	goto NEXT_CLIFD;
}

int rpc_parser_run()
{
	int i;
	
	g_thread_ids = malloc(sizeof(pthread_t)*g_thread_num);
	if (NULL == g_thread_ids) {
		return -1;
	}
	g_notify_stop = FALSE;
	for (i=0; i<g_thread_num; i++) {
		if (0 != pthread_create(&g_thread_ids[i],
			NULL, thread_work_func, NULL)) {
			break;
		}
	}
	if (i < g_thread_num) {
		g_notify_stop = TRUE;
		for (i=0; i<g_thread_num; i++) {
			pthread_cancel(g_thread_ids[i]);
		}
		free(g_thread_ids);
		printf("[rpc_parser]: fail to creat pool thread\n");
		return -2;
	}
	return 0;
}

int rpc_parser_stop()
{
	int i;
	
	g_notify_stop = TRUE;
	pthread_cond_broadcast(&g_waken_cond);
	for (i=0; i<g_thread_num; i++) {
		pthread_join(g_thread_ids[i], NULL);
	}
	free(g_thread_ids);
	return 0;
}
