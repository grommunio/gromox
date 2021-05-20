// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <gromox/defs.h>
#include <gromox/zcore_rpc.hpp>
#include <gromox/idset.hpp>
#include "rpc_ext.h"
#include "rpc_parser.h"
#include "common_util.h"
#include "zarafa_server.h"
#include <gromox/mapi_types.hpp>
#include <sys/socket.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <poll.h>

using RPC_REQUEST = ZCORE_RPC_REQUEST;
using RPC_RESPONSE = ZCORE_RPC_RESPONSE;

enum {
	DISPATCH_TRUE,
	DISPATCH_FALSE,
	DISPATCH_CONTINUE
};

namespace {
struct CLIENT_NODE {
	DOUBLE_LIST_NODE node;
	int clifd;
};
}

static int g_thread_num;
static std::atomic<bool> g_notify_stop{false};
static pthread_t *g_thread_ids;
static DOUBLE_LIST g_conn_list;
static std::condition_variable g_waken_cond;
static std::mutex g_conn_lock, g_cond_mutex;
unsigned int g_zrpc_debug;

void rpc_parser_init(int thread_num)
{
	g_notify_stop = true;
	g_thread_num = thread_num;
}

BOOL rpc_parser_activate_connection(int clifd)
{
	auto pclient = me_alloc<CLIENT_NODE>();
	if (NULL == pclient) {
		return FALSE;
	}
	pclient->node.pdata = pclient;
	pclient->clifd = clifd;
	std::unique_lock cl_hold(g_conn_lock);
	double_list_append_as_tail(&g_conn_list, &pclient->node);
	cl_hold.unlock();
	g_waken_cond.notify_one();
	return TRUE;
}

static int rpc_parser_dispatch(const RPC_REQUEST *prequest,
	RPC_RESPONSE *presponse)
{
	presponse->call_id = prequest->call_id;
	switch (prequest->call_id) {
	case zcore_callid::LOGON:
		presponse->result = zarafa_server_logon(
			prequest->payload.logon.username,
			prequest->payload.logon.password,
			prequest->payload.logon.flags,
			&presponse->payload.logon.hsession);
		break;
	case zcore_callid::CHECKSESSION:
		presponse->result = zarafa_server_checksession(
			prequest->payload.checksession.hsession);
		break;
	case zcore_callid::UINFO:
		presponse->result = zarafa_server_uinfo(
			prequest->payload.uinfo.username,
			&presponse->payload.uinfo.entryid,
			&presponse->payload.uinfo.pdisplay_name,
			&presponse->payload.uinfo.px500dn,
			&presponse->payload.uinfo.privilege_bits);
		break;
	case zcore_callid::UNLOADOBJECT:
		presponse->result = zarafa_server_unloadobject(
			prequest->payload.unloadobject.hsession,
			prequest->payload.unloadobject.hobject);
		break;
	case zcore_callid::OPENENTRY:
		presponse->result = zarafa_server_openentry(
			prequest->payload.openentry.hsession,
			prequest->payload.openentry.entryid,
			prequest->payload.openentry.flags,
			&presponse->payload.openentry.mapi_type,
			&presponse->payload.openentry.hobject);
		break;
	case zcore_callid::OPENSTOREENTRY:
		presponse->result = zarafa_server_openstoreentry(
			prequest->payload.openstoreentry.hsession,
			prequest->payload.openstoreentry.hobject,
			prequest->payload.openstoreentry.entryid,
			prequest->payload.openstoreentry.flags,
			&presponse->payload.openstoreentry.mapi_type,
			&presponse->payload.openstoreentry.hxobject);
		break;
	case zcore_callid::OPENABENTRY:
		presponse->result = zarafa_server_openabentry(
			prequest->payload.openabentry.hsession,
			prequest->payload.openabentry.entryid,
			&presponse->payload.openabentry.mapi_type,
			&presponse->payload.openabentry.hobject);
		break;
	case zcore_callid::RESOLVENAME:
		presponse->result = zarafa_server_resolvename(
			prequest->payload.resolvename.hsession,
			prequest->payload.resolvename.pcond_set,
			&presponse->payload.resolvename.result_set);
		break;
	case zcore_callid::GETPERMISSIONS:
		presponse->result = zarafa_server_getpermissions(
			prequest->payload.getpermissions.hsession,
			prequest->payload.getpermissions.hobject,
			&presponse->payload.getpermissions.perm_set);
		break;
	case zcore_callid::MODIFYPERMISSIONS:
		presponse->result = zarafa_server_modifypermissions(
			prequest->payload.modifypermissions.hsession,
			prequest->payload.modifypermissions.hfolder,
			prequest->payload.modifypermissions.pset);
		break;
	case zcore_callid::MODIFYRULES:
		presponse->result = zarafa_server_modifyrules(
			prequest->payload.modifyrules.hsession,
			prequest->payload.modifyrules.hfolder,
			prequest->payload.modifyrules.flags,
			prequest->payload.modifyrules.plist);
		break;
	case zcore_callid::GETABGAL:
		presponse->result = zarafa_server_getabgal(
			prequest->payload.getabgal.hsession,
			&presponse->payload.getabgal.entryid);
		break;
	case zcore_callid::LOADSTORETABLE:
		presponse->result = zarafa_server_loadstoretable(
			prequest->payload.loadstoretable.hsession,
			&presponse->payload.loadstoretable.hobject);
		break;
	case zcore_callid::OPENSTORE:
		presponse->result = zarafa_server_openstore(
			prequest->payload.openstore.hsession,
			prequest->payload.openstore.entryid,
			&presponse->payload.openstore.hobject);
		break;
	case zcore_callid::OPENPROPFILESEC:
		presponse->result = zarafa_server_openpropfilesec(
			prequest->payload.openpropfilesec.hsession,
			prequest->payload.openpropfilesec.puid,
			&presponse->payload.openpropfilesec.hobject);
		break;
	case zcore_callid::LOADHIERARCHYTABLE:
		presponse->result = zarafa_server_loadhierarchytable(
			prequest->payload.loadhierarchytable.hsession,
			prequest->payload.loadhierarchytable.hfolder,
			prequest->payload.loadhierarchytable.flags,
			&presponse->payload.loadhierarchytable.hobject);
		break;
	case zcore_callid::LOADCONTENTTABLE:
		presponse->result = zarafa_server_loadcontenttable(
			prequest->payload.loadcontenttable.hsession,
			prequest->payload.loadcontenttable.hfolder,
			prequest->payload.loadcontenttable.flags,
			&presponse->payload.loadcontenttable.hobject);
		break;
	case zcore_callid::LOADRECIPIENTTABLE:
		presponse->result = zarafa_server_loadrecipienttable(
			prequest->payload.loadrecipienttable.hsession,
			prequest->payload.loadrecipienttable.hmessage,
			&presponse->payload.loadrecipienttable.hobject);
		break;
	case zcore_callid::LOADRULETABLE:
		presponse->result = zarafa_server_loadruletable(
			prequest->payload.loadruletable.hsession,
			prequest->payload.loadruletable.hfolder,
			&presponse->payload.loadruletable.hobject);
		break;
	case zcore_callid::CREATEMESSAGE:
		presponse->result = zarafa_server_createmessage(
			prequest->payload.createmessage.hsession,
			prequest->payload.createmessage.hfolder,
			prequest->payload.createmessage.flags,
			&presponse->payload.createmessage.hobject);
		break;
	case zcore_callid::DELETEMESSAGES:
		presponse->result = zarafa_server_deletemessages(
			prequest->payload.deletemessages.hsession,
			prequest->payload.deletemessages.hfolder,
			prequest->payload.deletemessages.pentryids,
			prequest->payload.deletemessages.flags);
		break;
	case zcore_callid::COPYMESSAGES:
		presponse->result = zarafa_server_copymessages(
			prequest->payload.copymessages.hsession,
			prequest->payload.copymessages.hsrcfolder,
			prequest->payload.copymessages.hdstfolder,
			prequest->payload.copymessages.pentryids,
			prequest->payload.copymessages.flags);
		break;
	case zcore_callid::SETREADFLAGS:
		presponse->result = zarafa_server_setreadflags(
			prequest->payload.setreadflags.hsession,
			prequest->payload.setreadflags.hfolder,
			prequest->payload.setreadflags.pentryids,
			prequest->payload.setreadflags.flags);
		break;
	case zcore_callid::CREATEFOLDER:
		presponse->result = zarafa_server_createfolder(
			prequest->payload.createfolder.hsession,
			prequest->payload.createfolder.hparent_folder,
			prequest->payload.createfolder.folder_type,
			prequest->payload.createfolder.folder_name,
			prequest->payload.createfolder.folder_comment,
			prequest->payload.createfolder.flags,
			&presponse->payload.createfolder.hobject);
		break;
	case zcore_callid::DELETEFOLDER:
		presponse->result = zarafa_server_deletefolder(
			prequest->payload.deletefolder.hsession,
			prequest->payload.deletefolder.hparent_folder,
			prequest->payload.deletefolder.entryid,
			prequest->payload.deletefolder.flags);
		break;
	case zcore_callid::EMPTYFOLDER:
		presponse->result = zarafa_server_emptyfolder(
			prequest->payload.emptyfolder.hsession,
			prequest->payload.emptyfolder.hfolder,
			prequest->payload.emptyfolder.flags);
		break;
	case zcore_callid::COPYFOLDER:
		presponse->result = zarafa_server_copyfolder(
			prequest->payload.copyfolder.hsession,
			prequest->payload.copyfolder.hsrc_folder,
			prequest->payload.copyfolder.entryid,
			prequest->payload.copyfolder.hdst_folder,
			prequest->payload.copyfolder.new_name,
			prequest->payload.copyfolder.flags);
		break;
	case zcore_callid::GETSTOREENTRYID:
		presponse->result = zarafa_server_getstoreentryid(
			prequest->payload.getstoreentryid.mailbox_dn,
			&presponse->payload.getstoreentryid.entryid);
		break;
	case zcore_callid::ENTRYIDFROMSOURCEKEY:
		presponse->result = zarafa_server_entryidfromsourcekey(
			prequest->payload.entryidfromsourcekey.hsession,
			prequest->payload.entryidfromsourcekey.hstore,
			prequest->payload.entryidfromsourcekey.folder_key,
			prequest->payload.entryidfromsourcekey.pmessage_key,
			&presponse->payload.entryidfromsourcekey.entryid);
		break;
	case zcore_callid::STOREADVISE:
		presponse->result = zarafa_server_storeadvise(
			prequest->payload.storeadvise.hsession,
			prequest->payload.storeadvise.hstore,
			prequest->payload.storeadvise.pentryid,
			prequest->payload.storeadvise.event_mask,
			&presponse->payload.storeadvise.sub_id);
		break;
	case zcore_callid::UNADVISE:
		presponse->result = zarafa_server_unadvise(
			prequest->payload.unadvise.hsession,
			prequest->payload.unadvise.hstore,
			prequest->payload.unadvise.sub_id);
		break;
	case zcore_callid::NOTIFDEQUEUE:
		presponse->result = zarafa_server_notifdequeue(
			prequest->payload.notifdequeue.psink,
			prequest->payload.notifdequeue.timeval,
			&presponse->payload.notifdequeue.notifications);
		if (presponse->result == ecNotFound)
			return DISPATCH_CONTINUE;
		break;
	case zcore_callid::QUERYROWS:
		presponse->result = zarafa_server_queryrows(
			prequest->payload.queryrows.hsession,
			prequest->payload.queryrows.htable,
			prequest->payload.queryrows.start,
			prequest->payload.queryrows.count,
			prequest->payload.queryrows.prestriction,
			prequest->payload.queryrows.pproptags,
			&presponse->payload.queryrows.rowset);
		break;
	case zcore_callid::SETCOLUMNS:
		presponse->result = zarafa_server_setcolumns(
			prequest->payload.setcolumns.hsession,
			prequest->payload.setcolumns.htable,
			prequest->payload.setcolumns.pproptags,
			prequest->payload.setcolumns.flags);
		break;
	case zcore_callid::SEEKROW:
		presponse->result = zarafa_server_seekrow(
			prequest->payload.seekrow.hsession,
			prequest->payload.seekrow.htable,
			prequest->payload.seekrow.bookmark,
			prequest->payload.seekrow.seek_rows,
			&presponse->payload.seekrow.sought_rows);
		break;
	case zcore_callid::SORTTABLE:
		presponse->result = zarafa_server_sorttable(
			prequest->payload.sorttable.hsession,
			prequest->payload.sorttable.htable,
			prequest->payload.sorttable.psortset);
		break;
	case zcore_callid::GETROWCOUNT:
		presponse->result = zarafa_server_getrowcount(
			prequest->payload.getrowcount.hsession,
			prequest->payload.getrowcount.htable,
			&presponse->payload.getrowcount.count);
		break;
	case zcore_callid::RESTRICTTABLE:
		presponse->result = zarafa_server_restricttable(
			prequest->payload.restricttable.hsession,
			prequest->payload.restricttable.htable,
			prequest->payload.restricttable.prestriction,
			prequest->payload.restricttable.flags);
		break;
	case zcore_callid::FINDROW:
		presponse->result = zarafa_server_findrow(
			prequest->payload.findrow.hsession,
			prequest->payload.findrow.htable,
			prequest->payload.findrow.bookmark,
			prequest->payload.findrow.prestriction,
			prequest->payload.findrow.flags,
			&presponse->payload.findrow.row_idx);
		break;
	case zcore_callid::CREATEBOOKMARK:
		presponse->result = zarafa_server_createbookmark(
			prequest->payload.createbookmark.hsession,
			prequest->payload.createbookmark.htable,
			&presponse->payload.createbookmark.bookmark);
		break;
	case zcore_callid::FREEBOOKMARK:
		presponse->result = zarafa_server_freebookmark(
			prequest->payload.freebookmark.hsession,
			prequest->payload.freebookmark.htable,
			prequest->payload.freebookmark.bookmark);
		break;
	case zcore_callid::GETRECEIVEFOLDER:
		presponse->result = zarafa_server_getreceivefolder(
			prequest->payload.getreceivefolder.hsession,
			prequest->payload.getreceivefolder.hstore,
			prequest->payload.getreceivefolder.pstrclass,
			&presponse->payload.getreceivefolder.entryid);
		break;
	case zcore_callid::MODIFYRECIPIENTS:
		presponse->result = zarafa_server_modifyrecipients(
			prequest->payload.modifyrecipients.hsession,
			prequest->payload.modifyrecipients.hmessage,
			prequest->payload.modifyrecipients.flags,
			prequest->payload.modifyrecipients.prcpt_list);
		break;
	case zcore_callid::SUBMITMESSAGE:
		presponse->result = zarafa_server_submitmessage(
			prequest->payload.submitmessage.hsession,
			prequest->payload.submitmessage.hmessage);
		break;
	case zcore_callid::LOADATTACHMENTTABLE:
		presponse->result = zarafa_server_loadattachmenttable(
			prequest->payload.loadattachmenttable.hsession,
			prequest->payload.loadattachmenttable.hmessage,
			&presponse->payload.loadattachmenttable.hobject);
		break;
	case zcore_callid::OPENATTACHMENT:
		presponse->result = zarafa_server_openattachment(
			prequest->payload.openattachment.hsession,
			prequest->payload.openattachment.hmessage,
			prequest->payload.openattachment.attach_id,
			&presponse->payload.openattachment.hobject);
		break;
	case zcore_callid::CREATEATTACHMENT:
		presponse->result = zarafa_server_createattachment(
			prequest->payload.createattachment.hsession,
			prequest->payload.createattachment.hmessage,
			&presponse->payload.createattachment.hobject);
		break;
	case zcore_callid::DELETEATTACHMENT:
		presponse->result = zarafa_server_deleteattachment(
			prequest->payload.deleteattachment.hsession,
			prequest->payload.deleteattachment.hmessage,
			prequest->payload.deleteattachment.attach_id);
		break;
	case zcore_callid::SETPROPVALS:
		presponse->result = zarafa_server_setpropvals(
			prequest->payload.setpropvals.hsession,
			prequest->payload.setpropvals.hobject,
			prequest->payload.setpropvals.ppropvals);
		break;
	case zcore_callid::GETPROPVALS:
		presponse->result = zarafa_server_getpropvals(
			prequest->payload.getpropvals.hsession,
			prequest->payload.getpropvals.hobject,
			prequest->payload.getpropvals.pproptags,
			&presponse->payload.getpropvals.propvals);
		break;
	case zcore_callid::DELETEPROPVALS:
		presponse->result = zarafa_server_deletepropvals(
			prequest->payload.deletepropvals.hsession,
			prequest->payload.deletepropvals.hobject,
			prequest->payload.deletepropvals.pproptags);
		break;
	case zcore_callid::SETMESSAGEREADFLAG:
		presponse->result = zarafa_server_setmessagereadflag(
			prequest->payload.setmessagereadflag.hsession,
			prequest->payload.setmessagereadflag.hmessage,
			prequest->payload.setmessagereadflag.flags);
		break;
	case zcore_callid::OPENEMBEDDED:
		presponse->result = zarafa_server_openembedded(
			prequest->payload.openembedded.hsession,
			prequest->payload.openembedded.hattachment,
			prequest->payload.openembedded.flags,
			&presponse->payload.openembedded.hobject);
		break;
	case zcore_callid::GETNAMEDPROPIDS:
		presponse->result = zarafa_server_getnamedpropids(
			prequest->payload.getnamedpropids.hsession,
			prequest->payload.getnamedpropids.hstore,
			prequest->payload.getnamedpropids.ppropnames,
			&presponse->payload.getnamedpropids.propids);
		break;
	case zcore_callid::GETPROPNAMES:
		presponse->result = zarafa_server_getpropnames(
			prequest->payload.getpropnames.hsession,
			prequest->payload.getpropnames.hstore,
			prequest->payload.getpropnames.ppropids,
			&presponse->payload.getpropnames.propnames);
		break;
	case zcore_callid::COPYTO:
		presponse->result = zarafa_server_copyto(
			prequest->payload.copyto.hsession,
			prequest->payload.copyto.hsrcobject,
			prequest->payload.copyto.pexclude_proptags,
			prequest->payload.copyto.hdstobject,
			prequest->payload.copyto.flags);
		break;
	case zcore_callid::SAVECHANGES:
		presponse->result = zarafa_server_savechanges(
			prequest->payload.savechanges.hsession,
			prequest->payload.savechanges.hobject);
		break;
	case zcore_callid::HIERARCHYSYNC:
		presponse->result = zarafa_server_hierarchysync(
			prequest->payload.hierarchysync.hsession,
			prequest->payload.hierarchysync.hfolder,
			&presponse->payload.hierarchysync.hobject);
		break;
	case zcore_callid::CONTENTSYNC:
		presponse->result = zarafa_server_contentsync(
			prequest->payload.contentsync.hsession,
			prequest->payload.contentsync.hfolder,
			&presponse->payload.contentsync.hobject);
		break;
	case zcore_callid::CONFIGSYNC:
		presponse->result = zarafa_server_configsync(
			prequest->payload.configsync.hsession,
			prequest->payload.configsync.hctx,
			prequest->payload.configsync.flags,
			prequest->payload.configsync.pstate,
			prequest->payload.configsync.prestriction,
			&presponse->payload.configsync.b_changed,
			&presponse->payload.configsync.count);
		break;
	case zcore_callid::STATESYNC:
		presponse->result = zarafa_server_statesync(
			prequest->payload.statesync.hsession,
			prequest->payload.statesync.hctx,
			&presponse->payload.statesync.state);
		break;
	case zcore_callid::SYNCMESSAGECHANGE:
		presponse->result = zarafa_server_syncmessagechange(
			prequest->payload.syncmessagechange.hsession,
			prequest->payload.syncmessagechange.hctx,
			&presponse->payload.syncmessagechange.b_new,
			&presponse->payload.syncmessagechange.proplist);
		break;
	case zcore_callid::SYNCFOLDERCHANGE:
		presponse->result = zarafa_server_syncfolderchange(
			prequest->payload.syncfolderchange.hsession,
			prequest->payload.syncfolderchange.hctx,
			&presponse->payload.syncfolderchange.proplist);
		break;
	case zcore_callid::SYNCREADSTATECHANGES:
		presponse->result = zarafa_server_syncreadstatechanges(
			prequest->payload.syncreadstatechanges.hsession,
			prequest->payload.syncreadstatechanges.hctx,
			&presponse->payload.syncreadstatechanges.states);
		break;
	case zcore_callid::SYNCDELETIONS:
		presponse->result = zarafa_server_syncdeletions(
			prequest->payload.syncdeletions.hsession,
			prequest->payload.syncdeletions.hctx,
			prequest->payload.syncdeletions.flags,
			&presponse->payload.syncdeletions.bins);
		break;
	case zcore_callid::HIERARCHYIMPORT:
		presponse->result = zarafa_server_hierarchyimport(
			prequest->payload.hierarchyimport.hsession,
			prequest->payload.hierarchyimport.hfolder,
			&presponse->payload.hierarchyimport.hobject);
		break;
	case zcore_callid::CONTENTIMPORT:
		presponse->result = zarafa_server_contentimport(
			prequest->payload.contentimport.hsession,
			prequest->payload.contentimport.hfolder,
			&presponse->payload.contentimport.hobject);
		break;
	case zcore_callid::CONFIGIMPORT:
		presponse->result = zarafa_server_configimport(
			prequest->payload.configimport.hsession,
			prequest->payload.configimport.hctx,
			prequest->payload.configimport.sync_type,
			prequest->payload.configimport.pstate);
		break;
	case zcore_callid::STATEIMPORT:
		presponse->result = zarafa_server_stateimport(
			prequest->payload.stateimport.hsession,
			prequest->payload.stateimport.hctx,
			&presponse->payload.stateimport.state);
		break;
	case zcore_callid::IMPORTMESSAGE:
		presponse->result = zarafa_server_importmessage(
			prequest->payload.importmessage.hsession,
			prequest->payload.importmessage.hctx,
			prequest->payload.importmessage.flags,
			prequest->payload.importmessage.pproplist,
			&presponse->payload.importmessage.hobject);
		break;
	case zcore_callid::IMPORTFOLDER:
		presponse->result = zarafa_server_importfolder(
			prequest->payload.importfolder.hsession,
			prequest->payload.importfolder.hctx,
			prequest->payload.importfolder.pproplist);
		break;
	case zcore_callid::IMPORTDELETION:
		presponse->result = zarafa_server_importdeletion(
			prequest->payload.importdeletion.hsession,
			prequest->payload.importdeletion.hctx,
			prequest->payload.importdeletion.flags,
			prequest->payload.importdeletion.pbins);
		break;
	case zcore_callid::IMPORTREADSTATES:
		presponse->result = zarafa_server_importreadstates(
			prequest->payload.importreadstates.hsession,
			prequest->payload.importreadstates.hctx,
			prequest->payload.importreadstates.pstates);
		break;
	case zcore_callid::GETSEARCHCRITERIA:
		presponse->result = zarafa_server_getsearchcriteria(
			prequest->payload.getsearchcriteria.hsession,
			prequest->payload.getsearchcriteria.hfolder,
			&presponse->payload.getsearchcriteria.folder_array,
			&presponse->payload.getsearchcriteria.prestriction,
			&presponse->payload.getsearchcriteria.search_stat);
		break;
	case zcore_callid::SETSEARCHCRITERIA:
		presponse->result = zarafa_server_setsearchcriteria(
			prequest->payload.setsearchcriteria.hsession,
			prequest->payload.setsearchcriteria.hfolder,
			prequest->payload.setsearchcriteria.flags,
			prequest->payload.setsearchcriteria.pfolder_array,
			prequest->payload.setsearchcriteria.prestriction);
		break;
	case zcore_callid::MESSAGETORFC822:
		presponse->result = zarafa_server_messagetorfc822(
			prequest->payload.messagetorfc822.hsession,
			prequest->payload.messagetorfc822.hmessage,
			&presponse->payload.messagetorfc822.eml_bin);
		break;
	case zcore_callid::RFC822TOMESSAGE:
		presponse->result = zarafa_server_rfc822tomessage(
			prequest->payload.rfc822tomessage.hsession,
			prequest->payload.rfc822tomessage.hmessage,
			prequest->payload.rfc822tomessage.peml_bin);
		break;
	case zcore_callid::MESSAGETOICAL:
		presponse->result = zarafa_server_messagetoical(
			prequest->payload.messagetoical.hsession,
			prequest->payload.messagetoical.hmessage,
			&presponse->payload.messagetoical.ical_bin);
		break;
	case zcore_callid::ICALTOMESSAGE:
		presponse->result = zarafa_server_icaltomessage(
			prequest->payload.icaltomessage.hsession,
			prequest->payload.icaltomessage.hmessage,
			prequest->payload.icaltomessage.pical_bin);
		break;
	case zcore_callid::MESSAGETOVCF:
		presponse->result = zarafa_server_messagetovcf(
			prequest->payload.messagetovcf.hsession,
			prequest->payload.messagetovcf.hmessage,
			&presponse->payload.messagetovcf.vcf_bin);
		break;
	case zcore_callid::VCFTOMESSAGE:
		presponse->result = zarafa_server_vcftomessage(
			prequest->payload.vcftomessage.hsession,
			prequest->payload.vcftomessage.hmessage,
			prequest->payload.vcftomessage.pvcf_bin);
		break;
	case zcore_callid::GETUSERAVAILABILITY:
		presponse->result = zarafa_server_getuseravailability(
			prequest->payload.getuseravailability.hsession,
			prequest->payload.getuseravailability.entryid,
			prequest->payload.getuseravailability.starttime,
			prequest->payload.getuseravailability.endtime,
			&presponse->payload.getuseravailability.result_string);
		break;
	case zcore_callid::SETPASSWD:
		presponse->result = zarafa_server_setpasswd(
			prequest->payload.setpasswd.username,
			prequest->payload.setpasswd.passwd,
			prequest->payload.setpasswd.new_passwd);
		break;
	case zcore_callid::LINKMESSAGE:
		presponse->result = zarafa_server_linkmessage(
			prequest->payload.linkmessage.hsession,
			prequest->payload.linkmessage.search_entryid,
			prequest->payload.linkmessage.message_entryid);
		break;
	default:
		return DISPATCH_FALSE;
	}
	if (g_zrpc_debug == 0)
		return DISPATCH_TRUE;
	if (presponse->result != 0 || g_zrpc_debug == 2)
		fprintf(stderr, "ZRPC %s %xh\n", zcore_rpc_idtoname(prequest->call_id),
		        presponse->result);
	return DISPATCH_TRUE;
}

static void *zcrp_thrwork(void *param)
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
	std::unique_lock cm_hold(g_cond_mutex);
	g_waken_cond.wait(cm_hold);
	cm_hold.unlock();
 NEXT_CLIFD:
	std::unique_lock cl_hold(g_conn_lock);
	pnode = double_list_pop_front(&g_conn_list);
	cl_hold.unlock();
	if (NULL == pnode) {
		if (g_notify_stop)
			return nullptr;
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
		tmp_byte = zcore_response::LACK_MEMORY;
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
		read_len = read(clifd, static_cast<char *>(pbuff) + offset, buff_len - offset);
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
	tmp_bin.pv = pbuff;
	tmp_bin.cb = buff_len;
	if (FALSE == rpc_ext_pull_request(&tmp_bin, &request)) {
		free(pbuff);
		common_util_free_environment();
		tmp_byte = zcore_response::PULL_ERROR;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	free(pbuff);
	if (zcore_callid::NOTIFDEQUEUE == request.call_id) {
		common_util_set_clifd(clifd);
	}
	switch (rpc_parser_dispatch(&request, &response)) {
	case DISPATCH_FALSE:
		common_util_free_environment();
		tmp_byte = zcore_response::DISPATCH_ERROR;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	case DISPATCH_CONTINUE:
		common_util_free_environment();
		/* clifd will be maintained by zarafa_server */
		goto NEXT_CLIFD;
	}
	if (FALSE == rpc_ext_push_response(
		&response, &tmp_bin)) {
		common_util_free_environment();
		tmp_byte = zcore_response::PUSH_ERROR;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	common_util_free_environment();
	fdpoll.events = POLLOUT|POLLWRBAND;
	if (1 == poll(&fdpoll, 1, tv_msec)) {
		write(clifd, tmp_bin.pb, tmp_bin.cb);
	}
	shutdown(clifd, SHUT_WR);
	if (read(clifd, &tmp_byte, 1))
		/* ignore */;
	close(clifd);
	free(tmp_bin.pb);
	goto NEXT_CLIFD;
}

int rpc_parser_run()
{
	int i;
	
	g_thread_ids = me_alloc<pthread_t>(g_thread_num);
	if (NULL == g_thread_ids) {
		return -1;
	}
	g_notify_stop = false;
	int ret = 0;
	for (i=0; i<g_thread_num; i++) {
		ret = pthread_create(&g_thread_ids[i], nullptr, zcrp_thrwork, nullptr);
		if (ret != 0)
			break;
		char buf[32];
		snprintf(buf, sizeof(buf), "rpc/%u", i);
		pthread_setname_np(g_thread_ids[i], buf);
	}
	if (i < g_thread_num) {
		g_notify_stop = true;
		for (i=0; i<g_thread_num; i++) {
			pthread_cancel(g_thread_ids[i]);
		}
		free(g_thread_ids);
		printf("[rpc_parser]: failed to create pool thread: %s\n", strerror(ret));
		return -2;
	}
	return 0;
}

int rpc_parser_stop()
{
	int i;
	
	g_notify_stop = true;
	g_waken_cond.notify_all();
	for (i=0; i<g_thread_num; i++) {
		pthread_join(g_thread_ids[i], NULL);
	}
	free(g_thread_ids);
	return 0;
}
