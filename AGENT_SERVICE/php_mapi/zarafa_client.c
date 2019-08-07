#include "zarafa_client.h"
#include "rpc_ext.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#define RESPONSE_CODE_SUCCESS      			0x00

#define CS_PATH								"/var/medusa/token/zarafa"

static int zarafa_client_connect()
{
	int sockd, len;
	struct sockaddr_un un;
	
	sockd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockd < 0) {
		return -1;
	}
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, CS_PATH);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	if (connect(sockd, (struct sockaddr*)&un, len) < 0) {
		close(sockd);
		return -2;
	}
	return sockd;
}

static zend_bool zarafa_client_read_socket(int sockd, BINARY *pbin)
{
	int read_len;
	uint32_t offset;
	uint8_t resp_buff[5];
	
	pbin->pb = NULL;
	while (1) {
		if (NULL == pbin->pb) {
			read_len = read(sockd, resp_buff, 5);
			if (1 == read_len) {
				pbin->cb = 1;
				pbin->pb = emalloc(1);
				if (NULL == pbin->pb) {
					return 0;
				}
				*(uint8_t*)pbin->pb = resp_buff[0];
				return 1;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				pbin->pb = emalloc(pbin->cb);
				if (NULL == pbin->pb) {
					return 0;
				}
				memcpy(pbin->pb, resp_buff, 5);
				offset = 5;
				if (offset == pbin->cb) {
					return 1;
				}
				continue;
			} else {
				return 0;
			}
		}
		read_len = read(sockd, pbin->pb + offset, pbin->cb - offset);
		if (read_len <= 0) {
			return 0;
		}
		offset += read_len;
		if (offset == pbin->cb) {
			return 1;
		}
	}
}

static zend_bool zarafa_client_write_socket(int sockd, const BINARY *pbin)
{
	int written_len;
	uint32_t offset;
	
	offset = 0;
	while (1) {
		written_len = write(sockd, pbin->pb + offset, pbin->cb - offset);
		if (written_len <= 0) {
			return 0;
		}
		offset += written_len;
		if (offset == pbin->cb) {
			return 1;
		}
	}
}

static zend_bool zarafa_client_do_rpc(
	const RPC_REQUEST *prequest,
	RPC_RESPONSE *presponse)
{
	int sockd;
	BINARY tmp_bin;
	
	if (!rpc_ext_push_request(prequest, &tmp_bin)) {
		return 0;
	}
	sockd = zarafa_client_connect();
	if (sockd < 0) {
		efree(tmp_bin.pb);
		return 0;
	}
	if (!zarafa_client_write_socket(sockd, &tmp_bin)) {
		efree(tmp_bin.pb);
		close(sockd);
		return 0;
	}
	efree(tmp_bin.pb);
	if (!zarafa_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return 0;
	}
	close(sockd);
	if (tmp_bin.cb < 5 || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		if (NULL != tmp_bin.pb) {
			efree(tmp_bin.pb);
		}
		return 0;
	}
	presponse->call_id = prequest->call_id;
	tmp_bin.cb -= 5;
	tmp_bin.pb += 5;
	if (!rpc_ext_pull_response(&tmp_bin, presponse)) {
		efree(tmp_bin.pb - 5);
		return 0;
	}
	efree(tmp_bin.pb - 5);
	return 1;
}

uint32_t zarafa_client_logon(const char *username,
	const char *password, uint32_t flags, GUID *phsession)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_LOGON;
	request.payload.logon.username = (void*)username;
	request.payload.logon.password = (void*)password;
	request.payload.logon.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phsession = response.payload.logon.hsession;
	}
	return response.result;
}

uint32_t zarafa_client_checksession(GUID hsession)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CHECKSESSION;
	request.payload.checksession.hsession = hsession;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_uinfo(const char *username,
	BINARY *pentryid, char **ppdisplay_name, char **ppx500dn)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_UINFO;
	request.payload.uinfo.username = (void*)username;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pentryid = response.payload.uinfo.entryid;
		*ppdisplay_name = response.payload.uinfo.pdisplay_name;
		*ppx500dn = response.payload.uinfo.px500dn;
	}
	return response.result;
}

uint32_t zarafa_client_unloadobject(GUID hsession, uint32_t hobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_UNLOADOBJECT;
	request.payload.unloadobject.hsession = hsession;
	request.payload.unloadobject.hobject = hobject;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_openentry(GUID hsession, BINARY entryid,
	uint32_t flags, uint8_t *pmapi_type, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENENTRY;
	request.payload.openentry.hsession = hsession;
	request.payload.openentry.entryid = entryid;
	request.payload.openentry.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pmapi_type = response.payload.openentry.mapi_type;
		*phobject = response.payload.openentry.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_openstoreentry(GUID hsession, uint32_t hobject,
	BINARY entryid, uint32_t flags, uint8_t *pmapi_type, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENSTOREENTRY;
	request.payload.openstoreentry.hsession = hsession;
	request.payload.openstoreentry.hobject = hobject;
	request.payload.openstoreentry.entryid = entryid;
	request.payload.openstoreentry.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pmapi_type = response.payload.openstoreentry.mapi_type;
		*phobject = response.payload.openstoreentry.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_openabentry(GUID hsession,
	BINARY entryid, uint8_t *pmapi_type, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENABENTRY;
	request.payload.openabentry.hsession = hsession;
	request.payload.openabentry.entryid = entryid;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pmapi_type = response.payload.openabentry.mapi_type;
		*phobject = response.payload.openabentry.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_resolvename(GUID hsession,
	const TARRAY_SET *pcond_set, TARRAY_SET *presult_set)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_RESOLVENAME;
	request.payload.resolvename.hsession = hsession;
	request.payload.resolvename.pcond_set = (void*)pcond_set;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*presult_set = response.payload.resolvename.result_set;
	}
	return response.result;
}

uint32_t zarafa_client_openrules(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENRULES;
	request.payload.openrules.hsession = hsession;
	request.payload.openrules.hfolder = hfolder;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.openrules.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_getpermissions(GUID hsession,
	uint32_t hobject, PERMISSION_SET *pperm_set)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETPERMISSIONS;
	request.payload.getpermissions.hsession = hsession;
	request.payload.getpermissions.hobject = hobject;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pperm_set = response.payload.getpermissions.perm_set;
	}
	return response.result;
}

uint32_t zarafa_client_modifypermissions(GUID hsession,
	uint32_t hfolder, const PERMISSION_SET *pset)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_MODIFYPERMISSIONS;
	request.payload.modifypermissions.hsession = hsession;
	request.payload.modifypermissions.hfolder = hfolder;
	request.payload.modifypermissions.pset = (void*)pset;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_modifyrules(GUID hsession,
	uint32_t hrules, uint32_t flags, const RULE_LIST *plist)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_MODIFYRULES;
	request.payload.modifyrules.hsession = hsession;
	request.payload.modifyrules.hrules = hrules;
	request.payload.modifyrules.flags = flags;
	request.payload.modifyrules.plist = (void*)plist;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_getabgal(GUID hsession, BINARY *pentryid)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETABGAL;
	request.payload.getabgal.hsession = hsession;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pentryid = response.payload.getabgal.entryid;
	}
	return response.result;;
}

uint32_t zarafa_client_loadstoretable(
	GUID hsession, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_LOADSTORETABLE;
	request.payload.loadstoretable.hsession = hsession;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.loadstoretable.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_openstore(GUID hsession,
	BINARY entryid, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENSTORE;
	request.payload.openstore.hsession = hsession;
	request.payload.openstore.entryid = entryid;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.openstore.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_openpropfilesec(GUID hsession,
	const FLATUID *puid, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENPROPFILESEC;
	request.payload.openpropfilesec.hsession = hsession;
	request.payload.openpropfilesec.puid = puid;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.openpropfilesec.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_loadhierarchytable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_LOADHIERARCHYTABLE;
	request.payload.loadhierarchytable.hsession = hsession;
	request.payload.loadhierarchytable.hfolder = hfolder;
	request.payload.loadhierarchytable.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.loadhierarchytable.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_loadcontenttable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_LOADCONTENTTABLE;
	request.payload.loadcontenttable.hsession = hsession;
	request.payload.loadcontenttable.hfolder = hfolder;
	request.payload.loadcontenttable.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.loadcontenttable.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_loadrecipienttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_LOADRECIPIENTTABLE;
	request.payload.loadrecipienttable.hsession = hsession;
	request.payload.loadrecipienttable.hmessage = hmessage;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.loadrecipienttable.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_loadruletable(GUID hsession,
	uint32_t hrules, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_LOADRULETABLE;
	request.payload.loadruletable.hsession = hsession;
	request.payload.loadruletable.hrules = hrules;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.loadrecipienttable.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_createmessage(GUID hsession,
	uint32_t hfolder,  uint32_t flags, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CREATEMESSAGE;
	request.payload.createmessage.hsession = hsession;
	request.payload.createmessage.hfolder = hfolder;
	request.payload.createmessage.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.createmessage.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_deletemessages(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_DELETEMESSAGES;
	request.payload.deletemessages.hsession = hsession;
	request.payload.deletemessages.hfolder = hfolder;
	request.payload.deletemessages.pentryids = (void*)pentryids;
	request.payload.deletemessages.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_copymessages(GUID hsession,
	uint32_t hsrcfolder, uint32_t hdstfolder,
	const BINARY_ARRAY *pentryids, uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_COPYMESSAGES;
	request.payload.copymessages.hsession = hsession;
	request.payload.copymessages.hsrcfolder = hsrcfolder;
	request.payload.copymessages.hdstfolder = hdstfolder;
	request.payload.copymessages.pentryids = (void*)pentryids;
	request.payload.copymessages.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_setreadflags(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SETREADFLAGS;
	request.payload.setreadflags.hsession = hsession;
	request.payload.setreadflags.hfolder = hfolder;
	request.payload.setreadflags.pentryids = (void*)pentryids;
	request.payload.setreadflags.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_createfolder(GUID hsession,
	uint32_t hparent_folder, uint32_t folder_type,
	const char *folder_name, const char *folder_comment,
	uint32_t flags, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CREATEFOLDER;
	request.payload.createfolder.hsession = hsession;
	request.payload.createfolder.hparent_folder = hparent_folder;
	request.payload.createfolder.folder_type = folder_type;
	request.payload.createfolder.folder_name = (void*)folder_name;
	request.payload.createfolder.folder_comment = (void*)folder_comment;
	request.payload.createfolder.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.createfolder.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_deletefolder(GUID hsession,
	uint32_t hparent_folder, BINARY entryid, uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_DELETEFOLDER;
	request.payload.deletefolder.hsession = hsession;
	request.payload.deletefolder.hparent_folder = hparent_folder;
	request.payload.deletefolder.entryid = entryid;
	request.payload.deletefolder.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_emptyfolder(GUID hsession,
	uint32_t hfolder, uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_EMPTYFOLDER;
	request.payload.emptyfolder.hsession = hsession;
	request.payload.emptyfolder.hfolder = hfolder;
	request.payload.emptyfolder.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_copyfolder(GUID hsession,
	uint32_t hsrc_folder, BINARY entryid, uint32_t hdst_folder,
	const char *new_name, uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_COPYFOLDER;
	request.payload.copyfolder.hsession = hsession;
	request.payload.copyfolder.hsrc_folder = hsrc_folder;
	request.payload.copyfolder.entryid = entryid;
	request.payload.copyfolder.hdst_folder = hdst_folder;
	request.payload.copyfolder.new_name = (void*)new_name;
	request.payload.copyfolder.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_getstoreentryid(
	const char *mailbox_dn, BINARY *pentryid)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETSTOREENTRYID;
	request.payload.getstoreentryid.mailbox_dn = (void*)mailbox_dn;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pentryid = response.payload.getstoreentryid.entryid;
	}
	return response.result;
}

uint32_t zarafa_client_entryidfromsourcekey(
	GUID hsession, uint32_t hstore, BINARY folder_key,
	const BINARY *pmessage_key, BINARY *pentryid)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_ENTRYIDFROMSOURCEKEY;
	request.payload.entryidfromsourcekey.hsession = hsession;
	request.payload.entryidfromsourcekey.hstore = hstore;
	request.payload.entryidfromsourcekey.folder_key = folder_key;
	request.payload.entryidfromsourcekey.pmessage_key = (void*)pmessage_key;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pentryid = response.payload.entryidfromsourcekey.entryid;
	}
	return response.result;
}

uint32_t zarafa_client_storeadvise(GUID hsession,
	uint32_t hstore, const BINARY *pentryid,
	uint32_t event_mask, uint32_t *psub_id)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_STOREADVISE;
	request.payload.storeadvise.hsession = hsession;
	request.payload.storeadvise.hstore = hstore;
	request.payload.storeadvise.pentryid = (void*)pentryid;
	request.payload.storeadvise.event_mask = event_mask;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*psub_id = response.payload.storeadvise.sub_id;
	}
	return response.result;
}

uint32_t zarafa_client_unadvise(GUID hsession,
	uint32_t hstore, uint32_t sub_id)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_UNADVISE;
	request.payload.unadvise.hsession = hsession;
	request.payload.unadvise.hstore = hstore;
	request.payload.unadvise.sub_id = sub_id;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_notifdequeue(const NOTIF_SINK *psink,
	uint32_t timeval, ZNOTIFICATION_ARRAY *pnotifications)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_NOTIFDEQUEUE;
	request.payload.notifdequeue.psink = (void*)psink;
	request.payload.notifdequeue.timeval = timeval;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pnotifications = response.payload.notifdequeue.notifications;
	}
	return response.result;
}

uint32_t zarafa_client_queryrows(
	GUID hsession, uint32_t htable, uint32_t start,
	uint32_t count, const RESTRICTION *prestriction,
	const PROPTAG_ARRAY *pproptags, TARRAY_SET *prowset)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_QUERYROWS;
	request.payload.queryrows.hsession = hsession;
	request.payload.queryrows.htable = htable;
	request.payload.queryrows.start = start;
	request.payload.queryrows.count = count;
	request.payload.queryrows.prestriction = (void*)prestriction;
	request.payload.queryrows.pproptags = (void*)pproptags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*prowset = response.payload.queryrows.rowset;
	}
	return response.result;
}
	
uint32_t zarafa_client_setcolumns(GUID hsession, uint32_t htable,
	const PROPTAG_ARRAY *pproptags, uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SETCOLUMNS;
	request.payload.setcolumns.hsession = hsession;
	request.payload.setcolumns.htable = htable;
	request.payload.setcolumns.pproptags = (void*)pproptags;
	request.payload.setcolumns.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_seekrow(GUID hsession,
	uint32_t htable, uint32_t bookmark, int32_t seek_rows,
	int32_t *psought_rows)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SEEKROW;
	request.payload.seekrow.hsession = hsession;
	request.payload.seekrow.htable = htable;
	request.payload.seekrow.bookmark = bookmark;
	request.payload.seekrow.seek_rows = seek_rows;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*psought_rows = response.payload.seekrow.sought_rows;
	}
	return response.result;
}

uint32_t zarafa_client_sorttable(GUID hsession,
	uint32_t htable, const SORTORDER_SET *psortset)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SORTTABLE;
	request.payload.sorttable.hsession = hsession;
	request.payload.sorttable.htable = htable;
	request.payload.sorttable.psortset = (void*)psortset;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_getrowcount(GUID hsession,
	uint32_t htable, uint32_t *pcount)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETROWCOUNT;
	request.payload.getrowcount.hsession = hsession;
	request.payload.getrowcount.htable = htable;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pcount = response.payload.getrowcount.count;
	}
	return response.result;
}

uint32_t zarafa_client_restricttable(GUID hsession, uint32_t htable,
	const RESTRICTION *prestriction, uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_RESTRICTTABLE;
	request.payload.restricttable.hsession = hsession;
	request.payload.restricttable.htable = htable;
	request.payload.restricttable.prestriction = (void*)prestriction;
	request.payload.restricttable.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_findrow(GUID hsession, uint32_t htable,
	uint32_t bookmark, const RESTRICTION *prestriction,
	uint32_t flags, uint32_t *prow_idx)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_FINDROW;
	request.payload.findrow.hsession = hsession;
	request.payload.findrow.htable = htable;
	request.payload.findrow.bookmark = bookmark;
	request.payload.findrow.prestriction = (void*)prestriction;
	request.payload.findrow.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*prow_idx = response.payload.findrow.row_idx;
	}
	return response.result;
}

uint32_t zarafa_client_createbookmark(GUID hsession,
	uint32_t htable, uint32_t *pbookmark)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CREATEBOOKMARK;
	request.payload.createbookmark.hsession = hsession;
	request.payload.createbookmark.htable = htable;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pbookmark = response.payload.createbookmark.bookmark;
	}
	return response.result;
}

uint32_t zarafa_client_freebookmark(GUID hsession,
	uint32_t htable, uint32_t bookmark)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_FREEBOOKMARK;
	request.payload.freebookmark.hsession = hsession;
	request.payload.freebookmark.htable = htable;
	request.payload.freebookmark.bookmark = bookmark;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_getreceivefolder(GUID hsession,
	uint32_t hstore, const char *pstrclass, BINARY *pentryid)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETRECEIVEFOLDER;
	request.payload.getreceivefolder.hsession = hsession;
	request.payload.getreceivefolder.hstore = hstore;
	request.payload.getreceivefolder.pstrclass = (void*)pstrclass;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pentryid = response.payload.getreceivefolder.entryid;
	}
	return response.result;
}

uint32_t zarafa_client_modifyrecipients(GUID hsession,
	uint32_t hmessage, uint32_t flags, const TARRAY_SET *prcpt_list)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_MODIFYRECIPIENTS;
	request.payload.modifyrecipients.hsession = hsession;
	request.payload.modifyrecipients.hmessage = hmessage;
	request.payload.modifyrecipients.flags = flags;
	request.payload.modifyrecipients.prcpt_list = (void*)prcpt_list;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_submitmessage(GUID hsession, uint32_t hmessage)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SUBMITMESSAGE;
	request.payload.submitmessage.hsession = hsession;
	request.payload.submitmessage.hmessage = hmessage;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_loadattachmenttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_LOADATTACHMENTTABLE;
	request.payload.loadattachmenttable.hsession = hsession;
	request.payload.loadattachmenttable.hmessage = hmessage;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.loadattachmenttable.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_openattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENATTACHMENT;
	request.payload.openattachment.hsession = hsession;
	request.payload.openattachment.hmessage = hmessage;
	request.payload.openattachment.attach_id = attach_id;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.openattachment.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_createattachment(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CREATEATTACHMENT;
	request.payload.createattachment.hsession = hsession;
	request.payload.createattachment.hmessage = hmessage;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.createattachment.hobject;
	}
	return response.result;
}
	
uint32_t zarafa_client_deleteattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_DELETEATTACHMENT;
	request.payload.deleteattachment.hsession = hsession;
	request.payload.deleteattachment.hmessage = hmessage;
	request.payload.deleteattachment.attach_id = attach_id;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_setpropval(GUID hsession,
	uint32_t hobject, uint32_t proptag, const void *pvalue)
{
	TAGGED_PROPVAL propval;
	TPROPVAL_ARRAY propvals;
	
	propvals.count = 1;
	propvals.ppropval = &propval;
	propval.proptag = proptag;
	propval.pvalue = (void*)pvalue;
	return zarafa_client_setpropvals(hsession, hobject, &propvals);
}

uint32_t zarafa_client_setpropvals(GUID hsession,
	uint32_t hobject, const TPROPVAL_ARRAY *ppropvals)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SETPROPVALS;
	request.payload.setpropvals.hsession = hsession;
	request.payload.setpropvals.hobject = hobject;
	request.payload.setpropvals.ppropvals = (void*)ppropvals;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_getpropval(GUID hsession,
	uint32_t hobject, uint32_t proptag, void **ppvalue)
{
	uint32_t result;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	
	proptags.count = 1;
	proptags.pproptag = &proptag;
	result = zarafa_client_getpropvals(hsession,
				hobject, &proptags, &propvals);
	if (EC_SUCCESS != result) {
		return result;
	}
	if (0 == propvals.count) {
		*ppvalue = NULL;
	} else {
		*ppvalue = propvals.ppropval[0].pvalue;
	}
	return EC_SUCCESS;
}

uint32_t zarafa_client_getpropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETPROPVALS;
	request.payload.getpropvals.hsession = hsession;
	request.payload.getpropvals.hobject = hobject;
	request.payload.getpropvals.pproptags = (void*)pproptags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*ppropvals = response.payload.getpropvals.propvals;
	}
	return response.result;
}

uint32_t zarafa_client_deletepropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_DELETEPROPVALS;
	request.payload.deletepropvals.hsession = hsession;
	request.payload.deletepropvals.hobject = hobject;
	request.payload.deletepropvals.pproptags = (void*)pproptags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_setmessagereadflag(
	GUID hsession, uint32_t hmessage, uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SETMESSAGEREADFLAG;
	request.payload.setmessagereadflag.hsession = hsession;
	request.payload.setmessagereadflag.hmessage = hmessage;
	request.payload.setmessagereadflag.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_openembedded(GUID hsession,
	uint32_t hattachment, uint32_t flags, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENEMBEDDED;
	request.payload.openembedded.hsession = hsession;
	request.payload.openembedded.hattachment = hattachment;
	request.payload.openembedded.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.openembedded.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_getnamedpropids(GUID hsession, uint32_t hstore,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETNAMEDPROPIDS;
	request.payload.getnamedpropids.hsession = hsession;
	request.payload.getnamedpropids.hstore = hstore;
	request.payload.getnamedpropids.ppropnames = (void*)ppropnames;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*ppropids = response.payload.getnamedpropids.propids;
	}
	return response.result;
}

uint32_t zarafa_client_getpropnames(GUID hsession, uint32_t hstore,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETPROPNAMES;
	request.payload.getpropnames.hsession = hsession;
	request.payload.getpropnames.hstore = hstore;
	request.payload.getpropnames.ppropids = (void*)ppropids;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*ppropnames = response.payload.getpropnames.propnames;
	}
	return response.result;
}

uint32_t zarafa_client_copyto(GUID hsession, uint32_t hsrcobject,
	const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject,
	uint32_t flags)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_COPYTO;
	request.payload.copyto.hsession = hsession;
	request.payload.copyto.hsrcobject = hsrcobject;
	request.payload.copyto.pexclude_proptags = (void*)pexclude_proptags;
	request.payload.copyto.hdstobject = hdstobject;
	request.payload.copyto.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_savechanges(GUID hsession, uint32_t hobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SAVECHANGES;
	request.payload.savechanges.hsession = hsession;
	request.payload.savechanges.hobject = hobject;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_hierarchysync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_HIERARCHYSYNC;
	request.payload.hierarchysync.hsession = hsession;
	request.payload.hierarchysync.hfolder = hfolder;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.hierarchysync.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_contentsync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CONTENTSYNC;
	request.payload.contentsync.hsession = hsession;
	request.payload.contentsync.hfolder = hfolder;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.contentsync.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_configsync(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY *pstate,
	const RESTRICTION *prestriction, zend_bool *pb_changed,
	uint32_t *pcount)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CONFIGSYNC;
	request.payload.configsync.hsession = hsession;
	request.payload.configsync.hctx = hctx;
	request.payload.configsync.flags = flags;
	request.payload.configsync.pstate = (void*)pstate;
	request.payload.configsync.prestriction = (void*)prestriction;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pb_changed = response.payload.configsync.b_changed;
		*pcount = response.payload.configsync.count;
	}
	return response.result;
}

uint32_t zarafa_client_statesync(GUID hsession,
	uint32_t hctx, BINARY *pstate)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_STATESYNC;
	request.payload.statesync.hsession = hsession;
	request.payload.statesync.hctx = hctx;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pstate = response.payload.statesync.state;
	}
	return response.result;
}

uint32_t zarafa_client_syncmessagechange(GUID hsession,
	uint32_t hctx, zend_bool *pb_new, TPROPVAL_ARRAY *pproplist)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SYNCMESSAGECHANGE;
	request.payload.syncmessagechange.hsession = hsession;
	request.payload.syncmessagechange.hctx = hctx;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pb_new = response.payload.syncmessagechange.b_new;
		*pproplist = response.payload.syncmessagechange.proplist;
	}
	return response.result;
}

uint32_t zarafa_client_syncfolderchange(GUID hsession,
	uint32_t hctx, TPROPVAL_ARRAY *pproplist)
{
	
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SYNCFOLDERCHANGE;
	request.payload.syncfolderchange.hsession = hsession;
	request.payload.syncfolderchange.hctx = hctx;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pproplist = response.payload.syncfolderchange.proplist;
	}
	return response.result;
}

uint32_t zarafa_client_syncreadstatechanges(
	GUID hsession, uint32_t hctx, STATE_ARRAY *pstates)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SYNCREADSTATECHANGES;
	request.payload.syncreadstatechanges.hsession = hsession;
	request.payload.syncreadstatechanges.hctx = hctx;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pstates = response.payload.syncreadstatechanges.states;
	}
	return response.result;
}

uint32_t zarafa_client_syncdeletions(GUID hsession,
	uint32_t hctx, uint32_t flags, BINARY_ARRAY *pbins)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SYNCDELETIONS;
	request.payload.syncdeletions.hsession = hsession;
	request.payload.syncdeletions.hctx = hctx;
	request.payload.syncdeletions.flags = flags;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pbins = response.payload.syncdeletions.bins;
	}
	return response.result;
}

uint32_t zarafa_client_hierarchyimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_HIERARCHYIMPORT;
	request.payload.hierarchyimport.hsession = hsession;
	request.payload.hierarchyimport.hfolder = hfolder;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.hierarchyimport.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_contentimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CONTENTIMPORT;
	request.payload.contentimport.hsession = hsession;
	request.payload.contentimport.hfolder = hfolder;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.contentimport.hobject;
	}
	return response.result;
}
	
uint32_t zarafa_client_configimport(GUID hsession,
	uint32_t hctx, uint8_t sync_type, const BINARY *pstate)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_CONFIGIMPORT;
	request.payload.configimport.hsession = hsession;
	request.payload.configimport.hctx = hctx;
	request.payload.configimport.sync_type = sync_type;
	request.payload.configimport.pstate = (void*)pstate;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_stateimport(GUID hsession,
	uint32_t hctx, BINARY *pstate)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_STATEIMPORT;
	request.payload.stateimport.hsession = hsession;
	request.payload.stateimport.hctx = hctx;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pstate = response.payload.stateimport.state;
	}
	return response.result;
}

uint32_t zarafa_client_importmessage(GUID hsession, uint32_t hctx,
	uint32_t flags, const TPROPVAL_ARRAY *pproplist, uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_IMPORTMESSAGE;
	request.payload.importmessage.hsession = hsession;
	request.payload.importmessage.hctx = hctx;
	request.payload.importmessage.flags = flags;
	request.payload.importmessage.pproplist = (void*)pproplist;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.importmessage.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_importfolder(GUID hsession,
	uint32_t hctx, const TPROPVAL_ARRAY *pproplist)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_IMPORTFOLDER;
	request.payload.importfolder.hsession = hsession;
	request.payload.importfolder.hctx = hctx;
	request.payload.importfolder.pproplist = (void*)pproplist;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_importdeletion(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY_ARRAY *pbins)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_IMPORTDELETION;
	request.payload.importdeletion.hsession = hsession;
	request.payload.importdeletion.hctx = hctx;
	request.payload.importdeletion.flags = flags;
	request.payload.importdeletion.pbins = (void*)pbins;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_importreadstates(GUID hsession,
	uint32_t hctx, const STATE_ARRAY *pstates)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_IMPORTREADSTATES;
	request.payload.importreadstates.hsession = hsession;
	request.payload.importreadstates.hctx = hctx;
	request.payload.importreadstates.pstates = (void*)pstates;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_getsearchcriteria(GUID hsession,
	uint32_t hfolder, BINARY_ARRAY *pfolder_array,
	RESTRICTION **pprestriction, uint32_t *psearch_stat)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETSEARCHCRITERIA;
	request.payload.getsearchcriteria.hsession = hsession;
	request.payload.getsearchcriteria.hfolder = hfolder;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pfolder_array = response.payload.getsearchcriteria.folder_array;
		*pprestriction = response.payload.getsearchcriteria.prestriction;
		*psearch_stat = response.payload.getsearchcriteria.search_stat;
	}
	return response.result;
}

uint32_t zarafa_client_setsearchcriteria(
	GUID hsession, uint32_t hfolder, uint32_t flags,
	const BINARY_ARRAY *pfolder_array,
	const RESTRICTION *prestriction)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_SETSEARCHCRITERIA;
	request.payload.setsearchcriteria.hsession = hsession;
	request.payload.setsearchcriteria.hfolder = hfolder;
	request.payload.setsearchcriteria.flags = flags;
	request.payload.setsearchcriteria.pfolder_array = (void*)pfolder_array;
	request.payload.setsearchcriteria.prestriction = (void*)prestriction;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_openfreebusydata(GUID hsession,
	uint32_t hsupport, const BINARY_ARRAY *pentryids,
	LONG_ARRAY *phobject_array)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_OPENFREEBUSYDATA;
	request.payload.openfreebusydata.hsession = hsession;
	request.payload.openfreebusydata.hsupport = hsupport;
	request.payload.openfreebusydata.pentryids = (void*)pentryids;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject_array = response.payload.openfreebusydata.hobject_array;
	}
	return response.result;
}

uint32_t zarafa_client_enumfreebusyblocks(GUID hsession,
	uint32_t hfbdata, uint64_t nttime_start, uint64_t nttime_end,
	uint32_t *phobject)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_ENUMFREEBUSYBLOCKS;
	request.payload.enumfreebusyblocks.hsession = hsession;
	request.payload.enumfreebusyblocks.hfbdata = hfbdata;
	request.payload.enumfreebusyblocks.nttime_start = nttime_start;
	request.payload.enumfreebusyblocks.nttime_end = nttime_end;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*phobject = response.payload.enumfreebusyblocks.hobject;
	}
	return response.result;
}

uint32_t zarafa_client_fbenumreset(GUID hsession, uint32_t hfbenum)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_FBENUMRESET;
	request.payload.fbenumreset.hsession = hsession;
	request.payload.fbenumreset.hfbenum = hfbenum;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_fbenumskip(GUID hsession,
	uint32_t hfbenum, uint32_t num)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_FBENUMSKIP;
	request.payload.fbenumskip.hsession = hsession;
	request.payload.fbenumskip.hfbenum = hfbenum;
	request.payload.fbenumskip.num = num;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_fbenumrestrict(GUID hsession,
	uint32_t hfbenum, uint64_t nttime_start, uint64_t nttime_end)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_FBENUMRESTRICT;
	request.payload.fbenumrestrict.hsession = hsession;
	request.payload.fbenumrestrict.hfbenum = hfbenum;
	request.payload.fbenumrestrict.nttime_start = nttime_start;
	request.payload.fbenumrestrict.nttime_end = nttime_end;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_fbenumexport(GUID hsession,
	uint32_t hfbenum, uint32_t count, uint64_t nttime_start,
	uint64_t nttime_end, const char *organizer_name,
	const char *username, const char *uid_string,
	BINARY *pbin_ical)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_FBENUMEXPORT;
	request.payload.fbenumexport.hsession = hsession;
	request.payload.fbenumexport.hfbenum = hfbenum;
	request.payload.fbenumexport.count = count;
	request.payload.fbenumexport.nttime_start = nttime_start;
	request.payload.fbenumexport.nttime_end = nttime_end;
	request.payload.fbenumexport.organizer_name = (void*)organizer_name;
	request.payload.fbenumexport.username = (void*)username;
	request.payload.fbenumexport.uid_string = (void*)uid_string;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pbin_ical = response.payload.fbenumexport.bin_ical;
	}
	return response.result;
}

uint32_t zarafa_client_fetchfreebusyblocks(GUID hsession,
	uint32_t hfbenum, uint32_t celt, FBBLOCK_ARRAY *pblocks)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_FETCHFREEBUSYBLOCKS;
	request.payload.fetchfreebusyblocks.hsession = hsession;
	request.payload.fetchfreebusyblocks.hfbenum = hfbenum;
	request.payload.fetchfreebusyblocks.celt = celt;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pblocks = response.payload.fetchfreebusyblocks.blocks;
	}
	return response.result;
}

uint32_t zarafa_client_getfreebusyrange(GUID hsession,
	uint32_t hfbdata, uint64_t *pnttime_start, uint64_t *pnttime_end)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_GETFREEBUSYRANGE;
	request.payload.getfreebusyrange.hsession = hsession;
	request.payload.getfreebusyrange.hfbdata = hfbdata;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pnttime_start = response.payload.getfreebusyrange.nttime_start;
		*pnttime_end = response.payload.getfreebusyrange.nttime_end;
	}
	return response.result;
}
	
uint32_t zarafa_client_messagetorfc822(GUID hsession,
	uint32_t hmessage, BINARY *peml_bin)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_MESSAGETORFC822;
	request.payload.messagetorfc822.hsession = hsession;
	request.payload.messagetorfc822.hmessage = hmessage;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*peml_bin = response.payload.messagetorfc822.eml_bin;
	}
	return response.result;
}

uint32_t zarafa_client_rfc822tomessage(GUID hsession,
	uint32_t hmessage, const BINARY *peml_bin)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_RFC822TOMESSAGE;
	request.payload.rfc822tomessage.hsession = hsession;
	request.payload.rfc822tomessage.hmessage = hmessage;
	request.payload.rfc822tomessage.peml_bin = (void*)peml_bin;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_messagetoical(GUID hsession,
	uint32_t hmessage, BINARY *pical_bin)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_MESSAGETOICAL;
	request.payload.messagetoical.hsession = hsession;
	request.payload.messagetoical.hmessage = hmessage;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pical_bin = response.payload.messagetoical.ical_bin;
	}
	return response.result;
}

uint32_t zarafa_client_icaltomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pical_bin)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_ICALTOMESSAGE;
	request.payload.icaltomessage.hsession = hsession;
	request.payload.icaltomessage.hmessage = hmessage;
	request.payload.icaltomessage.pical_bin = (void*)pical_bin;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}

uint32_t zarafa_client_messagetovcf(GUID hsession,
	uint32_t hmessage, BINARY *pvcf_bin)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_MESSAGETOVCF;
	request.payload.messagetovcf.hsession = hsession;
	request.payload.messagetovcf.hmessage = hmessage;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	if (EC_SUCCESS == response.result) {
		*pvcf_bin = response.payload.messagetovcf.vcf_bin;
	}
	return response.result;
}

uint32_t zarafa_client_vcftomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pvcf_bin)
{
	RPC_REQUEST request;
	RPC_RESPONSE response;
	
	request.call_id = CALL_ID_VCFTOMESSAGE;
	request.payload.vcftomessage.hsession = hsession;
	request.payload.vcftomessage.hmessage = hmessage;
	request.payload.vcftomessage.pvcf_bin = (void*)pvcf_bin;
	if (!zarafa_client_do_rpc(&request, &response)) {
		return EC_RPC_FAIL;
	}
	return response.result;
}
