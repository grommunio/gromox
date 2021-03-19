#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>
#include <gromox/zcore_rpc.hpp>
#include "common_util.h"

struct RESP_LOGON {
	GUID hsession;
};

struct RESP_UINFO {
	BINARY entryid;
	char *pdisplay_name;
	char *px500dn;
	uint32_t privilege_bits;
};

struct RESP_OPENENTRY {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct RESP_OPENSTOREENTRY {
	uint8_t mapi_type;
	uint32_t hxobject;
};

struct RESP_OPENABENTRY {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct RESP_RESOLVENAME {
	TARRAY_SET result_set;
};

struct RESP_GETPERMISSIONS {
	PERMISSION_SET perm_set;
};

struct RESP_GETABGAL {
	BINARY entryid;
};

struct RESP_LOADSTORETABLE {
	uint32_t hobject;
};

struct RESP_OPENSTORE {
	uint32_t hobject;
};

struct RESP_OPENPROPFILESEC {
	uint32_t hobject;
};

struct RESP_LOADHIERARCHYTABLE {
	uint32_t hobject;
};

struct RESP_LOADCONTENTTABLE {
	uint32_t hobject;
};

struct RESP_LOADRECIPIENTTABLE {
	uint32_t hobject;
};

struct RESP_LOADRULETABLE {
	uint32_t hobject;
};
	
struct RESP_CREATEMESSAGE {
	uint32_t hobject;
};

struct RESP_CREATEFOLDER {
	uint32_t hobject;
};

struct RESP_GETSTOREENTRYID {
	BINARY entryid;
};

struct RESP_ENTRYIDFROMSOURCEKEY {
	BINARY entryid;
};

struct RESP_STOREADVISE {
	uint32_t sub_id;
};

struct RESP_NOTIFDEQUEUE {
	ZNOTIFICATION_ARRAY notifications;
};

struct RESP_QUERYROWS {
	TARRAY_SET rowset;
};

struct RESP_SETCOLUMNS {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct RESP_SEEKROW {
	int32_t sought_rows;
};

struct RESP_GETROWCOUNT {
	uint32_t count;
};

struct RESP_FINDROW {
	uint32_t row_idx;
};

struct RESP_CREATEBOOKMARK {
	uint32_t bookmark;
};

struct RESP_GETRECEIVEFOLDER {
	BINARY entryid;
};

struct RESP_LOADATTACHMENTTABLE {
	uint32_t hobject;
};

struct RESP_OPENATTACHMENT {
	uint32_t hobject;
};

struct RESP_CREATEATTACHMENT {
	uint32_t hobject;
};

struct RESP_GETPROPVALS {
	TPROPVAL_ARRAY propvals;
};

struct RESP_OPENEMBEDDED {
	uint32_t hobject;
};

struct RESP_GETNAMEDPROPIDS {
	PROPID_ARRAY propids;
};

struct RESP_GETPROPNAMES {
	PROPNAME_ARRAY propnames;
};

struct RESP_HIERARCHYSYNC {
	uint32_t hobject;
};

struct RESP_CONTENTSYNC {
	uint32_t hobject;
};

struct RESP_CONFIGSYNC {
	BOOL b_changed;
	uint32_t count;
};

struct RESP_STATESYNC {
	BINARY state;
};

struct RESP_SYNCMESSAGECHANGE {
	BOOL b_new;
	TPROPVAL_ARRAY proplist;
};

struct RESP_SYNCFOLDERCHANGE {
	TPROPVAL_ARRAY proplist;
};

struct RESP_SYNCREADSTATECHANGES {
	STATE_ARRAY states;
};

struct RESP_SYNCDELETIONS {
	BINARY_ARRAY bins;
};

struct RESP_HIERARCHYIMPORT {
	uint32_t hobject;
};

struct RESP_CONTENTIMPORT {
	uint32_t hobject;
};
	
struct RESP_STATEIMPORT {
	BINARY state;
};

struct RESP_IMPORTMESSAGE {
	uint32_t hobject;
};

struct RESP_GETSEARCHCRITERIA {
	BINARY_ARRAY folder_array;
	RESTRICTION *prestriction;
	uint32_t search_stat;
};

struct RESP_MESSAGETORFC822 {
	BINARY eml_bin;
};

struct RESP_MESSAGETOICAL {
	BINARY ical_bin;
};

struct RESP_MESSAGETOVCF {
	BINARY vcf_bin;
};

struct RESP_GETUSERAVAILABILITY {
	char *result_string;
};

union ZCORE_RESPONSE_PAYLOAD {
	RESP_LOGON logon;
	RESP_UINFO uinfo;
	RESP_OPENENTRY openentry;
	RESP_OPENSTOREENTRY openstoreentry;
	RESP_OPENABENTRY openabentry;
	RESP_RESOLVENAME resolvename;
	RESP_GETPERMISSIONS getpermissions;
	RESP_GETABGAL getabgal;
	RESP_LOADSTORETABLE loadstoretable;
	RESP_OPENSTORE openstore;
	RESP_OPENPROPFILESEC openpropfilesec;
	RESP_LOADHIERARCHYTABLE loadhierarchytable;
	RESP_LOADCONTENTTABLE loadcontenttable;
	RESP_LOADRECIPIENTTABLE loadrecipienttable;
	RESP_LOADRULETABLE loadruletable;
	RESP_CREATEMESSAGE createmessage;
	RESP_CREATEFOLDER createfolder;
	RESP_GETSTOREENTRYID getstoreentryid;
	RESP_ENTRYIDFROMSOURCEKEY entryidfromsourcekey;
	RESP_STOREADVISE storeadvise;
	RESP_NOTIFDEQUEUE notifdequeue;
	RESP_QUERYROWS queryrows;
	RESP_SEEKROW seekrow;
	RESP_GETROWCOUNT getrowcount;
	RESP_FINDROW findrow;
	RESP_CREATEBOOKMARK createbookmark;
	RESP_GETRECEIVEFOLDER getreceivefolder;
	RESP_LOADATTACHMENTTABLE loadattachmenttable;
	RESP_OPENATTACHMENT openattachment;
	RESP_CREATEATTACHMENT createattachment;
	RESP_GETPROPVALS getpropvals;
	RESP_OPENEMBEDDED openembedded;
	RESP_GETNAMEDPROPIDS getnamedpropids;
	RESP_GETPROPNAMES getpropnames;
	RESP_HIERARCHYSYNC hierarchysync;
	RESP_CONTENTSYNC contentsync;
	RESP_CONFIGSYNC configsync;
	RESP_STATESYNC statesync;
	RESP_SYNCMESSAGECHANGE syncmessagechange;
	RESP_SYNCFOLDERCHANGE syncfolderchange;
	RESP_SYNCREADSTATECHANGES syncreadstatechanges;
	RESP_SYNCDELETIONS syncdeletions;
	RESP_HIERARCHYIMPORT hierarchyimport;
	RESP_CONTENTIMPORT contentimport;
	RESP_STATEIMPORT stateimport;
	RESP_IMPORTMESSAGE importmessage;
	RESP_GETSEARCHCRITERIA getsearchcriteria;
	RESP_MESSAGETORFC822 messagetorfc822;
	RESP_MESSAGETOICAL messagetoical;
	RESP_MESSAGETOVCF messagetovcf;
	RESP_GETUSERAVAILABILITY getuseravailability;
};

struct RPC_RESPONSE {
	uint8_t call_id;
	uint32_t result;
	ZCORE_RESPONSE_PAYLOAD payload;
};

extern BOOL rpc_ext_pull_request(const BINARY *, ZCORE_RPC_REQUEST *);
BOOL rpc_ext_push_response(const RPC_RESPONSE *presponse,
	BINARY *pbin_out);
