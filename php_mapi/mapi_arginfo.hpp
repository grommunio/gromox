/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 4c0a9dc60cd87c6d2c69bb5ad191f93582d2d07c */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_load_mapidefs, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, level, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_last_hresult, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_prop_type, 0, 1, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, proptag, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_mapi_prop_id arginfo_mapi_prop_type

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_is_error, 0, 1, MAY_BE_BOOL|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, errcode, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_make_scode, 0, 2, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, sev, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, code, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_prop_tag, 0, 2, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, proptype, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, propid, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_createoneoff, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, displayname, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, address, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_parseoneoff, 0, 1, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, entryid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_logon_zarafa, 0, 2, resource, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, username, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, server, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sslcert, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sslpass, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, wa_version, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, misc_version, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_logon_ex, 0, 3, resource, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, username, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_getmsgstorestable, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, session, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_openmsgstore, 0, 2, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_TYPE_INFO(0, entryid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_openprofilesection, 0, 2, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_TYPE_INFO(0, uid, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_mapi_openaddressbook arginfo_mapi_getmsgstorestable

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_openentry, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, entryid, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_ab_openentry, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, entryid, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_ab_resolvename, 0, 2, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
	ZEND_ARG_TYPE_INFO(0, names, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_ab_getdefaultdir, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_msgstore_createentryid, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_TYPE_INFO(0, mailbox_dn, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_msgstore_getarchiveentryid, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_TYPE_INFO(0, user, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, server, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_msgstore_openentry, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, entryid, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_msgstore_getreceivefolder, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_msgstore_entryidfromsourcekey, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_TYPE_INFO(0, sk_fld, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sk_msg, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_msgstore_advise, 0, 4, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_TYPE_INFO(0, entryid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, event_mask, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, sink, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_msgstore_unadvise, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_TYPE_INFO(0, sub_id, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_mapi_msgstore_abortsubmit, 0, 1, true, 0)
	ZEND_ARG_OBJ_INFO(0, store, resource, 1)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, entryid, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_sink_create, 0, 0, resource, MAY_BE_FALSE)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_sink_timedwait, 0, 2, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, sink, resource, 0)
	ZEND_ARG_TYPE_INFO(0, time, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_table_queryallrows, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, proptags, IS_ARRAY, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, restrict, IS_ARRAY, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_table_queryrows, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, proptags, IS_ARRAY, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, start, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, limit, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_table_getrowcount, 0, 1, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_table_setcolumns, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO(0, columns, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_table_seekrow, 0, 3, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO(0, bookmark, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, rowcount, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_table_sort, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO(0, sortcrit, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_table_restrict, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO(0, restrict, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_table_findrow, 0, 2, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO(0, restrict, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, bookmark, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

#define arginfo_mapi_table_createbookmark arginfo_mapi_table_getrowcount

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_table_freebookmark, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, table, resource, 0)
	ZEND_ARG_TYPE_INFO(0, bookmark, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_folder_gethierarchytable, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

#define arginfo_mapi_folder_getcontentstable arginfo_mapi_folder_gethierarchytable

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_folder_getrulestable, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
ZEND_END_ARG_INFO()

#define arginfo_mapi_folder_createmessage arginfo_mapi_folder_gethierarchytable

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_folder_createfolder, 0, 2, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, fname, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, comment, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, folder_type, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_deletemessages, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, entryids, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_copymessages, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, srcfld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, entryids, IS_ARRAY, 0)
	ZEND_ARG_OBJ_INFO(0, dstfld, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_emptyfolder, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_copyfolder, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, srcfld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, entryid, IS_STRING, 0)
	ZEND_ARG_OBJ_INFO(0, dstfld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_deletefolder, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, entryid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

#define arginfo_mapi_folder_setreadflags arginfo_mapi_folder_deletemessages

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_setsearchcriteria, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, restriction, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, folderlist, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_getsearchcriteria, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_folder_modifyrules, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, rows, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_message_getattachmenttable, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
ZEND_END_ARG_INFO()

#define arginfo_mapi_message_getrecipienttable arginfo_mapi_message_getattachmenttable

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_message_openattach, 0, 2, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, id, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_message_createattach, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_message_deleteattach, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, id, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "flags")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_message_modifyrecipients, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, adrlist, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_message_submitmessage, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_message_setreadflag, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_openpropertytostream, 0, 2, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO(0, proptag, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, guid, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_stream_write, 0, 2, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_stream_read, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
	ZEND_ARG_TYPE_INFO(0, size, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_stream_stat, 0, 1, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_stream_seek, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
	ZEND_ARG_TYPE_INFO(0, offset, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_stream_commit, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_stream_setsize, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
	ZEND_ARG_TYPE_INFO(0, size, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_mapi_stream_create arginfo_mapi_sink_create

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_attach_openobj, 0, 1, resource, MAY_BE_BOOL)
	ZEND_ARG_OBJ_INFO(0, attach, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_savechanges, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_getprops, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, proptags, IS_ARRAY, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_setprops, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO(0, propvals, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_copyto, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, src, resource, 0)
	ZEND_ARG_TYPE_INFO(0, excliid, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, exclprop, IS_ARRAY, 0)
	ZEND_ARG_OBJ_INFO(0, dst, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 1, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_openproperty, 0, 2, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO(0, proptag, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_deleteprops, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO(0, proptags, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_getnamesfromids, 0, 1, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, names, IS_ARRAY, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_getidsfromnames, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_TYPE_INFO(0, names, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, guids, IS_ARRAY, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_decompressrtf, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_zarafa_getpermissionrules, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO(0, type, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_zarafa_setpermissionrules, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, any, resource, 0)
	ZEND_ARG_TYPE_INFO(0, perms, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_getuseravailability, 0, 4, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_TYPE_INFO(0, entryid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, start, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, end, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_exportchanges_config, 0, 8, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, e, resource, 0)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, i, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, restrict, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, inclprop, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, exclprop, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, bufsize, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_exportchanges_synchronize, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, x, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_exportchanges_updatestate, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, e, resource, 0)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_exportchanges_getchangecount, 0, 1, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, r, resource, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importcontentschanges_config, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importcontentschanges_updatestate, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_OBJ_INFO_WITH_DEFAULT_VALUE(0, stream, resource, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importcontentschanges_importmessagechange, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_TYPE_INFO(0, props, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(1, msg, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importcontentschanges_importmessagedeletion, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, msgs, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importcontentschanges_importperuserreadstatechange, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_TYPE_INFO(0, readst, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importcontentschanges_importmessagemove, 0, 6, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, r, resource, 0)
	ZEND_ARG_TYPE_INFO(0, a, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, b, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, c, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, d, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, e, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_mapi_importhierarchychanges_config arginfo_mapi_importcontentschanges_config

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importhierarchychanges_updatestate, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_OBJ_INFO(0, stream, resource, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importhierarchychanges_importfolderchange, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_TYPE_INFO(0, props, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_importhierarchychanges_importfolderdeletion, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, i, resource, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, folders, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_wrap_importcontentschanges, 0, 1, resource, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(1, object, IS_OBJECT, 0)
ZEND_END_ARG_INFO()

#define arginfo_mapi_wrap_importhierarchychanges arginfo_mapi_wrap_importcontentschanges

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_mapi_inetmapi_imtoinet, 0, 4, resource, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, opts, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_inetmapi_imtomapi, 0, 6, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, str, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, opts, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_icaltomapi, 0, 6, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, str, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, norecip, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_icaltomapi2, 0, 3, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, ics, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_mapitoical, 0, 4, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_OBJ_INFO(0, abk, resource, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, opts, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_vcftomapi, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_OBJ_INFO(0, store, resource, 0)
	ZEND_ARG_OBJ_INFO(0, msg, resource, 0)
	ZEND_ARG_TYPE_INFO(0, str, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_vcftomapi2, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, fld, resource, 0)
	ZEND_ARG_TYPE_INFO(0, vcard, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_mapi_mapitovcf, 0, 4, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_OBJ_INFO(0, abk, res, 0)
	ZEND_ARG_OBJ_INFO(0, msg, res, 0)
	ZEND_ARG_TYPE_INFO(0, opts, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_enable_exceptions, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, cls, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_feature, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, ft, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_kc_session_save, 0, 2, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_TYPE_INFO(1, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_kc_session_restore, 0, 2, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(1, res, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_nsp_getuserinfo, 0, 1, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, username, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nsp_setuserpasswd, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, username, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, oldpass, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, newpass, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_mapi_linkmessage, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, ses, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, srcheid, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, msgeid, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()
