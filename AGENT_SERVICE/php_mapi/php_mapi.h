#ifndef PHP_MAPI_H
#define PHP_MAPI_H 1

#ifdef ZTS
#include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(mapi)
// this is the global hresult value, used in *every* php mapi function
	unsigned long hr;
// this is a reference to the MAPI exception class
	zend_class_entry *exception_ce;
	zend_bool exceptions_enabled;
ZEND_END_MODULE_GLOBALS(mapi)

#ifdef ZTS
#define MAPI_G(v) TSRMG(mapi_globals_id, zend_mapi_globals *, v)
#else
#define MAPI_G(v) (mapi_globals.v)
#endif

#define PHP_MAPI_VERSION "steep-1.0"
#define PHP_MAPI_EXTNAME "mapi"

PHP_MINIT_FUNCTION(mapi);
PHP_MINFO_FUNCTION(mapi);
PHP_MSHUTDOWN_FUNCTION(mapi);
PHP_RINIT_FUNCTION(mapi);
PHP_RSHUTDOWN_FUNCTION(mapi);

/* All the functions that will be exported (available) must be declared */
PHP_MINIT_FUNCTION(mapi);
PHP_MINFO_FUNCTION(mapi);
PHP_MSHUTDOWN_FUNCTION(mapi);
PHP_RINIT_FUNCTION(mapi);
PHP_RSHUTDOWN_FUNCTION(mapi);

ZEND_FUNCTION(mapi_last_hresult);
ZEND_FUNCTION(mapi_prop_type);
ZEND_FUNCTION(mapi_prop_id);
ZEND_FUNCTION(mapi_is_error);
ZEND_FUNCTION(mapi_make_scode);
ZEND_FUNCTION(mapi_prop_tag);

ZEND_FUNCTION(mapi_createoneoff);
ZEND_FUNCTION(mapi_parseoneoff);

ZEND_FUNCTION(mapi_logon_zarafa);
ZEND_FUNCTION(mapi_logon_ex);
ZEND_FUNCTION(mapi_getmsgstorestable);
ZEND_FUNCTION(mapi_openmsgstore);
ZEND_FUNCTION(mapi_openprofilesection);

ZEND_FUNCTION(mapi_openentry);
ZEND_FUNCTION(mapi_openaddressbook);
ZEND_FUNCTION(mapi_ab_openentry);
ZEND_FUNCTION(mapi_ab_resolvename);
ZEND_FUNCTION(mapi_ab_getdefaultdir);

ZEND_FUNCTION(mapi_msgstore_createentryid);
ZEND_FUNCTION(mapi_msgstore_getarchiveentryid);
ZEND_FUNCTION(mapi_msgstore_openentry);
ZEND_FUNCTION(mapi_msgstore_getreceivefolder);
ZEND_FUNCTION(mapi_msgstore_entryidfromsourcekey);
ZEND_FUNCTION(mapi_msgstore_advise);
ZEND_FUNCTION(mapi_msgstore_unadvise);
ZEND_FUNCTION(mapi_msgstore_abortsubmit);

ZEND_FUNCTION(mapi_sink_create);
ZEND_FUNCTION(mapi_sink_timedwait);

ZEND_FUNCTION(mapi_table_queryallrows);
ZEND_FUNCTION(mapi_table_queryrows);
ZEND_FUNCTION(mapi_table_getrowcount);
ZEND_FUNCTION(mapi_table_setcolumns);
ZEND_FUNCTION(mapi_table_seekrow);
ZEND_FUNCTION(mapi_table_sort);
ZEND_FUNCTION(mapi_table_restrict);
ZEND_FUNCTION(mapi_table_findrow);
ZEND_FUNCTION(mapi_table_createbookmark);
ZEND_FUNCTION(mapi_table_freebookmark);

ZEND_FUNCTION(mapi_folder_gethierarchytable);
ZEND_FUNCTION(mapi_folder_getcontentstable);
ZEND_FUNCTION(mapi_folder_getrulestable);
ZEND_FUNCTION(mapi_folder_createmessage);
ZEND_FUNCTION(mapi_folder_createfolder);
ZEND_FUNCTION(mapi_folder_deletefolder);
ZEND_FUNCTION(mapi_folder_deletemessages);
ZEND_FUNCTION(mapi_folder_copymessages);
ZEND_FUNCTION(mapi_folder_copyfolder);
ZEND_FUNCTION(mapi_folder_emptyfolder);
ZEND_FUNCTION(mapi_folder_setreadflags);
ZEND_FUNCTION(mapi_folder_getsearchcriteria);
ZEND_FUNCTION(mapi_folder_setsearchcriteria);
ZEND_FUNCTION(mapi_folder_modifyrules);

ZEND_FUNCTION(mapi_message_getattachmenttable);
ZEND_FUNCTION(mapi_message_getrecipienttable);
ZEND_FUNCTION(mapi_message_openattach);
ZEND_FUNCTION(mapi_message_createattach);
ZEND_FUNCTION(mapi_message_deleteattach);
ZEND_FUNCTION(mapi_message_modifyrecipients);
ZEND_FUNCTION(mapi_message_submitmessage);
ZEND_FUNCTION(mapi_message_setreadflag);

ZEND_FUNCTION(mapi_attach_openbin);
ZEND_FUNCTION(mapi_attach_openobj);

ZEND_FUNCTION(mapi_getnamesfromids);
ZEND_FUNCTION(mapi_getidsfromnames);

ZEND_FUNCTION(mapi_decompressrtf);

ZEND_FUNCTION(mapi_stream_write);
ZEND_FUNCTION(mapi_stream_read);
ZEND_FUNCTION(mapi_openpropertytostream);
ZEND_FUNCTION(mapi_stream_stat);
ZEND_FUNCTION(mapi_stream_seek);
ZEND_FUNCTION(mapi_stream_commit);
ZEND_FUNCTION(mapi_stream_setsize);
ZEND_FUNCTION(mapi_stream_create);

ZEND_FUNCTION(mapi_getprops);
ZEND_FUNCTION(mapi_setprops);
ZEND_FUNCTION(mapi_copyto);

ZEND_FUNCTION(mapi_openproperty);
ZEND_FUNCTION(mapi_deleteprops);
ZEND_FUNCTION(mapi_savechanges);

ZEND_FUNCTION(mapi_zarafa_getpermissionrules);
ZEND_FUNCTION(mapi_zarafa_setpermissionrules);

ZEND_FUNCTION(mapi_getuseravailability);

ZEND_FUNCTION(mapi_exportchanges_config);
ZEND_FUNCTION(mapi_exportchanges_synchronize);
ZEND_FUNCTION(mapi_exportchanges_updatestate);
ZEND_FUNCTION(mapi_exportchanges_getchangecount);

ZEND_FUNCTION(mapi_importcontentschanges_config);
ZEND_FUNCTION(mapi_importcontentschanges_updatestate);
ZEND_FUNCTION(mapi_importcontentschanges_importmessagechange);
ZEND_FUNCTION(mapi_importcontentschanges_importmessagedeletion);
ZEND_FUNCTION(mapi_importcontentschanges_importperuserreadstatechange);
ZEND_FUNCTION(mapi_importcontentschanges_importmessagemove);

ZEND_FUNCTION(mapi_importhierarchychanges_config);
ZEND_FUNCTION(mapi_importhierarchychanges_updatestate);
ZEND_FUNCTION(mapi_importhierarchychanges_importfolderchange);
ZEND_FUNCTION(mapi_importhierarchychanges_importfolderdeletion);

ZEND_FUNCTION(mapi_wrap_importcontentschanges);
ZEND_FUNCTION(mapi_wrap_importhierarchychanges);

ZEND_FUNCTION(mapi_inetmapi_imtoinet);
ZEND_FUNCTION(mapi_inetmapi_imtomapi);

ZEND_FUNCTION(mapi_icaltomapi);
ZEND_FUNCTION(mapi_mapitoical);
ZEND_FUNCTION(mapi_vcftomapi);
ZEND_FUNCTION(mapi_mapitovcf);

ZEND_FUNCTION(mapi_enable_exceptions);

ZEND_FUNCTION(mapi_feature);

ZEND_FUNCTION(kc_session_save);
ZEND_FUNCTION(kc_session_restore);

ZEND_FUNCTION(nsp_getuserinfo);
ZEND_FUNCTION(nsp_setuserpasswd);

ZEND_FUNCTION(mapi_linkmessage);

extern zend_module_entry mapi_module_entry;
#define phpext_mapi_ptr &mapi_module_entry

#endif
