<?php
function mapi_load_mapidefs() : void {}
function mapi_last_hresult() : int {}
function mapi_prop_type(int $proptag) : int|false {}
function mapi_prop_id(int $proptag) : int|false {}
function mapi_is_error(int $errcode) : bool|false {}
function mapi_make_scode(int $sev, int $code) : int|false {}
function mapi_prop_tag(int $proptype, int $propid) : int|false {}
function mapi_createoneoff(?string $displayname, string $type, string $address, ?int $flags = 0) : string|false {}
function mapi_parseoneoff(string $entryid) : array|false {}
function mapi_logon_zarafa(string $username, string $password, ?string $server = null, ?string $sslcert = null, ?string $sslpass = null, ?int $flags = 0, ?string $wa_version = null, ?string $misc_version = null) : resource|false {}
function mapi_logon_ex(string $username, string $password, int $flags) : resource|false {}
function mapi_getmsgstorestable(resource $session) : resource|false {}
function mapi_openmsgstore(resource $ses, string $entryid) : resource|false {}
function mapi_openprofilesection(resource $ses, string $uid) : resource|false {}
function mapi_openaddressbook(resource $session) : resource|false {}
function mapi_openentry(resource $ses, ?string $entryid = null, ?int $flags = 0) : resource|false {}
function mapi_ab_openentry(resource $abk, ?string $entryid = null, ?int $flags = 0) : resource|false {}
function mapi_ab_resolvename(resource $abk, array $names, ?int $flags = 0) : mixed {}
function mapi_ab_getdefaultdir(resource $abk) : string|false {}
function mapi_msgstore_createentryid(resource $store, string $mailbox_dn) : string|false {}
function mapi_msgstore_getarchiveentryid(resource $store, string $user, string $server) : bool {}
function mapi_msgstore_openentry(resource $store, ?string $entryid = null, ?int $flags = 0) : resource|false {}
function mapi_msgstore_getreceivefolder(resource $store) : resource|false {}
function mapi_msgstore_entryidfromsourcekey(resource $store, string $sk_fld, ?string $sk_msg = null) : string|false {}
function mapi_msgstore_advise(resource $store, string $entryid, int $event_mask, resource $sink) : int|false {}
function mapi_msgstore_unadvise(resource $store, int $sub_id) : bool {}
function mapi_msgstore_abortsubmit(?resource $store, ?string $entryid = null) : true {}
function mapi_sink_create() : resource|false {}
function mapi_sink_timedwait(resource $sink, int $time) : mixed {}
function mapi_table_queryallrows(resource $table, ?array $proptags = null, ?array $restrict = null) : mixed {}
function mapi_table_queryrows(resource $table, ?array $proptags = null, ?int $start = 0, ?int $limit = 0) : mixed {}
function mapi_table_getrowcount(resource $table) : int|false {}
function mapi_table_setcolumns(resource $table, array $columns, ?int $flags = 0) : bool {}
function mapi_table_seekrow(resource $table, int $bookmark, int $rowcount) : int|false {}
function mapi_table_sort(resource $table, array $sortcrit, ?int $flags = 0) : bool {}
function mapi_table_restrict(resource $table, array $restrict, ?int $flags = 0) : bool {}
function mapi_table_findrow(resource $table, array $restrict, ?int $bookmark = 0, ?int $flags = 0) : int|false {}
function mapi_table_createbookmark(resource $table) : int|false {}
function mapi_table_freebookmark(resource $table, int $bookmark) : bool {}
function mapi_folder_gethierarchytable(resource $fld, ?int $flags = 0) : resource|false {}
function mapi_folder_getcontentstable(resource $fld, ?int $flags = 0) : resource|false {}
function mapi_folder_getrulestable(resource $fld) : resource|false {}
function mapi_folder_createmessage(resource $fld, ?int $flags = 0) : resource|false {}
function mapi_folder_createfolder(resource $fld, string $fname, ?string $comment = null, ?int $flags = 0, ?int $folder_type = 0) : resource|false {}
function mapi_folder_deletemessages(resource $fld, array $entryids, ?int $flags = 0) : bool {}
function mapi_folder_copymessages(resource $srcfld, array $entryids, resource $dstfld, ?int $flags = 0) : bool {}
function mapi_folder_emptyfolder(resource $fld, ?int $flags = 0) : bool {}
function mapi_folder_copyfolder(resource $srcfld, string $entryid, resource $dstfld, ?string $name, ?int $flags = 0) : bool {}
function mapi_folder_deletefolder(resource $fld, string $entryid, ?int $flags = 0) : bool {}
function mapi_folder_setreadflags(resource $fld, array $entryids, ?int $flags = 0) : bool {}
function mapi_folder_setsearchcriteria(resource $fld, array $restriction, array $folderlist, int $flags) : bool {}
function mapi_folder_getsearchcriteria(resource $fld, ?int $flags = 0) : mixed {}
function mapi_folder_modifyrules(resource $fld, array $rows, ?int $flags = 0) : bool {}
function mapi_message_getattachmenttable(resource $msg) : resource|false {}
function mapi_message_getrecipienttable(resource $msg) : resource|false {}
function mapi_message_openattach(resource $msg, int $id) : resource|false {}
function mapi_message_createattach(resource $msg, ?int $flags = 0) : resource|false {}
function mapi_message_deleteattach(resource $msg, int $id = 0, ?int $flags = flags) : bool {}
function mapi_message_modifyrecipients(resource $msg, int $flags, array $adrlist) : bool {}
function mapi_message_submitmessage(resource $msg) : bool {}
function mapi_message_setreadflag(resource $msg, int $flags) : bool {}
function mapi_openpropertytostream(resource $any, int $proptag, ?int $flags = 0, ?string $guid = null) : resource|false {}
function mapi_stream_write(resource $stream, string $data) : int|false {}
function mapi_stream_read(resource $stream, int $size) : string|false {}
function mapi_stream_stat(resource $stream) : array|false {}
function mapi_stream_seek(resource $stream, int $offset, ?int $flags = 0) : bool {}
function mapi_stream_commit(resource $stream) : bool {}
function mapi_stream_setsize(resource $stream, int $size) : bool {}
function mapi_stream_create() : resource|false {}
function mapi_attach_openobj(resource $attach, ?int $flags = 0) : resource|bool {}
function mapi_savechanges(resource $any, ?int $flags = 0) : bool {}
function mapi_getprops(resource $any, ?array $proptags = null) : mixed {}
function mapi_setprops(resource $any, array $propvals) : bool {}
function mapi_copyto(resource $src, array $excliid, array $exclprop, resource $dst, ?int $flags = 0) : bool {}
function mapi_openproperty(resource $any, int $proptag /* [more] */) : resource|false {}
function mapi_deleteprops(resource $any, array $proptags) : bool {}
function mapi_getnamesfromids(resource $any, ?array $names = null) : array|false {}
function mapi_getidsfromnames(resource $store, array $names, ?array $guids = null) : array|false {}
function mapi_decompressrtf(string $data) : string|false {}
function mapi_zarafa_getpermissionrules(resource $any, int $type) : array|false {}
function mapi_zarafa_setpermissionrules(resource $any, array $perms) : bool {}
function mapi_getuseravailability(resource $ses, string $entryid, int $start, int $end) : string|false {}
function mapi_exportchanges_config(resource $e, resource $stream, int $flags, mixed $i, mixed $restrict, mixed $inclprop, mixed $exclprop, int $bufsize) : bool {}
function mapi_exportchanges_synchronize(resource $x) : mixed {}
function mapi_exportchanges_updatestate(resource $e, resource $stream) : bool {}
function mapi_exportchanges_getchangecount(resource $r) : int|false {}
function mapi_importcontentschanges_config(resource $i, resource $stream, int $flags) : bool {}
function mapi_importcontentschanges_updatestate(resource $i, ?resource $stream = null) : bool {}
function mapi_importcontentschanges_importmessagechange(resource $i, array $props, int $flags, mixed &$msg) : bool {}
function mapi_importcontentschanges_importmessagedeletion(resource $i, int $flags, array $msgs) : bool {}
function mapi_importcontentschanges_importperuserreadstatechange(resource $i, array $readst) : bool {}
function mapi_importcontentschanges_importmessagemove(resource $r, string $a, string $b, string $c, string $d, string $e) : bool {}
function mapi_importhierarchychanges_config(resource $i, resource $stream, int $flags) : bool {}
function mapi_importhierarchychanges_updatestate(resource $i, ?resource $stream) : bool {}
function mapi_importhierarchychanges_importfolderchange(resource $i, array $props) : bool {}
function mapi_importhierarchychanges_importfolderdeletion(resource $i, int $flags, array $folders) : bool {}
function mapi_wrap_importcontentschanges(object &$object) : resource|false {}
function mapi_wrap_importhierarchychanges(object &$object) : resource|false {}
function mapi_inetmapi_imtoinet(resource $ses, resource $abk, resource $msg, array $opts) : resource|false {}
function mapi_inetmapi_imtomapi(resource $ses, resource $store, resource $abk, resource $msg, string $str, array $opts) : bool {}
function mapi_icaltomapi(resource $ses, resource $store, resource $abk, resource $msg, string $str, bool $norecip) : bool {}
function mapi_mapitoical(resource $ses, resource $abk, resource $msg, array $opts) : string|false {}
function mapi_vcftomapi(resource $ses, resource $store, resource $msg, string $str) : bool {}
function mapi_mapitovcf(resource $ses, res $abk, res $msg, array $opts) : string|false {}
function mapi_enable_exceptions(string $cls) : bool {}
function mapi_feature(string $ft) : bool {}
function kc_session_save(resource $ses, string &$data) : int {}
function kc_session_restore(mixed $data, mixed &$res) : int {}
function nsp_getuserinfo(string $username) : array|false {}
function nsp_setuserpasswd(string $username, string $oldpass, string $newpass) : bool {}
function mapi_linkmessage(resource $ses, ?string $srcheid = null, ?string $msgeid = null) : mixed {}
