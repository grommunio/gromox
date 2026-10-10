<?php
function mapi_load_mapidefs(?int $level) : void {}
function mapi_last_hresult() : int {}
function mapi_prop_type(int $proptag) : int|bool {}
function mapi_prop_id(int $proptag) : int|bool {}
function mapi_is_error(int $errcode) : bool {}
function mapi_make_scode(int $sev, int $code) : int|bool {}
function mapi_prop_tag(int $proptype, int $propid) : int|bool {}
function mapi_createoneoff(?string $displayname, string $type, string $address, ?int $flags = 0) : string|bool {}
function mapi_parseoneoff(string $entryid) : array|bool {}
/** @return resource|bool */
function mapi_logon_zarafa(string $username, string $password, ?string $server = null, ?string $sslcert = null, ?string $sslpass = null, ?int $flags = 0, ?string $wa_version = null, ?string $misc_version = null) {}
/** @return resource|bool */
function mapi_logon_ex(string $username, string $password, int $flags) {}
/** @return resource|bool */
function mapi_logon_np(string $username, int $flags) {}
/** @return resource|bool */
function mapi_logon_token(string $token) {}
/**
 * @param resource $session
 * @return resource|bool
 */
function mapi_getmsgstorestable($session) {}
/**
 * @param resource $ses
 * @return resource|bool
 */
function mapi_openmsgstore($ses, string $entryid) {}
/**
 * @param resource $ses
 * @return resource|bool
 */
function mapi_openprofilesection($ses, string $uid) {}
/**
 * @param resource $session
 * @return resource|bool
 */
function mapi_openaddressbook($session) {}
/**
 * @param resource $ses
 * @return resource|bool
 */
function mapi_openentry($ses, ?string $entryid = null, ?int $flags = 0) {}
/**
 * @param resource $abk
 * @return resource|bool
 */
function mapi_ab_openentry($abk, ?string $entryid = null, ?int $flags = 0) {}
/** @param resource $abk */
function mapi_ab_resolvename($abk, array $names, ?int $flags = 0) : mixed {}
/** @param resource $abk */
function mapi_ab_getdefaultdir($abk) : string|bool {}
/** @param resource $store */
function mapi_msgstore_createentryid($store, string $mailbox_dn) : string|bool {}
/** @param resource $store */
function mapi_msgstore_getarchiveentryid($store, string $user, string $server) : bool {}
/**
 * @param resource $store
 * @return resource|bool
 */
function mapi_msgstore_openentry($store, ?string $entryid = null, ?int $flags = 0) {}
/**
 * @param resource $store
 * @return resource|bool
 */
function mapi_msgstore_getreceivefolder($store) {}
/** @param resource $store */
function mapi_msgstore_entryidfromsourcekey($store, string $sk_fld, ?string $sk_msg = null) : string|bool {}
/**
 * @param resource $store
 * @param resource $sink
 */
function mapi_msgstore_advise($store, string $entryid, int $event_mask, $sink) : int|bool {}
/** @param resource $store */
function mapi_msgstore_unadvise($store, int $sub_id) : bool {}
/** @param resource|null $store */
function mapi_msgstore_abortsubmit($store, ?string $entryid = null) : bool {}
/** @return resource|bool */
function mapi_sink_create() {}
/** @param resource $sink */
function mapi_sink_timedwait($sink, int $time) : mixed {}
/** @param resource $table */
function mapi_table_queryallrows($table, ?array $proptags = null, ?array $restrict = null) : mixed {}
/** @param resource $table */
function mapi_table_queryrows($table, ?array $proptags = null, ?int $start = 0, ?int $limit = 0) : mixed {}
/** @param resource $table */
function mapi_table_getrowcount($table) : int|bool {}
/** @param resource $table */
function mapi_table_setcolumns($table, array $columns, ?int $flags = 0) : bool {}
/** @param resource $table */
function mapi_table_seekrow($table, int $bookmark, int $rowcount) : int|bool {}
/** @param resource $table */
function mapi_table_sort($table, array $sortcrit, ?int $flags = 0) : bool {}
/** @param resource $table */
function mapi_table_restrict($table, array $restrict, ?int $flags = 0) : bool {}
/** @param resource $table */
function mapi_table_findrow($table, array $restrict, ?int $bookmark = 0, ?int $flags = 0) : int|bool {}
/** @param resource $table */
function mapi_table_createbookmark($table) : int|bool {}
/** @param resource $table */
function mapi_table_freebookmark($table, int $bookmark) : bool {}
/**
 * @param resource $fld
 * @return resource|bool
 */
function mapi_folder_gethierarchytable($fld, ?int $flags = 0) {}
/**
 * @param resource $fld
 * @return resource|bool
 */
function mapi_folder_getcontentstable($fld, ?int $flags = 0) {}
/**
 * @param resource $fld
 * @return resource|bool
 */
function mapi_folder_getrulestable($fld) {}
/**
 * @param resource $fld
 * @return resource|bool
 */
function mapi_folder_createmessage($fld, ?int $flags = 0) {}
/**
 * @param resource $fld
 * @return resource|bool
 */
function mapi_folder_createfolder($fld, string $fname, ?string $comment = null, ?int $flags = 0, ?int $folder_type = 0) {}
/** @param resource $fld */
function mapi_folder_deletemessages($fld, array $entryids, ?int $flags = 0) : bool {}
/**
 * @param resource $srcfld
 * @param resource $dstfld
 */
function mapi_folder_copymessages($srcfld, array $entryids, $dstfld, ?int $flags = 0) : bool {}
/** @param resource $fld */
function mapi_folder_emptyfolder($fld, ?int $flags = 0) : bool {}
/**
 * @param resource $srcfld
 * @param resource $dstfld
 */
function mapi_folder_copyfolder($srcfld, string $entryid, $dstfld, ?string $name, ?int $flags = 0) : bool {}
/** @param resource $fld */
function mapi_folder_deletefolder($fld, string $entryid, ?int $flags = 0) : bool {}
/** @param resource $fld */
function mapi_folder_setreadflags($fld, array $entryids, ?int $flags = 0) : bool {}
/** @param resource $fld */
function mapi_folder_setsearchcriteria($fld, array $restriction, array $folderlist, int $flags) : bool {}
/** @param resource $fld */
function mapi_folder_getsearchcriteria($fld, ?int $flags = 0) : mixed {}
/** @param resource $fld */
function mapi_folder_modifyrules($fld, array $rows, ?int $flags = 0) : bool {}
/**
 * @param resource $msg
 * @return resource|bool
 */
function mapi_message_getattachmenttable($msg) {}
/**
 * @param resource $msg
 * @return resource|bool
 */
function mapi_message_getrecipienttable($msg) {}
/**
 * @param resource $msg
 * @return resource|bool
 */
function mapi_message_openattach($msg, int $id) {}
/**
 * @param resource $msg
 * @return resource|bool
 */
function mapi_message_createattach($msg, ?int $flags = 0) {}
/** @param resource $msg */
function mapi_message_deleteattach($msg, int $id = 0, ?int $flags = 0) : bool {}
/** @param resource $msg */
function mapi_message_modifyrecipients($msg, int $flags, array $adrlist) : bool {}
/** @param resource $msg */
function mapi_message_submitmessage($msg) : bool {}
/** @param resource $msg */
function mapi_message_setreadflag($msg, int $flags) : bool {}
/**
 * @param resource $any
 * @return resource|bool
 */
function mapi_openpropertytostream($any, int $proptag, ?int $flags = 0, ?string $guid = null) {}
/** @param resource $stream */
function mapi_stream_write($stream, string $data) : int|bool {}
/** @param resource $stream */
function mapi_stream_read($stream, int $size) : string|bool {}
/** @param resource $stream */
function mapi_stream_stat($stream) : array|bool {}
/** @param resource $stream */
function mapi_stream_seek($stream, int $offset, ?int $flags = 0) : bool {}
/** @param resource $stream */
function mapi_stream_commit($stream) : bool {}
/** @param resource $stream */
function mapi_stream_setsize($stream, int $size) : bool {}
/** @return resource|bool */
function mapi_stream_create() {}
/**
 * @param resource $attach
 * @return resource|bool
 */
function mapi_attach_openobj($attach, ?int $flags = 0) {}
/** @param resource $any */
function mapi_savechanges($any, ?int $flags = 0) : bool {}
/** @param resource $any */
function mapi_getprops($any, ?array $proptags = null) : mixed {}
/** @param resource $any */
function mapi_setprops($any, array $propvals) : bool {}
/**
 * @param resource $src
 * @param resource $dst
 */
function mapi_copyto($src, array $excliid, array $exclprop, $dst, ?int $flags = 0) : bool {}
/**
 * @param resource $any
 * @return resource|bool
 */
function mapi_openproperty($any, int $proptag, ?string $iid = null, ?int $interfaceflags = 0, ?int $flags = 0) {}
/** @param resource $any */
function mapi_deleteprops($any, array $proptags) : bool {}
/** @param resource $any */
function mapi_getnamesfromids($any, ?array $names = null) : array|bool {}
/** @param resource $store */
function mapi_getidsfromnames($store, array $names, ?array $guids = null) : array|bool {}
function mapi_decompressrtf(string $data) : string|bool {}
/** @param resource $any */
function mapi_zarafa_getpermissionrules($any, int $type) : array|bool {}
/** @param resource $any */
function mapi_zarafa_setpermissionrules($any, array $perms) : bool {}
/** @param resource $ses */
function mapi_getuserfreebusy($ses, string $entryid, int $start, int $end) : array|bool {}
/** @param resource $ses */
function mapi_getuserfreebusyical($ses, string $entryid, int $start, int $end) : string|bool {}
/**
 * @param resource $e
 * @param resource $stream
 */
function mapi_exportchanges_config($e, $stream, int $flags, mixed $i, mixed $restrict, mixed $inclprop, mixed $exclprop, int $bufsize) : bool {}
/** @param resource $x */
function mapi_exportchanges_synchronize($x) : mixed {}
/**
 * @param resource $e
 * @param resource $stream
 */
function mapi_exportchanges_updatestate($e, $stream) : bool {}
/** @param resource $r */
function mapi_exportchanges_getchangecount($r) : int|bool {}
/**
 * @param resource $i
 * @param resource $stream
 */
function mapi_importcontentschanges_config($i, $stream, int $flags) : bool {}
/**
 * @param resource $i
 * @param resource|null $stream
 */
function mapi_importcontentschanges_updatestate($i, $stream = null) : bool {}
/** @param resource $i */
function mapi_importcontentschanges_importmessagechange($i, array $props, int $flags, mixed &$msg) : bool {}
/** @param resource $i */
function mapi_importcontentschanges_importmessagedeletion($i, int $flags, array $msgs) : bool {}
/** @param resource $i */
function mapi_importcontentschanges_importperuserreadstatechange($i, array $readst) : bool {}
/** @param resource $r */
function mapi_importcontentschanges_importmessagemove($r, string $a, string $b, string $c, string $d, string $e) : bool {}
/**
 * @param resource $i
 * @param resource $stream
 */
function mapi_importhierarchychanges_config($i, $stream, int $flags) : bool {}
/**
 * @param resource $i
 * @param resource|null $stream
 */
function mapi_importhierarchychanges_updatestate($i, $stream) : bool {}
/** @param resource $i */
function mapi_importhierarchychanges_importfolderchange($i, array $props) : bool {}
/** @param resource $i */
function mapi_importhierarchychanges_importfolderdeletion($i, int $flags, array $folders) : bool {}
/** @return resource|bool */
function mapi_wrap_importcontentschanges(object &$object) {}
/** @return resource|bool */
function mapi_wrap_importhierarchychanges(object &$object) {}
/**
 * @param resource $ses
 * @param resource $abk
 * @param resource $msg
 * @return resource|bool
 */
function mapi_inetmapi_imtoinet($ses, $abk, $msg, array $opts) {}
/**
 * @param resource $ses
 * @param resource $store
 * @param resource $abk
 * @param resource $msg
 */
function mapi_inetmapi_imtomapi($ses, $store, $abk, $msg, string $str, array $opts) : bool {}
/**
 * @param resource $ses
 * @param resource $store
 * @param resource $abk
 * @param resource $msg
 */
function mapi_icaltomapi($ses, $store, $abk, $msg, string $str, bool $norecip) : bool {}
/**
 * @param resource $abk
 * @param resource $fld
 */
function mapi_icaltomapi2($abk, $fld, string $ics) : array|bool {}
/**
 * @param resource $ses
 * @param resource $abk
 * @param resource $msg
 */
function mapi_mapitoical($ses, $abk, $msg, array $opts) : string|bool {}
/**
 * @param resource $ses
 * @param resource $store
 * @param resource $msg
 */
function mapi_vcftomapi($ses, $store, $msg, string $str) : bool {}
/** @param resource $fld */
function mapi_vcftomapi2($fld, string $vcard) : array|bool {}
/**
 * @param resource $ses
 * @param resource $abk
 * @param resource $msg
 */
function mapi_mapitovcf($ses, $abk, $msg, array $opts) : string|bool {}
function mapi_enable_exceptions(string $cls) : bool {}
function mapi_feature(string $ft) : bool {}
/** @param resource $ses */
function kc_session_save($ses, string &$data) : int {}
function kc_session_restore(mixed $data, mixed &$res) : int {}
function nsp_getuserinfo(string $username) : array|bool {}
function nsp_setuserpasswd(string $username, string $oldpass, string $newpass) : bool {}
function nsp_essdn_to_username(string $essdn) : string|bool {}
/** @param resource $ses */
function mapi_linkmessage($ses, ?string $srcheid = null, ?string $msgeid = null) : mixed {}
/** @param resource $ses */
function mapi_linkmessages($ses, string $srcheid, array $msgeids) : mixed {}
function mapi_ianatz_to_tzdef(string $tz) : string|bool {}
function mapi_strerror(int $code) : string {}
/** @param resource $session */
function mapi_getsendpermissions($session, string $entryid) : int|bool {}
/** @param resource $session */
function mapi_getdelegates($session, int $mode) : array|bool {}
