1.24 (2022-06-01)
=================

Enhancements:

* Added a config directive ``tls_min_proto`` so one can set a minimum TLS
  standard when your distro doesn't have crypto-policies
  (https://gitlab.com/redhat-crypto/fedora-crypto-policies )
* autodiscover.ini: new directives ``advertise_mh`` and ``advertise_rpch``
  for finer grained control over individual protocol advertisements;
  replaces ``mapihttp``.
* exmdb_provider: lifted the folder limit from 10k to 28 billion
* oxcmail: cease excessive base64 encoding.
* Messages are now preferably encoded as quoted-printable during conversion to
  Internet Mail format. This might help with spam classification.
* delivery-queue: the maximum mail size is now strictly enforced rather than
  rounded up to the next 2 megabytes
* gromox-dscli: the -h option is no longer strictly needed, it will be derived
  from the -e argument if absent

Fixes:

* http: resolve a crash on shutdown due to wrong order of teardown
* exmdb_provider: fix buffer overread (crash) when a truncated /cid/N file
  is read.
* emsmdb: fix buffer overread (crash) when common_util_check_message_class is
  called with an empty string.


1.23 (2022-05-13)
=================

Fixes:

* exmdb_provider: fix search opening the exmdb store with wrong flags
  and skipping 200 messages during the search operation
* exmdb_provider: speed up Online Mode searches by 14 to 18-fold
* mt2exm: avoid crash when an import message has no properties at all

Enhancements:

* exmdb_provider: add a config directive ``exmdb_search_pacing``

Changes:

* kdb2mt: skip ``IPM.Microsoft.FolderDesign.NamedView`` rather than
  ``IPM.MessageManager`` messages


1.22 (2022-05-12)
=================

Fixes:

* imap: add a default for the `imap_cmd_debug` directive
* service_loader: resolve crash when first module is unloadable
* eml2mt, exm2eml: rectify wrong service plugin search path

Enhancements:

* eml2mt: add iCalendar and vCard file import
* doc: added configuration file overview lists to gromox(7)
* kdb2mt: skip IPM.MessageManager FAI messages (cause Outlook to sometimes
  refuse opening a folder)

Changes:

* The `/usr/libexec/gromox/autodiscover` command has been renamed to just
  `gromox-dscli`.


1.21 (2022-05-08)
=================

Fixes:

* lib: repair wrong propid for PR_IPM_PUBLIC_FOLDERS_ENTRYID
* exmdb_provider: avoid use-after-free crash related to Public Store read
  state username handling
* oxcmail: rework classification of S/MIME mails
* email_lib: make ICAL_TIME::twcompare behave symmetrically
* oxcical: appointments were prone to being in the wrong timezone due to
  DTSTART values being emitted with dayofmonth 32..35 in certain years
* exmdb_provider: output autosynthesized HTML in the proper character set

Enhancements:

* doc: mention issues related to senders/recipients with ZARAFA address type
* autodiscover: test URLs inside Autodiscover responses for validity
* exmdb_provider: add "exmdb_pf_read_states" config directive
* exmdb_provider: add "exmdb_pf_read_per_user" config directive
* imap: add directive "imap_cmd_debug"

Changes:

* zcore: return ecNotFound from mapi_getstoreentryid when unable to resolve user


1.20 (2022-04-30)
=================

Fixes:

* Resolve a use-after-free in gromox-eml2mt
* oxcmail: conversion of Reply-To MAPI field to Internet Mail had only used the last
  ONEOFF-type recipient, now it uses all ONEOFF recipients.
* oxcmail: set IPM.Note.SMIME.MultipartSigned only for incoming S/MIME mails,
  not for OpenPGP mails.
* autodiscover: Change the way autodiscover.ini is parsed. This allows a few
  more non-alphanumeric characters in the MariaDB password. ';' is still
  unusable.
* exmdb_provider: Evaluate restrictions against absent values differently;
  this makes messages without a sensitivity tag and which are located
  in a non-default store visible in Outlook again.
* pop3: SIGHUP now really reloads pop3_cmd_debug from the .cfg file

Changes:

* zcore: entryids for PAB entries now follow the ZCSAB entryid scheme

Known issues:

* oxcmail: Reply-To still skips EX-type recipients (W-1964)


1.19 (2022-04-14)
=================

Enhancements:

* kdb2mt: added the --with-acl option for partial conversion of ACLs
* pff2mt: added the --only-obj option to extract a specific object
* mt2exm: added the -B option for the placement of unanchored messages
* eml2mt: new utility to import mails from files
* exmdb_provider: new config directive "exmdb_schema_upgrades"
* midb: new config directive "midb_schema_upgrades"
* mkprivate, mkpublic and mkmidb now recognize the -U option to upgrade SQLite
  database schemas
* mbop: new utility
* rebuild: added progress indicator
* zcore: new config directive "zcore_max_obh_per_session"
* emsmdb: new config directives "emsmdb_max_obh_per_session",
  "emsmdb_max_cxh_per_user" to allow higher resource use when a lot of stores
  are used by an Outlook profile (warning W-1580).

Fixes:

* emsmdb: no longer send folder named properties in ICS streams
* mapi_lib: resolve use-after-free in idset::remove
* http: cure a crash in pdu_processor_auth_bind_ack when NTLMSSP authentication
  is attempted
* exmdb_client: when the exmdb server is not reachable, fail immediately rather
  than timeout
* Change SQLite db schema to use BLOB column type/affinity instead of NONE,
  resolving an unwanted auto-conversion from certain strings that look like
  numbers, e.g. E.164 telephone numbers without spaces.
* lib: add missing RFC 2047 Base64 recognition to some mail functions
* lib: autodetect iso-2022-jp-ms (un)availability in iconv to resolve
  conversion problems with RFC 2047 encoded-words using iso-2022-jp

Behavioral changes:

* rebuild: no longer performs implicit schema updates; see
  gromox-mkprivate/mkpublic/mkmidb -U, or the exmdb_schema_upgrades directive
  for replacement.
* rebuild: no longer performs db unload/reload; this operation moved to
  gromox-mbop.
* zcore: move socket creation after privilege drop


1.18 (2022-03-19)
=================

Enhancements:

* The mkprivate, mkpublic, mkmidb utilities gained an -f option.
* autodiscover: New diagnostic utility to analyze Autodiscover message
  from the command-line.
* gromox-exm2eml: New diagnostic utility to export one message as Internet
  Mail.
* delmsg: New diagnostic utility to delete messages in an ICS-conforming way.
* exmdb_provider: New config directive "sqlite_debug" for enabling analysis of
  all SQLite queries made.
* nsp: New config directive "nsp_trace" for enabling analysis of (some)
  NSPI RPC calls and their parameters.

Fixes:

* exmdb_provider: Abort asynchronous search folder population when the very
  search folder has been closed.
* exmdb_providier: do not close idle databases that still have active
  notification listeners
* nsp: Fix janky row seeking and crashing when using the name search feature in
  Outlook's Address Book dialog.
* mysql_adaptor: Lookup of rooms and equipment by maildir has been restored.
* midb had erroneously processed only the first command for every network read
* exmdb_client again groups notify connections per PID

Changes:

* nsp: When performing a name search in Outlook's Address Book dialog,
  scan the entire table rather than just the entries from the currently
  highlighted line forwards.


1.17 (2022-03-09)
=================

Enhancements:

* emsmdb: Faststream temporary state files are now written to
  /var/tmp/gromox instead and with O_TMPFILE, because they need not
  be persisted at all, and if /var/lib/gromox is a network filesystem,
  the network roundtrip can be eliminated.
* exmdb_provider: emit a log message when host not in exmdb_acl
* ldap_adaptor: add a "ldap_edirectory_workarounds" config directive
* zcore: user settings are saved to disk much more rapidly now
  (Settings could get lost when zcore terminated unexpectedly because
  of very long caching periods.)
* zcore: allow reducing zarafa_threads_num directive to a minimum of 1

Fixes:

* oxcmail: conversion of recurring meeting requests from MAPI to IM/RFC5322
  misconstructed the exmdb RPC for querying PidLidTimeZoneStruct,
  likely failing the export as a whole.
* exmdb_provider: avoid a SQL query error when placing a new message
  into public folder
* exmdb_provider: delete W-1595/W-1596 false positive warning
* exmdb_provider: avoid giving a negative/wrapped unread message count for
  folders (PR_CONTENT_UNREAD)
* exmdb_provider: the presence of PR_PARENT_DISPLAY (normally a computed property)
  in the sqlite db (hence not computed) had caused the READ_MESSAGE RPC to fail
* kdb2mt: skip importing PR_PARENT_DISPLAY
* kdb2mt: skip importing PR_ACL_DATA, PR_RULES_DATA, PR_EC_WEBACCESS_SETTINGS_JSON
  (has KC-specific entryids that have no meaning when in Gromox)
* zcore: cure an out-of-bounds access in
  container_object_get_user_table_all_proptags
* zcore: fix mis-setting of the internal/external OOF message
* mkmidb: fix a startup crash (add missing CFG_TABLE_END marker)
* authmgr: zero-terminate reason string

Known issues:

* emsmdb: Moving a message from one store to another in Cached Mode
  is rejected; a new message "E-1664: message has GUID of another
  store, cannot import" is produced until implemented.


1.16 (2022-02-11)
=================

Enhancements:

* exchange2grommunio: add robust file lock detection for exported PST
* exch: avoid re-use of Message-Id when message is submitted twice
* pff2mt: do not choke on NO_ATTACHMENT objects (resolves PF-1012 warning)

Fixes:

* emsmdb: oxcfold_deletemessages had incorrectly tested for PR_READ
* emsmdb: fix OL entering infinite loop deleting messages with read receipt requests
* zcore: PR_SENT_REPRESENTING_SEARCH_KEY was not set on submit
* exmdb_provider: restore fxstream ability to read PT_OBJECT attachments
* emsmdb: resolve a case of synchro repetition occurring in clients
* rpc_lib: clear NTLMSSP_CTX and resolve a crash due to garbage pointers


1.15 (2022-02-04)
=================

Fixes:

* oxcical: repair import of ICAL recurrences being 60x longer than projected
* oxcical: rerecognize busy status type "OOF"
* mapi_lib: cease emission of InTransitMessageCorrelator property to RFC5322
  header as garbage / stop emitting non-string PS_INTERNET_HEADERS properties
  completely.
* imap/pop3: resolve dlname type mismatch warnings
* email_lib: fix infinite loop in ical_check_empty_line
* midb: fix nullptr deref when startup has aborted
* http: fix double free when startup has aborted

Enhancements:

* emsmdb: add log messages for failed delegate lookup
* exchange2grommunio: replace PIPESTATUS test by something workable
* zcore: allow setting Out Of Office status of other mailboxes


1.14 (2022-01-29)
=================

Enhancements:

* Add powershell script for Exchange to grommunio/Gromox migration
  (source tree only)
* zcore: enhance mapi_getmsgstoretable to show all stores with
  access permissions
* pff2mt: add --with-hidden/--without-hidden
* kdb2mt: add --with-hidden/--without-hidden

Fixes:

* pff2mt: scan attachments for named property info too
* midb/imap: add back recognition for condition keywords
* emsmdb: MAPI bodies between 4K and 8K were not displayed correctly
  due to propval_utf16_len giving the wrong codepoint count
* emsmdb/rpclib: fix crash during NTLM negotiation
* exmdb_provider: cure "INSERT INTO search_result" SQL collision warnings
* mapi_lib: make conversion of S/MIME MAPI objects to RFC5322 independent
  of the number of header lines

Changes:

* delivery: replace domain_list text file plugin by an implementation
  searching SQL directly


1.13 (2022-01-17)
=================

Enhancements:

* pff2mt: support reading multi-value variable-length property types,
  and obscure single-value types.
* pff2mt: support reading receivefolders for Inbox mapping
  (only OST files have the desired info)

Fixes:

* midb: Avoid storing the primary email address in midb.sqlite3, and instead
  derive it from SQL.
  (pop3 used to reject DELE commands after the email address of a user was
  changed.)

Changes:

* The adaptor(8gx) daemon has been removed following its earlier obsoletion.
* telnet console support has been removed.


1.12 (2022-01-09)
=================

Enhancements:

* midb: SIGHUP will now reload the midb_cmd_debug directive
* lib: add error reporting to sqlite3_exec calls
* pam_gromox: Additional service mode checks.
  One can now use e.g. ``auth required pam_gromox.so service=chat``
  in ``/etc/pam.d/xyz`` to test for the CHAT privilege bit.
* doc: document more MRO field caveats for gromox-kdb2mt
* kdb2mt: analyze Receive Folder Table and map inbox to inbox when -s is used
* kdb2mt: recognize PT_MV_SHORT and PT_MV_CLSID properties
* pff2mt: display NID type in verbose tree view
* zcore: support emission of PR_ACCESS in content tables
* mkprivate, mkpublic: generate mailbox directory structure if
  it does not exist yet

Fixes:

* imap: resolve the Thunderbird folder view showing all rows without subject
  and sender
* Recognize config directives with intervals of value "0" without unit
* pff2mt: recipient objects were erroneously skipped
* pff2mt: scan all available record sets for named properties
* mkprivate: a base translation for Conversation Action Settings was restored;
  the folder is no longer named "FLG-ERR-2".

Changes:

* mod_fastcgi: switch URL processing to case-sensitive
* mda: alias resolution is now done by the delivery(8gx) daemon itself
  through the new alias_resolve(4gx) module, and the adaptor(8gx)
  daemon's textfile outputs are no longer used


1.11 (2021-12-16)
=================

Enhancements:

* mt2exm: perform named property translation on folder properties, message
  recipient properties and attachment properties

Fixes:

* mapi_lib: Resolved a crash when ingesting an iCal attachment with
  SUMMARY lines and time-based as well as timeless exceptions.
* mapi_lib: Resolved a crash when emitting messages that have
  some properties from the PS_INTERNET_HEADERS group set.
* mapi_lib: Resolved a crash when emitting messages that have
  the PSETID_GROMOX:vcarduid property.
* delivery-queue: The message_enqueue plugin had written an improperly-sized
  integer to mail data files, and message_dequeue could not read them.
  (32-bit platforms only)
* daemons: resolve a slow startup under strace

Changes:

* http, imap, pop3: Addresses in log messages are now (more
  consistently) in square brackets.
* kdb2mt: skip over IMAP properties when reading databases


1.10 (2021-12-07)
=================

Fixes:

* exmdb_provider: cease adding a broken recipient when deleting last recipient
* exmdb_provider: synthesize mandatory recipient properties essential for MSMAPI
  (The source of incomplete recipients is from imported KGWC databases.)
* autodiscover: repair double @@ appearing in EXCH server name
* emsmdb: work around Outlook not displaying any body in Cached Mode when
  there is no HTML body
* mapi_lib: avoid making underscores in subjects when there are umlauts

Enhancements:

* exmdb_provider: add config directives mbox_contention_warning and
  mbox_contention_reject


1.9 (2021-11-27)
================

Fixes:

* emsmdb: fix dangling data pointer when setting ``PR_LAST_MODIFIER_NAME``
* emsmdb: propagate "modified" flag upwards when saving embedded messages
* exmdb_provider: raise limit for local replica IDs

Enhancements:

* kdb2mt: support ``-s`` for public stores
* exmdb_provider: add config directive ``dbg_synthesize_content``
* Recognize MH/ABK PropertyRestriction format for the ``nspiResolveNames`` RPC

Changes:

* On mail ingestion, the Content-Disposition header value is now used instead
  of the Content-ID header presence to determine whether an attachment is
  inline (and possibly "hidden").


1.8 (2021-11-13)
================

Fixes:

* mysql_adaptor: fix nullptr deref in get_user_info
* exchange_nsp: fix crash when an addressbook datum was to be copied
* exchange_emsmdb: do not send unresolvable namedprops into faststream;
  reduce "Synchronization Issues" messages popping up in Outlook
* zcore: integer values of freeform user properties were truncated
* zcore: fix unbounded buffer writes when returning certain propvals
* exmdb_provider: fix SQL logic error appearing during folder emptying
* mapi_lib: when vCards cannot be ingested as a MAPI object, ingest
  them as files - set missing PR_ATTACH_METHOD for this.
* email_lib: fix infinite loop in vcard_check_empty_line

Enhancements:

* php: do print reason when autodiscover.ini cannot be read
* mapi_lib: set PR_SUPPLEMENTARY_INFO when ingesting mail
* kdb2mt: support --src-mbox "" to get a listing of all stores


1.7 (2021-11-07)
================

Fixes:

* mapi_lib: fix misparsing of X-Priority/Priority header on mail ingestion
* kdb2mt, pff2mt: do not splice-import IPM_COMMON_VIEWS (may contain
  entryids no longer applicable)

Enhancements:

* delivery & queue: recognize shared mailboxes
* doc: add Grommunio Admin API directives to ldap_adaptor manpage
* exch: add handling for PT_MV_SYSTIME, PT_MV_CURRENCY property types
* kdb2mt: support extraction of PT_CURRENCY, PT_MV_{I8,SYSTIME,CURRENCY}
  properties from KDBs


1.6 (2021-10-30)
================

Fixes:

* delivery-queue: fix three crashes involving stream processing
* exmdb_local: stop emitting bogus message length into temporary message files
* exmdb_local: fix crash on read-back of temporary message files
* mda: add a delivery mechanism for Out Of Office autoreplies
* mt2exm: fix an inverted condition that would erroneously
  raise error code PG-1122

Enhancements:

* mt2exm: add an -x option for ignoring duplicated folder creations
* kdb2mt: the special folder for junk e-mail is now recognized
  (relevant for when the -s command-line option is used).

Changes:

* delivery-queue: the flusher plugin mechanism has been dropped; the only
  plugin there was, libgxf_message_enqueue, is now directly in the program.
* Scope-based resource management for a number of internal library classes.


1.5 (2021-10-21)
================

Fixes:

* exmdb_provider: repair two erroneously inverted conditions involving
  message instance saving
* exchange_emsmdb, zcore: fix crash in conjunction with modifyrecipients RPC

Enhancements:

* cgkrepair: new utility to replace broken PR_CHANGE_KEYs and PCLs generated by
  libexmdbpp/admin-api/mkprivate/mkpublic.


1.4 (2021-10-08)
================

Fixes:

* exmdb_provider: repair an erroneously inverted condition for
  OP_MOVE Deferred Action Message generation.
  If Outlook crashes, you should clear the "Deferred Action"
  folder with MFCMAPI once.
* exmdb_provider: Deletion of folders within a public mailbox
  used to be ineffective, which was fixed.

Enhancements:

* Daemons support now socket activation.
* The event(8gx) and timer(8gx) daemons now run unprivileged.
* gromox-pff2mt now skips over unrecognizable MAPI properties
  rather than exiting.
* gromox-mt2exm now supports storing to public mailboxes.


1.3 (2021-09-29)
================

Fixes:

* kdb2mt: put FAI messages in the right place & transfer read flag
* zcore: stop accidental truncation of autoreply.cfg
* mda_local: fix an uninitialized buffer read that caused OOF
  replies not to be generated
* exmdb_provider: cure bug that prevented deletion of mails in Public Folders

Changes:

* delivery & imap: the log priority of some messages has been raised
  to more sensible levels.
* mkprivate, mkpublic, mkmidb: install tools to sbindir
* autodiscover: support users without a PR_DISPLAY_NAME

Enhancements:

* http: add config directive "http_debug"
* exmdb_provider: add a config directive "enable_dam"


1.2 (2021-09-01)
================

Fixes:

* zcore: repair wrong (parent_)entryid being passed to syncers
* lib: unbreak save/restore of inbox rules from zcore
* http: fix a hang during Outlook's autodiscovery due to incorrect
  HTTP request-body processing
* kdb2mt: implement documented SRCPASS environment variable
* kdb2mt: reduce a false condition in checking for attachment existence
  (reduces PK-1012)
* kdb2mt: recognize fixated namedprops in the range 0x8000..0x84FF
  (appointment data, contact data)

Enhancements:

* kdb2mt: new ``-v`` option to show progress for large folders
* kdb2mt: implement support for embedded messages (reducing PK-1012)
* kdb2mt: support reading gzip attachments
* kdb2mt: make ``--src-mbox`` option more useful by ignoring orphan stores when
  resolving. (Orphan stores can still be extracted with ``--src-guid``.)
* kdb2mt: make ``-s`` (splice) actually effective, by looking for the needed
  PR_IPM_SUBTREE property in the proper MAPI object.
* kdb2mt: added more folder mappings for splice mode (appointments, contacts,
  journal, notes, tasks, drafts) so that e.g. Drafts does get copied to Drafts,
  rather than making a new "Drafts" folder.
* kdb2mt: skip search folders on extraction (these are empty anyway)


1.1 (2021-08-17)
================

Changes:


* mt2exm: wait for pff2mt stream begin before connecting to exmdb
  so as to not run into a timeout
* mysql_adaptor: complain if there is an overlap between user and
  alias table


1.0 (2021-08-06)
================

Enhancements:

* Added an importer for Kopano databases, gromox-kdb2mt.
  This is meant to be used with gromox-mt2exm.
* ldap_adaptor: referrals in search results emitted by MSAD are now ignored.

Changes:

* gromox-pffimport was split into two programs that now need to be
  used as a piped combination, gromox-pff2mt and gromox-mt2exm.
* gromox-smtp has been renamed to gromox-delivery-queue.

Fixes:

* pffimport/pff2mt no longer aborts with assertion PF-1034/1038.


0.27 (2021-07-13)
=================

Fixes:

* oxcical: recognize calendar scale "LunarRokuyou"
* oxcical: fix PidLidIntendedStatus always being olTentative
* pam_gromox: fix NULL deref when the plugin is used
* Avoid double UTF-8 transformation by html_to_plain
* zcore: do not switch to Chinese when desired store language is unavailable

Changes:

* SIGHUP now reloads the exrpc_debug, rop_debug and/or zrpc_debug config
  directives.
* smtp: bump logmsg severity for rejected deliveries so that they become
  default-visible in journalctl.

Enhancements:

* exchange_emsmdb, zcore: store ownership bit (tentatively configured by
  setting owner on Top Of Information Store)
* oxcical: support for the olWorkingElsewhere busy status
* authmgr: implement "allow_all" auth mode
* authmgr: switch default mode to "externid"
* dbop: new db schema n77 to support sync policy of mobile devices


0.26 (2021-07-03)
=================

Fixes:

* exmdb_provider: cure "SELECT count(idx) ..." error messages
* exmdb_provider: fix nonfunctional recursive deletion of folders

Changes:

* config parser: reduce potency of the '#' character in config files /
  '#' only introduces a comment if it is at the start of line now.
  This allows for using '#' in the credentials for MySQL/LDAP.

Enhancements:

* pffimport: skip over broken attachments rather than abort
* pffimport: new -p option to dump properties in more detail
* pffimport: translation of named properties is now implemented
* pffimport: contacts, notes, tasks are now handled
* pffimport: new -s option to splice PFF folders into existing mailbox
* exmdb_provider: requests to set the read flag are now honored
* authmgr, ldap_adaptor, mysql_adaptor: config is now reloaded on SIGHUP


0.25 (2021-05-09)
=================

Fixes:

* http: fix a garbage return code in the emsmdb logon procedure
* zcore: fix a use-after-free crash when opening the addressbook
* event: speedier shutdown of service


0.24 (2021-05-31)
=================

Enhancements:

* zcore: new config directive "zrpc_debug"
* exchamge_emsmdb: new config directory "exrpc_debug"

Fixes:

* imap: fix standard folders' garbled name display (Sent Items, Junk, etc.)
* authmgr: quench stray password resets to the SQL DB
* pffimport: skip over nonsensical bytes in Unicode string properties
* pffimport: skip over unknown nodes when doing tree-analyze (-t)
* tools: fix crash when /etc/gromox is unreadable
* Overquota events are now signalled with better error message
  in grommunio-web (MAPI_E_STORE_FULL rather than MAPI_E_DISK_FULL).

Changes:

* mysql_adaptor: first-time password functionality is now disabled by default;
  new config directive "enable_firsttimepw".
* mysql_adaptor: SHA512-crypt is now used.


0.23 (2021-05-13)
=================

Enhancements:

* New utility ``gromox-pffimport`` for importing PFF/PST/OST

Fixes:

* exchange_emsmdb: fix a crash upon retrieval of calculated properties
* lib: fix crash when zcore uses a zero-length name during
  zcore_callid::copyfolder


0.22 (2021-05-03)
=================

Enhancements:

* exch: implement send quota
* logthru: add logfile support, add an close-open-cycle on SIGHUP
  to facilitate external log rotation

Changes:

* mysql_adaptor: change default schema_upgrades action to "skip"
* exch: remove log_plugin service plugin
* exch: remove mod_proxy plugin

Fixes:

* midb: fix leftover debugging breakpoint infinite loop
* ldap_adaptor: fix null deref when LDAP server is away
* exmdb_provider: fix double-free on shutdown
* delivery: replace pthread_cancel calls, fixing a crash on shutdown


0.21 (2021-04-20)
=================

Enhancements:

* exmdb_provider, midb: emit log message when and which sqlite
  DB cannot be opened

Fixes:

* imap: do not advertise RFC2971 commands when so disabled
* imap: fix misparsing of {octet}-prefixed literals
* imap: quote folder names in LIST, LSUB, XLIST, STATUS results
* exmdb_provider: add a missing iterator advancements in message_rectify_message
* timer: avoid crash on shutdown
* midb: fix concurrent use of sqlite data structure
* midb_agent: speed up termination during midb connection trying


0.20 (2021-04-14)
=================

Enhancements:

* daemons: SIGHUP support / `systemctl reload` is now possible for
  a general reload action
* http: much speedier shutdown, and hence `systemctl restart`
* exchange_nsp: reload now causes the Outlook-facing AB cache to empty
* domain_list: reload now causes rereading of domain_list.txt
* alias_translator: reload now causes rereading of alias_addresses.txt
* adaptor: reload now causes immediate regeneration of all txt files
  that adaptor would normally generate only periodocally
* mysql_adaptor: the "schema_upgrades" config gained an option for "host:"

Fixes:

* exmdb_provider: the wrong store quota property was evaluated when
  copying/moving messages
* exmdb_provider: fix a mutex double unlock
* exchange_emsmdb: fix a crash during rop_getpropertiesall
* mod_proxy: fix an out-of-bounds access while parsing proxy.txt
* imap: fix a double-free that occurred during shutdown
* lib: fix use-after-destruction near ext_buffer_push_release


0.19 (2021-03-30)
=================

Changes:

* exmdb_provider: allow reduction of cache_interval down to 1s

Fixes:

* dbop: classes.filter column was not created on dbop -C
* exchange_emsmdb: fix integer multiplication overflow during quota check
* exchange_emsmdb: fix ftstream_parser_create running into EISDIR error
* exchange_emsmdb: fix read from uninitialized variable
* php-ews: send error messages to error log rather than stdout


0.18 (2021-03-26)
=================

Changes:

* http: Split some unspecific HTTP 500 errors into 500, 502, 503, 504.
* http: Incomplete RTF documents are now decoded rather than "Not Found"
  being emitted.
* mod_cache: added the /web path to the built-in defaults
* mod_fastcgi: fix php-fpm yielding Not Found for /web
* mod_fastcgi: changed the underlying path of the built-in rule for
  /web to /usr/share/grommunio-web
* The systemd .target units were removed

Fixes:

* zcore: moving mails between two stores had erroneously used the
  old mail folder's id for deletion and failed.
* daemons: Fix a crash when programs shut down before entering the mainloop.


0.17 (2021-03-06)
=================

Enhancements:

* http: Raise max_router_connections & max_rpc_stub_threads limits
  to cope with reconnect storms from midb and zcore.
* doc: manpage for autodiscover

Changes:

* all daemons: Disabled the ip6_container and ip6_filter plugins
  for now; the default settings block too many connections.

Fixes:

* http: fix crash when user_default_lang is unset
* imap: advertise STARTTLS when indeed supported
* all daemons: avoid rejecting IPv6 connections from long addresses


0.16
====
* Configuration that lived in ${datadir} was moved to /etc/gromox:
  cache.txt, exmdb_list.txt, event_acl.txt, fastcgi.txt, midb_acl.txt,
  proxy.txt, rewrite.txt, timer_acl.txt. Their presence is also
  optional now; built-in defaults will be used if absent.
* domain_list.cfg and user_filter.cfg are now optional


0.15
====
* ldap_adaptor: new "ldap_start_tls" config directive to control STARTTLS.
* exchange_nsp: deliver PT_MV_UNICODE properties to clients
* authmgr: new config directive "auth_backend_selection"
* oxcical: escaped commas in values were misparsed, now fixed
  ("TZID:Amsterdam\, Berlin\, etc.")
