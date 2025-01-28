Gromox 2.40 (2025-01-28)
========================

Fixes:

* zcore: avoid unwrapping Content-Transfer-Encoding twice for
  clearsigned S/MIME
* ews: calculate timezone offsets for local time only
* ews: deserialize no-content XML tags as empty strings rather than as absence
  of the element

Enhancements:

* imap, pop3: multi-server capability, replacing direct disk I/O by network
  RPCs to the exmdb storage backend


Gromox 2.39 (2025-01-21)
========================

Fixes:

* midb: resolve protocol mismatches with imap, pop3; resolves rejection of
  IMAP CREATE, POP3 PASS commands
* midb: synchronize "Answered", "Forwarded" and "Flagged" flags between
  MAPI and midb
* midb: pass message flag modification notifications
  (answered/forwarded/flagged/read/etc.) to imapd
* midb: stop producing the TRYCREATE response for every command
  (e.g. message deletion will not succeed even if a non-existing folder is
  created, because the message will obviously not be in an empty folder)

Enhancements:

* When using import tools, no longer overwrite PR_LAST_MODIFICATION_TIME with
  the current time; retain the original timestamp if one exists.
* mbop: new foreach.* command group which replaces for-all-users

Behavioral changes:

* The default value for the ``outgoing_smtp_url`` config directive changed
  to ``sendmail://`` (using postdrop rather than direct SMTP contact).


Gromox 2.38 (2024-12-07)
========================

Fixes:

* oxcical: ignore zero-length PidLidTimeZoneStruct on export rather than
  failing the operation
* freebusy: process events with recurrence patterns > 510 bytes
* mbop-get-freeubsy: respect the absence of start_time,end_time (-a/-b)
  parameters
* mapi_lib: support TNEF export of messages without PR_INTERNET_CPID
* email_lib: no longer reject import of time-based recurrent series (`RRULE`
  line with `UNTIL` specifier) with a single occurrence

Enhancements:

* midb: deal with folder changes that occurr during times when midb is not
  running
* exm2eml: add TNEF file export support

Behavioral changes:

* imap: reject creating extant folder
* midb: change M-COPY from a read-write cycle to server-side copy,
  thereby preserving mail headers from now on
* midb/imapd: folder names are now treated case-sensitive, just like MAPI did
  it already


Gromox 2.37 (2024-11-20)
========================

Fixes:

* exmdb: fix garbage being returned to clients when reading v1z files from cid/
* exmdb: stop an SQL error from appearing when `gromox-mbop recalc-sizes`
  is used on an empty store
* oxcical: evaluate all, instead of just two, STANDARD/DAYLIGHT tzprops for
  determining the relevant DST timezone
* ews: fix time elements, e.g. in OOF settings, always having value 1970-01-01
* email_lib: on vCard ingestion, treat ORG lines as the structured field that
  they are specified as, rather than as one text value
* exmdb_local: autovivify new named properties on delivery, fixing log message
  ``D-1220: cu_set_properties called with PR_NULL`` when ingesting a vCard
  message into an empty store via SMTP/LMTP
* dbop_sqlite: avoid use of the ``UNIXEPOCH`` function since it is not
  available in AlmaLinux 9
* lib: add missing chown call on newly-created logfiles to account for
  subsequent privilege separation

Enhancements:

* dscli: evaluate not just one AutoDiscover URL but multiple as the specifation
  asks for
* mbop: stop printing the help text multiple times when the "for-all-users"
  subcommand was used but options were rejected
* gromox-mbsize: new debug utility for mailbox size analysis
* gromox-tnef2mt: add support for importing standalone TNEF files

Changes:

* stderr being a tty previously overruled daemons' log_file
  directive such as http.cfg:``http_log_file=/somewhere.log``. This has now
  changed and http_log_file has precedence over any tty-ness of stderr.


Gromox 2.36 (2024-11-06)
========================

Fixes:

* ews: fix an ABA locking problem when EWS unsubscribe actions were processed
* genimport: fix a data juggling issue that led to mt2exm printing ``proptag …
  from input stream has no named property info``
* mbck: do not attempt to repair allocated_eids if repair mode was not
  selected, fixing mbck printing ``sqlite3_prep(INSERT INTO allocated_eids) …
  inside a readonly TXN``.
* exmdb: fix an issue where creating new messages-embedded-in-messages could
  lead to ``sqlite3_exec(… INSERT INTO messages … VALUES (65536, …): UNIQUE
  constraint failed: messages.message_id (19)``, for msgids very close to the
  end of the block
* mkprivate et al: fix an issue where force-overwriting databases would print
  ``database is locked``
* oxcmail: during conversion from RFC5322 to MAPI form, avoid generating a
  zero-length attachment for a zero-length mail

Enhancements:

* mbop: new commands "ping", "for-all-users", "echo-username"
* exmdb: faster process shutdown through parallelized closing of sqlite files
* exmdb: better location diagnostics for RO-RO transactions, for RW-in-RO,
  and ROLLBACK issues

Changes:

* exmdb: the default value for exmdb_provider.cfg:cache_interval (time until
  inactive sqlite files are closed) was reduced from 2h to 15min to curb system
  resource use
* exmdb: the default value for exmdb_provider.cfg:populating_threads_num
  (asynchronous search folder population threads) from 50 to 4 to curb system
  resource use
* exmdb: deactivate implicit integrity check when upgrading a mailbox's
  database schema, it takes too much time
* (Integrity checks can still be done offline with ``mkprivate -U --integ``)


Gromox 2.35 (2024-10-15)
========================

Fixes:

* alias_resolve: resolve nullptr deref crash
* ews: resolve nullptr deref crash
* mapi_lib: fix out-of-bounds access in PROBLEM_ARRAY::transform
* mapi_lib: rop_util_get_gc_value used the wrong mask, which caused
  "Change commit failed because the object was changed separately"

Changes:

* exmdb: let PR_ACCESS include permissions from all group memberships


Gromox 2.34 (2024-10-08)
========================

Fixes:

* php_mapi: cure crash occurring with mapi_getidsfromnames
* midb: resolve "inside a readonly TXN" warnings during message deletion
* exmdb: emit notifications only after SQL transactions are complete
* imap: resolve unstable EXPUNGE observability

Enhancements:

* exm2eml: do output named property map when -p is used
* exm2eml: show named property mnemonics when -p is used twice
* php_mapi: allow calling namedprop resolution functions with
  not just store objects, but also folder/message/attachment objects


Gromox 2.33 (2024-10-01)
========================

Fixes:

* oxdisco: serve TB Autoconfig XML without requiring authentication
  (clients do not expect it to be protected)
* oxcical: revert commit which evaluates different MAPI timezone properties to
  generate DTSTART/DTEND's TZID value

Enhancements:

* oxcmail: Implement MIME fragment joining for the construction of the
  contents of PR_HTML.
  That is, MIME parts which have declared ``Content-Type: multipart/mixed`` and
  where the first subpart of the Mixed container is ``text/html`` now trigger
  the creation of a "jumbo" HTML document where other subparts of types
  ``text/plain`` and further ``text/html`` from that container, are integrated.
* dscli: add --ac option to test Mail Autoconfig (what Thunderbird uses
  in leu of AutoDiscover)
* http: credential caching for HTTP Basic (config directive
  ``http_basic_auth_cred_caching``, defaulting to 60s)

Changes:

* The user_filter(4gx) plugin was replaced by a new implementation.
  user_filter.cfg is no longer read. New config directives (with new names)
  are in gromox.cfg.


Gromox 2.32 (2024-09-04)
========================

Fixes:

* mysql_adaptor: re-speedup queries that came to ran without an index
* mbop: make the "clear-profile" operation do clear g-web settings again
* zcore: workaround potential hang during shutdown

Enhancements:

* emsmdb, zcore: allow "Empty Folder" operations in public stores
* exmdb: increased verbosity during shutdown phase so it does not appear
  like a hang


Gromox 2.31 (2024-08-14)
========================

Fixes:

* freebusy: get_freebusy erroneously underreported occurrences for
  yearly occurrences
* freebusy: the get_freebusy routine erroneously landed in an infinite loop if
  a yearly-recurring February 29 appointment was originally created in a year
  not divisible by 12.

Enhancements:

* oxcmail: take /etc/mime.types under consideration when adding extensions
  to attachments

Changes:

* oxcmail: priorities for MIME parts have been rectified for
  multipart/alternative and non-alternative containers; the conversion routine
  is no longer making picks across multiple container siblings.


2.30 (2024-06-21)
=================

Fixes:

* exmdb: instace_load_message RPC with unsynthesizable properties will no
  longer yield an erroneous error
* exmdb: setting anonymous-ID permissions on folders was erroneously
  treated as wanting to set default-ID permissions and did not complete
* oxcical: emit VTIMEZONE for events without
  PidLidAppointmentTimeZoneDefinitionStartDisplay
* php_mapi: delete nonsensical return types from function stubs used for
  introspection
* Set syslog process names (meaningful for non-glibc platforms)
* pam_gromox: resolve a use-after-free when the module is invoked twice
  in a row (as is the case with e.g. saslauthd)
* exmdb: resolve use-after-free/crash on process shutdown (search folder
  shutdown)

Enhancements:

* gromox-mbop: new subcommand ``set-locale`` to change store language
* exmdb: add more SQLite transactions and make concurrent read access for
  stores possible
* ruleproc: initial autoprocessing for meeting requests
  * conflict detection, response sending for conflicts,
    automatic addition to calendar
  * needs to be enabled with gromox.cfg:``lda_mrautoproc``=yes
* imap, pop3, delivery-queue: HAProxy protocol support (send-proxy-v2)
* zcore: show private distribution lists the grommunio-web address book


Gromox 2.29 (2024-06-04)
========================

Fixes:

* dnsbl_filter: support DNSBL servers that do not emit TXT records
* email_lib: cure IMAP Structure Descriptions indicating a mail size 2 bytes
  larger than it is
* imap: cope with truncated EML files
* exmdb: delete leftover stray ROLLBACK statement
* ews: cure null dereference in tInternetMessageHeader::parse
* ews: use vmime parser to break down IMHs and reset an Apple workaround for
  "From" lines

Changes:

* emsmdb: attempt to synthesize PR_SENDER_ADDRTYPE &
  PR_SENT_REPRESENTING_ADDRTYPE when they are missing (also warn when those
  properties are deleted)


Gromox 2.28 (2024-05-02)
========================

Fixes:

* exmdb: set PR_DELETED_ON property during softdelete
* imap: repair messages not getting added to midb during 64K+ append
* imap: cure client session hang when midb failed to add
  a mail during 64K-append
* mysql_adaptor: gracefully handle attempts to use Unicode in usernames
  (treat as non-existing user rather than failing the user lookup altogether)
* zcore: a crash on shutdown was addressed

Enhancements:

* mysql_adaptor: allow Unicode in alternate usernames (altnames)
* Populate PR_DELETED_ON property for softdeleted items
* exmdb: ``exmdb_rpc_debug`` will now emit execution time for EXRPCs
* zcore: ``zrpc_debug`` logging now includes the session GUID
  to help correlate which ZRPCs are executed by which user
* imap: ``imap_cmd_debug`` logging now includes the client IP address
  to help correlate which actions are executed by which user
* pop3: ``pop3_cmd_debug`` logging now includes the client IP address
  to help correlate which actions are executed by which user

Changes:

* remote_delivery.cfg is obsolete! If you need an SMTP relay for outgoing mail
  (and you do not have a local postfix to take care of that), you should set
  gromox.cfg:outgoing_smtp_url.


Gromox 2.27 (2024-04-07)
========================

Fixes:

* email_lib: avoid splitting UTF-8 code units across lines
* imap: avoid emitting NIL for body-fld-lines

Enhancements:

* php_mapi: expose default+anonymous ACEs to PHP programs
* zcore: expose new PR_EC_ENABLED_FEATURES_L property
* ews: implement updating folder permissions
* eml2mt: emit a hint if an Outlook .msg file is erroneously passed to eml2mt

Changes:

* exch: start ICS Change Numbers at 0 rather than 2^47
  (new mailboxes only)
* PR_MAILBOX_OWNER_ENTRYID is generated for public stores
* exmdb database layer remodeled to support concurrent reads per mailbox in
  the future


Gromox 2.26 (2024-03-11)
========================

Fixes:

* exmdb: Fix restriction mismatching on ``PR_PARENT_SVREID`` &
  ``PR_PARENT_ENTRYID``, which had caused reminders to go off even after
  appointments were moved to the wastebasket.
* exmdb_local: rectify wrong/empty ``From:`` lines in bounce messages
* ews: fix segfault when loading public folder item
* zcore: repaired thumbnail retrieval, which used the wrong directory

Enhancements:

* mbop: add subcommands for manipulating websettings_persistent

Changes:

* zcore: store websettings_persistent directly in the store rather than
  the zcore shadow store object (automatic migration is in place)
* kdb2mt: avoid importing ``PR_EC_WEBAPP_PERSISTENT_SETTINGS_JSON``


Gromox 2.25 (2024-02-29)
========================

Fixes:

* mkpublic: newly created public stores lacked a ``replguidmap`` table
* exmdb: repair initialization of PR_ATTACH_NUM when instances are opened
* oxcmail: strip leftover right angled bracket from Content-ID on
  oxcmail_import
* http: do not terminate if an illegal ``outgoing_smtp_url`` is used
* http: avoid garbage From line in non-delivery reports generated by
  OP_BOUNCE rules

Changes:

* oxcmail: export no longer generates a MIME epilogue, which should
  workaround Outlook's broken S/MIME validator which fails to include
  epilogues in the signature verification.
* http: recognition for the ``http_old_php_hanlder`` directive
  has been removed
* zcore: g-web settings are now stored in a named property rather than the
  shadow store object (automatic migration is in place)

Enhancements:

* mt2exm: the -B option can be used with all folder names
* mbop: new commands ``get-photo``, ``set-photo``, ``get-websettings``,
  ``set-websettings``


Gromox 2.24 (2024-02-10)
========================

Fixes:

* email_lib: the last byte of a MIME part was erroneously deleted
* emsmdb: repair garbage memory read when creating a stream on a PT_STRING8
  property
* ews: repair a potential lack of results with the ResolveNames operation
  when searching by email address

Enhancements:

* ews: add t:AlternateIdType attribute


Gromox 2.23 (2024-02-05)
========================

Fixes:

* snapshot: on btrfs, fallback to rm when encountering reflink-based snapshots
* oxcmail: make PR_REPLY_RECIPIENT_NAMES be consistent with _ENTRYIDS
* oxcmail: deal with semicolons in Reply-To
* oxcmail: do not ignore IDN addresses when reading headers
* oxcmail: resolve a case with trashed body bytes when a line began with dot

Enhancements:

* exmdb: add config directive ``exmdb_contention_reject_time`` for configuring
  contention timeout
* exmdb: have DB_ITEM instances track which function holds them, and report
  this upon reaching contention timeouts
* exmdb: make dbg_synth_content work with read_message RPC
* new command: gromox-exm2mt


Gromox 2.22 (2024-01-29)
========================

Fixes:

* exmdb_client: discard connections when EOF is detected
* mda: resolve a case where four extra bytes of garbage were be added to the
  front of the first transport header (usually the unimportant "X-Lasthop")
  when the first delivery attempt had failed and redelivery was tried
* mda: resolve a case with one extra byte of garbage added to the
  PR_TRANSPORT_MESSAGE_HEADERS MAPI property
* mda: resolve a case with trashed body bytes when a line began with dot
* ews: proper CN generation for public store objects
* http: reduce overreporting of E-5310
* oxcmail: drop unintended doublequotes around RFC 2047-style =?..?=
  encoded-words

Enhancements:

* oxcical: support emission of iCalendar VFREEBUSY objects
* nsp,ab: support name resolution of IDN addresses
* twostep_ruleproc: support Outlook-style public folder entryids in Move/Copy
  rules (as opposed to GWeb-style entryids)
* daemons: report when time-based config directive are lacking units


Gromox 2.21 (2024-01-08)
========================

Fixes:

* exch: fix nonsensical compare operation in check_message_owner
* lib: guard against an integer overflow when inserting last element in range_set
* imap: do not flag zero-length usernames/passwords as a syntax error
* exmdb: avoid showing E-5310/5311 for absent files

Enhancements:

* Support for outgoing message submission via postdrop. Use the new config
  directive ``outgoing_smtp_url=sendmail://localhost`` in gromox.cfg.
* gromox-snapshot: Support snapshots on XFS
* zcore: log REMOTE_ADDR on authentication failure for fail2ban
* ews: improve contact item and task item support
* php-mapi: add ``mapi_getuserfreebusyical`` function
* exmdb: add ICS request dumper (config directive
  gromox.cfg:``exmdb_ics_log_file``)

Behavioral changes:

* kdb2mt: remove option aliases that have been deprecated for a year


Gromox 2.20 (2023-12-15)
========================

Fixes:

* oxdisco: allow autodiscover for room/equipment stores
* oxcical: allday events are now emitted (pursuant to the
  ``oxcical_allday_ymd`` config directive) as "floating time" per the OXCICAL
  spec recommendations
* oxcical: resolve integer underflow that botched weekorder
  computation in weekly-recurring events
* oxcical: resolve out-of-bounds access during generation of iCal RDATE lines
* ews: avoid a heap-use-after-free during freebusy retrieval
* zcore: zs_getuserfreebusy had failed to resolve usernames
  and display freebusy status in the scheduling matrix view
* ldap_adaptor: resolve data race with double-free when per-organization LDAP
  settings were used

Enhancements:

* ews: improve calendar item coverage for mac calendar app
* all daemons: add various config directives to set file descriptor table
  limits
* zcore: add new error code and string for when the MAPI object handles have
  been exhausted by a user (as will normally happen when importing a
  multi-vCard/multi-iCal file with 400+ contacts/events, due to config
  directive ``zcore_max_obh_per_session``)

Behavioral changes:

* http: the file descriptor table limit is by default set to the environment
  hard limit (instead of 2256 fds, one will have 512K in Linux-systemd
  environments now)
* php_mapi: do not convert freebusy_event_details fields which are not available


Gromox 2.19 (2023-12-04)
========================

Fixes:

* exmdb: send "object created" notifications as search folders re-populate
* oxcmail: ignore zero-length From fields, which should help sending from
  Windows Mail
* Thunderbird/IMAP now picks up deletion events done by other clients
* imap placed eml files in the wrong spot.
  You may need to `mmv /var/lib/gromox/user/X/Y/eml1*
  /var/lib/gromox/user/X/Y/eml/1#1` for the various user directories.
* imap: the IMAP STATUS command did not cause any immediate response
* imap: announce EXPUNGE events on all typical commands
* imap: avoid double-reporting EXPUNGE events on EXPUNGE command
* http: resolve altnames and update user context after authentication success
  with krb
* ews: resolve crash during CreateItem RPC

Enhancements:

* `gromox-mbop emptyfld` now recognizes a `-t` option to limit deletion to
  messages of certain age.
* `gromox-mbop emptyfld` now recognizes a `--nuke-folders` option
* gromox-eml2mt now recognizes a `--mbox` option to support RFC4155 Unix mboxes
* exmdb: search pacing is now time-based, which should give more predictable
  interactivity during background searches
* emsmdb: do not treat the absence of the PR_LAST_MODIFICATION_TIME message
  property during ICS downloads as an error any longer

Behavioral changes:

* oxcmail: zero-length headers are ignored altogether (inspired by Alpine's
  behavior in that regard)
* daemons: repeal the allocation limiter function from source code;
  all "The buffer pool %s is full" messages should be gone now


Gromox 2.18 (2023-11-27)
========================

Fixes:

* exmdb: synthesized PR_RTF_COMPRESSED properties (in relation to the
  "dbg_synthesize_content" config directive) had an incomplete header
* oxcmail: repair inadvertent propid/proptag swap causing TNEF export to fail
* mbop/purge-softdelete: make pathspec `SENT/2022` actually work
* imap: messages delete events from OL/g-web now make it to IMAP clients

Enhancements:

* midb: propagate folder change events; IMAP clients now recognize when a
  message was deleted in g-web/Outlook
* http: RFC 7617 support for the Basic authentication header line
* nsp: allow connections from Windows with UTF-8 locale
* midb: removal of seqid renumbering, which speeds up
  IMAP SELECT/LIST/FETCH commands.
* authmgr: PAM is now offered as an authentication backend


Gromox 2.17 (2023-11-11)
========================

Fixes:

* http: repair hanging communication with MAPI/RPC connections
* oxcmail: reinstate read requests for non-IPM.Schedule messages
* daemons: set umask such that created files have group write
  permissions for AAPI
* imap/midb_agent: fix a crash when some JSON files are empty
* midb: avoid a hang during the P-DTLU command when an eml/ file is absent
* mkprivate, mkdomain: repair wrong byte ordering in initial PR_CHANGE_KEYs

Enhancements:

* http: Windows SSO support via HTTP Negotiate authentication
* daemons: support for alternate login names
  (this allows for assigning shorter usernames for grommunio-web)
* exmdb: augment create_folder and movecopy_folder RPCs with a 32-bit error
  code, which allows g-web to better detect folders with duplicate names
* ews: implement Subscribe, Unsubscribe, GetEvents, GetUserPhoto
* mbop: add subcommand `clear-rwz` to clear out RuleOrganizer FAI messages

Behavioral changes:

* exmdb: the delivery_message RPC will now return with status "partial_write"
  if major parts of a message (body/attachments) could not be written
  (disk full/permission denied/etc.)
* delivery: partially-written messages now lead to bounce generation and
  emergency save action to disk


Gromox 2.16 (2023-10-29)
========================

Fixes:

* oxvcard: export to .vcf now positions the VERSION property in accordance with
  the vCard 4.0 specification.
* oxcmail: cease gratuitous RTF conversion of calendar items
* mysql_adaptor: a wrong string search was used for recipient delimiters,
  which could lead to Recipient Invalid/User Not Found

Enhancements:

* Define the "suspended" user state (think of it as a "non-receiving shared
  mailbox").
* emsmdb, zcore: the ``emsmdb_max_cxh_per_user``,
  ``emsmdb_max_obh_per_session`` and ``zcore_max_obh_per_session`` config
  directives can now be set to 0 for unlimited.


Gromox 2.15 (2023-10-18)
========================

Fixes:

* imap: do not emit continuation request on LITERAL+
  (now also for large literals >64K)
* exmdb: ignore softdeleted folders when validating new folder name
* exmdb: explicitly rollback SQLite transactions when the commit operation
  failed, to resolve cases of ``cannot start a transaction within a
  transaction``
* exmdb: ACE entries for anonymous were misreported to clients

Enhancements:

* delivery: support for plus-addresses/recipient delimiters,
  e.g. <user+extension@example.com>
* delivery: new config directive ``lda_recipient_delimiters``
* mbop: new subcommand ``recalc-size`` to recalculate store size

Changes:

* alias_resolve: config directives are no longer read from
  ``/etc/gromox/alias_resolve.cfg`` but now from ``/etc/gromox/gromox.cfg``
* oxcmail: do not emit Content-Disposition creation-time/modification-time
  parameters when those fields are not present in the MAPI object
* Delete unused columns and indexes from the ``associations`` MariaDB table;
  (grommunio-admin-api should be updated to >= 1.12)

Last-minute notes:

* When gromox-dbop attempts to upgrade to table schema version 127, an SQL
  query is issued to set a new PRIMARY KEY on a table. It has been brought to
  our attention that somewhat older MariaDB server versions (namely 10.4.13,
  10.4.22) contain a bug/not_implemented_feature which makes this query never
  succeed. The issue is resolved in MariaDB 10.6.15 (as used by the Grommunio
  Appliance) and newer versions. Details are still under investigation.


Gromox 2.14 (2023-10-04)
========================

Enhancements:

* daemons: better SSL_accept error log messages
* alias_resolve: support for nested mlist expansion
* alias_resolve: support for Global Contact Objects
* delivery: SIGHUP triggers a reload of (more) plugins now
* gromox-mbop: add emptyfld options -a, -M

Fixes:

* oxdisco, oab: avoid emitting extraneous NUL byte at end of XML document
* imap: do not emit continuation request on LITERAL+
* mbop: restore emptyfld functionality after switch to empty_folder v2 RPC
* mbop: ``delmsg -f DRAFT 12345`` did nothing due to a bad translation
  of the special name


Gromox 2.13 (2023-09-23)
========================

Enhancements:

* emsmdb: eliminiate duplicate message appearing when copying to a
  private non-default / shared store
* EWS: support the {Create,Delete,Move,Copy,Update,Empty}Folder operation(s)
* EWS: support the {Copy,Move}Item operation(s)


Gromox 2.12 (2023-09-04)
========================

Enhancements:

* ews: support CreateItem, DeleteItem, SendItem requests
* oxm2mt: support multi-valued properties

Fixes:

* kdb2mt: do not abort when --src-mbox is used
* exmdb_provider: opening the detail view of Personal Addressbook entries now
  works in Outlook, as does selecting them as message recipients
* zcore: fix a flaw in permissions dialog that caused the delegates
  to be able to see the private items of the delegator

Behavioral changes:

* exch: remove old PHP EWS handler
* zcore: delete getuseravailability RPC and replace by new getuserfreebusy RPC


Gromox 2.11 (2023-08-21)
========================

Enhancements:

* exmdb: attachment storage with hash-based filenames
* exmdb_local: persistent (on-disk) last-autoreply time tracking
* imap: allow large literals with APPEND
* imap: add RFC 7888 support
* oxdisco: allow AutoDiscover information retrieval from secondary
  mailboxes even if the scndstore_hints table does not have an entry.
* emsmdb: "Mark all as read" in OL (Online mode) now works

Fixes:

* oxcical: resolved another case of recurring appointments shifting due to
  timezone/daylightbias
* exmdb_provider: resolve constraint failure on movecopy_messages
* email_lib: add back CRLF when MIME::read_head is reconstructing headers
* mapi_lib: resolve an infinite loop during html_to_rtf
* exmdb_provider: ignore absent directories during `gromox-mbop
  purge-datafiles`
* exmdb_provider: make exmdb_pf_read_states=1 hide folder sumamry counts
  as advertised by manpage
* zcore: delegation dialog had erroneously set too many permission bits

Changes:

* exmdb_client: disable timeout during active calls
* delivery: raise context_average_mime limit from 8 to 500
* nsp: drop "custom address list" name suffix from mlists


Gromox 2.10 (2023-06-15)
========================

Fixes:

* imap: restore notifications during IDLE
* midb: do not present softdeleted messages to IMAP
* zcore: validate permissions when inbox rules or folder permissions are edited
* lda_twostep_ruleproc: resolve array out-of-bounds access when
  resolving named properties
* snapshot: switch back to root user identity to be able to purge snapshots

Enhancements:

* DNSBL filtering mechanism, cf. ``man dnsbl_filter``
* Address book name resolution now evaluates alias addresses
* pff2mt: speedup operation by 70%+
* emsmdb: strike limits (raise to infinity) for session handles, user handles
  and notify handles, and raise limit for ems_max_pending_sesnotif to 1K
* emsmdb: new configuration directives ems_max_active_notifh,
  ems_max_active_sessions, ems_max_active_users, ems_max_pending_sesnotif
* mbop: new subcommands ``clear-photo``, ``clear-profile``,
  ``purge-softdelete``, ``purge-datafiles``

Changes:

* The PHP-MAPI profile is now stored in the mail store as a property
  rather than as a flat file. The upgrade is automatically performed
  when the MAPI profile gets modified via PHP-MAPI.
* The user profile picture is now stored in the mail store as a
  property rather than as a flat file. The upgrade is automatically
  performed when the photo is modified via PHP-MAPI.
* ``/usr/libexec/gromox/cleaner`` is obsolete and replaced by mbop subcommand
  ``purge-datafiles``.


Gromox 2.9 (2023-05-10)
=======================

Fixes:

* zcore: plug memory leak when address book data structure reloads
* zcore: fix inverted evaluation of RES_CONTENT::comparable
* zcore: moving messages from one store to another obtained CNs
  from the wrong store and could fail the operation
* oxcical: add TZID for allday events
* imap: consistently show EXISTS status before RECENT
* imap: move EXISTS/RECENT response after SEARCH result
* imap: skip reporting EXISTS/RECENT if folder is unchanged
* imap: make FETCH RFC822 report FLAGS as well
* imap: SEARCH by size used the wrong column
* imap: avoid double status reporting when one message is changed multiple times
* imap: add and populate a per-context seqid list
* midb: unbreak search matching based on dates and sizes
* imap: cease emitting extraneous FETCH FLAGS responses
  (works around a shortcoming in the KDE kmail client)
* imap: resolve E-1995 erroneously showing when memory use is fine
* emsmdb: avoid hitting an assertion when sort-reloading a table of a
  deleted folder

Enhancements:

* emsmdb: support forwarding meeting requests from organizers
  that are not local to the installation
* imap: broadcast changes to mailbox from EXPUNGE commands
* midb: auto-regenerate ext/ digests when missing
* Log the filename of the SQLite database when a query fails
* emsmdb: add log messages for notification queue limits


Gromox 2.8 (2023-04-15)
=======================

Fixes:

* exmdb_provider: repair a 4-byte cutoff when reading PR_BODY,
  PR_TRANSPORT_MESSAGE_HEADERS if they are compressed on disk
* emsmdb: setting multiple mails as read/unread was repaired
* php_mapi: fix a case where proptag arrays had bogus keys
* midb: resolve a crash when a P-SRHL HEADER search has not enough arguments
* zcore: do not lose folder for OP_MOVE rules when that folder is
  in a public store
* mda: the DATA command in LMTP mode did not emit one status line
  for every RCPT
* nsp: fix janky addressbook navigation when the GAL has hidden entries
* authmgr: resolve altnames before searching them in the LDAP backend
* php_mapi: reduce memory block retention scopes so that requests with a large
  response (~128MB+) won't die from Out Of Memory
* midb: fix E-1903 error appearing on shutdown

Enhancements:

* The "Hide from addresbook" functionality has gained another bit, so that name
  resolution ("Check names" button in OL/g-web) is no longer tied to visibility
  in the GAL.
* Support for non-default stores in the IMAP and POP3 protocols;
  use "actualusername!sharedmbox" as the username for login.
* imap: allow setting \Recent flag with STORE command
* imap: send TRYCREATE on failed SELECT
* imap: output \Junk alongside \Spam for the junk folder
* imap: emit special-use flags with plain LIST when so requested in the command
* imap: add LIST response to SELECT/EXAMINE
* pff2mt: add --with-assoc, --without-assoc

Changes:

* daemons: the files /etc/gromox/exmdb_acl.txt, midb_acl.txt, event_acl.txt,
  timer_acl.txt were made obsolete and replaced by the new (exmdb_provider.cfg)
  "exmdb_hosts_allow", (midb.cfg) "midb_hosts_allow, (event.cfg)
  "event_hosts_allow", (timer.cfg) "timer_hosts_allow" directives.
* http: adjust the built-in PHP-FPM socket paths to reflect changes in
  g-web and g-sync (this impacts test setups that run gromox-http without an
  nginx in front)
* mda: update "Received" headers in messages to look more like Postfix's
* pff2mt: --without-assoc is now the default
  (This is only a concern with .ost files, as .pst does not have FAI messages.)


Gromox 2.7 (2023-03-24)
=======================

Fixes:

* mbop: support folder strings for delmsg -f as was documented
* oxcmail: do not fail exporting DSNs with unresolvable addresses
* oxcical: do not fail exporting calendar objects with unresolvable addresses
* oxvcard: repair NULL deref when exporting PR_CHILDRENS_NAMES
* exmdb_provider: support mbox_contention_*=0 as was documented
* gromox-snapshot: safer parsing of snapshot.cfg
* emsmdb: resolve infinite loop when counting property value size of
  invalid UTF-8 strings

Behavioral changes:

* exmdb_provider: default to mbox_contention_reject=0
* exch: support absent values with RES_PROPERTY, RES_BITMASK and
  RES_CONTENT comparisons
* zcore: make mapi_message_imtoinet operate on message instances, not messages


Gromox 2.6 (2023-03-10)
=======================

Fixes:

* exmdb_provider: filter duplicate propids when they occur in the mailbox,
  resolving a failure to export (broken) recipients to MSG,
  and resolving _one_ instance of OL sync error 80070057.
* oxvcard: PidLidBusinessCardDisplayDefinition named property was not
  assigned the right namespace (PSETID_Address)
* oxcmail: do not abort export routine if SMIME message is lacking an SMIME
  body (just treat it as empty instead)
* oxcical: do not abort export routine if IPM.*.Resp.* has no attendee
* exmdb_local: perform online lookup of named properties,
  resolving vcarduid being erroneously assigned propid 0
* exmdb_provider: do not write propid 0 properties to database
* midb, imap: FETCHing some mails did not function due to a misparse of the
  compat format of the "mimes" structure in mjson_parse_array
* mapi_lib: rectify emission of \cf code in htmltortf
* delivery: reduce number of default worker threads to number of client
  connections to temporarily address "too many connections"
* delivery: retain queue messages on processing errors
* mlist_expand: resolve null dereference during mlist_expand

Behavioral changes:

* delivery: rename delivery_log_file -> lda_log_file (+ log_level)
* Errors from sqlite3_step() will now be logged.
* exch: consistently accept PT_STRING8 & PT_BINARY for RES_CONTENT evaluations


Gromox 2.5 (2023-03-06)
=======================

Fixes:

* Repair a null deref during HTML-to-text conversion
* Inbox rules had RES_OR conditions wrongly evaluated
* Synchronization of embedded messages now works,
  resolving OL sync reports with error 80040301.
* Saving a draft in grommunio-web would erroneously strip the Re: subject prefix
* exmdb_provider: PR_NULL is now excluded from get_all_proptags's results,
  resolving _one_ instance of OL sync error 80070057.
* EWS: Detailed FreeBusy requests did not return detailed info

Enhancements:

* authmgr: Alternate username support
* mt2exm: add --skip-notif, --skip-rules options

Behavioral changes:

* Treat standard and extended inbox rules equal per PR_RULE_SEQUENCE, instead
  of "(by sequence number) all standard rules first, then all (by sequence
  number) extended rules".
* The build no longer depends on the gumbo-parser library
  (a HTML parser); instead, it now uses libxml2 to do the same.
* daemons: disable client-side TLS renegotiation in OpenSSL 1.x and LibreSSL
  (OpenSSL 3.x defaults to this behavior already)
* php_mapi: block opcache from being present in the same process


Gromox 2.4 (2023-02-26)
=======================

Enhancements:

* php_mapi: add new functions "nsp_essdn_to_username" and "mapi_strerror"
  (requires new version of mapi-header-php which does not provide a
  now-colliding variant)
* mbop: emptyfld/delmsg support folder names now
* dscli: added an --eas option
* oxdisco: support autodiscover.json requests
* exmdb_provider: report overquota events with MAPI_E_STORE_FULL
  rather than MAPI_E_DISK_FULL

Fixes:

* php_mapi: fix stack corruption in zif_mapi_createfolder
* exmdb_provider: resolved possible use-after-free in OP_DELEGATE rule handling
* emsmdb: fix stream_object::commit evaluating wrong member for open flags
* Parse Windows timezone list better and support multiple IANA timezone names
  per territory

Behavioral changes:

* exmdb_provider: enable CID file compression by default
* exch: remove old PHP-OXDISCO and PHP-OAB implementation


Gromox 2.3 (2023-02-03)
=======================

Enhancements:

* pff2mt: support non-Unicode PFF files
* ldap_adaptor: read ldap_start_tls, ldap_mail_attr from orgparam table
* Support Emojis in HTML-to-RTF conversion code
* exmdb_provider: implement message store softdelete count properties
* dbop_sqlite: guard schema upgrades with transaction

Fixes:

* Do not fail entire HTML-to-RTF conversion or calls like
  getpropvals(PR_RTF_COMPRESSED) when encountering garbage bytes.
* exmdb_provider: have folder message count properties respect softdelete
* zcore: mapi_copyto had inverted meaning of MAPI_NOREPLACE

Implementation changes:

* Replace custom SMTP sending code with vmime's
* emsmdb: temporarily deactivate ROP chaining for OL2013,2016 to work
  around a case where OL corrupts larger attachments (2 MB+)


Gromox 2.2 (2023-01-16)
=======================

Behavioral changes:

* The /usr/libexec/gromox/rebuild utility has been removed in favor
  of using SQLite's own `.clone` / `.recover` commands.
* dbop_sqlite: perform integrity check ahead of sqlite database upgrades

Fixes:

* emsmdb: sending mail could have yielded success even if there was
  an outgoing SMTP server outage
* exmdb_provider: repair SQL logic errors showing up when a folder's
  contents are requested in Conversation mode
* exmdb_provider: only delete links, not messages, from search folders

Enhancements:

* tools: add --integrity option for mkprivate, mkpublic, mkmidb


Gromox 2.1 (2023-01-12)
=======================

Behavioral changes:

* exmdb_provider: the "exmdb_schema_upgrade" config directive is
  now enabled by default
* midb: the "midb_schema_upgrade" config directive is now enabled by default
* exmdb_provider: increase default value for the "max_store_message_count"
  directive from 200k to infinity
* mkmidb: removed the no-op -T command-line option
* dscli: XML dumps are now only shown with the (newly added) -v option

Enhancements:

* exmdb_provider: support for private store message and folder softdelete
  (and thus the Recover Deleted Items feature in OL)
* http: print HTTP responses in full, not just until the first \0
* mapi_lib: parse "Received" headers into PR_MESSAGE_DELIVERY_TIME for the
  sake of EML imports
* oxm2mt: named property translation
* oxdisco: homeserver support for EAS block
* zcore: allow opening oneoff entryids with openabentry RPC

Fixes:

* emsmdb: work around OL crash with Recover Deleted Items dialog
* emsmdb: rework interpretation of PR_SENT_REPRESENTING on
  IPM.Schedule objects (relates to the organizer of a meeting when such
  meeting is forwarded)
* Deletion of a folder from a public store did trash the store size counter and
  reduce it by an arbitrary amount towards 0, reporting the store to be smaller
  than it really was.
* zcore: perform texttohtml conversion in UTF-8 not Windows-1252
* nsp: attempt to fix infinite function recursion when trying to resolve
  ESSDN which are present in the GAB forest but out-of-organization
* oxcmail: recognize RFC822/5322 dates without a day-of-week part
* mt2exm: avoid running into PF-1123 error when -D option is used
* dscli: repair the warning that the tool was not built with DNS SRV support
* oxdisco: avoid read beyond end of buffer when request_logging is on
* exmdb_provider: fix an out of bounds write when PR_HTML_U is requested


Gromox 2.0 (2023-01-03)
=======================

Enhancements:

* gromox-mbop: added "emptyfld" command
* gromox-oxm2mt: new utility to read .msg files

Fixes:

* midb: IMAP SEARCH commands had numeric sequence ranges "m:n" misparsed
* midb, imap: recognize "*" in sequence sets (alias for "*:*")
* nsp: resolve a wrong allocation size that led to a crash

Changes:

* oxdisco: new module providing the AutoDiscover endpoints,
  replacing the PHP-based implementation
* oab: new module providing the OAB endpoint
* ews: new module providing the EWS endpoint,
  replacing the PHP-based implementation
* delmsg: program has been merged into gromox-mbop as a subcommand
* emsmdb: rework interpretation of the PR_SENT_REPRESENTING_* proptags on
  meeting request objects


Gromox 1.37 (2022-12-18)
========================

Enhancements:

* kdb2mt: full user resolution with new option --mbox-name/--user-map
* kdb2mt: translate PR_*_ADDRTYPE from ZARAFA to SMTP (via --user-map)

Fixes:

* kdb2mt: repair printing of tree graphics when ACL lists are dumped with -t -p
* Fixed a parsing inconsistency between LF and CRLF mail input
* zcore: support on-the-fly EML (re-)generation in zs_messagetorfc822
* zcore: allow zs_linktomessage RPC if store permissions allow for it
* emsmdb: avoid synchronizing PR_PREVIEW

Changes:

* kdb2mt: rename SQL parameter options
* kdb2mt: rename mailbox selection options
* kdb-uidextract: new output format
* kdb2mt: add new --acl option for fine-grained control over ACL extraction
* nsp: avoid generating ephemeral entryids from ResolveNamesW
  (Selecting addresses from the "From" dropdown in OL's
  compose mail dialog works now)
* zcore: reduce threads_num to below rpc_proxy_connection_num
  (Addresses "exmdb_client: reached maximum connections ...")
* emsmdb: stop syncing named props on folders to OL
  (it does not support them anyway)


Gromox 1.36 (2022-12-09)
========================

Enhancements:

* exmdb_provider: on-disk content file compression, controllable using
  the "exmdb_file_compression" config directive (affects only new files)
* tools: new utility `gromox-compress` to compress existing content files
* exmdb_provider: support evaluation of inbox rules that have RES_CONTENT
  restrictions with PT_BINARY properties

Fixes:

* Asynchronous notification over MH was not responsive due to a malformed
  HTTP response, which was fixed.

Changes:

* Bounce template generation was rewritten for size
* mysql_adaptor: silence PR_DISPLAY_TYPE_EX warning for admin user
* emsmdb: let ropSaveChangesMessage return ecObjectDeleted
* exmdb_provider: set PR_RULE_ERROR property when Deferred Error Messages
  (DEMs) are generated
