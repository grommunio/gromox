Gromox 3.3.139 (Development)
===========================

Enhancements:

* mbop: new "zaddrxlat" command
* delivery: add pre-delivery junk shelving and ``lda_junk_rules``
  config directive
exmdb_local: replace direct disk I/O with imapfile_read/write EXRPCs

Fixes:

* mrautoproc: server-side processed meeting requests automatically entered into
  the calendar had lacked the flags asfMeeting+asfReceived, which was fixed.
* nsp: seeking backwards with the seekEntries routine jumped too far backwards,
  causing the last screenful of the Outlook GAL to be misrepresented.
* oxcmail: the "Keywords:" RFC5322 header (Categories) used to get filled with
  text garbage, which is now fixed.
* zcore: plug a memory leak occuring when importing vCards
* Any data, when converted from windows-1255 or 1258 character set to Unicode,
  sometimes lost the last character in the conversion, which has been fixed.

Changes:

* oxcmail: limit nesting depth of attachments during export to 7
* oxcmail: RFC 5322 header fields are now treated as US-ASCII as mandated,
  and no longer magically assumed to be in the same charset as the body.
* exporter: FAI messages are no longer emitted by default and explicitly need
  to be requested with the -a option.
* daemons: deleted the oxcical_allday_ymd config directive


Gromox 3.3 (2025-12-27)
=======================

Enhancements:

* oxvcard: include photo when converting MAPI contact objects to VCARD
* exporter: support export of multiple messages to GXMT
* exporter: support for folder export to GXMT
* importer: support a read-only mode
* exmdb: include RTF in the cross-body format synchronization when the message
  is saved, making Outlook Notes or Outlook Contact notes display something in
  grommunio-web and other clients
* exmdb: new read_delegate/write_delegate EXRPCs so that delegates.txt is no
  longer accessed via filesystem
* exch: allow user sending mail with From: line set to own aliases
* mysql_adaptor: regard aliases for user_ids and displayname
* midb: log when incoming connection count has been reached
* ews: recognize <TimeZoneContext> elements located in the SOAP header

Fixes:

* ews: avoid sending newly created message items when message invitation flag
  is set
* zcore: obtain freebusy information for own mailbox using owner mode, so that
  setting e.g. the "default" ACL default for one's calender does not deprive
  the user of his own freebusy view.
* exmdb: the event volley when the last row of a MAPI table with categories
  got deleted had wrong event data
* nsp: results from nspiGetMatches were not always capped as requested by
  clients (potentially crashing OL)
* zcore: make openstream treat MAPI_BEST_ACCESS as documented
* emsmdb: calls over RPCH with large outputs would sometimes just report an
  error due to insufficient buffer sizes, which has been fixed.
* mapi_lib: repair botched html_to_rtf with non-UTF-8 HTML input
* rtf_to_html and html_to_plain misconverted U+007F,U+07FF,U+7FFF,U+7FFFF to
  faulty UTF-8, which has been fixed
* mbsize: NTS error rate computation had an unsigned underflow and was
  misreported

Changes:

* tools: renamed gromox-{mt2exm,exm2eml} to gromox-{import,export}
  and added the old aliases for the tools
* nsp: make resolvenames skip over empty strings in line with the specification


Gromox 3.2 (2025-11-24)
=======================

Enhancements:

* ews: implement ``GetRoomLists`` and ``GetRooms`` handlers
* ews: implement ``tItemAttachment``, ``tUserConfigurationName`` types
* ews: implement types related to ``CategoryList``
* ews: load ReplyTo recipients
* ews: map item flag/reminder and message sender fields
* istore: standalone exmdb_provider process launcher
  (splits the gromox-http process into two for better debuggability)
* oxcmail: on export (MAPI-to-IM), recognize EX-in-ONEOFF and EMSAB (GAB)
  entryids in the Reply-To field and substitute them accordingly
* kdb2mt: entries in the user map file are now allowed to
  lack the ``sv`` and ``id`` fields
* kdb2mt: entryids and search keys for senders/recipients are now translated
  with the help of user maps

Fixes:

* mt2exm: avoid generating zero-sized ``/var/lib/gromox/user/*/eml/*`` files
  (and thus bogus imapstructure ext files) in the internal mailbox directory
  when a message object to import has no RFC5322 representation
* midb: ignore incomplete imapstructure files in
  ``/var/lib/gromox/user/**/ext``
* delivery: stop treating non-existing users as a temporary condition
* oxcmail: ONEOFF_ENTRYIDs did not have their email address/name set properly
  after some refactoring in 3.0, which was fixed
* ab_tree: users with HIDE_FROM_GAL or HIDE_FROM_AL were not hidden in all
  cases, which has been rectified
* imap: suppress ``AUTH=LOGIN`` advertisement before TLS established and
  instead emit ``LOGINDISABLED`` "capability" in accordance with RFC 2595
* ews: avoid dereference of unenganged std::optional, which had led to
  spurious use-after-free/crash
* ews: include PR_CONTAINER_CLASS in response when obtaining folder properties
* ews: add missing locking for concurrent ``EWSPlugin::unsubscribe`` invocation
* ews: avoid sending out emClient's draft messages
* emsmdb: ``ropOpenStream`` with MAPI_CREATE did not truncate the result to the
  right length, which was fixed
* html2rtf: map some CSS ``font-size`` keywords to sensible point sizes for RTF
* ab_tree: rework our Minimal EntryID encoding to avoid values >= 0x80000000,
  solving a hypothetical problem reading the addressbook data
  for the 589821th domain in the user database
* exmdb: MAPI table row deletion events were not being delivered,
  which was fixed
* oxvcard: fix crash when importing/exporting PR_HOBBIES property

Changes:

* imap: the combination of the config directive ``imap_force_tls=yes`` with
  ``imap_support_tls=no`` is now rejected on startup
* delivery: the OOF autoresponder was rewritten so it does not use direct
  filesystem access anymore (since the mailbox might not be present on the same
  host where the LDA runs)


Gromox 3.1 (2025-10-26)
=======================

Enhancements:

* http: support for SPNEGO authentication (Kerberos-in-SPNEGO or NTLMSSP-in-SPNEGO)
  with the HTTP "Authorization: Negotiate" header.
* dscli: try all oxdisco URLs until one succeeds
* exmdb: support repeated import of permission data (e.g. from kdb2mt)
* ews: create calendar item after accepting a MR with MacMail
* mbop: new `sync-midb` subcommand to prebuild midb caches ahead of the first IMAP login

Fixes:

* emsmdb: the total mail count in a contents view was not updated
* emsmdb,zcore: Send-As mail now correctly has the delegator in Envelope-From
* email_lib: deal with MIME parts with zero header lines
* tools: reinstate submit.php for delayed sending
* nsp: avoid buffer overruns in nsp_interface_fetch_property
* emsmdb: Partial message change tracking was bug-ridden and deleted. Standard
  transfers are now used instead. (E.g. an IPM.Task object where only the
  percentage-completed field was changed would be mis-synchronized to another
  Cached Mode client as "delete start/end dates".)
* exmdb: Public folders were missing timeindex queries and their content tables
  might have shown fewer messages.
* http: A workaround was added for OpenSSL 3.0 so that connections from
  Outlook 2010 once again succeed.
* mysql_adaptor: Improve the time needed to compute the composite mailbox
  permission for user in a case of a mailbox with 100K ACL entries.

Changes:

* exmdb: deactivate movecopy/deletemessages event storm compaction
* emsmdb: outgoing lzxpress compression in the EMSMDB protocol is now
  disabled as it does not compress well for the time invested.
* http: the ``ntlm_program_helper`` config directive was removed;
  your ``gss_program`` simply needs to handle both GSS and NTLM.
* event: support for reading the old event_acl.txt was deleted.
  The replacement is the ``event_hosts_allow`` config directive.
* timer: support for reading the old timer_acl.txt was deleted.
  The replacement is the ``timer_hosts_allow`` config directive.


Gromox 3.0 (2025-10-01)
=======================

Enhancements:

* eml2mt now transmits the RFC5322 representation into the message store so
  that IMAP clients can serve that instead of representation synthesized from
  MAPI data. / Messages imported via eml2mt no longer "lose" their original
  structure and headers when viewed in IMAP.
* midb now transmits the RFC5322 representations of messages created via IMAP
  into the message store. (Previously: just into the midb cache.) / Messages
  which have been client-side copied in IMAP, i.e. with FETCH+STORE rather than
  COPY, no longer "lose" their structure and headers.
* oxcical: implement support for VTODO and VJOURNAL
* mbop: add "freeze" and "thaw" commands
* mbop: support UTC/zone suffixes for getfreebusy -a/-b arguments
* mbop: using the -v option will now additionaly report the mailbox and
  subcommand in error messages
* exmdb: new config directive ``exmdb_eph_prefix`` to put ephmeral files like
  tables.sqlite3 on a local disk (in case a mailbox is regularly on NFS).
* exmdb: add a time index over messages to speed up common cases of
  grommunio-web GetContentsTable requests.
* exmdb: the derivation for the PR_MESSAGE_*_ME property value, upon delivery,
  now includes PR_EMAIL_ADDRESS as a fallback if PR_SMTP_ADDRESS is unset.
* oxdisco: the AutoConfig mechanism now emits an EWS server information block
* ews: include ParentFolderId in FindFolder/GetFolder response
* ews: implemented GetDelegate, CreateAttachment, FindPeople (GAL lookup),
  PushSubscriptionRequest request handlers
* ews: implemented oofReply responses like EX/365
* ews: Direct Meeting Response related serialization was added
* ews: referenced calendar items are now updated when a CreateItem request
  contains AcceptItem or DeclineItem tags.
* ews: support GetUserAvailabilityRequest request TimeZoneContext tag.
* zcore: Out of Office configuration reading and writing is now performed over
  the network rather than through direct filesystem access.

Fixes:

* fnevObjectCreate event notifications were not created when a mail was processed
  through TWOSTEP Rule Processor, now fixed.
* fnevObjectCreated event notifications were not created when a mail was
  processed by ONESTEP Rule Processor when that executed a OP_COPY operation.
* oxcical: iCal events with a date in DTSTART & DTEND but without
  X-MICROSOFT-CDO-ALLDAYEVENT are now transformed into Allday events even if
  the event is longer than one day.
* delivery: emit MDN-RRT messages even with ``lda_twostep_ruleproc`` is set.
* oxdisco: config-v1.1.xml now contains the homeservers as it should.
* oxdisco: AutoConfig XML now features the incomingServer type parameter
  in the right place.
* oxdisco: AutoConfig now emits outgoing server port 587 as type smtp.
* ruleproc: auto-enter MRs into target calender even if the sender is not going
  to get a response.
* ews: Avoid sending multiple ``<?xml ?>`` lines into the notification stream
  HTTP response body.
* ews: trim "duplicate" recipients when a newly-created item has recipients in
  both <mimeContent> and <To>/<Cc>
* ews: prevent FAI messages from polluting the Normal Message Set during ICS
* ews: when the FindItem requests finds no objects, an empty RootFolder tag
  is now still returned.
* ews: delete excess NUL byte from tCalendarItem:UID tags

Changes:

* kdb2mt no longer imports LocalFreebusy control messages, since dangling
  references in those can make delegate permission editing via OL
  nonfunctional.


Gromox 2.48 (2025-07-31)
========================

Enhancements:

* gromox.cfg now has a ``ruleproc_debug`` directive (applies to the TWOSTEP
  Processor only)

Fixes:

* ews: repair a nullptr dereference from the OOF XML change
* exmdb: make EXRPC write_message_v2 fill in return MID/CN values
* ab_tree: restore filtering of objects with AB_HIDE_FROM_GAL for NSP (this was
  lost in a Global Address Book provider rewrite in 2.40)


Gromox 2.47 (2025-07-28)
========================

Enhancements:

* oxdisco: support RFC 6764 well-known endpoints for CalDAV/CardDAV
  (if not running grommunio nginx config in front)
* oxcical: try to handle ICS files with missing VTIMEZONE blocks
* oxcical: support YEARLY recurrences with BYDAY without BYSETPOS
* imap: offer $Forwarded keyword for APPEND/STORE commands
* edb2mt, eml2mt, kdb2mt, oxm2mt, pff2mt, exm2eml: add ``--loglevel`` option

Fixes:

* nsp: remove meaningless session_check directive;
  no longer erroneously reject requests after daemon received SIGHUP
* oxcical: avoid setting out-of-spec MAPI recurnum for FREQ=MONTHLY,BYDAY=
  recurrences
* oxcical: fix wrong BYMONTH calculation for MONTHNTH recurrences being
  exported to iCal
* midb, imap: make EXPUNGE synchronous so that old UIDs don't reappear in
  a subsequent FETCH
* midb: respect setting \Deleted, \Answered, \Flagged during APPEND
* exmdb: resolve a case of "INSERT INTO t... UNIQUE constraint failed" log
  message appearing when the Twostep Rule Processor and a Move rule is
  encountered and a MAPI client has a Content Table with Sort Order open.
* exmdb: stop losing RFC5322 representation when a message is copied
* HTML-to-Text conversion using w3m suffered from an encoding mismatch, which
  was fixed.

Changes:

* oxcmail: upon ingestion, the ``Precedence`` header (RFC 2076) is now
  transformed to the MAPI property ``PR_INTERNET_PRECEDENCE``.
* exmdb_local: Out-of-office autoreply logic now recognizes
  PR_INTERNET_PRECEDENCE values ``bulk`` and ``list`` to inhibit certain and
  all responses, respectively.
* oxcmail: upon ingestion, the ``Auto-Submitted`` header (RFC 3834) and
  ``List-Help``, ``List-Subscribe`` and ``List-Unsubscribe`` are now
  transformed into the MAPI property ``PR_AUTO_RESPONSE_SUPPRESS``.
* ews: unconditionally emit all OOF XML tags upon GetUserOofSettingsRequest to
  workaround OL crash when modifying Out-of-office settings.


Gromox 2.46 (2025-05-28)
========================

Enhancements:

* cgkrepair: detect Change Keys with impossibly high values
* cgkrepair: retain a PCL's foreign XIDs
* ical2mapi: support FREQ=MONTHLY recurrences using BYDAY= but no BYSETPOS=
* mt2exm: the -B option now supports numeric identifiers
* ical2mapi: expand E-2718 error into new codes E-28xx with extended reason
* imap: allow '%' '*' and '?' in folder names

Fixes:

* PR_CHANGE_KEY/PR_PREDECESSOR_LIST was incorrectly generated between
  Gromox >=2.29.70 <=2.45.161, which has been fixed, and you may want to run
  cgkrepair.

Behavioral changes:

* daemons: the default log destination is now "automatic" (stderr/syslog
  autodetect) rather than "stderr"
* mapi2ical: deal with strange allday events that do not start/end on midnight
* htmltotext: w3m is now instructed on charsets and does not need to guess
  anymore
* exch: value for the PR_MAX_SUBMIT_MESSAGE_SIZE property was off by a factor
  of 1024, which has been fixed
* mkprivate/mkpublic: generate a PR_MAPPING_SIGNATURE value distinct from
  PR_STORE_RECORD_KEY for newly-initialized stores
* ical2mt, vcf2mt: messages are no longer emitted with an anchor,
  which now allows free placement with mt2exm -B
* ical2mapi: ignore unreasonable requests like BYMONTHDAY=32


Gromox 2.45 (2025-04-15)
========================

Fixes:

* emsmdb: avoid emissions of PR_MESSAGE_SIZE in fastdownctx streams
  (this makes PST export possible)
* email_lib: fix a lost space in IMAP BODYSTRUCTURE response

Enhancements:

* mysql_adaptor: add support for nesting mlists in permission checks
* Recognize the IANA Character Set names `utf-16le`, `utf-16be`
  (and 32) when converting from RFC5322 to MAPI.

Behavioral changes:

* MAPI tables now always offer a valid PR_ROW_TYPE value
* emsmdb: the set of default properties (on blank message objects) has changed
  to be closer to what EXC2019 does


Gromox 2.44 (2025-03-19)
========================

Fixes:

* mysql_adaptor: do not fail organization-level GAL population when a
  domain belonging to the org has zero members
* gab: resolve assertion when traversing GAL [new implementation from
  Gromox 2.42]
* mysql_adaptor: fix OOB when reading PT_DOUBLE entries from user_properties
* emsmdb: fix OOB write when computing PR_MAILBOX_OWNER_NAME_A
* zcore: PR_EMS_AB_DISPLAY_NAME_PRINTABLE of an address book object was filled
  with the email address even if the user's common name was umlaut-free
* ews: PR_LAST_MODIFIER_NAME was filled with the email address even if the
  user's common name was umlaut-free
* mbop: make clear-profile nuke all profile parts again
* The documented default value `outgoing_smtp_url=sendmail://localhost`
  is now in effect.

Behavioral changes:

* Recognition for the `smtp_server_ip` config directive has been removed.
  Users must upgrade to `outgoing_smtp_url` (added in Gromox 2.21).


Gromox 2.43 (2025-03-06)
========================

Fixes:

* imap: reduce memory footprint when FETCHing messages
* imap: resolve shutdown ordering crash
* exmdb: upgrade 0-length PR_ENTRYIDs to fake 1 byte to soothe Outlook Cached
  Mode syncer
* ews: heed MAPI proptype semantics and interpret 0xffffffff as a signed int
  when serializing to XML (-1 rather than 4294967295)
* gab: resolve out-of-bounds access in dntomid

Enhancements:

* oxm2mt: support embedded messages
* oxm2mt: add option to extract just an attachment embedded message
* eml2mt: add option to extract just an attachment embedded message
* mysql_adaptor: add TLS connection config directives

Behavioral changes:

* exmdb: launch threads in more rapid succession when there is job queue
  contention


Gromox 2.42 (2025-02-19)
========================

Fixes:

* exmdb_local: plug memory leak resulting from RPC execution
* alias_resolve: plug memory leak resulting from GAB refreshes
* alias_resolve: avoid unnecessary GAB refresh on shutdown

Enhancements:

* nsp: a few more RPCs now emit log messages under nsp_trace=2
* mh_nsp: support transfer of additional undocumented property types
* oxdisco: recognize /mail/config-v1.1.xml URI

Behavioral changes:

* New internal addressbook implementation backing the NSPI-provided and
  Zcore-provided AB functionality.

Packaging changes:

* dscli: DNS resolution via LDNS/libldns (desirable for linux-musl and BSDs)
  was replaced by c-ares/libcares.


Gromox 2.41 (2025-02-07)
========================

Fixes:

* ldap_adaptor: plug two memory leaks
* exmdb: plug a memory leak related to subscription destruction
* oxcical: do process TRIGGER duration value type for reminders
* midb: resolve flakey update of flagged/replied/forwarded status
* midb: when a MAPI message has changed and requires a new IMAPUID,
  convey the expunge of the old IMAPUID much sooner to IMAP clients
* pop3: resolve a NULL deref/crash during RETR command
* imap: restore SEARCH command looking at right portion of a QP-encoded message

Enhancements:

* ews: send flag status to clients
* imap: include username for IMAP actions when imap_cmd_debug logging is
  activated
* midb, imap: print asynchronous notification events when imap_cmd_debug>=2
* oxcical: invalid iCal timezone inputs are now logged when
  <daemon>_log_level=6 (debug)

Behavioral changes:

* mkprivate: new message stores now have `frightsVisible` set on the calendar
  folder, because grommunio-web is picky about the existence of the calendar
  folder even if obtaining just freebusy blocks.


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


Gromox 2.16 (2023-10-29)
========================

Enhancements:

* http: support for NTLM authentication with the HTTP "Authorization:
  Negotiate" header.
