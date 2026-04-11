Milestone 3.6.13
================

Fixes:

* The "percentage complete" of an appointment was mangled when passing through
  EWS, which has been fixed. (EWS uses [0, 100], but MAPI uses [0, 1.0])
* EWS now synthesizes a value for the "Received Time" field
* AutoDiscover no longer erroneously advertises OWA API support.
  This had made it impossible for Thunderbird to connect.
* The EWS implementation now performs retrieval/update of Out Of Office
  settings such that it works in multi-server environments.


Gromox 3.6 (2026-03-26)
=======================

Enhancements:

* Gromox has gained a component that now serves the Offline Addressbook.
* EWS: Task operations (creation, update, property retrieval) have been
  implemented.
* EWS: Calendar occurrence operations (create, update, delete), including
  timezone support for those, have been implemented.
* EWS: A number of request have been implemented: ExpandDL, GetPersona,
  CreateUserConfiguration, UpdateUserConfiguration, DeleteUserConfiguration,
  DeleteAttachment, AddDelegate, UpdateDelegate and RemoveDelegate.
* EWS: Lifecycle for meetings have been implemented, i.e. invitation sending
  when the `UpdateItem` operation is exercised, cancellation sending on
  `DeleteItem`, and response sending to the organizer when a participant
  accepts/declines a request.
* EWS: Read receipts are now generated when a user messages are marked as read;
  the `SuppressReadReceipts` attribute of the `UpdateItem` operation is honored
  as well.
* EWS: The `ResolveNames` operation now performs partial matches too.
* EWS: Added delegate permission level support and cross-mailbox permission
  checks.
* EWS: eM Client reported "no conversion for Message::Flag" when toggling the
  flagged state of a message, which has been fixed/implemented.
* The server-side meeting autoprocessor now updates the organizer's calendar
  when a meeting response is received, and sets the flag that XY has responded.
* The AutoDiscover handler now supports the impersonation username syntax
  (auth@a.de!sharedmbox@b.de) in conjunction with EAS
* Conversion of appointments from MAPI to iCal form now can deal with a
  zero-length PidLidAppointmentTimeZoneDefinitionStartDisplay attribute
* The eml2mt conversion utility now emits messages sooner (previously it
  collected all messages first before outputting)
* Conversions from HTML to plaintext now support and prefer the use of the
  external converter Chawan

Fixes:

* The midb daemon had looked at the wrong config file for the
  `midb_sqlite_busy_timeout` setting and as a result generated a "config key ..
  has no default" log message on startup, both of which are fixed.
* The command-line utilities' log messages no longer contain ANSI/VT100 color
  sequences when stderr is not an interactive shell.
* The Information Store no longer returns garbage in MAPI Content Taeble cells
  when the table sort order contains a column of type
  PT_MV_UNICODE|MV_INSTANCE.
* Conversion from iCal to MAPI now sets the PidLidAppointmentStateFlags,
  PidLidResponseStatus, PidLidMeetingType properties. (Some clients do not show
  appointments without those.)
* Meeting requests that were created with the EWS `SendOnlyToAll` flag had,
  when converted to iCal, the wrong `METHOD` field value and lacked all the
  attendees, which has been fixed.

Changes:

* The multi-server map is now exclusively read from SQL; the exmdb_list.txt
  file has been obsoleted.
* EWS XML responses, e.g. when a message body is retrieved by an EWS client,
  are now sanitized and invalid XML characters stripped.
* The IMAP implementation has been tuned to require a bit less memory.
* Conversions from Internet Messages to MAPI now produce senders/receiver
  properties with SMTP rather than EX addressing.


Gromox 3.5 (2025-02-26)
=======================

Enhancements:

* Finer-grained control over listening socket creation, including new config
  directives (`http_listen`, `imap_listen_tls`, etc.) for specifying these.
  This makes it possible not having to use the wildcard address.
* importer: make -B option usable with public stores

Fixes:

* emsmdb: async notification connections were not marked active and would not
  deliver a signal of new pending events.
* emsmdb: repair EcDoAsyncWaitEx to immediately return when notifications are
  already pending in the session queue
* emsmdb: fix UAF/crash when notifications are sent over RPCH
* oxcical: upon reception of non-recurring appointments, the PidLidRecurring=0
  property will be set now, as some Outlook versions fail to show appointments
  in the daily/weekly/monthly view if the property is absent.
* oxcmail: messages with timezones ±08xx/09xx were mistreated as UTC
* oxvcard: fixed a field shift in the ADR line's parsing and emission
* ews: trim all C0 control codes from XML responses
* exmdb: limit production of PR_RTF_COMPRESSED variants of
  PR_BODY/PR_HTML when saving messages to IPM.Task objects, as OL
  only depends on it for those message classes.
* Plugged a memory leak that occurred when a multi-HTML Internet Mail is
  converted to MAPI
* Plugged a memory leak that occurred when HTML is converted to RTF
* Plugged a logical memleak stemming from never shrinking the buffer of
  `FETCH RFC822` and related commands

Changes:

* php_mapi can now tolerate the _presence_ of the PHP `opcache` module,
  though opcache must still be disabled due to miscompilation.


Gromox 3.4 (2026-02-02)
=======================

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
* exmdb: abort purge-datafiles if there is a database error midway
* imap: release potentially-large APPEND buffers much earlier
* exporter: plug two memory leaks

Changes:

* oxcmail: limit nesting depth of attachments during export to 7
* oxcmail: RFC 5322 header fields are now treated as US-ASCII as mandated,
  and no longer magically assumed to be in the same charset as the body.
* exporter: FAI messages are no longer emitted by default and explicitly need
  to be requested with the -a option.
* ruleproc: treat not only "Busy" as a collision, but also "Tentative" and
  "Out-Of-Office"
* ruleproc: evaluate not just PR_START_DATE but also
  PidLidAppointmentStartWhole (and their end counterparts)
* ab_tree: PR_COMPANY_NAME is no longer synthesized from the title of the
  domain a user belongs to
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
