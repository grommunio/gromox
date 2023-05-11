Development 2.9.7
=================

Enhancements:

* pff2mt: speedup operation by 70%+
* emsmdb: strike limits (raise to infinity) for session handles, user handles
  and notify handles
* emsmdb: new configuration directives ems_max_active_notifh,
  ems_max_active_sessions, ems_max_active_users


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
  assigned the right namespace (PSETID_ADDRESS)
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
  (To go back to the old implementation, set http.cfg:http_old_php_handler=1)
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


1.35 (2022-11-25)
=================

Enhancements:

* exmdb_provider: mlists that were granted the StoreOwner permission bit
  through an ACL now propagate it to the individuals in the mlist.

Fixes:

* imap: the response to the IDLE command had been malformed
* emsmdb: On outgoing mails, the Return-Receipt-To (Read Receipt Request)
  header was malformed. On the incoming side, this would then be
  translated back to invalid@invalid.

Changes:

* http: only show HTTP context log messages when the "g_http_debug"
  config directive is set to a non-zero value


Gromox 1.34 (2022-11-21)
========================

Enhancements:

* Daemons have a new log level directive (e.g. http_log_level, zcore_log_level,
  etc.) which defaults to 4 (NOTICE) and needs to be set to 6 (DEBUG) before
  other debug knobs like http_debug, zrpc_debug, etc. actually emit something.
* User accounts can now be hidden from the GAL and other address lists
* The gromox-dscli command-line utility now performs DNS SRV lookups.
* mod_cache: remodel the whole module to be a passthrough to the kernel's
  buffer cache by using mmap and thus saving a lot of resident memory.

Changes:

* The `logthru` service plugin has been removed in favor of
  direct function calls.
* `log_plugin.cfg` is no longer used, switch to (e.g.)
  `http.cfg`:`http_log_level`.

Fixes:

* oxcical: resolve Exchange complaining about the X-MICROSOFT-CDO-OWNERAPPTID
  line our implementation generated
* dscli: in absence of SRV records, fall back to autodiscover.<domain>,
  not <domain>.
* ldap_adaptor: the per-org LDAP base was erroneously used with the
  default LDAP.
* midb: resolve a startup crash in conjunction with musl libc.
* exmdb_provider: fix a buffer overrun in common_util_load_search_scopes
* lib: rectify return value of html_to_plain_boring.
  On systems without w3m installed, HTML-to-text conversion would
  produce garbage when the output was exactly 65001 bytes long.
* mod_cache: support continuation via `curl -C` and `wget -c`
* mod_cache: report errors with various 4xx and 5xx status codes rather than
  exclusively 404


1.33 (2022-10-20)
=================

Enhancements:

* tools: add kdb-uidextract and kdb-uidextract-limited scripts to
  facilitate ACL conversion
* Per-organization LDAP server support
* Show more distinct icons in GAL (mailing lists now show the ML icon)
* Support PR_THUMBNAIL_PHOTO for room, equipment and mlists
* FreeBSD and OpenBSD compilation support
* nsp: reload config on SIGHUP
* oxcical: minimal VJOURNAL export
* oxcical: implement VTODO export

Fixes:

* zcore, emsmdb: remodel code relating to send-on-behalf/-as detection.
  zcore now sends with the exact PR_SENT_REPRESENTING as specified by a client.
* php_mapi: make mapi_parseoneoff recognize UTF-16 ONEOFF_ENTRYIDs

Changes:

* authmgr: obsolete the `auth_backend_selection` config directive's values
  `always_mysql` and `always_ldap`; these are treated like `externid` now.
* imap: rename `imap_force_starttls` config directive to `imap_force_tls` and
  `imap_support_starttls` to `imap_support_tls`, since it affects encryption as
  a whole, not just the STARTTLS command on the unencrypted port.
* pop3: rename the `pop3_force_stls` config directive to `pop3_force_tls` and
  `pop3_support_stls` to `pop3_support_tls`, since it affects encryption as a
  whole, not just the STLS command on the unencrypted port.



1.32 (2022-09-23)
=================

Enhancements:

* kdb2mt: detect unsupported "db" attachment layout
* kdb2mt: add option for mapping ACL identities using a text file
* nsp: support reading PR_EMS_MEMBER property
* zcore: support GetContentsTable on distlist objects
* exm2eml: add options --ical and --vcard

Fixes:

* oxcical: some RECURRENCE-ID may have been emitted based on undefined contents
* oxcical: emit allday events as YMDHMS when YMD cannot be computed due to lack
  of timezone information

Changes:

* email_lib: reimplementation of MJSON parsing using jsoncpp


1.31 (2022-08-30)
=================

Enhancements:

* kdb2mt: add a size column to the disambiguation table
* exmdb_provider: added the "exmdb_search_yield" and "exmdb_search_nice" config
  directives
* exmdb_provider: add a vacuum RPC (and expose via gromox-mbop(8gx))
* emsmdb: implement cached mode cross-store move support

Fixes:

* kdb2mt: filter unwanted properties on writeout rather than readout
  (rerecognize special folders)
* oxcical: recurring appointments now have their summary ("effective ... from
  02:00 to 02:15") displayed without uncanny time shift
* oxcical: oxcical_export_timezone had missed emitting BYMONTHDAY subvalues
* oxcical: avoid month wraparound with recurring events in December
* dscli: fix nullptr deref when -x option is used
* nsp: show DT_DISTLIST icon for mlists
* oxcical: set PidLidRecurring and PidLidRecurrenceType tags when importing
  recurring events
* Check for iconv capabilities on startup so that we do not start on containers
  with too few libc components installed
* zcore: avoid UAF when unpacking SMIME messages
* imap: do not emit body-QP in () groups when encoded-word-QP is expected
* imap, pop3: avoid hanging clients if response buffer is full

Changes:

* The default value for "exmdb_search_pacing" was changed to 250 to improve
  interactivity with OL during online search.
* oxvcard: disable pedantic behavior on import


1.28 (2022-07-25)
=================

Enhancements:

* oxcmail: add support for multi-iCal and multi-vCard support
* php_mapi: add ``mapi_icaltomapi2`` and ``mapi_vcftomapi2`` APIs
* emsmdb, zcore: Send-As support
* midb_agent: make midb command buffer size for SRHL/SRHU configurable

Fixes:

* freebusy: do not publicize private recurrence exceptions
* Delayed Sending had left messages in Outbox
* midb: P-DTLU command incorrectly sorted by received date
* emsmdb: the contact folder list erroneously rejected sort requests
  that grouped and sorted by the same column
* oxcical: add missing ``PR_ATTACH_METHOD`` to iCal appointment
  collection members
* oxvcard: do not map unrecognized types of telephone numbers to
  ``PR_RADIO_TELEPHONE_NUMBER`` on import
* oxvcard: avoid filing ``PR_NORMALIZED_SUBJECT`` with garbage
* exch: ``PR_SENDER_ENTRYID`` was filled with the wrong value in
  delegate mail sending
* exmdb_provider: avoid sending ``PR_DISPLAY_NAME`` to clients twice

Changes:

* The config directives "service_plugin_list", "service_plugin_path",
  "hpm_plugin_list", "hpm_plugin_path", "proc_plugin_list", "proc_plugin_path",
  "mpc_plugin_list", "mpc_plugin_path" have been removed.


1.27 (2022-07-11)
=================

Fixes:

* nsp: repaired a nullptr deref with the resolvenamesw RPC
* nsp: fix erroneous writeout to path "/delegates.txt" (would always fail due
  to absence of filesystem permission)
* nsp: disable OneOff synthesis for non-existing GAL objects
* mh_nsp: fix seekentries RPC performing garbage ANR matching
* oxcmail: avoid running the encoded-word decoder in sender/recipient
  names twice (umlaut breakage)
* oxcical: avoid crash when RRULE:BYMONTH=12 is used
* exmdb_local: reword duplicate error strings for delivery failures

Enhancements:

* kdb2mt: support recovering broken attachments lacking PR_ATTACH_METHOD
* kdb2mt: remove PK-1005 warning since now implemented
* delmsg: support mailbox lookup using just the mailbox directory name
* http: added the "msrpc_debug" config directive
* nsp: added the "nsp_trace" config directive
* mh_nsp: make the addition of delegates functional


1.26 (2022-06-28)
=================

Fixes:

* imap: sender/recipient umlauts were not represented correctly,
  which has been fixed
* zcore: repair retrieval of PR_EMS_AB_THUMBNAIL_PHOTO
* eml2mt: avoid putting non-vcard messages into Contacts by default
* oxcmail: better handle To/Cc/Bcc/Reply-To fields when the target
  mailbox display name contains a U+002C character.
* zcore: allow settings freebusy permission bits for calendars

Enhancements:

* http, imap, pop3, delivery-queue: new config directives ``http_listen_addr``,
  ``imap_listen_addr``, ``pop3_listen_addr`` and ``lda_listen_addr``
* php_mapi: support imtomapi ``parse_smime_signed`` option
* midb: treat folders with absent ``PR_CONTAINER_CLASS`` like ``IPF.Note``
* mt2exm: added a ``-D`` option that will do a delivery rather than import
* imap: raised the default value for ``context_average_mitem`` to 64K

Changes:

* autodiscover: enable default advertisement of RPCH & MH irrespective
  of User-Agent
* midb, zcore, exmdb_local: remove config directive ``default_timezone``


1.25 (2022-06-12)
=================

Fixes:

* exmdb_provider: repair PR_MEMBER_NAME transition
* zcore: fix randomly occurring set_permission failures
* autodiscover: resolve '&' being misrepresented
* autodiscover: force-remove single quotes from ini values
* imap: improved the tokenization for unusual values found
  in the From/To/Reply-To etc. headers
* imap: stop emitting excess parenthesis pairs for "RFC822" field
  values during FETCH
* imap: stop offering STARTTLS capability keyword when the STARTTLS command
  can, at the same time, not be issued anyway
* imap: IMAP commands emitted to the log (under ``imap_cmd_debug``) were
  truncated sometimes
* midb: resolve potential crash when the IMAP ``SEARCH`` command is used

Enhancements:

* imap: emit gratuitous CAPABILITY lines upon connect and login
* imap, pop3: support recognizing LF as a line terminator as well
  (other than CRLF)

Changes:

* midb: change mail_engine_ct_match to use stdlib containers
* oxcmail: stop emitting zero-length display-names
* oxcmail: always generate angle brackets for exported addresses


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
