e4a2gromox — migrating exchange4all (Kopanion / kopano.cloud) to gromox
=======================================================================

exchange4all ("e4a", the backend of the Kopanion appliance sold as
kopano.cloud) stores mailboxes in the gromox on-disk format: every mailbox is a
directory with ``exmdb/exchange.sqlite3``, ``cid/`` (bodies and attachments),
``config/`` (autoreply, ``zarafa.dat`` settings), plus the midb caches
``eml/``, ``ext/``, ``exmdb/midb.sqlite3``. The sqlite schema is an old
pre-grommunio one (no ``CONFIG_ID_SCHEMAVERSION`` row), which gromox upgrades
in place when the store is first loaded. The migration therefore copies store
directories instead of converting items, which is the better choice for
performance

What differs between the two systems and has to be handled:

+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Aspect           | e4a                                        | gromox                      | Handling                            |
+==================+============================================+=============================+=====================================+
| Account database | MariaDB ``email``, old gromox schema       | MariaDB ``grommunio``,      | ``inventory`` + ``plan`` +          |
|                  | (``users.address_type`` 0 user / 1 alias   | managed by grommunio-admin  | ``provision`` recreate domains,     |
|                  | row / 2 list)                              |                             | users, aliases, lists               |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Mailbox identity | by ``users.id``; EX addresses embed        | ids differ on the target    | ``fixup`` rewrites EX participants  |
|                  | ``domain_id``/``user_id``                  |                             | to SMTP offline in the sqlite file  |
|                  | (``/O=My Organization/.../CN=<ids>-NAME``) |                             | (``e4a_store_fixup.py xlat-addrs``) |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| ACLs             | ``permissions.username`` = e-mail address, | same                        | kept; renamed when a domain is      |
|                  | lists allowed                              |                             | renamed; lists are recreated so     |
|                  |                                            |                             | they resolve                        |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Schema           | configurations 1..9 (schema "EV-0"),       | dbop_sqlite upgrade EV-0 →  | ``fixup`` runs                      |
|                  | e4a-own table ``migration_system``         | EV-29                       | ``gromox-mkprivate -U`` offline     |
|                  |                                            |                             | (would otherwise happen on first    |
|                  |                                            |                             | load, blocking exmdb; ~36 s per GB  |
|                  |                                            |                             | of sqlite)                          |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Body/attachment  | ``cid/<n>`` plain files, 4-byte length     | reads the same "v0" layout  | copied verbatim, no conversion      |
| files            | prefix on text bodies                      | (``cu_get_object_text_v0``) |                                     |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Caches           | ``eml/ ext/ midb.sqlite3 fts/ dac/``       | ``eml/ ext/ midb.sqlite3``  | not copied; a fresh                 |
|                  | (e4a's ``eml/`` of the Public mailbox      | rebuilt lazily by midb;     | ``midb.sqlite3`` is created with    |
|                  | alone is ~1 TB)                            | search index is             | ``gromox-mkmidb -f``; IMAP clients  |
|                  |                                            | grommunio-index             | re-download                         |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Passwords        | yescrypt ``$y$`` crypt hashes              | crypt(3) verification       | hashes are copied verbatim          |
|                  |                                            |                             | (``PASSWORD_MODE=copy``), users     |
|                  |                                            |                             | keep their passwords; ``random``    |
|                  |                                            |                             | generates new ones into             |
|                  |                                            |                             | ``credentials.txt``                 |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Store GUID in    | ``rop_util_make_user_guid(users.id)`` of   | same scheme, different id   | ``fixup`` rewrites the GUID (binary |
| entryids         | the e4a id                                 |                             | and hex) in all property blobs,     |
|                  |                                            |                             | search criteria and ``zarafa.dat``; |
|                  |                                            |                             | without it zcore rejects every      |
|                  |                                            |                             | persisted entryid (To-do search,    |
|                  |                                            |                             | reminders, default folders) with    |
|                  |                                            |                             | ``MAPI_E_INVALID_PARAMETER``        |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+
| Web settings     | ``config/zarafa.dat`` (Kopano WebApp       | zcore reads the same legacy | copied; the ``shared_stores`` list  |
|                  | settings, zcore profile)                   | file                        | is removed (it names other          |
|                  |                                            |                             | mailboxes by source identity; users |
|                  |                                            |                             | re-add them)                        |
+------------------+--------------------------------------------+-----------------------------+-------------------------------------+

Prerequisites
-------------

On the **target** (gromox host, run everything there as root):

- gromox ≥ 3.11 with ``gromox-mbop``, grommunio-admin-api, ``rsync``,
  ``sqlite3``, ``python3``.
- Free space ≥ size of the source ``u-data`` tree.
- Key-based SSH as root to the **e4a host** (the Debian machine running Docker,
  not the container). Root needs to read the store directories (owned by uid
  2101, mode 0750) and to run ``docker exec``. A jump host can be given in
  ``SRC_SSH_OPTS`` (``-o ProxyJump=user@jump``).

On the **source** nothing is installed; ``e4a_inventory.py`` is streamed over
SSH to the host's ``python3``. The source is never modified.

Verified on
-----------

gromox 3.11.134 / grommunio-admin-api 1.21.23 (openSUSE Leap 16) with an e4a
5.11.4 (container image 8.7.4) store: EV-0 → EV-29 upgrade, folder tree, ACLs,
RFC 5322 and iCalendar export, IMAP and grommunio-web login all good; folder
and message counts identical.

Procedure
---------

::

   cp e4a2gromox.conf.example /etc/e4a2gromox.conf   # edit: SRC_SSH, DOMAIN_MAP SHARED_MAILBOXES, quotas
   ./e4a2gromox.sh inventory                         # -> /var/lib/e4a2gromox/inventory.json
   ./e4a2gromox.sh plan                              # -> plan.tsv; review, delete unwanted lines
   ./e4a2gromox.sh provision                         # domains, users, aliases, lists on gromox
   ./e4a2gromox.sh transfer                          # pre-sync while e4a is live (hours/days)
   # --- cutover: stop e4a cleanly on the appliance ---
   #     docker stop -t 120 kopanion_exchange4all_1
   ./e4a2gromox.sh transfer --final                  # delta sync incl. the sqlite WAL files
   ./e4a2gromox.sh fixup                             # pre-flight, ACLs, addresses, schema, quota
   ./e4a2gromox.sh verify                            # folder/message counts source vs target

``-o addr`` limits ``provision``/``transfer``/``fixup``/``verify`` to one
source mailbox, list or alias (repeatable); ``-n`` prints the commands instead
of running them; ``-f`` overrides the safety interlocks (regenerating an
existing ``plan.tsv``, replacing a target mailbox this tool did not create,
``fixup`` without a recorded final sync). All steps can be re-run; ``transfer``
is a plain rsync ``--delete`` of the store directory minus caches, and it
refuses to touch a mailbox that ``provision`` did not create.

e4a stores run sqlite in WAL mode, so committed mail can sit in
``exchange.sqlite3-wal`` for hours. The pre-sync leaves WAL files out (they are
torn on a live source); ``transfer --final`` checks that the e4a container is
stopped, copies the WAL/SHM files along and sqlite replays them when the store
is first opened on the target. ``fixup`` refuses stores without a recorded
final sync. Without network connectivity between the hosts use
``SRC_MODE=archive`` (one ``<address>.tar.zst`` per store made after e4a was
stopped, see the comment in ``transfer_one``).

``fixup`` per store: freeze/unload in exmdb, pre-flight (duplicate named
properties would abort the schema upgrade), ACL/delegate renames, offline
EX→SMTP translation, store-GUID rewrite of persisted entryids, removal of the
shared-store web settings, ``gromox-mkprivate -U`` schema upgrade, thaw + ping,
re-application of quota and display name (the copied store carried e4a's),
``recalc-sizes``. Run the full-text indexer afterwards
(``systemctl start grommunio-index.service``). ``verify`` re-reads the counts
from the stopped source over SSH.

The pre-sync copies live sqlite files, which may be torn; that is fine because
the final ``transfer`` after stopping e4a replaces them. Do not run ``fixup``
before the final sync (it upgrades the schema and the next rsync would
overwrite the upgraded file anyway).

Public folders
--------------

If real public folders are wanted (not encountered so far), convert on the
target with the MT pipeline (item-level, slow for this size):

::

   gromox-exm2mt -u publicFolder@domain IPM_SUBTREE | gromox-mt2exm -u @domain -B /IPM_SUBTREE

Address rewriting (why not just exaddrxlat)
-------------------------------------------

Mail stored by e4a references internal participants as X.500 EX addresses of
the form
``/O=MY ORGANIZATION/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=0200000016000000-GIVENNAME.SURNAME``
where the hex part encodes the *source* ``domain_id``\ =2 and ``user_id``\ =22.
gromox resolves such DNs through its own ``x500_org_name`` and database ids, so
on the target they resolve to nothing (reply, free/busy and "own item" checks
break). ``fixup`` scans the copied stores for every distinct DN, builds a map
(``exaddr-map.json``, format of kdb-uidextract(8)) from the e4a users table —
deleted accounts are mapped from the ``-NAME`` suffix — and rewrites the stores
*offline* with ``e4a_store_fixup.py xlat-addrs``. It applies the same rules as
``gromox-mbop exaddrxlat`` (addrtype, e-mail address, one-off entryid, search
key per participant set) but also covers the recipient rows, the
creator/last-modifier entryids and the Email1-3 fields of contact items, which
mbop does not, applies the domain rename to existing SMTP addresses, and does
not rewrite messages through exmdb: exaddrxlat would re-write every message
(and its cid files) of the 680 GB archive. Not translated: ``rules.actions``
blobs (recreate the two forwarding rules by hand) and
``PR_SCHDINFO_DELEGATE_ENTRYIDS`` (re-add delegates in the client).

Noteworthy mentions
-------------------

- midb/IMAP state: UIDs are reassigned, clients download again.
- ``config/zarafa.dat`` is copied; if a mailbox's web settings misbehave,
  ``gromox-mbop -u user clear-profile`` resets them.
- e4a accounts with ``address_status != 0`` are created suspended and their
  password hash is not copied.
- The two inbox rules on the source (forwarding rules) embed e4a address book
  entryids and should be recreated by hand.
- Addresses left over from the customer's earlier Kopano era
  (``user@mhpa-ch-swb01-kop01``) are SMTP-typed and are not touched.
- Server-side rules referencing other mailboxes keep working only if the
  referenced folders exist (same store) — unchanged by the copy.

Dependencies
------------

- Python ≥ 3.6 on both hosts
- ``sqlite3`` CLI on the target
- ``rsync`` on the target
- ``zstd`` on the target
