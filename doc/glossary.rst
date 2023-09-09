..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2023 grommunio GmbH

Concept index
=============

Roughly sorted to get a bottom-up view.

Default Store
	In a *MAPI profile*, there is a "default store" (default mailbox).
	This is the user's home store.

Private Store
	A type of mailbox. In Gromox, this is prepopulated by gromox-mkprivate
	with about 19 undeletable essential folders, e.g. Top of Information
	store, Inbox, Outbox, etc.

	Though stores could exist individually (after all, they have
	MailboxGUID, DatabaseGUID, StoreGUID to be referenced), each store is
	generally tied from and to one user object (and thus exactly one
	ESSDN), because utilizing a username is so much more convenient for
	humans than a GUID.

Public Store
	A type of mailbox. Each user can have at most one public store linked, because the
	way they are opened in MSMAPI is by specifying the user's ESSDN.

	In Exchange, there is a ``cn=PUBS`` user in MSAD for owning the store.
	It has no associated ESSDN (thus is invisible in Groupware), though it
	does have an SMTP address of its own. In MFCMAPI, one can observe that
	``PR_STORE_ENTRYID`` contains: ``ServerShortName=PUBS@example.com``,
	``MailboxDN=/o=foo/cn=user15``, ``SmtpAddress=PUBS@example.com``,
	whereby user15 is whatever you used to logon with. Messages to
	``PUBS@domain.com`` are ignored.

	In Gromox, public stores are owned by/tied to Gromox domain objects.
	The schema for domain objects is separate from user objects, and there
	is no SMTP address nor ESSDN assigned. Though one can observe
	``public.folder.root@example.com`` in ``PR_STORE_ENTRYID``, this is
	just a placeholder for Autodiscover/MSMAPI. When working with Gromox
	command-line utilities, only the domain name is used, sometimes as
	``example.com``, sometimes as ``@example.com``.

	Each domain can have at most one public store. The SQLite database
	underlying a Gromox public store is slightly different from a private
	store, e.g. it has tables to track read states per user.

Non-default store
	Refers to any store that is not the user's home store, e.g. public
	stores, private stores of other users, Zarafa archive stores, or even
	extra PSTs opened in a MAPI profile.

Shared Store
	A term used for a non-default private store to which multiple users
	have some form of access.

MAPI Profile
	A list of one or more mailboxes. This concept only exists client-side,
	e.g. in MSMAPI or PHP-MAPI. Other mailboxes can still be opened even if
	they are not part of a MAPI profile.

exchange.sqlite3
	An SQLite database file used by Gromox which stores a significant
	portion of what makes up a mailbox, including the folder hierarchy and
	messages. What is not included, but stored as loose files on the
	operating system's filesystem, are: message bodies, transport header
	property value, file attachments.

FLATUID
	A GUID which is treated as 16 raw bytes.

GUID
	Globally Unique Identifier. Also known as Universally Unique Identifier
	(UUID). 128 bits in length. Not all bits are random; RFC 4122 defines
	semantic meaning for certain bits. GUIDs are encoded little-endian so
	byteorder is a concern for text representations. Common text forms are
	32 chars (32 hex nibbles), 36 chars (added 4 dashes for RFC 4122
	fields), 38 chars (added 2 curly braces).

Mailbox GUID
	A value which is found in ``mdb01.edb`` in table ``Mailbox``, column
	``MailboxGuid``. It is unclear why a distinction between mailbox and
	store was necessary for Exchange. In Gromox, Mailbox GUID is the same
	as Store GUID.

MAPIHTTP MailboxId
	The MH request URI has a parameter ``MailboxId``. It is something like
	``https://g.net/mapi/emsmdb/?MailboxId=754af46e-6310-4e07-aea1-2c911e595644@g.net``.
	In Exchange, the parameter is the GUID36 rendition of the Mailbox GUID.
	In Gromox, the parameter is a GUID36 rendition of 12 filler bytes plus
	4 LE bytes conveying the user ID, but the parameter is never really used,
	because the user id is obtained from HTTP authentication headers.

Database GUID
	A value which is found in ``mdb01.edb`` in table ``MailboxIdentity``,
	column ``LocalIdGuid``.
	In Exchange, dbguid is distinct from Store GUID.
	In Gromox, dbguid is the same value as GABUID.

Folder Database GUID
	Visible in EX entryids (with conditions) at bytes 22-38.
	In Exchange, fdguid generally has the same value as dbguid.
	In Gromox, fdguid always has the same value as dbguid.

Message Database GUID
	Visible in EX entryids (with conditions) at bytes 46-62.
	In Exchange, the mdguid can be different from dbguid in case a
	message	is located in a Public Folder Secondary Hierarchy mailbox.
	In Gromox, mdguid always has the same value as dbguid.

Mapping Signature
	Visible in ``mdb01.edb`` in table ``Mailbox``, column ``MappingSignatureGuid``.
	Visible in MAPI in the ``PR_MAPPING_SIGNATURE`` property.
	The mapping signature indicates which objects share a Named Property
	propid<->propname map.
	It is unspecified whether this also declares the validity scope for
	ReplIDs.
	In Gromox, the Mapping Signature has the same value as the Store GUID.

Internal Identifier
	Either a FID or MID.

IID_
	A prefix in source code for "interface identifier", related to the
	MSMAPI C API and the ``IUnknown::QueryInterface`` function therein.
	Identifiers may be ``IID_IMessage``, ``IID_IMAPIFolder``,
	``IID_IMAPITable``, etc.

Folder Identifier, FID
	Visible in EX entryids (with conditions) at bytes 38-46.
	Consists of GCV (6 bytes) + ReplID (2 bytes) = 8 bytes.
	Because those 8 bytes are treated as a 64-bit integer
	in Gromox, FIDs in Gromox often look reversed.
	In Gromox, "fid" as a variable name sometimes refers to
	either the 8-byte FID or just the GCV.

Message Identifier, MID
	Visible in EX entryids (with conditions) at bytes 62-70.
	Consists of GCV (6 bytes) + ReplID (2 bytes) = 8 bytes.
	Because those 8 bytes are treated as a 64-bit integer
	in Gromox, FIDs in Gromox often look reversed.
	In Gromox, "mid" as a variable name sometimes refers to
	either the 8-byte MID or just the GCV.

Global Identifier, GID
	Database GUID (16 bytes) + GCV (6 bytes) = 22 bytes.

External Identifier for objects, XID
	EX: 16-byte namespace GUID (which?) + GCV (6 bytes) = 22 bytes.

External Identifier for changesets (in PCL)
	EX: 22 bytes
	OST: 16-byte GUID + CN (4 bytes)

LongTermID
	XID (22 bytes) + 2 pad bytes = 24 bytes.

Entryid
	A variable-length identifier which refers to a folder or message in a
	particular mailbox in a particular namespace. Entryids are always at
	least 20 bytes in length, consisting of 4 flag bytes, a 16 byte MAPI
	Provider UID and then provider-specific more data.
	* EX entryid
	* EMSAB entryid

EMSAB entryid
	Provider UID is {c840a7dc-42c0-1a10-b4b9-08002b2fe182}.

EX entryid
	If the MAPI Provider UID refers to an Exchange-like store, the
	remainder from byte 22 onwards specifies an Exchange-style entryid.
	If byte 22-24 is {0x01,0x00}, read bytes 0-n as an EX Folder Entryid
	(gromox: `struct FOLDER_ENTRYID`).
	If byte 22-24 is {0x07,0x00}, read bytes 0-n as an EX Message Entryid
	(gromox: `struct MESSAGE_ENTRYID`).

GABUID
	16-byte GUID value composed of 4 bytes Gromox user ID plus
	12 fixed bytes {XXXXXXXX-18a5-6f7b-bcdc-ea1ed03c5657}.

	16-byte GUID value composed of 4 bytes Gromox domain ID plus
	12 fixed bytes {XXXXXXXX-0afb-7df6-9192-49886aa738ce}.

GLOBCNT / GCV
	Global object count. Scope: mailbox. Limit: 2^48.
	Every new folder and message is assigned a GC value.
	ICS clients can bulk-reserve GCV blocks on the server
	for delegation. The GC counter on the server is effectively
	strictly monotonically increasing. Because ICS clients
	can upload objects late, the GC value is no indicator for
	any particular order.

PR_CHANGE_KEY
	Identifier for the most recent change.

PR_SOURCE_KEY
	Internal/global identifier (GID) for the object (folder/message).
	16-byte dbguid + 6-byte GCV. When Outlook creates new objects in a
	mailbox, it allocates a GCV number from the *primary mailbox of the
	profile* rather than the mailbox where the object is created. As a
	result, the dbguid of PR_SOURCE_KEY need not match the dbguid of the
	mailbox where the object is created.

PR_RECORD_KEY
	In Exchange, similar to EX entryid.
	4-byte flags, 16-byte PR_STORE_RECORD_KEY, 2-byte type, 16-byte dbguid, 6-byte GCV, 2-byte pad.

PR_MDB_PROVIDER
	When emsmdb32.dll is the provider, the 16-byte value is
	549a34683d32384a9aa9e00a683131ba.

MAPI Provider UID
	Bytes 4-20 in every entryid.
	Can be a fixed value like muidOOP, muidContabDLL, muidEMSAB, etc.
	If not, it is often MailboxInstanceGuid/PR_STORE_RECORD_KEY.

Replicas
	A set of Database GUIDs of actors that have modified objects in a
	mailbox. For example, if user15 modifies a message in user21's mailbox,
	then user15's primary mailbox's dbguid is added to the user21's
	replguidmap. This is because Outlook, when creating new objects in
	user21's mailbox, use user15's GIDs for PR_SOURCE_KEY.

Replica ID
	16-bit shorthand value for a particular Replica GUID. Likely purpose
	was reduction of network traffic in transferring ICS data.

ReplidGuidMap, replguidmap
	A per-mailbox table with a bijective mapping between 16-bit replids and
	16-byte replguids.

	It is found in ``mdb01.edb`` as ReplidGuidMap, containing:

	* replid 1 generally contains the Database GUID (mandated by OXCFXICS
	  etc.)
	* replid 2's GUID seems to be the same across all Exchange mailboxes
	* replid 3's GUID corresponds to the value of ``PR_MDB_PROVIDER``
	* replid 4's GUID seems to be the same across all Exchange mailboxes
	* replid 5 generally contains the Mapping Signature GUID

	Subsequent replids are freely assigned on a first-come-first-serve basis.

	The ExtensionBlob column of the ReplidGuidMap table has a property that
	can hint at the trigger of the map entry creation, e.g. ``Admin``,
	``Task``, ``IdFromLongTermId``, ``ExecuteSearch``.

	In Gromox, the replguidmap is in ``exchange.sqlite3``. replid 1 and 5
	are delivered by source rather than database (was easier than doing db
	content upgrades in dbop_sqlite.cpp). replid 2 to 4 are not mapped.

ropLogon ReplID, ReplGUID fields
	Different replguidmaps lead to different values in ropLogon.ReplGUID
	[Cf. MS-OXCSTOR §3.1.4.2]. As EXC2019 and Gromox have a per-mailbox
	replguidmap (rather than one global map as in EXC2003),
	ropLogon.ReplGUID is different for every store. Generally,
	ropLogon.ReplGUID is filled with the value that is used for Named
	Property mapping (PR_MAPPING_SIGNATURE).

Store GUID
	It can be found in ``mdb01.edb`` in table ``Mailbox``, column
	``MailboxInstanceGuid``.
	It can be found in ``exchange.sqlite3`` in table ``configurations``,
	config_id 1.
	It shows up in ``ropLogon`` responses in the ``MailboxGuid`` field.
	It shows up in MAPI in the ``PR_STORE_RECORD_KEY`` property.

property
	Blurry term; can either refer to proptag or propid, and depending on
	that context, may either be unique for some object O, or not.

propid, property identifier
	A 16-bit number used to identify a given property logically. propids
	below 0x8000 are fixed; e.g. the Subject is assigned 0x37. propids above
	0x8000 are dynamically assigned during the runtime of a program, cf.
	propname.

propname, property name
	A property identifier that includes a namespace GUID and a
	GUID-specific integer or string. This mechanism allows to have much
	more than 32767 properties defined, though only at most 32767 can be
	active at any one time for a program or a mail store.

proptag, property tag
	The property tag is an ORed combination of a propid and a proptype.
	Objects like folders and messages etc. have an associative array of
	proptags to values. This implies that a propid can occur multiple
	times — in general though, at most one per object.
	
proptype, property type
	A 16-bit number used to denote the semantics of the memory block that
	makes up a property's assigned value.

Folder Associated Item, FAI
	aka Hidden Item
	Contains Metadata of various kinds, usually discoverable by very specific PR_MESSAGE_CLASS.


Limits
======

GLOBCNT_MAX = 2^47
	Maximum number of unique objects that could,
	over the entire liftime of the mailbox, ever exist.
