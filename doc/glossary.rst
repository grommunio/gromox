..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2023-2024 grommunio GmbH

Overview
========

The sorting of sections was chosen so that a bottom-up view builds as one
reads. Terms within one section are likewise sorted.


Stores
======

MAPI Provider
	A component within a connector that actually delivers data. The
	``emsmdb32.dll`` connector for example offers "Microsoft Exchange
	Message Store" (a store provider), "Microsoft Exchange Directory
	Services" (an address book provider) and then some.

MAPI Service
	A service is an instantiation of an IMsgService object produced by a
	connector plugin. It corresponds roughly to an account (a identity to
	use for accessing the providers in a service).

MAPI Profile
	A profile consists of zero or more service instances. In essence, a
	profile is a list of stores to open and address books to draw data
	from.

Primary Store
	In MSMAPI documentation, this term is used for a message store which is
	used during the ropLogon procedure. There is just one primary store for
	a profile, so, unfortunately, it does not refer to a user's home store.

	Outside of MSMAPI, the term might be used in reference to the home store.

Secondary Store
	In MSMAPI documentation, this term is used for a message store which
	can be promoted to primary if the original primary is unavailable. (We
	have never observed the SECONDARY flag in MSMAPI profiles.)

	In other situations, the term might be used in reference to any store
	other than the home store (even to stores that are not promotable in
	this fashion).

Default Store
	In MSMAPI documentation, this is the, well, default store for
	a *profile*. It is not necessarily referring to a home store.

Home store
	(We are still looking for a suitable term to denote a user identity's
	intrinsic mailbox.)

Private Store
	A type of mailbox. In Gromox, a private store is prepopulated by
	gromox-mkprivate with about 19 undeletable essential folders, e.g. Top
	of Information Store (IPM_SUBTREE), Inbox, Outbox, etc.

Delegate Store
	A term used in Exchange to denote private stores which are not the
	default store.

Public Store
	A type of mailbox. Because entryids in MSMAPI make reference to a
	public store using a *private* user's identity, at most one public
	store can be associated with one user.

	In Exchange, each public store has an MSAD user object and
	ESSDN/LegacyDN, as well as a (admin-pickable) Service Principal
	Name/mail address (even though that mail address is not enabled).

	In Gromox, public stores are owned by Gromox domain objects (not Gromox
	user objects). The schema for domain objects is separate from user
	objects. The SPN is fixed to public.folder.root@<domain>. Public stores
	are prepopulated by gromox-mkpublic with a few undeleteable essential
	folders, e.g. IPM_SUBTREE, IPM_NON_SUBTREE. The sqlite database schema
	is different, e.g. it has tables to track read states per user. Some
	Gromox command-line utilities require the use of ``@example.com``,
	others as ``example.com`` when referencing a domain's public store.

Non-default store
	Refers to any store that is not the user's home store, e.g. public
	stores, private stores of other users, Zarafa archive stores, or even
	extra PSTs opened in a MAPI profile.

Shared Store
	A term used for a non-default private store.

exchange.sqlite3
	An SQLite database file used by Gromox which stores a significant
	portion of what makes up a mailbox, including the folder hierarchy and
	messages. What is not included, but stored as loose files on the
	operating system's filesystem, are: message bodies, transport header
	property value, file attachments.


Numbers and identifiers
=======================

FLATUID
	16 raw octets.

GUID
	Globally Unique Identifier. Also known as Universally Unique Identifier
	(UUID). 128 bits in length. Not all bits are random; RFC 4122 defines
	semantic meaning for certain bits.

GUID.Host36
	Herein refers to a textual 36-character representation of a GUID, e.g.
	``44332211-6655-8877-b0a0-fedbca987654``.

GUID.Host38
	Herein refers to a textual 38-character representation of a GUID, e.g.
	``{44332211-6655-8877-b0a0-fedbca987654}``.

GUID.beflat
	Herein refers to a 16-byte encoding of a GUID. Per RFC 4122, the
	flat form for the example GUID above is ``uint8_t x[] = {0x44, 0x33,
	0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0xb0, 0xa0, 0xfe, 0xdb, 0xca, 0x98,
	0x76, 0x54};``.

GUID.dceflat
	Herein refers to a 16-byte encoding of a GUID. DCE/MS UUIDs use a
	mixed-endian format (3x le32, 2x u8, 1x be48). The flat form is
	``uint8_t x[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xb0,
	0xa0, 0xfe, 0xdb, 0xca, 0x98, 0x76, 0x54};``.

GUID.dcetxt
	Herein refers to a textual 32-character representation of a GUID, a
	hexdump of a dceflat, e.g. ``1122334455667788a0b0fedbca987654``.

Mailbox GUID
	Randomly-generated value on mailbox creation.
	It can be found in MSAD in the ``msExchMailboxGuid`` attribute
	in Host36 form.
	It can be found in ``mdb01.edb`` in table ``Mailbox``, column
	``MailboxGuid`` in dceflat/dcetxt form (dependent on esedbexport).
	In the EWS protocol as spoken by Exchange Server, the "ItemId"
	attribute contains the Mailbox GUID in ASCII from byte 4-28.
	The GUID shows up in MAPI store objects (MFCMAPI/OLSpy) in the
	0x67070102 (MailboxDSGuid) property.
	The GUID shows up in ABK objects in the 0x8c730102 property.
	In Gromox, the Mailbox GUID is constructed from 12 filler bytes plus 4
	bytes conveying a user ID. Exchange just makes random GUIDs.

Store GUID
	Randomly-generated value on mailbox creation.
	It can be found in ``mdb01.edb`` in table ``Mailbox``, column
	``MailboxInstanceGuid`` in dceflat/dcetxt form.
	It can be found in ``exchange.sqlite3`` in table ``configurations``,
	config_id 1 in Host36 form.
	It shows up in ``ropLogon`` responses in the ``MailboxGuid`` field.
	It shows up in MAPI objects (MFCMAPI/OLSpy) in the
	``PR_STORE_RECORD_KEY`` property.

MAPIHTTP MailboxId parameter
	Autodiscover responses contain a URL like
	``https://g.net/mapi/emsmdb/?MailboxId=754af46e-6310-4e07-aea1-2c911e595644@domain.example``.
	Though the value contains the Mailbox GUID, it is actually a copy of
	the value in the ``<Server>`` element of an RPCH-enabled server.

ESSDN
	"Enterprise/site/server distinguished name", a.k.a. Legacy DN. In
	Gromox and contemporary versions of Exchange Server, it is a fake X.500
	Distinguished Name that is not tied to any real LDAP tree(s). The ESSDN
	text representation is root-first and uses slash as a hierarchy
	separator (``/DC=com/DC=example/CN=Users``), whereas MSAD/OpenLDAP DNs
	are root-last using comma (``CN=Users,DC=example,DC=com``). Different
	ESSDN have been identified, see below.

ESSDN.User (Addressbook entry) in Exchange
	Typical form:
	``/o=myexch/ou=EAG/cn=Recipients/cn=<guid-32nibbles>-<cn>`` and
	``/o=myexch/ou=EAG/cn=Recipients/cn=user<8nibbles>``. It can be found
	in MSAD in the ``legacyExchangeDN`` attribute of a user object.
	``myexch`` is a name chosen by the administrator during Gromox or
	Exchange installation. The 8-nibble form is used when <cn> contains
	reserved characters like '/', '=', non-ASCII or (presumably also)
	non-printable. The GUID part probably exists to accomodate multiple
	users with same Common Name in the LDAP tree/forest. It is unclear if
	the GUID is flatlsb32 or host32. It is unclear if the 32-bit userid is
	le32 or be32. In the ropLogon ROP, the user/ABK ESSDN is used to open a
	particular store. (Autodiscover is used ahead of time to resolve
	SPN/email addresses to user ESSDNs as necessary.) Logon to public
	stores happens with the user's ESSDN plus a flag bit, rather than the
	public store's ESSDN.

ESSDN.User in Gromox
	Typical form for private and public stores respectively:
	``/o=myexch/ou=EAG/cn=Recipients/cn=<leuint32-domid><leuint32-userid>-<localpart>``,
	``/o=myexch/ou=EAG/cn=Recipients/cn=<leuint32-domid>00000000-<domainpart>``.

ESSDN.Server
	Typical form:
	``/o=myexch/ou=EAG/cn=Configuration/cn=Servers/cn=SRV-EXCHANGE-01``. In
	MSAD, the server ESSDN can be found in the ``msExchHomeServer``
	attribute of a user object. This ESSDN kind does not appear to be used
	outside of MSAD.

ESSDN.MailboxServer
	Typical form:
	``/o=myexch/ou=EAG/cn=Configuration/cn=Servers/cn=<mailboxid>@<emaildomain>``.
	Exchange and Gromox can generate this ESSDN kind for the ``<Server>``
	element in Autodiscover responses. Practical use has to do with Public
	Folders, but is only exercised in obscure ROPs.

ESSDN.MdbDN
	Typical form:
	``/o=myexch/ou=EAG/cn=Configuration/cn=Servers/cn=<mailboxid>@<emaildomain>``.
	Exchange and Gromox can generate this ESSDN kind for the ``<MdbDN>``
	element, but no practical use has been seen.

Database GUID
	Randomly-generated value on mailbox creation.
	A value which is found in ``mdb01.edb`` in table ``MailboxIdentity``,
	column ``LocalIdGuid`` in flatlsb32 representation.
	In Exchange, dbguid is distinct from Store GUID.
	In Gromox, dbguid is the same value as GABUID.
	In Outlook Cached Mode, every OST file has its own dbguid. (Deleting
	the OST file leads a new dbguid being generated.)
	It MFCMAPI/OLSpy, the value shows up as part of Change Keys, PCLs,
	entryids, etc.

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

IID_
	A prefix in source code for "interface identifier", related to the
	MSMAPI C API and the ``IUnknown::QueryInterface`` function therein.
	Identifiers may be ``IID_IMessage``, ``IID_IMAPIFolder``,
	``IID_IMAPITable``, etc. Not to be confused with "internal identifier"
	(see below).

GLOBCNT / GCV
	Short for "global object count(er)". Scope: one mailbox replica. Limit:
	2^48. Every folder and message object is assigned a **unique,
	non-reusable** GC value (GCV). GCVs need not be assigned in any
	particular order, and no particular order should be inferred from GCVs.
	In practice, a strictly monotonically increasing counter is used.

	Some components can perform a *range reservation* (e.g.
	``ropGetLocalReplicaIds`` and the gromox-exmdb ``create_folder`` RPC),
	which can cause GCV values to apparently jump around: For example, in
	Gromox, a created folder may receive GCV 0x10000 and, because
	``create_folder`` reserves 0x10001..0x1ffff for messages, the next
	folder gets GCV 0x20000. Once the first folder has exceeded its
	reservation, it will make another, e.g. 0x30000..0x3ffff. The
	per-folder range reservations improve the locality of a folder's
	message IDs, which is conducive to IDSET compression and reducing
	network traffic a little bit.

	In Gromox (2.17), the SQLite fields ``folder_id`` and ``message_id``
	are GCVs rather than internal identifiers. (This may change at a later
	time.)

	Generally speaking,

	* on the wire and in ``struct GLOBCNT``, GCVs are MSB-first (big-endian)
	* when stored as part of a ``eid_t``/``uint64_t`` variable in source
	  code that holds an *Internal Identifier* (see below), the GCV is in
	  the upper 48 bits of the logical value, and reversed per groups of 8
	  bits
	* otherwise, a ``uint64_t`` holds the GCV in host-endian

Change number / CN
	Scope: one mailbox replica. Limit: 2^48. Every time a folder or message
	is modified, a new change number is assigned. CNs are assigned in
	strictly monotonically increasing order. There is no reservation; in a
	sense, a replica in itself could be seen as a 2^48-sized reservation in
	the space of unsigned 64-bit integers.

	In Gromox (2.27), the SQLite field ``change_number`` contains this
	48-bit CN for the server replica (replid 1).

	Like GCVs, CNs may occur in MSB/GLOBCNT form, or be part of a 64-bit
	aggregated integer (like *Internal Identifier*, see below), or be
	host-endian stand-alone.

Internal Identifier
	The aggregation of the 16-bit *replid* of the creator plus the
	48-bit *GLOBCNT* (of a GCV or CN).
	Scope: all replicas of a mailbox. Limit: not defined because
	aggregate. Total size: 8 octets. IIDs have no particular order. On the
	wire, replid is LSB-first, but GLOBCNT is MSB-first. MS-OXCDATA
	specifies IIDs as an aggregate, while MS-OXCROPS specifies them as
	64-bit integers. Gromox, MAPI Inspector For Fiddler, but also Exchange
	Server indeed read/write IIDs from/to network as one leuint64 rather
	than as one leuint16 and a beuint48 (this artifact is visible in the
	PidTagCn value of an object). This causes the logical value to have odd
	bit order too, e.g. the byte sequence ``01 00 00 00 00 00 00 0d``
	(replid 1, folder 0xd) is 0xd00000000000001 when printed in MFCMAPI.
	Functions like ``rop_util_get_gc_value`` are needed to make sense of
	it. The type ``eid_t`` is being introduced in source code to markup the
	places where this weird uint64 is in use.

Folder Identifier, FID
	Name for *internal identifier* when talking about a folder object. The
	FID can be observed in *EX entryids* (with conditions) at bytes 38–46.
	In Gromox source code (as of 2.17), ``fid`` as a variable name
	sometimes refers to either to the mixed-byteorder *Internal Identifier*
	(see above) or the (host-endian) GCV. ``fid_val`` is almost exclusively
	the host-endian GCV form.

Message Identifier, MID
	Name for *internal identifier* when talking about a message object. The
	MID can be observed in *EX entryids* (with conditions) at bytes 62–70.
	In Gromox source code (as of 2.17), ``mid`` as a variable name
	sometimes refers to either the mixed-byteorder *Internal Identifier*
	(see above) or the (host-endian) GCV. ``mid_val`` is almost exclusively
	the host-endian GCV form.

Global Identifier, GID
	The aggregation of the 128-bit *Database GUID* plus the 48-bit
	*GLOBCNT*/*CN*. Scope: all replicas of a mailbox. Limit: not defined
	because aggregate. Total size: 22 octets.

External Identifier, XID
	The aggregation of a 128-bit namespace GUID plus a storage-specific
	*GLOBCNT*/*CN*. Scope: all replicas of a mailbox. Limit: not defined
	because aggregate. Total size: varies, but at most 255 bytes.

	EX: 16-byte *Database GUID* + GCV/CN (6 bytes, MSB)
	OST: 16-byte *Database GUID* + GCV/CN (4 bytes, MSB)

LongTermID
	The aggregation of a *GID* (22 bytes) plus 2 NUL pad bytes. Total size:
	24 octets. The pad bytes do not indicate a replid 0, because the
	replica is already identified by the 16-byte GUID that is part of the
	GID.

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

	It is found in ``mdb01.edb`` as table ``ReplidGuidMap``, containing:

	* replid 1 generally contains the Database GUID (mandated by OXCFXICS
	  etc.)
	* replid 2 is the same across different mailboxes and deployments:
	  {ed33cbe5-94e2-48b6-8bea-bba984896933}
	* replid 3 same: {68349a54-323d-4a38-9aa9-e00a683131ba}
	* replid 4 same: {bb0754de-7f26-4d08-932f-fe7a9d22f8bd}
	* replid 5 generally contains the Mapping Signature GUID

	Subsequent replids are freely assigned on a first-come-first-serve basis.

	The ExtensionBlob column of the ReplidGuidMap table has a property that
	can hint at the trigger of the map entry creation, e.g. ``Admin``,
	``Task``, ``IdFromLongTermId``, ``ExecuteSearch``.

	In Gromox, the replguidmap is in ``exchange.sqlite3``. replid 1 to 5
	are delivered by source rather than database (was easier than doing db
	content upgrades in dbop_sqlite.cpp).

ropLogon ReplID, ReplGUID fields
	Different replguidmaps lead to different values in ropLogon.ReplGUID
	[Cf. MS-OXCSTOR §3.1.4.2]. As EXC2019 and Gromox have a per-mailbox
	replguidmap (rather than one global map as in EXC2003),
	ropLogon.ReplGUID is different for every store. Generally,
	ropLogon.ReplGUID is filled with the value that is used for Named
	Property mapping (PR_MAPPING_SIGNATURE).

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

Global user count
	Gromox limit: 2^31 - 16, based on ab_tree minid limits.
	Upper theoretical limit: 2^32 - 16.

Global domain count
	Gromox limit: 2^29 - 16, based on ab_tree minid limits.
	Upper theoretical limit: 2^32 - 16.

Global department count
	Gromox limit: 2^29 - 16, based on ab_tree minid limits.
	Upper theoretical limit: 2^32 - 16.

Global AB class count
	Gromox limit: 2^29 - 16, based on ab_tree minid limits.
	Upper theoretical limit: 2^32 - 16.

Username
	Length limit: 319.
	64 characters for the localpart left of the '@' sign, 253 characters
	for the hostname right of the '@' sign [254 chars if trailing dots are
	used]. (RFC 1035)

Mailbox size
	Limit: 15 exabytes.
	The range of the ``PR_MESSAGESIZE_EXTENDED`` property is 0..2^63, the
	unit is in bytes.

Mailbox quota restriction
	Limit: 2 terabytes.
	The range of the ``PR_PROHIBIT_RECEIVE_QUOTA``,
	``PR_PROHIBIT_SEND_QUOTA``, ``PR_STORAGE_QUOTA_LIMIT`` property is
	0..2^31, the unit is kilobytes.

Changes
	Limit: 2^48 changes per replid.
	Upper theoretical limit: 2^64 (by starting to use multiple replids for
	one "replica").

GLOBCNT
	Regular specced limit: 2^48. (imposed by limit for *Changes*)
	Upper theoretical limit: 2^64.

Folders
	Lowest known limit: 2^31. Gromox 2.17 does range reservations when a
	folder is created in online mode (cf. ``SYSTEM_ALLOCATED_EID_RANGE``
	and ``ALLOCATED_EID_RANGE`` in source code), so the GLOBCNT space could
	already be used up after 2^31 folders.
	Regular specced limit: 2^48 (cf. *GLOBCNT*).
	Upper theoretical limit: 2^64 (cf. *GLOBCNT*).

Messages
	Lowest known limit: 2^31. If you restrict yourself to place only one
	message per folder, then *folders* is the limit.
	Regular specced limit: 2^48 (cf. *GLOBCNT*).
	Upper theoretical limit: 2^64 (cf. *GLOBCNT*).

Receive folders
	Lowest known limit: 2000, due to a mystery historic choice for the
	``MAXIMUM_RECEIVE_FOLDERS`` constant in the Gromox 2.17 source code.
	Regular specced limit: 2^48 (cf. *Folders*).
	Upper theoretical limit: 2^64 (cf. *Folders*).

Named properties
	Lowest knwon limit: 28672 (propids 0x8000..0xefff inclusive) per
	mailbox, due to a mystery historic choice for the
	``MAXIMUM_PROPNAME_NUMBER`` constant in the Gromox 2.17 source code.
	Technical limit: 32767 (propids 0x8000..0xfffe inclusive) per mailbox.

Replicas
	Lowest anticipated limit: 32763.
	Upper theoretical limit: 65535.
	(replid 0 is unused, replid 1 is already used at mailbox creation time,
	Exchange/Gromox reserve another 4, and we are unsure whether replids
	are treated as a signed or unsigned 16-bit quantity.)


Foreign limits
==============

* PFF files are said to have a technical limit of 4096 TB, but Outlook has imposed
  `extra arbitary limits
  <https://support.microsoft.com/en-gb/topic/how-to-configure-the-size-limit-for-both-pst-and-ost-files-in-outlook-2f13f558-d40e-9c2a-e3b6-02806fa535f4>`_.
