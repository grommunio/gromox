..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2023 grommunio GmbH

Default Store
	In a *MAPI profile*, there is a "default store" (default mailbox).
	This is the user's home store.

Non-default store
	Refers to e.g. public stores, stores of other users
	or e.g. Zarafa archive stores.

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
	A value which is found in ``mdb01.mdb`` in table ``Mailbox``, column
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

MAPI Profile
	A list of one or more mailboxes. This concept only exists client-side,
	e.g. in MSMAPI or PHP-MAPI. Other mailboxes can still be opened even if
	they are not part of a MAPI profile.

Mapping Signature
	Visible in ``mdb01.mdb`` in table ``Mailbox``, column ``MappingSignatureGuid``.
	Visible in MAPI in the ``PR_MAPPING_SIGNATURE`` property.
	The mapping signature indicates which objects share a Named Property
	propid<->propname map.
	It is unspecified whether this also declares the validity scope for
	ReplIDs.
	In Gromox, the Mapping Signature has the same value as the Store GUID.

Store GUID
	It can be found in ``mdb01.mdb`` in table ``Mailbox``, column
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
