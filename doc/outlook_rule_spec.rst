..
        SPDX-License-Identifier: CC-BY-SA-4.0 or-later
        SPDX-FileCopyrightText: 2019 Jan Engelhardt

Specification for the Outlook RWZ rule stream and file format

version 2021-05-12

written up by Jan Engelhardt


Table of Contents
=================

* `Introduction`_
* `FAI Message: RuleOrganizer`_
* `FAI Message: RuleV2`_
* `Notation`_
* `Length fields`_
* `Timestamps`_
* `Rules Stream`_
* `XR_Begin`_
* `XR_Rule`_
* `XR_Header`_
* `XR_Separator: Element Separator`_
* `XR_PropValArray: Property value array`_
* `Condition 100 (0x64): Unknown`_
* `Condition 200 (0xc8): Name in To`_
* `Condition 201 (0xc9): Only to me`_
* `Condition 202 (0xca): Name not in To`_
* `Condition 203 (0xcb): From`_
* `Condition 204 (0xcc): To`_
* `Condition 205 (0xcd): Subject words`_
* `Condition 206 (0xce): Body words`_
* `Condition 207 (0xcf): Subject or body words`_
* `Condition 208 (0xd0): Flagged for action`_
* `Condition 210 (0xd2): Importance`_
* `Condition 211 (0xd3): Sensitivity`_
* `Condition 215 (0xd7): Category`_
* `Condition 220 (0xdc): Automatic reply`_
* `Condition 222 (0xde): Attachment`_
* `Condition 223 (0xdf): Form property`_
* `Condition 224 (0xe0): Size`_
* `Condition 225 (0xe1): Date`_
* `Condition 226 (0xe2): Name in Cc`_
* `Condition 227 (0xe3): Name in To or Cc`_
* `Condition 228 (0xe4): Form / Message class`_
* `Condition 229 (0xe5): Recipient words`_
* `Condition 230 (0xe6): Sender words`_
* `Condition 232 (0xe8): Header words`_
* `Condition 238 (0xee): Account`_
* `Condition 239 (0xef): Machine`_
* `Condition 240 (0xf0): Addressbook`_
* `Condition 241 (0xf1): Meeting request`_
* `Condition 245 (0xf5): RSS feed`_
* `Condition 246 (0xf6): Any category`_
* `Condition 247 (0xf7): Any RSS feed`_
* `Action 300 (0x12c): Move`_
* `Action 301 (0x12d): Soft delete`_
* `Action 302 (0x12e): Forward`_
* `Action 303 (0x12f): Reply with template`_
* `Action 304 (0x130): Show Outlook notification`_
* `Action 305 (0x131): Flag for action`_
* `Action 306 (0x132): Clear follow-up flag`_
* `Action 307 (0x133): Set categories`_
* `Action 310 (0x136): Play sound`_
* `Action 311 (0x137): Set importance`_
* `Action 313 (0x139): Copy`_
* `Action 314 (0x13a): Notify when read`_
* `Action 315 (0x13b): Notify when delivered`_
* `Action 316 (0x13c): Cc`_
* `Action 318 (0x13e): Defer`_
* `Action 322 (0x142): Stop rule processing`_
* `Action 324 (0x144): Redirect`_
* `Action 326 (0x146): Reply`_
* `Action 327 (0x147): Forward as attachment`_
* `Action 328 (0x148): Print`_
* `Action 330 (0x14a): Hard delete`_
* `Action 332 (0x14c): Mark as read`_
* `Action 335 (0x14f): Desktop notification`_
* `Action 337 (0x151): Set follow-up flag`_
* `Action 338 (0x152): Clear categories`_
* `Condition 400 (0x190): Receive/Send`_
* `Condition 500 (0x1f4): Except name in To`_
* `Condition 501 (0x1f5): Except only to me`_
* `Condition 502 (0x1f6): Except name not in To`_
* `Condition 503 (0x1f7): Except from`_
* `Condition 504 (0x1f8): Except to`_
* `Condition 505 (0x1f9): Except subject words`_
* `Condition 506 (0x1fa): Except body words`_
* `Condition 507 (0x1fb): Except subject or body words`_
* `Condition 508 (0x1fc): Except flagged for action`_
* `Condition 510 (0x1fe): Except importance`_
* `Condition 511 (0x1ff): Except sensitivity`_
* `Condition 515 (0x203): Except category`_
* `Condition 520 (0x208): Except automated reply`_
* `Condition 522 (0x20a): Except attachment`_
* `Condition 523 (0x20b): Except form property`_
* `Condition 524 (0x20c): Except size`_
* `Condition 525 (0x20d): Except date`_
* `Condition 526 (0x20e): Except name in Cc`_
* `Condition 527 (0x20f): Except name in To or Cc`_
* `Condition 528 (0x210): Except form / message class`_
* `Condition 529 (0x211): Except recipient words`_
* `Condition 530 (0x212): Except sender words`_
* `Condition 531 (0x213): Except header words`_
* `Condition 532 (0x214): Except account`_
* `Condition 533 (0x215): Except address book`_
* `Condition 534 (0x216): Except meeting request`_
* `Condition 537 (0x219): Except RSS feed`_
* `Condition 538 (0x21a): Except any category`_
* `Condition 539 (0x21b): Except any RSS feed`_
* `Condition ??: Form class`_
* `Condition ??: Except form class`_
* `Server-side Rules Table`_
* `SSRT: Organizer2`_
* `SSRT: OOF rules`_


Introduction
============

Rules are used to do custom processing on messages. Both incoming and
outgoing messages can be modified or otherwise acted upon. Common
tasks are, for example: sorting incoming messages into different
folders, marking incoming messages with certain colors, issuing
automatic responses while out of office, or automatic forwarding
while out of office.

Such rules are stored by Outlook all over the place (unfortunately).

* Rules configured in "Files ▶ Manage Rules & Alerts" are stored in a FAI
  message. See section `FAI message: RuleOrganizer`_.

  * Of these, specifically those which are enabled and which apply to incoming
    messages only, are cloned to ``PR_RULES_TABLE`` rows. See section
    `Server-side Rules Table`_ and `SSRT: Organizer2`_.

  * Of these, each rule is cloned to another FAI message, see section `FAI
    message: RuleV2`_.

* Rules configured in "Files ▶ Automatic replies" (Out of Office) are stored in
  ``PR_RULES_TABLE``. See section `Server-side Rules Table`_ and `SSRT: OOF
  rules`_.

  * Each rule is cloned to a FAI message, see section `FAI message: RuleV2`_.

* In ``.rwz`` files, if you choose to export rules. This appears to be the same
  as the stream format, see `Rules Stream`_.

Deferred actions are called client-side rules in Exchange/Outlook circles, but
this name is misleading since only very few of the conditions and actions one
could possibly use in rules actually require a running client in the first
place.


FAI message: RuleOrganizer
==========================

In the Inbox's Associated Contents folder, there is one message containing
distinctive properties:

``PR_SUBJECT``
	Static value ``OutlookRulesOrganizer``.

``PR_MESSAGE_CLASS``
	Static value ``IPM.RuleOrganizer``.

``PR_RW_RULES_STREAM``
	See section `Rules Stream`_

``PR_RW_RULES_STREAM`` contains most of the ruleset, including receiving and
sending rules, but not OOF rules. See section `Rules stream`_.


FAI message: RuleV2
===================

In the Inbox's Associated Contents folder, there are a *number* of messages
that represent each rule from ``PR_RW_RULES_STREAM``. These RuleV2 messages
have these characteristic properties:

``PR_MESSAGE_CLASS``
	Static value ``IPM.Rule.Version2.Message``.

``PR_RULE_MSG_LEVEL``
	Equivalent to ``PR_RULE_LEVEL``.

``PR_RULE_MSG_NAME``
	Equivalent to ``PR_RULE_NAME``.

``PR_RULE_MSG_PROVIDER``
	Static value ``Organizer2``.

``PR_RULE_MSG_PROVIDER_DATA``
	Equivalent to ``PR_RULE_PROVIDER_DATA``.

	For TDX OOF, the property is unset.

	For Organizer2, a 16-byte packed value:

	.. code-block:: c

		struct {
			uint32_t magic[2] = {1, 1};
			double timestamp; /* PT_APPTIME */
		};

``PR_RULE_MSG_SEQUENCE``
	Equivalent to ``PR_RULE_SEQUENCE``. Outlook starts with sequence number
	10.

``PR_RULE_MSG_STATE``
	Equivalent to ``PR_RULE_STATE``.

``PR_RULE_MSG_USER_FLAGS``
	Equivalent to ``PR_RULE_USER_FLAGS``.

``PR_EXTENDED_RULE_MSG_CONDITION``
	Binary data, pretty much equivalent to the data presented through
	``PR_RULE_CONDITION`` without significant differences. Some 16-bit
	fields are now 32-bit, and, according to MSDN, there is some additional
	room for expressing named properties; Unicode strings are forced.

``PR_EXTENDED_RULE_MSG_ACTION``
	(no notes)


Notation
========

A notation similar to C++ struct declarations with initializers is used in this
document. Numeric values are presented as an abstract number and their
representation in the rule stream is in little-endian format. That is, the
notation ``uint16_t x = 0x8001;`` concurs with a byte sequence of ``01 80``.

Unless otherwise noted, there is no NUL termination for strings.


Length fields
=============

If an 8-bit length field has value 0xFF, there is generally a 16-bit length
field following, which overrides it. It is not known if the 3B encoding for
values below 255 is to be rejected in similar spirit how UTF-8 mandates exactly
one encoding only.

	=============    ===========    ============
	Logical value    1B encoding    3B encoding
	=============    ===========    ============
	            0    ``00``         ``ff 00 00``
	            …    …              …
	          253    ``fd``         ``ff fd 00``
	          254    ``fe``         ``ff fe 00``
	          255    —              ``ff ff 00``
	          256    —              ``ff 00 01``
	          257    —              ``ff 01 01``
	            …    …              …
	        65534    —              ``ff fe ff``
		65535    —              ``ff ff ff``
	=============    ===========    ============

In the XR element sections further below, this is always spelled out, in three
ways:

#. The absence of 3B encoding has been verified:

   .. code-block:: c

	   uint8_t len;

#. The Outlook UI prevents the user from entering a long enough value,
   or the user cannot otherwise influence its length to observe
   behavior with 255 chars or more:

   .. code-block:: c

	uint8_t len;
	if (len == 0xff) /* conjecture */
		uint16_t len;

#. The presence of 3B encoding has been verified:

   .. code-block:: c

	uint8_t len;
	if (len == 0xff)
		uint16_t len;


Timestamps
==========

PT_APPTIME timestamps are a 64-bit IEEE floating point number, in which the
integral part represents the number of days since about December 30, 1899, and
the fractional part represents the fraction of a day since midnight. There is
no timezone information attached.

This unusual base date stems from three defining characteristics:

* the first usable day is 1900-01-01
* the starting index is 1
* index 60 maps to the (non-existing) 1900-02-29,
  and 1900-03-01 is then index 61.

A condition shown in the UI as "before 2018-01-01" is stored as
less-than(0x40e5394e...). "after 2017-12-31" is stored as
greater-than(0x40e5394d...), rather than a more straightforward
greater-or-equals(0x40e5394e...), so one will see different patterns for
effectively the same point in time.

The OL2019 UI erroneously applies the *current time* when constructing the
timestamp value from the date picker. Creating the same conditions "before
2019-01-01" twice, once at 11:58 and once at 12:00, will actually yield two
different bit patterns (0x40e5395227d2d728 and 0x40e5393222222222) and
different semantics, but the user is never told.

Detailed derivation:

==========    ================    ================
Date          Observed value 1    Observed value 2
==========    ================    ================
2019-01-01    0xd27d27d2          0x40e53950
2018-12-31    0xd27d27d2          0x40e53930
1989-09-18    ignored             0x40e00020
1989-09-17    ignored             0x40e00000
1989-09-16    ignored             0x40dfffd0
1989-09-15    ignored             0x40dfff90
1989-09-14    ignored             0x40dfff50
==========    ================    ================

OV1 has a prominent bit pattern, suggestive of a canary value for indicating
freed memory — however, 12 bits is an usual repeat cadence for such magic
markers. OV2 steps in units of 32 per day. The pattern breaks between
1989-09-16 and 1989-06-15. The DST switch however is one week away. The step
for earlier dates is 64 units per day. An increase of precision for smaller
values is strongly suggestive of a floating-point value (as the integral part
requires fewer bits, more are available for the fractional part). By trying
around, one finds that OV1 does actually belong to the float.

OL applies the hour and minute to the timestamp, but not seconds or subseconds,
so the fractional part is always a multiple of 1/1440. The curious bit patterns
in OV1 are a result of 9 being a factor of 1440.


Rules Stream
============

.. code-block:: c

	uint32_t magic[] =
		{0x00140000, 0x06140000, 0, 0,
		0, 0, 0, 0, 1, 1, 0};
	uint16_t numrules;
	repeat numrules {
		XR_Begin;
	};
	uint32_t tdlen;
	char16_t template_dir[tdlen];
	uint32_t magic = 0;
	double timestamp;
	uint32_t magic = 0;

``template_dir``
	The most recently used location from which a template file was used.
	(This is used for UI display purposes only.)

Rule order is defined by their logical position to one another in XR_Begin.


XR_Begin
========

.. code-block:: c

	uint8_t magic[3];

``magic``
	The bit pattern suggests this could be a flags field. However, before
	OL2019 for the first time created e0c810 rules, it warned of backwards
	compatibility (once only), so this is perhaps a version field.

	* ``40 42 0f``: XR_Rule (alternative 1)
	* ``80 4f 12``: XR_Rule (alternative 2)
	* ``e0 c8 10``: XR_Rule (alternative 3)
	* ``6e 54 3d``: AR_DeferAction


XR_Rule
=======

.. code-block:: c

	XR_Header
	repeat zero-or-more {
		<any XR_Condition or XR_Action>;
		if (there are more conds/actions)
			XR_Separator
	};

The size of a XR element can be variadic and generally there are no length
indiciators. The byte stream is therefore best parsed field-by-field rather
than struct-at-a-time.

The Unknown 0x190 is practically present at all times as the first element.

The Condition 0x64 is practically present at all times as the second element
(i.e. first condition), even though it does not serve any observable purpose
and is not displayed as anything in the UI.

The order of elements is generally: 0x190, then all conditions, then all
actions, and only then exception conditions.


XR_Header
=========

.. code-block:: c

	uint8_t locator;
	uint8_t rname_len;
	if (rname_len == 0xff)
		uint16_t rname_len;
	char16_t rule_name[rname_len];
	uint32_t rule_is_active;
	alternative {
		uint32_t ptact_recv_rule_activated[]  = {0, 0, 0, 1};
		uint32_t ptact_recv_rule_activated2[] = {0, 0, 0, 2};
		uint32_t strm_recv_rule_activated[]   = {0, 1, 0, 1};
		uint32_t strm_recv_rule_activated2[]  = {0, 1, 0, 2};
		uint32_t strm_recv_rule_activated3[]  = {0, 1, 0, 3};
		uint32_t strm_recv_rule_deactivated[] = {0, 0, 0, 0};
		uint32_t strm_send_rule_activated[]   = {0, 0, 0, 0};
		uint32_t strm_send_rule_deactivated[] = {0, 0, 0, 0};
	} magic;
	uint32_t bytecount;
	uint16_t rule_elements;
	uint16_t separator;
	if (separator == 0xffff) {
		uint16_t magic = 0;
		uint16_t rcls_len;
		char rule_class[rcls_len];
	} else if (separator == 0x8001) {
		/* ok */
	} else {
		REJECT-PARSE;
	}

``locator``
	A magic value:

	* ``00``: via ``PR_RULE_ACTIONS``
	* ``06``: via ``PR_RW_RULES_STREAM``

``bytecount``
	The bytecount of literally everything following the bytecount member;
	this includes not only the remaining fields of the XR Header, but also
	all the other XR separators and elements.

``rule_elements``
	The number of subsequent XR elements. XR separators do not count into
	this.

``rule_class``
	Static value ``CRuleElement``.

The OL2019 UI arbitrarily restricts rule names to 256 characters by ignoring
excess keypresses.


XR_Separator: Element Separator
===============================

.. code-block:: c

	uint16_t magic = 0x8001;


XR_PropValArray: Property value array
=====================================

This common structure appears for reference in other XR elements.

.. code-block:: c

	uint32_t magic = 0;
	uint32_t numprops;
	uint32_t bytes_in_propblock;

	/* propblock begins here */
	repeat numprops {
		uint32_t proptag;
		switch (PROP_TYPE(proptag)) {
		case PT_UNICODE:
			/* Conjecture: probably also applies for PT_STRING8 */
			uint32_t magic = 0;
			uint32_t offset_from_propblock;
			uint32_t magic = 0;
			break;
		case PT_BINARY:
			uint32_t magic = 0;
			uint32_t proplen;
			uint32_t offset_from_propblock;
			break;
		case PT_LONG:
		case PT_ERROR:
		case PT_BOOLEAN:
			uint32_t magic = 0;
			uint32_t propvalue;
			uint32_t magic = 0;
			break;
		}
	} propindex;

	char data[bytes_in_propblock - 16 * numprops];
	/* propblock ends here */

``data``
	This is a concatenation of the values for properties of type PT_BINARY
	and PT_UNICODE, in the same order as the index. Within XR_PropValArray,
	PT_UNICODE strings *are* followed by a U+0000 codepoint, and this is
	the only way to determine their length.

Emission of PT_STRING8 was not observed with OL2019.


Condition 100 (0x64): Unknown
=============================

UI label:

Not visible in the UI at all.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x64;
	uint32_t magic[] = {1, 0, 1};


Condition 200 (0xc8): Name in To
================================

UI label:

* EN: ``where my name is in the To box``
* DE: ``die meinen Namen im Feld "An" enthält``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xc8;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_TO_ME, true}


Condition 201 (0xc9): Only to me
================================

UI label:

* EN: ``sent only to me``
* DE: ``die nur an mich gesendet wurde``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xc9;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_AND, {
		{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_TO_ME, true},
		{RES_NOT, {RES_CONTENT, FL_SUBSTRING, PR_DISPLAY_TO, ";"}},
		{RES_PROPERTY, RELOP_EQ, PR_DISPLAY_CC, ""},
	}}


Condition 202 (0xca): Name not in To
====================================

UI label:

* EN: ``where my name is not in the To box``
* DE: ``die meinen Namen im Feld "An" nicht enthält``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xca;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_TO_ME, false}


Condition 203 (0xcb): From
==========================

UI label:

* EN: ``from <people or public group>``
* DE: ``die von <einer Person/öffentlichen Gruppe> kommt``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xcb;
	uint32_t magic[] = {1, 0};
	uint32_t numrcpt; /* numsenders */
	repeat numrcpt {
		XR_PropValArray;
	};
	uint32_t magic[] = {1, 0};

SRestriction:

.. code-block:: c

	{RES_COMMENT,
	lpProp={
		{PROP_TAG(PT_LONG, 0x6000), 1},
		{PROP_TAG(PT_BINARY, 0x0001), <PR_ENTRYID from an ABK or OneOff>},
		{PROP_TAG(PT_TSTRING, 0x0001), <Display name of recipient>},
		{PR_DISPLAY_TYPE, DT_MAILUSER}},
	lpRes={
		{RES_PROPERTY, RELOP_EQ, PR_SENDER_SEARCH_KEY,
			"EX:/O=TOPORGUM/..."}},
	}

Specifying multiple senders will add a level of RES_OR.

The propvalarray for an EX entity typically includes 11 props:

=================================== == ===================================== =====
proptag                             v1 v2                                    v3
=================================== == ===================================== =====
0x0c150003 (``PR_RECIPIENT_TYPE``)  0  1 (``MAPI_TO``)                       0
0x3001001f (``PR_DISPLAY_NAME``)    0  0xb0                                  0
0x0fff0102 (``PR_ENTRYID``)         0  0x7d                                  0xd0
0x3002001f (``PR_ADDRTYPE``)        0  0x14d                                 0
0x300b0102 (``PR_SEARCH_KEY``)      0  0x64                                  0x153
0x39fe001f (``PR_SMTP_ADDRESS``)    0  0x1b7                                 0
0x0ffe0003 (``PR_OBJECT_TYPE``)     0  0x6 (MAPI_MAILUSER)                   0
0x39000003 (``PR_DISPLAY_TYPE``)    0  0 (DT_MAILUSER)                       0
0x39050003 (``PR_DISPLAY_TYPE_EX``) 0  0x40000000 (``DTE_FLAG_ACL_CAPABLE``) 0
0x3003001f (``PR_EMAIL_ADDRESS``)   0  0x1d9                                 0
0x3d010102 (``PR_AB_PROVIDERS``)    0  0x10                                  0x2b9
=================================== == ===================================== =====

``PR_RECIPIENT_TYPE``
	``MAPI_TO`` apparently serves double purpose here.
``PR_ENTRYID``
	``00000000dca740c8c042101ab4b908002b2fe18201000000000000002f6f3d636f6d70616e792f636e3d2e2e2e00``
``PR_ADDRTYPE``
	``EX``
``PR_SEARCH_KEY``
	``EX:/O=COMPANY/...``
``PR_SMTP_ADDRESS``
	``abcdefgh@ijkl.de``
``PR_EMAIL_ADDRESS``
	``/o=company/...``
``PR_AB_PROVIDERS``
	{02c29c57-985c-417b-e084-c5f0b5f7be02}

Note that both senders and recipients share the same representation (here, as
MAPI Recipients); this is just like how addr-spec is used in RFC5322-style
e-mails.

The propvalarray for an SMTP entity typically includes 12 props:

========================================== == ===================================== =====
proptag                                    v1 v2                                    v3
========================================== == ===================================== =====
0x0c150003 (``PR_RECIPIENT_TYPE``)         0  1 (``MAPI_TO``)                       0
0x3001001f (``PR_DISPLAY_NAME``)           0  0xc0                                  0
0x0fff0102 (``PR_ENTRYID``)                0  0x62                                  0xe0
0x3002001f (``PR_ADDRTYPE``)               0  0x142                                 0
0x300b0102 (``PR_SEARCH_KEY``)             0  0x15                                  0x14c
0x39fe000a (``PR_SMTP_ADDRESS:PT_ERROR``)  0  0x8004010f (``MAPI_E_NOT_FOUND``)     0
0x3a710003 (``PR_SEND_INTERNET_ENCODING``) 0  0                                     0
0x3a40000b (``PR_SEND_RICH_INFO``)         0  0                                     0
0x39000003 (``PR_DISPLAY_TYPE``)           0  0 (``DT_MAILUSER``)                   0
0x0ff90102 (``PR_RECORD_KEY``)             0  0x62                                  0x161
0x0ffe0003 (``PR_OBJECT_TYPE``)            0  0x6                                   0
0x3003001f (``PR_EMAIL_ADDRESS``)          0  0x1c3                                 0
========================================== == ===================================== =====

``PR_RECIPIENT_TYPE``
	``MAPI_TO``
``PR_ENTRYID``
	Happens to be the same value as ``PR_RECORD_KEY``.
``PR_ADDRTYPE``
	``SMTP``
``PR_SEARCH_KEY``
	``SMTP:ABCDEFG@IJKL.DE``
``PR_RECORD_KEY``
	``00000000812b1fa4bea310199d6e00dd010f5402000001906100620063006400650066006700400069006a006b006c002e0064006500000053004d005400500000006100620063006400650066006700400069006a006b006c002e00640065000000``
``PR_EMAIL_ADDRESS``
	``abcdefg@ijkl.de``


Condition 204 (0xcc): To
========================

UI label:

* EN: ``sent to <people or public group>``
* DE: ``die an <einer Person/öffentlichen Gruppe> gesendet wurde`` [sic]

The layout is the same as From (0xcb), but with act_kind=0xcc.

SRestriction:

.. code-block:: c

	{RES_COMMENT,
	lpProp={
		{PROP_TAG(PT_LONG, 0x6000), 1},
		{PROP_TAG(PT_BINARY, 0x0001), <PR_ENTRYID from an ABK or OneOff>},
		{PROP_TAG(PT_TSTRING, 0x0001), <Display name of recipient>},
		{PR_DISPLAY_TYPE, DT_MAILUSER}},
	lpRes={
		{RES_PROPERTY, RELOP_EQ, PR_SEARCH_KEY,
			"EX:/O=TOPORGUM/..."}},
	}

Specifying multiple recipients will add a level of RES_OR.


Condition 205 (0xcd): Subject words
===================================

UI label:

* EN: ``with <specific words> in the subject``
* DE: ``mit <bestimmten Wörtern> im Betreff``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xcd;
	uint32_t matches;
	repeat matches {
		uint32_t possibly_flags = 0;
		uint8_t mlen;
		if (mlen == 0xff)
			uint16_t mlen;
		char16_t substring[mlen];
	} m;

SRestriction:

.. code-block:: c

	{RES_CONTENT, FL_IGNORECASE | FL_SUBSTRING, PR_SUBJECT, "text"}

Specifying multiple strings will add a level of RES_OR.

UI behavior:

The UI offers no way to set any flags, and based upon the UI text and observed
runtime behavior, FL_IGNORECASE|FL_SUBSTRING is always in effect with flags==0.

The OL2019 UI arbitrarily restricts substrings to 255 characters by ignoring
excess keypresses.


Condition 206 (0xce): Body words
================================

UI label:

* EN:"with <specific words> in the body"
* DE:"mit <bestimmten Wörtern> im Text"

The layout is the same as Subject (0xcd), but with act_kind=0xce.

SRestriction:

.. code-block:: c

	{RES_CONTENT, FL_IGNORECASE | FL_SUBSTRING, PR_BODY, "text"}

Specifying multiple strings will add a level of RES_OR.


Condition 207 (0xcf): Subject or body words
===========================================

UI label:

* EN: ``with <specific words> in the subject or body``
* DE: ``mit <bestimmten Wörtern> im Betreff oder Text``

The layout is the same as Subject (0xcd), but with act_kind=0xcf.

SRestriction:

.. code-block:: c

	{RES_OR, {
		{RES_CONTENT, FL_IGNORECASE | FL_SUBSTRING, PR_SUBJECT, "t"},
		{RES_CONTENT, FL_IGNORECASE | FL_SUBSTRING, PR_BODY, "t"},
	}}

Specifying multiple strings will not add a level of RES_OR; the existing RES_OR
will be filled.


Condition 208 (0xd0): Flagged for action
========================================

UI label:

* EN: ``flagged for <action>``
* DE: ``die mit <einer Aktion> gekennzeichnet ist``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xd0;
	uint32_t magic[] = {1, 0, 0};
	uint8_t nlen;
	if (nlen == 0xff)
		uint16_t nlen;
	char16_t action[nlen];
	uint32_t magic = 1;

SRestriction:

.. code-block:: c

	{RES_AND, {
		{RES_PROPERTY, RELOP_EQ, PR_FLAG_STATUS, followupFlagged},
		{RES_PROPERTY, RELOP_EQ,
			PROP_TAG(PT_TSTRING, 0x802A), "action"},
	}}


Condition 210 (0xd2): Importance
================================

UI label:

* EN: ``marked as <importance>``
* DE: ``die mit <Priorität> markiert ist``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xd2;
	uint32_t magic[] = {1, 0};
	enum : uint32_t {
		IMPORTANCE_LOW = 0
		IMPORTANCE_MEDIUM = 1,
		IMPORTANCE_HIGH = 2,
	} level;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_EQ, PR_IMPORTANCE, level}


Condition 211 (0xd3): Sensitivity
=================================

UI label:

* EN: ``marked as <sensitivity>``
* DE: ``die mit <Vertraulichkeit> markiert ist``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xd3;
	uint32_t magic[] = {1, 0};
	enum : uint32_t {
		SENSITIVITY_NORMAL = 0
		SENSITIVITY_PERSONAL = 1,
		SENSITIVITY_PRIVATE = 2,
		SENSITIVITY_COMPANY_CONFIDENTIAL = 3,
	} level;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_EQ, PR_SENSITIVITY, level}


Condition 215 (0xd7): Category
==============================

UI label:

* EN: ``assigned to <category> category``
* DE: ``die Kategorie <Kategorie zugeordnet ist>``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xd7;
	uint32_t magic[] = {1, 0};
	uint8_t cname_len;
	if (cname_len == 0xff)
		uint16_t cname_len;
	char16_t categories[cname_len];

SRestriction:

(Not mapped)

``categories``
	A semicolon-separated string of categories. As a consequence, category
	names are not allowed to contain semicolons, and the OL2019 UI inhibits
	the keypress.

All specified categories must be present on the message for the match to occur.
(Labeling: DE:``Nach Erhalt einer Nachricht ... die Kategorie C1 und C2
zugeordnet ist...``)


Condition 220 (0xdc): Automatic reply
=====================================

UI label:

* EN: ``which is an automatic reply``
* DE: ``die eine automatische Antwort ist``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xdc;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_CLASS,
		"IPM.Note.Rules.OofTemplate.Microsoft"}


Condition 222 (0xde): Attachment
================================

UI label:

* EN: ``which has an attachment``
* DE: ``mit einer Anlage``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xde;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_BITMASK, BMR_NEZ, PR_MESSAGE_FLAGS, MSGFLAG_HASATTACH}


Condition 223 (0xdf): Form property
===================================

UI label:

* EN: ``with <selected properties> of documents or forms``
* DE: ``mit Dokument-/Formular-<Eigenschaften>``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xdf;
	uint32_t magic[] = {1, 0};
	uint8_t flen;
	if (flen == 0xff)
		uint16_t flen;
	char16_t forms[flen];
	uint16_t numprops;
	repeat numprops {
		uint8_t flen;
		if (flen == 0xff) /* conjecture */
			uint16_t flen;
		char16_t fieldname[flen];
		uint32_t proptag;

		enum : uint32_t {
			CONTAINS = 0,
			IS_EQUAL = 1,
			NOT_CONTAINS = 2,
		} string_match_type;
		uint8_t svlen;
		if (svlen == 0xff) /* conjecture */
			uint16_t svlen;
		char16_t v_string[svlen];
		enum : uint32_t {
			EQ = 0,
			NE = 1,
			LE = 2, /* called "at most" */
			GE = 3, /* called "at least" */
			GT = 4,
			LT = 5,
		} long_match_type;
		uint32_t magic = 0;
		uint32_t v_long;
		uint32_t v_boolean; /* seemingly inverted */
		uint32_t magic = 1;
		enum : uint32_t {
			BEFORE = 0,
			AFTER = 1,
		} time_match_type;
		uint32_t magic = 0;
		double v_apptime;
		uint32_t magic = 0;
	};
	uint32_t classcount;
	repeat classcount {
		uint8_t clen;
		if (clen == 0xff) /* conjecture */
			uint16_t clen;
		char msgclass[clen];
	};

SRestriction:

(Not mapped)

``forms``
	A semicolon-space-separated list of forms to load (e.g. ``Aufgabe
	annehmen; InfoPath-Formular``).

``flen``
	(When constructing custom forms, Outlook arbitrarily restricts field
	names to 32 characters by ignoring excess keypresses. A clen >= 255 was
	not observable.)

``fieldname``
	Descriptive string for the property/field.

``proptag``
	* ``0x68010003``: ``IPM.Outlook.Recall`` a.k.a. DE:``Nachrichtenrückruf:
	  Kennzeichnungen``
	* ``0x6803000b``: ``IPM.Outlook.Recall`` a.k.a. DE:``Nachrichtenrückruf:
	  Sendebericht``
	* ``0x8zzzzzzz``: various named properties

	Even though some properties have ``PROP_TYPE()==PT_SYSTIME``, the value
	is converted and stored as a floating point timestamp in the stream.

``string_match_type``
	For PT_UNICODE, contains the choice the user made. Otherwise, 0.

``svlen``
	For PT_UNICODE, contains the length of the substring following.
	Otherwise, 0.

``v_string``
	For PT_UNICODE, contains the choice the user made.

``long_match_type``
	For PT_LONG, contains the choice the user made. Otherwise, 0.

``v_long``
	For PT_LONG, contains the choice the user made. Otherwise, 0.

``v_boolean``
	For PT_BOOLEAN, contains the inverse of the choice the user made
	(Yes=0, No=1). Otherwise, 0.

``v_apptime``
	For PT_SYSTIME/PT_APPTIME, contains the date/time choice the user made.
	Otherwise, OL fills this with the creation date of the subcondition.


Condition 224 (0xe0): Size
==========================

UI label:

* EN: ``with a size <in a specific range>``
* DE: ``mit <einer bestimmten Größe> (KB)``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xe0;
	uint32_t magic[] = {1, 0};
	uint32_t min_size_kb;
	uint32_t max_size_kb;

SRestriction:

.. code-block:: c

	{RES_AND, {
		{RES_PROPERTY, RELOP_GT, PR_MESSAGE_SIZE, xx},
		{RES_PROPERTY, RELOP_LE, PR_MESSAGE_SIZE, yy},
	}}


Condition 225 (0xe1): Date
==========================

UI label:

* EN: ``received <in a specific date span>``
* DE: ``die <in einem bestimmten Zeitraum> erhalten wurde``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xe1;
	uint32_t magic[] = {1, 0};
	uint32_t test_after;
	uint32_t magic = 0;
	double ts_after;
	uint32_t test_before;
	uint32_t magic = 0;
	double ts_before;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_GT, PR_MESSAGE_DELIVERY_TIME, xx}

or

.. code-block:: c

	{RES_PROPERTY, RELOP_LE, PR_MESSAGE_DELIVERY_TIME, yy}

both combined via ``RES_AND``.

``test_after``
	Boolean indicating whether or not to run a comparison ``NOW >
	ts_after``.

``test_before``
	Boolean indicating whether or not to run a comparison ``NOW <
	ts_before``.

``ts_after``
	Timestamp for the "is-after" check. See the "Timestamp" section for
	details.

``ts_before``
	Timestamp for the "is-before" check. Curiously, this field, together
	with the ``ts_before`` field from the Except date condition (Element
	0x20d), are the only two timestamps which have its fractional part
	correctly set to zero by the OL2019 Date Picker.


Condition 226 (0xe2): Name in Cc
================================

UI label:

* EN: ``where my name is in the Cc box``
* DE: ``die meinen Namen im Feld "Cc" enthält``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xe2;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_AND, {
		{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_CC_ME, true},
		{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_RECIP_ME, true},
		{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_TO_ME, false},
	}}


Condition 227 (0xe3): Name in To or Cc
======================================

UI label:

* EN: ``where my name is in the To or Cc box``
* DE: ``die meinen Namen im Feld "An" oder "Cc" enthält``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xe3;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_RECIP_ME, true}


Condition 228 (0xe4): Form / message class
==========================================

UI label:

* EN: ``uses the <form name> form``
* DE: ``die das Formular <Formularname> verwendet``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xe4;
	uint32_t numforms;
	uint32_t magic = 0;
	repeat numforms {
		uint8_t nlen;
		if (nlen == 0xff)
			uint16_t nlen;
		char16_t name[nlen];
		uint8_t clen;
		if (clen == 0xff) /* conjecture */
			uint16_t clen;
		char msgclass[clen];
	};

SRestriction:

.. code-block:: c

	{RES_OR, {
		{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_CLASS, "IPM.Note.MyName"},
	}}

The ``RES_OR`` is always present, even if just a single class is used.

The OL2019 UI, when saving forms, arbitrarily restricts form names to 128
characters by ignoring excess keypresses. A nlen >= 255 was therefore not
observable. Through the Options menu, one can subsequently edit the display
name (but not the message class) and set longer names.

If the message has at least one of the forms (same as message class?) presented
in this condition element, then the condition will already match.

``name``
	The display name of the form.

``msgclass``
	The form's message class. See `Message Classes`_ for a list of observed
	values.


Condition 229 (0xe5): Recipient words
=====================================

UI label:

* EN: ``with <specific words> in the recipient's address``
* DE: ``mit <bestimmten Wörtern> in der Empfängeradresse``

The layout is the same as Subject words (0xcd), but with act_kind=0xe5.

SRestriction:

.. code-block:: c

	{RES_CONTENT, FL_SUBSTRING, PR_SEARCH_KEY, "SMTP:FOO@BAR.DE"}


Condition 230 (0xe6): Sender words
==================================

UI label:

* EN: ``with <specific words> in the sender's address``
* DE: ``mit <bestimmten Wörtern> in der Absenderadresse``

UI behavior:

Only selectable for receive rules.

The layout is the same as Subject words (0xcd), but with act_kind=0xe6.

SRestriction:

.. code-block:: c

	{RES_CONTENT, FL_SUBSTRING, PR_SENDER_SEARCH_KEY, "SMTP:FOO@BAR.DE"}


Condition 232 (0xe8): Header words
==================================

UI label:

* EN: ``with <specific words> in the message header``
* DE: ``mit <bestimmten Wörtern> im Nachrichtenkopf``

UI behavior:

Only selectable for receive rules.

The layout is the same as Subject (0xcd), but with act_kind=0xe8.

SRestriction:

.. code-block:: c

	{RES_CONTENT, FL_IGNORECASE | FL_SUBSTRING,
	PR_TRANSPORT_MESSAGE_HEADERS, "text"}


Condition 238 (0xee): Account
=============================

UI label:

* EN: ``though the <specified> account``
* DE: ``über Konto <Kontoname>``

UI behavior:

When this element is selected, Outlook also selects "Condition:
Machine", and one cannot deselect Machine.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xee;
	uint32_t magic[] = {1, 0};
	uint8_t alen;
	if (alen == 0xff) /* conjecture */
		uint16_t alen;
	char16_t account_name[alen];
	uint8_t abc_len;
	if (abc_len == 0xff) /* conjecture */
		uint16_t abc_len;
	char abc[abc_len];

SRestriction:

(Not mapped)

(The MAPI control panel limits profile names to 63 characters, by the way.)

``account_name``
	An account *within* the current MAPI profile, specifically the
	account's display name (which is usually an e-mail address and which
	the MAPI/OL config dialogs refuse to make editable).

``abc``
	Content unclear. It was observed to be a 10-digit number represented as
	an ASCII string.


Condition 239 (0xef): Machine
=============================

UI label:

* EN: ``on this computer only``
* DE: ``nur auf diesem Computer``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xef;
	uint32_t magic[] = {1, 0};
	unsigned char some_guid[16];

SRestriction:

(Not mapped)


Condition 240 (0xf0): Addressbook
=================================

UI label:

* EN: ``sender is in <specified> Address Book``
* DE: ``deren Versender im Adressbuch <Adressbuchname> vorkommt``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xf0;
	uint32_t magic[] = {1, 0};
	uint32_t eidlen;
	char eid[eidlen];
	uint8_t nlen;
	if (nlen == 0xff) /* conjecture */
		uint16_t nlen;
	char16_t name[nlen];

SRestriction:

(Not mapped)

``eid``
	For example,

	::

		00000000  00 00 00 00 87 12 f5 ef  5b 95 8f 43 94 a0 89 8c  ........[..C....
		00000010  07 4d 16 c4 01 00 00 00  00 01 00 00 2f 67 75 69  .M........../gui
		00000020  64 3d 33 34 45 46 39 34  38 39 30 34 44 42 34 33  d=34EF948904DB43
		00000030  37 37 39 31 32 36 33 41  37 34 42 42 46 39 31 32  7791263A74BBF912
		00000040  34 42 00                                          4B.
		00000043

``name``
	For example, "Global Addressbook"


Condition 241 (0xf1): Meeting request
=====================================

UI label:

* EN: ``which is a meeting invitation or update``
* DE: ``die eine Besprechungsanfrage oder -aktualisierung ist``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xf1;
	uint32_t magic = 0;


Condition 245 (0xf5): RSS feed
==============================

UI label:

* EN: ``from RSS Feeds with <specified text> in the title``
* DE: ``aus RSS-Feeds mit <angegebener Text> im Titel`` [sic]

Layout:

.. code-block:: c

	uint32_t act_kind = 0xf5;
	uint32_t mgc[] = {1, 0};
	uint8_t nlen;
	if (nlen == 0xff)
		uint16_t nlen;
	char16_t name[nlen];

SRestriction:

.. code-block:: c

	{RES_OR, {
		{RES_CONTENT, RELOP_EQ, PR_MESSAGE_CLASS,
			"IPM.Schedule.Meeting.Request"},
		{RES_CONTENT, RELOP_EQ, PR_MESSAGE_CLASS,
			"IPM.Schedule.Meeting.Canceled"},
	}}


Condition 246 (0xf6): Any category
==================================

UI label:

* EN: ``assigned to any category``
* DE: ``einer beliebigen Kategorie zugewiesen``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xf6;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_EXIST, PROP_TAG(PT_MV_STRING8, 0x8002)}

Namedprop: PT_MV_STRING8:PS_PUBLIC_STRINGS:Keywords

Matches if the message has any category set. (This only works for messages
received directly through MAPI or as TNEF.)


Condition 247 (0xf7): Any RSS feed
==================================

UI label:

* EN: ``from any RSS Feed``
* DE: ``von beliebigen RSS-Feeds``

Layout:

.. code-block:: c

	uint32_t act_kind = 0xf7;
	uint32_t magic = 0;

SRestriction:

.. code-block:: c

	{RES_PROPERTY, RELOP_EQ, PR_MESSAGE_CLASS, ""}


Action 300 (0x12c): Move
========================

UI label:

* EN: ``move it to the <specified> folder``
* DE: ``diese in den Ordner <Zielordner> verschieben``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x12c;
	uint32_t magic[] = {1, 0};
	uint32_t feid_len;
	char folder_eid[feid_len];
	uint32_t seid_len;
	char store_eid[seid_len];
	uint8_t fname_len;
	if (fname_len == 0xff)
		uint16_t fname_len;
	char16_t folder_name[fname_len];
	uint32_t magic = 0;

SSRT:

.. code-block:: c

	given ACTION *act;
	act->acttype = OP_MOVE
	act->ulActionFlavor = 0
	act->actMoveCopy.cbStoreEntryId = @seid_len
	act->actMoveCopy.lpStoreEntryId = @store_eid
	act->actMoveCopy.cbFldEntryId = @feid_len
	act->actMoveCopy.lpFldEntryId = @folder_eid

The OL2019 UI's left pane arbitrarily restricts folder names to 127 characters
by ignoring excess keypresses. The folder property dialog (via context menu)
allows longer names, but still arbitrarily restricts folder names to 255
characters by ignoring excess keypresses. Longer names can be set up using
MFCMAPI.


Action 301 (0x12d): Soft delete
===============================

This is "move to wastebasket".

UI label:

* EN: ``delete it``
* DE: ``diese löschen``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x12d;
	uint32_t magic = 0;

SSRT:

.. code-block:: c

	given ACTION *act;
	act->acttype = OP_MOVE
	act->ulActionFlavor = 0
	act->actMoveCopy = (set to the wastebasket)


Action 302 (0x12e): Forward
===========================

UI label:

* DE: ``diese an <einer Person/öffentlichen Gruppe> weiterleiten" [sic]

UI behavior:

OL2019 offers no way to set the flavor bits FWD_PRESERVE_SENDER...?, etc. (see edkmdb.h).

Layout:

.. code-block:: c

	uint32_t act_kind = 0x12e;
	uint32_t magic[] = {1, 0};
	uint32_t numrcpt;
	repeat numrcpt {
		XR_PropValArray;
	};
	uint32_t magic[] = {0, 0};

The propvalarray for a recipient is the same as for a sender (0xcb).

SSRT:

.. code-block:: c

	given ACTION *act;
	act->acttype = OP_FORWARD
	act->ulActionFlavor = 0
	act->lpadrlist = ...

Typically 12 props for an SMTP target:

* ``PR_ENTRYID``
* ``PR_DISPLAY_NAME``
* ``PR_OBJECT_TYPE`` = 6
* ``PR_DISPLAY_TYPE`` = 0
* ``PR_TRANSMITTABLE_DISPLAY_NAME``
* ``PR_EMAIL_ADDRESS`` = ``foo@bar.de``
* ``PR_ADDRTYPE`` = ``SMTP``
* ``PR_SEND_RICH_INFO`` = false
* ``PR_SEND_INTERNET_ENCODING`` = 0
* ``PR_RECIPIENT_TYPE`` = 1 (``MAPI_TO``)
* ``PR_SEARCH_KEY`` = ``SMTP:FOO@BAR.DE``
* ``PR_RECORD_KEY``

Typically 14 props for an EX target:

* ``PR_ENTRYID``
* ``PR_DISPLAY_NAME``
* ``PR_OBJECT_TYPE`` = 6
* ``PR_DISPLAY_TYPE`` = 0
* ``PR_TRANSMITTABLE_DISPLAY_NAME``
* ``PR_EMAIL_ADDRESS``
* ``PR_ADDRTYPE`` = ``EX``
* ``PR_7BIT_DISPLAY_NAME`` = ``foo#bar.de``
* ``PR_SMTP_ADDRESS`` = ``foo@bar.de``
* ``PR_SEND_INTERNET_ENCODING`` = 0
* ``PR_RECIPIENT_TYPE`` = 1 (``MAPI_TO``)
* ``PR_SEARCH_KEY``
* ``PR_DISPLAY_TYPE_EX``
* ``PR_AB_PROVIDERS``


Action 303 (0x12f): Reply with template
=======================================

UI label:

* EN: ``reply using <a specific template>"
* DE: ``diese mit <einer bestimmten Vorlage> beantworten"

UI behavior:

The OL2019 file dialog's text field restricts entering pathnames to 260
characters by ignoring excess keypresses. Furthermore, the UI rejects pathnames
longer than 255 characters with a modal error dialog. The pathname from the
dialog is used as-is, so there is no automatic conversion between drive letters
and \\unc\paths.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x12f;
	uint32_t magic[] = {1, 0};
	uint8_t plen;
	if (plen == 0xff)
		uint16_t plen;
	char16_t pathname[plen];

SSRT:

.. code-block:: c

	given ACTION *act;
	act->acttype = OP_DEFER_ACTION
	act->ulActionFlavor = 0
	act->actDeferAction.pbData = /* see XR_Begin */


Action 304 (0x130): Show Outlook notification
=============================================

UI label:

* EN: ``display <a specific message> in the New Item Alert window``
* DE: ``Im Benachrichtigungsfenster für neue Elemente <diesen Text> anzeigen``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x130;
	uint32_t magic[] = {1, 0};
	uint8_t tlen;
	if (tlen == 0xff)
		uint16_t tlen;
	char16_t text[tlen];

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``)

The OL2019 UI restricts entering messages to 65536 characters by ignoring
excess keypresses. When trying to save such a large text, OL will claim
Exchange Server has a problem with it. The rule stays deactivated. Deactivated
client-side rules are not present in the MAPI Rules Table (PR_ACTIONS), but
only in the Rule FAI Message's PR_RW_RULES_STREAM property. Bringing up the
rules dialog in OL again shows the message text has been silently truncated to
65535 characters, which suggests that there is no 7B extension to the 3B
encoding of length fields.

There are additional limitations with PR_ACTIONS; only some 14539 bytes of the
``action::actDeferAction::pbData`` stream are returned by MSMAPI.


Action 305 (0x131): Flag for action
===================================

UI label:

* EN: ``flag message for <action in a number of days>``
* DE: ``diese mit <einer Aktion in ... Tagen> kennzeichnen``

UI behavior:

Only selectable for send rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x131;
	uint32_t magic[] = {1, 0};
	uint32_t days;
	uint8_t nlen;
	if (nlen == 0xff)
		uint16_t nlen;
	char16_t action[nlen];
	uint32_t magic = 0;

SSRT:

(Not mapped)


Action 306 (0x132): Clear follow-up flag
========================================

UI label:

* EN: ``clear the Message Flag``
* DE: ``die Nachrichtenkennzeichnung löschen``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x132;
	uint32_t magic = 0;

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``)


Action 307 (0x133): Set categories
==================================

UI label:

* EN: ``assign it to the <category> category``
* DE: ``diese der Kategorie <Kategorie> zuordnen``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x133;
	uint32_t magic[] = {1, 0};
	uint8_t clen;
	if (clen == 0xff)
		uint16_t clen;
	char16_t categories[clen];

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``, because ``OP_TAG`` resets the
property, i.e. would unset all previous categories.)

``categories``
	This is a semicolon-separated string of categories that shall be set on
	the message. No categories are hereby unset. (Property is
	PS_PUBLIC_STRINGS:Keywords:PT_MV_UNICODE) For this reason, category
	names themselves cannot have a semicolon in them. According to
	MS-OXOCFG, the following characters are also forbidden: U+061B (ARABIC
	SEMICOLON), U+FE54 (SMALL SEMICOLON) and U+FF1B (FULLWIDTH SEMICOLON).

UI behavior:

The OL2019 UI restricts entering category names by ignoring semicolon
keypresses.

Category name-to-color mappings are stored in a FAI message
(see ol_category_spec.rst).


Action 310 (0x136): Play sound
==============================

UI label:

* EN: ``play <a sound>``
* DE: ``<einen Sound> wiedergeben``

UI behavior:

When this element is selected, Outlook also selects "Condition: Machine".
However, one can deselect Machine by going back, and then forward again.

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``)

The layout is the same as Reply with Template (0x12f), but with act_kind=0x136.


Action 311 (0x137): Set importance
==================================

UI label:

* EN: ``mark it as <importance>``
* DE: ``diese als <Priorität> markieren``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x137;
	uint32_t magic[] = {1, 0};
	enum : uint32_t {
		IMPORTANCE_LOW = 0,
		IMPORTANCE_MEDIUM = 1,
		IMPORTANCE_HIGH = 2,
	} importance;

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``, even though ``OP_TAG`` could do
it.)


Action 313 (0x139): Copy
========================

UI label:

* EN: ``move a copy to the <specified> folder``
* DE: ``eine Kopie davon in den Ordner <Zielordner> verschieben``

The layout is the same as Move (0x12c), but with act_kind=0x139.

SSRT:

The layout is the same as Move (300), but with

.. code-block:: c

	act->acttype = OP_COPY
	act->ulActionFlavor = 0


Action 314 (0x13a): Notify when read
====================================

UI label:

* EN: ``notify me when it is read``
* DE: ``mich benachrichtigen, wenn sie gelesen wurde``

UI behavior:

Only selectable for send rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x13a;
	uint32_t magic = 0;

SSRT:

(Not mapped)


Action 315 (0x13b): Notify when delivered
=========================================

UI label:

* EN: ``notify me when it is delivered``
* DE: ``mich benachrichtigen, wenn sie erhalten wurde``

UI behavior:

Only selectable for send rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x13b;
	uint32_t magic = 0;

SSRT:

(Not mapped)


Action 316 (0x13c): Cc
======================

UI label:

* EN: ``Cc the message to <people or public group>``
* DE: ``diese an <einer Person/öffentlichen Gruppe> kopieren (Cc)`` [sic]

UI behavior:

Only selectable for send rules.

The layout is the same as Forward (0x12e), but with act_kind=0x13c.

PR_RECIPIENT_TYPE in the propvalarray still has value MAPI_TO rather than
MAPI_CC!

SSRT:

(Not mapped)


Action 318 (0x13e): Defer
=========================

UI label:

* EN: ``defer delivery by <a number of> minutes``
* DE: ``diese <eine Anzahl von> Minuten verzögert übermitteln``

UI behavior:

Only selectable for send rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x13e;
	uint32_t magic[] = {1, 0};
	uint32_t minutes;

SSRT:

(Not mapped)


Action 322 (0x142): Stop rule processing
========================================

UI label:

* EN: ``stop processing more rules``
* DE: ``keine weiteren Regeln anwenden``

UI behavior:

Understandably, Outlook always ensures this action is at the end of the
action list.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x142;
	uint32_t magic = 0;

SSRT:

.. code-block:: c

	PR_RULE_STATE |= ST_EXIT_LEVEL


Action 324 (0x144): Redirect
============================

UI label:

* EN: ``redirect it to <people or public group>``
* DE: ``diese umleiten an <einer Person/öffentlichen Gruppe>`` [sic]

UI behavior:

The OL2019 UI does not permit mixing this action with other actions not
representable as server-side rules.

The layout is the same as Forward (0x12e), but with act_kind=0x144.

SSRT:

The layout is the same as Forward (302), but with

.. code-block:: c

	act->acttype = OP_FORWARD
	act->ulActionFlavor = FWD_PRESERVE_SENDER | FWD_DO_NOT_MUNGE_MSG


Action 326 (0x146): Reply
=========================

UI label:

* EN: ``have server reply using <a specific message>``
* DE: ``diese vom Server mit <einer Nachricht> beantworten``

UI behavior:

The OL2019 UI does not permit mixing this action with other actions not
representable as server-side rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x146;
	uint32_t magic[] = {1, 0};
	uint32_t eidlen;
	char eid[eidlen];
	uint8_t slen;
	if (slen == 0xff)
		uint16_t slen;
	char16_t subject[slen];

SSRT:

.. code-block:: c

	act->acttype = OP_REPLY
	act->ulActionFlavor = 0
	act->actReply.cbEntryId = @eidlen
	act->actReply.lpEntryId = @eid

The associated message referenced by ``eid`` is stored in the inbox's
Associated Contents and has a PR_MESSAGE_CLASS of
``IPM.Note.Rules.ReplyTemplate.Microsoft``.


Action 327 (0x147): Forward as attachment
=========================================

UI label:

* DE: ``diese als Anlage an <einer Person/öffentlichen Gruppe>
  weiterleiten" [sic]

The layout is the same as Forward (0x12e), but with act_kind=0x147.

SSRT:

The layout is the same as Forward (302), but with

.. code-block:: c

	act->acttype = OP_FORWARD
	act->ulActionFlavor = FWD_AS_ATTACHMENT


Action 328 (0x148): Print
=========================

UI label:

* EN: ``print it``
* DE: ``diese drucken``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x148;
	uint32_t magic = 0;

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``)


Action 330 (0x14a): Hard delete
===============================

UI label:

* EN: ``permanently delete it``
* DE: ``diese endgültig löschen``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x14a;
	uint32_t magic = 0;

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``, even though it could use
``OP_DELETE``.)


Action 332 (0x14c): Mark as read
================================

UI label:

* EN: ``mark it as read``
* DE: ``als gelesen markieren``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x14c;
	uint32_t magic = 0;

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``.)


Action 335 (0x14f): Desktop notification
========================================

UI label:

* EN: ``display a Desktop Alert``
* DE: ``Desktopbenachrichtigung anzeigen``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x14f;
	uint32_t magic = 0;

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``.)


Action 337 (0x151): Set follow-up flag
======================================

UI label:

* EN: ``flag message for <follow up at this time>``
* DE: ``Nachricht kennzeichnen für <zu diesem Zeitpunkt nachverfolgen>``

UI behavior:

Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x151;
	uint32_t magic[] = {1, 0};
	enum : uint32_t {
		FOLLOWUP_TODAY = 0x1,
		FOLLOWUP_TOMORROW = 0x2,
		FOLLOWUP_THISWEEK = 0x3,
		FOLLOWUP_NEXTWEEK = 0x4,
		FOLLOWUP_NODATE = 0x7,
		FOLLOWUP_DONE = 0xa,
	};
	uint8_t fu_name_len;
	char16_t fu_name[fu_name_len];

SSRT:

(Mapped to ``OP_DEFER_ACTION``/``XR_Begin``.)


Action 338 (0x152): Clear categories
====================================

UI label:

* EN: ``clear message's categories``
* DE: ``Kategorien der Nachricht löschen``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x152;
	uint32_t magic = 0;

SSRT:

.. code-block:: c

	given ACTION *act;
	act->acttype = OP_TAG
	act->ulActionFlavor = 0
	act->propTag.ulPropTag = PROP_TAG(PT_MV_UNICODE, 0x8002)


Condition 400 (0x190): Receive/Send
===================================

UI label:

* EN: ``Apply this rule after the message arrives``
* DE: ``Nach Erhalt einer Nachricht``
* EN: ``Apply this rule after I send the message``
* DE: ``Nach dem Senden einer Nachricht``

Layout:

.. code-block:: c

	uint32_t act_kind = 0x190;
	uint32_t magic[] = {1, 0};
	uint32_t flagbits;

SSRT:

All rules in the SSRT are receive rules by definition.
The SSRT does not keep send rules.

``flagbits``
	* ``0x01``: message was received
	* ``0x04``: message was sent


Condition 500 (0x1f4): Except name in To
========================================

UI label:

* EN: ``except where my name is in the To box``
* DE: ``außer wenn mein Name im Feld "An" steht``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x1f4;
	uint32_t magic = 0;


Condition 501 (0x1f5): Except only to me
========================================

UI label:

* EN: ``except if sent only to me``
* DE: ``außer wenn sie nur an mich gesendet wurde``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0xc9;
	uint32_t magic = 0;


Condition 502 (0x1f6): Except name not in To
============================================

UI label:

* EN: ``except where my name is in the To box``
* DE: ``außer wenn mein Name nicht im Feld "An" steht``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x1f4;
	uint32_t magic = 0;


Condition 503 (0x1f7): Except from
==================================

UI label:

* EN: ``except if from <people or public group>``
* DE: ``außer diese ist von ...``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

The layout is the same as From (0xcb), but with act_kind=0x1f7.


Condition 504 (0x1f8): Except to
================================

UI label:

* EN: ``except if sent to <people or public group>``
* DE: ``außer bei Versand an <einer Person/öffentlichen Gruppe>`` [sic]

UI behavior:

Availability: OL2007 OL2019
Only selectable for receive rules.

The layout is the same as To (0xcc), but with act_kind=0x1f8.


Condition 505 (0x1f9): Except subject words
===========================================

UI label:

* EN: ``except if the subject contains <specific words>``
* DE: ``außer mit <bestimmten Wörtern> im Betreff``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Subject words (0xcd), but with act_kind=0x1f9.


Condition 506 (0x1fa): Except body words
========================================

UI label:

* EN: ``except if the body contains <specific words>``
* DE: ``außer mit <bestimmten Wörtern> im Text``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Subject words (0xcd), but with act_kind=0x1fa.


Condition 507 (0x1fb): Except subject or body words
===================================================

UI label:

* EN: ``except if the subject or body contains <specific words>``
* DE: ``außer mit <bestimmten Wörtern> im Betreff oder Text``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Subject words (0xcd), but with act_kind=0x1fb.


Condition 508 (0x1fc): Except flagged for action
================================================

UI label:

* EN: ``except if it is flagged for <action>``
* DE: ``außer wenn sie mit <einer Aktion> markiert ist``

UI behavior:

Availability: !OL2007 OL2019

The layout is the same as Flagged for action (0xd0), but with act_kind=0x1fc.


Condition 510 (0x1fe): Except importance
========================================

UI label:

* EN: ``except if it is marked as <importance>``
* DE: ``außer wenn mit <Priorität> markiert``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Importance (0xd2), but with act_kind=0x1fe.


Condition 511 (0x1ff): Except sensitivity
=========================================

UI label:

* EN: ``except if it is marked as <sensitivity>``
* DE: ``außer wenn mit <Vertraulichkeit> markiert``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Sensitivity (0xd3), but with act_kind=0x1ff.


Condition 515 (0x203): Except category
======================================

UI label:

* EN: ``except if assigned to <category> category``
* DE: ``außer wenn sie Kategorie <Kategorie> zugeordnet ist``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Category (0xd7), but with act_kind=0x203.


Condition 520 (0x208): Except automated reply
=============================================

UI label:

* DE: ``außer es ist eine automatische Antwort"

UI behavior:

Availability: !OL2007 OL2019

Layout:

.. code-block:: c

	uint32_t act_kind = 0x208;
	uint32_t magic = 0;


Condition 522 (0x20a): Except attachment
========================================

UI label:

* EN: ``except if it has an attachment``
* DE: ``außer es ist eine Anlage dabei``

UI behavior:

Availability: OL2007 OL2019

Layout:

.. code-block:: c

	uint32_t act_kind = 0x20a;
	uint32_t magic = 0;


Condition 523 (0x20b): Except form property
===========================================

UI label:

* EN: ``except with <selected properties> of documents or forms``
* DE: ``außer mit Dokument-/Formular-<Eigenschaften>``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Form property (0xd4), but with act_kind=0x20b.


Condition 524 (0x20c): Except size
==================================

UI label:

* EN: ``except with a size <in a specific range>``
* DE: ``außer mit <einer bestimmten Größe> (KB)``

UI behavior:

Availability: OL2007 OL2019

Layout:

.. code-block:: c

	uint32_t act_kind = 0x20c;
	uint32_t magic[] = {1, 0};
	uint32_t min_size_kb;
	uint32_t max_size_kb;


Condition 525 (0x20d): Except date
==================================

UI label:

* DE: ``außer bei Erhalt <in einem bestimmten Zeitraum>"

UI behavior:

Availability: !OL2007 OL2019

The layout is the same as Date (0xe1), but with act_kind=0x20d.


Condition 526 (0x20e): Except name in Cc
========================================

UI label:

* EN: ``except where my name is in the Cc box``
* DE: ``außer wenn mein Name im Feld "Cc" steht``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x20e;
	uint32_t magic = 0;


Condition 527 (0x20f): Except name in To or Cc
==============================================

UI label:

* EN: ``except if my name is in the To or Cc box``
* DE: ``außer wenn mein Name im Feld "An" oder "Cc" steht``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

Layout:

.. code-block:: c

	uint32_t act_kind = 0x20f;
	uint32_t magic = 0;


Condition 528 (0x210): Except form / message class
==================================================

UI label:

* EN: ``except if it uses the <form name> form``
* DE: ``außer diese verwendet das Formular <Formularname>``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Form (0xe4), but with act_kind=0x210.


Condition 529 (0x211): Except recipient words
=============================================

UI label:

* EN: ``except with <specified words> in the recipient's address``
* DE: ``außer mit <bestimmten Wörtern> in der Empfängeradresse``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as Subject words (0xcd), but with act_kind=0x211.


Condition 530 (0x212): Except sender words
==========================================

UI label:

* EN: ``except with <specified words> in the sender's address``
* DE: ``außer mit <bestimmten Wörtern> in der Absenderadresse``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

The layout is the same as Subject words (0xcd), but with act_kind=0x211.


Condition 531 (0x213): Except header words
==========================================

UI label:

* EN: ``except if the message header contains <specific words>``
* DE: ``außer mit <bestimmten Wörtern> im Nachrichtenkopf``

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

The layout is the same as Subject words (0xcd), but with act_kind=0x213.


Condition 532 (0x214): Except account
=====================================

UI label:

* EN: ``except through the <specified> account``
* DE: ``außer wenn über Konto <Kontoname> erhalten``

UI behavior:

Availability: OL2007 OL2019
When this element is selected, Outlook also selects "Condition: Machine".
However, one can deselect Machine by going back, and then forward again.

The layout is the same as Account (0xee), but with act_kind=0x214.


Condition 533 (0x215): Except address book
==========================================

UI label:

* DE: ``außer der Versender ist im Adressbuch <Adressbuchname>"

UI behavior:

Availability: !OL2007 OL2019
Only selectable for receive rules.

The layout is the same as Address book (0xf0), but with act_kind=0x215.


Condition 534 (0x216): Except meeting request
=============================================

UI label:

* EN: ``except if it is a meeting invitation or update``
* DE: ``außer es handelt sich um eine Besprechungsanfrage oder -aktualisierung``

UI behavior:

Availability: OL2007 OL2019

Layout:

.. code-block:: c

	uint32_t act_kind = 0x216;
	uint32_t magic = 0;


Condition 537 (0x219): Except RSS feed
======================================

UI label:

* EN: ``except if it is from RSS Feeds with <specified text> in the title``
* DE: ``außer von RSS-Feeds mit '<angegebener Text>' im Titel``

UI behavior:

Availability: OL2007 OL2019

The layout is the same as RSS feed (0xf5), but with act_kind=0x219.


Condition 538 (0x21a): Except any category
==========================================

UI label:

* EN: ``except if assigned to any category``
* DE: ``außer bei Zuweisung zu einer beliebigen Kategorie``

UI behavior:

Availability: OL2007 OL2019

Layout:

.. code-block:: c

	uint32_t act_kind = 0x21a;
	uint32_t magic = 0;


Condition 539 (0x21b): Except any RSS feed
==========================================

UI label:

* EN: ``except if from any RSS Feed``
* DE: ``außer von beliebigen RSS-Feeds``

UI behavior:

Availability: OL2007 OL2019

Layout:

.. code-block:: c

	uint32_t act_kind = 0x21b;
	uint32_t magic = 0;


Condition ??: Form class
========================

UI label:

* EN:?
* DE: ``vom Formulartyp '<bestimmt>'"

UI behavior:

In OL2019, clicking the ``<...>`` hyperlink leads to no dialog and no action.
The feature is practically not observable.


Condition ??: Except form class
===============================

UI label:

* EN: ?
* DE: ``außer Formulare vom Typ '<bestimmt>'"

UI behavior:

In OL2019, clicking the ``<...>`` hyperlink leads to no dialog and no action.
The feature is practically not observable.

The layout is presumably the same as Form class.


Server-side Rules Table
=======================

Perhaps the earliest way inbox rules were defined. The "Inside MAPI" book from
1996 does not mention it (nor does it any other method).

The rules table is a special property (i.e. cannot be obtained with
``IMessage::GetProps``) on the inbox, which is to be accessed using:

.. code-block:: c

	object_ptr<IExchangeModifyTable> emt;
	object_ptr<IMAPITable> tbl;
	inbox->OpenProperty(PR_RULES_TABLE, &IID_IExchangeModifyTable, 0, 0, &~emt);
	emt->GetTable(&~tbl);

From there on, it is a regular IMAPITable with a number of properties. This
table is documented on MSDN, therefore abridged here and limited to notes.

``PR_RULE_NAME``
	Rule display name.

``PR_RULE_ID``
	uint64_t which commonly seems to be `0x01000002 | (rand() << 32)`. This
	field is arguably created by the server and a client adding a new rule
	must not present this property.

``PR_RULE_PROVIDER``
	Observed values: ``MSFT:TDX OOF Rules``, ``Organizer2``

``PR_RULE_PROVIDER_DATA``
	Left undocumented by MSDN, piecewise unraveled in this document.

``PR_RULE_SEQUENCE``
	Integer specifying the order of the rule with respect to others.
	Apparently, no one could be bothered to insert rules at the right spot
	and just use PR_ROWID.


SSRT: Organizer2
================

Rules are cloned by Outlook to the SSRT if they are enabled and for incoming
messages. Conditions and actions supported by the Rule Stream get mapped onto
the SSRT fields in various ways.

Properties:

``PR_RULE_PROVIDER_DATA``
	This seems to be a GUID (due to 16 bytes), and this GUID can also be
	found on FAI message Rule.Version2 as PR_MSG_RULE_PROVIDER_DATA.

Conditions:

See the individual sections on conditions how they get mapped to SSRT
SRestrictions. If a rule has been defined without any conditions, or when none
of these conditions were mapped to the SSRT, a dummy SRestriction ``{RES_EXIST,
PR_MESSAGE_CLASS}`` may be attached.

Exceptions:

Exceptions are treated like conditions; they just get wrapped in another
RES_NOT container.

Actions:

See the individual sections on actions how they get mapped to SSRT actions. If a
rule has been defined with any actions, or when the only action is "stop
processing more rules", OP_DEFER_ACTION/XR_Begin is also used.


SSRT: OOF rules
===============

OOF was originally "Out of Facility", nowadays "Out of Office".

In PR_RULES_TABLE, there will be rows with:

``PR_RULE_PROVIDER``
	Static value consisting of "MSFT:TDX OOF Rules" followed by 32 hex chars
	`[0-9a-f]` forming some GUID.

``PR_RULE_SEQEUENCE``
	OL2019 makes them start with 100, effectively putting them after inbox
	rules, and possibly mixing them for the worse should the normal receive
	rules exceed 89.

The OOF dialog does not permit many actions at all; basically just the features
that map to the ``edkmdb.h:OP_*`` values. There are only two extra actions
implemented using ``OP_DEFER_ACTION``. The dialog has plenty of bugs and loses
information.


AR_DeferAction
==============

.. code-block:: c

	uint8_t magic[5] = {0x20, 0x20, 0x20, 0x20, 0x20};
	uint8_t actionbytes[2];


AR Action 0x30 0x3b: Notify with string
=======================================

.. code-block:: c

	char8_t message[]; /* \0-terminated */


AR Action 0x32 0x37: Notify with sound
======================================

.. code-block:: c

	char8_t path_and_msg[]; /* \0-terminated */

``path_and_msg``
	e.g. ``C:\foo.wav;Message here`` or just ``C:\foo.wav;`` for no
	message.


Message classes
===============

``IPM``
	* DE: ``Generisches Standardformular``
``IPM.Activity`` (C*)
	* EN: ``Journal entry``
	* DE: ``Journaleintrag``
``IPM.Appointment`` (C*)
	* EN: ``Appointment``
	* DE: ``Termin``
``IPM.Conflict``
	* EN: ``Conflict Message``
	* DE: ``Konfliktnachricht``
``IPM.Conflict.Resolution.Message``
	* EN: ``Conflict resolution form``
	* DE: ``Formular zur Konfliktbeseitigung``
``IPM.Contact`` (C*)
	* EN: ``Contact``
	* DE: ``Kontakt``
``IPM.DistList``
	* DE: ``Verteilerliste``
``IPM.Document``
	* DE: ``Dokument``
``IPM.InfoPathForm``
	* DE: ``InfoPath-Formular``
``IPM.Note`` (C*)
	* EN: ``Message``
	* DE: ``Nachricht``
``IPM.Note.Mobile.MMS``
	* EN: ``Multimedia Message``
	* DE: ``Multimedianachricht (MMS)``
``IPM.Note.Mobile.SMS``
	* DE: ``Textnachricht (SMS)``
``IPM.Note.RECEIPT.SMIME``
	* DE: ``SMIME-Bestätigung``
``IPM.Note.Rules.OofTemplate.Microsoft``
	* EN: ``Automatic Replies template``
	* DE: ``Vorlage für automatische Antworten``
``IPM.Note.Rules.ReplyTemplate.Microsoft``
	* EN: ``Rule reply template``
	* DE: ``Regelantwortvorlage``
``IPM.Note.SMIME``
	* DE: ``SMIME-Verschlüsselungsformular``
``IPM.Note.SMIME.MultipartSigned``
	* DE: ``Formular SMIME digital signiert``
``IPM.Note.Secure``
	* DE: ``Verschlüsselte Nachricht``
``IPM.Note.Secure.Sign``
	* EN: ``Digitally signed message``
	* DE: ``Nachricht mit digitaler Signatur``
``IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}``
	* DE: ``Ausnahme``
``IPM.Outlook.Recall``
	* EN: ``Recall Message Form``
	* DE: ``Formular zum Nachrichtenrückruf``
``IPM.POST`` (C*)
	* DE: ``Bereitstellen``
``IPM.POST.RSS`` (C*)
	* EN: ``RSS Article``
	* DE: ``RSS-Artikel``
``IPM.Recall``
	* EN: ``Message Recall Report``
	* DE: ``Nachrichtenrückrufbericht``
``IPM.Remote``
	* EN: ``Remote``
	* DE: ``Remote``
``IPM.Resend``
	* EN: ``Resend``
	* DE: ``Noch mal senden``
``IPM.Schedule.Meeting.Canceled``
	* EN: ``Meeting Cancellation``
	* DE: ``Besprechungsabsage``
``IPM.Schedule.Meeting.Request`` (C*)
	* EN: ``Meeting Request``
	* DE: ``Besprechungsanfrage``
``IPM.Schedule.Meeting.Request.Neg``
	* EN: ``Decline Meeting Response``
	* DE: ``Besprechung ablehnen``
``IPM.Schedule.Meeting.Resp.Pos``
	* EN: ``Accept Meeting Response``
	* DE: ``Besprechungseinladung annehmen``
``IPM.Schedule.Meeting.Resp.Tent``
	* DE: ``Besprechungszusage mit Vorbehalt``
``IPM.Sharing``
	* EN: ``Sharing Request``
	* DE: ``Freigabeanfrage``
``IPM.StickyNote``
	* EN: ``Note``
	* DE: ``Notiz``
``IPM.Task`` (C*)
	* DE: ``Aufgabe``
``IPM.TaskRequest`` (C*)
	* DE: ``Aufgabenanfrage``
``IPM.TaskRequest.Accept``
	* DE: ``Aufgabe annehmen``
``IPM.TaskRequest.Decline``
	* DE: ``Aufgabe ablehnen``
``IPM.TaskRequest.Update``
	* DE: ``Aufgabe aktualisieren``
``REPORT``
	* DE: ``Bericht``

Custom forms may be created from the classes/forms designated ``C*``. The
resulting message class will use that prefix. For example, deriving from the
``IPM.Note`` form and saving it under the name ``MyForm`` will make it
available under the class name ``IPM.Note.MyForm``.
