..
        SPDX-License-Identifier: CC-BY-SA-4.0 or-later
        SPDX-FileCopyrightText: 2021-2022 grommunio GmbH

Dialog templates
================

Exchange stores dialog templates at

	CN=Display-Templates,CN=Addressing,CN=OurMail,CN=Microsoft Exchange,
	CN=Services,CN=Configuration,DC=company,DC=com

Within Display-Templates, there are nodes for every locale offered.
This is the base-16 representation of the locale ID, cf. ``lcid.txt``.

* ``CN=409``: English (1033/0x409)

Within each locale, there are nodes for different templates.

* ``CN=0``: User
* ``CN=1``: Group
* ``CN=2``: Public Folder
* ``CN=3``: Mailbox Agent
* ``CN=6``: Contact
* ``CN=200``: Search Dialog
* ``CN=Exchange``: Exchange Send Options

Within each template, there are a number of attributes that may
appear of interest. The following four are type-1 ABKT templates:

* ``addressEntryDisplayTable``: current settings (possibly user-modified;
  or possibly Exchange default) for the domain
* ``addressEntryDisplayTableMSDOS``: current settings, tailored for
  Outlook for DOS (Exchange 5.5), uses row/col addressing instead of
  pixel units
* ``originalDisplayTable``: Exchange default for Outlook
* ``originalDisplayTableMSDOS``: Exchange default for DOS

A fifth attribute exists, but it uses a type-2 ABKT template, which is not
documented by MS-OXOABKT. It appears to be a remnant of Exchange 2003.

* ``perMsgDialogDisplayTable``: Exchange Send Options


Type-2 template
===============

Type-2 templates have a CNTRL structure of 16 instead of 12 bytes (TRow
structure of 40 instead 36 bytes).

.. code-block:: c

	struct TRow_v2 {
		uint32_t XPos, DeltaX, YPos, DeltaY, ControlType, ControlFlags;
		struct CNTRL_v2 ControlStructure;
	};
	struct CNTRL_v2 {
		uint32_t extra2;
		uint32_t dwSize, ulSize, ulString;
	};

Possible values for ``ControlType`` are given by ``DTCT_`` definitions in
``mapidefs.h`` (and/or ``wabdefs.h``). “New” control types — MAPI has known
these all along — are: combobox (0x3), dropdown listbox (0x4), radio button
(0x9).

CNTRL structure describing a combobox
-------------------------------------

* ``gxT2Extra`` (presumably ``ulPRTableName``). No info. In the only ABKT-2
  template ever seen, it specifies a ``PT_LONG`` property.
* ``dwType`` (``ulPRPropertyName``): Property tag of type ``PT_TSTRING``.
* ``ulSize`` (``ulNumCharsAllowed``): Number of characters allowed to be
  entered into the edit control.
* ``ulString``: Offset to a string specifying the regular expression for characters
  allowed in the edit control.

CNTRL structure describing a dropdown listbox
---------------------------------------------

* ``gxT2Extra`` (``ulPRDisplayProperty``): Property tag of type ``PT_TSTRING``.
  This property is one of the columns in the table identified by the
  ``ulPRTableName`` member. The values for this property are displayed in the
  list. (Unused? Because the values are in ulString…)
* ``dwType``. No info. In the only ABKT-2 template ever seen, it specifies a
  ``PT_LONG`` property.
* ``ulSize``. No info. In the only ABKT-2 template ever seen, it specifies a
  ``PT_LONG`` property.
* ``ulString``: Offset to a string specifying a backslash-separated list of
  selectable list values.

CNTRL structure describing a radiobutton
----------------------------------------

* ``gxT2Extra`` (``ulcButtons``): Count of buttons in the radio button group.
  The structures for the other buttons in the group must be contained in
  successive rows of the display table. Each of these rows must contain the
  same value for the ``ulcButtons`` member.
* ``dwType`` (``ulPropTag``): Property tag of type ``PT_LONG``. The initial
  selection in the radio button group is based on the initial value of this
  property. Each button in the group must have the same ``ulPropTag``.
* ``ulSize`` (``lReturnValue``): Unique number that identifies the selected
  button.
* ``ulString``: Offset to the label text of the control.


Icon association for Exchange objects
=====================================

===============  ========  ========  ===============  ===========  =====
Exchange Object  Otyp      Dtyp      DtypEx           OL icon      OWA
===============  ========  ========  ===============  ===========  =====
Root container   ABCONT    unset     unset            -            -
GAL              ABCONT    GLOBAL    unset            -            -
NSPI container   ABCONT    LOCAL     unset            -            -
Outlook AB       ABCONT    NOT_SPEC  unset            -            -
Regular user     MAILUSER  MAILUSER  MAILUSER | ACL   1 pax        1 pax
Shared mailbox   MAILUSER  MAILUSER  unset            1 pax        1 pax
E-mail user      MAILUSER  REMOTE_M  REMOTE_MAILUSER  World        1 pax
E-mail contact   MAILUSER  REMOTE_M  REMOTE_MAILUSER  World        1 pax
Room             MAILUSER  MAILUSER  ROOM             Room         Room
Equipment        MAILUSER  MAILUSER  EQUIPMENT        Board        1 pax
Dist. list       DISTLIST  DISTLIST  DISTLIST         2 pax        3 pax
Dynamic list     MAILUSER  AGENT     AGENT            2 pax+gear   3 pax
Security group   DISTLIST  DISTLIST  DISTLIST | ACL   2 pax        3 pax
Public folder    FOLDER    FORUM     unset            Folder+mail  1 pax
===============  ========  ========  ===============  ===========  =====

For Otyp, see ``mapidefs.h:enum mapi_object_type``. This tells
the object type in C API terms (IABContainer, IMailUser,
IDistList, IMAPIFolder, etc.).

For Dtyp, Dtypex, see ``mapidefs.h:enum display_type``.


MSMAPI exposed data
===================

The Minimal EntryID expressed by the NSPI protocol makes an appearance
in MSMAPI in the PR_INSTANCE_ID property.

The "Contacts" folder itself in private mailboxes:

* PR_CONTAINER_CLASS=``IPM.Contacts``

Contact in private "Contacts" folder:

* PR_OBJECT_TYPE=5 MAPI_MESSAGE
* PR_MESSAGE_CLASS=``IPM.Contact``
* PidLidEmail1AddressType=``SMTP``/``EX``

Same contact as seen in the AB Hierarchy:

* PR_ADDRTYPE=``SMTP``/``EX``
* PR_DISPLAY_TYPE=``0`` DT_MAILUSER
* PR_OBJECT_TYPE=``6`` MAPI_MAILUSER

Contact group in private "Contacts" folder:

* PR_OBJECT_TYPE=``5`` MAPI_MESSAGE
* PR_MESSAGE_CLASS=``IPM.DistList``
* members in PidLidDistributionListOneOffMembers (PSETID_Address:0x8054:PT_MV_BINARY)
* members in PidLidDistributionListMembers (PSETID_Address:0x8055:PT_MV_BINARY)
* entryids found in 8054 are all muidOOP
* entryids found in 8055 can be either muidOOP or WAB_GUID {d3ad91c0-9d51-11cf-a4a9-00aa0047faa4} wrapping muidEMSAB

Same contact group as seen in the AB Hierarchy:

* PR_ADDRTYPE=``MAPIPDL``
* PR_DISPLAY_TYPE_EX={unset}
* PR_DISPLAY_TYPE=``5`` DT_PRIVATE_DISTLIST
* PR_OBJECT_TYPE=``8`` MAPI_DISTLIST

Properties that may appear on GAL objects
=========================================

* PR_COMMENT: basic description
* PR_DISPLAY_NAME: display name
* PR_DISPLAY_TYPE
* PR_DISPLAY_TYPE_EX
* PR_OBJECT_TYPE: relevant for ::OpenEntry
* PR_EMAIL_ADDRESS: limit of 128 chars with EX addrtype
* PR_EMS_AB_COUNTRY_NAME: ISO code
* PR_EMS_AB_DL_SENDER_HINT_TRANSLATIONS (PT_MV_UNICODE): another description field, supposedly limited to 175 Unicode chars
* PR_EMS_AB_EXTERNAL_MEMBER_COUNT
* PR_EMS_AB_TOTAL_MEMBER_COUNT
* PR_EMS_AB_INSTANCE_TYPE=``0x4``
* PR_EMS_AB_PROXY_ADDRESSES: aliases
* PR_EMS_AB_ROOM_CAPACITY (also for equipment etc.)
* PR_EMS_AB_USN_CHANGED: cf. LDAP entry
* PR_EMS_AB_USN_CREATED: cf. LDAP entry
* PR_MHS_COMMON_NAME: display name
* PR_SMTP_ADDRESS
* PR_TRANSMITABLE_DISPLAY_NAME: display name
* 0x68c40102: a 16-byte GUID
* 0x8202001f: display name
* 0x8c730102: 16-byte GUID
* 0x8c750102: 12-byte fixed blob ``0101 000000000005 0A000000``, present on shared mailboxes and room/equipment
* 0x8cb1001f: X500 for the/a sysmailbox
* 0x8cb30003: join restrictions for DLs. 0=join only via owner, 1=free to join, 2=moderated
* 0x8cb40003: leave restrictions for DLs. 0=leave only via owner, 1=free to leave
* 0x8cb60003=``6``
* 0x8ccc0003=``0``
* 0x8cec0003=``1``
* 0x8c9f001f: some language list (``de-DE,bn-BD``)
* 0x8d0f0003=``0``
