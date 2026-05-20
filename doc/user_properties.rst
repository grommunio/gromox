The following properties are structural (essential for the navigation
of the address book by MAPI clients), are never read from SQL but
generated at all times by the address book provider (ABP):

* ``PR_EMS_AB_CONTAINERID``
* ``PR_EMS_AB_OBJECT_GUID``
* ``PR_ENTRYID``
* ``PR_INSTANCE_KEY``
* ``PR_MAPPING_SIGNATURE``
* ``PR_ORIGINAL_ENTRYID``
* ``PR_RECORD_KEY``
* ``PR_SEARCH_KEY``

The following properties are sourced from SQL data in perhaps indirect ways and
possibly transformed by the ABP:

* ``PR_ACCOUNT``: Not read from SQL, but copied from PR_SMTP_ADDRESS.

* ``PR_ADDRTYPE``: Not read, but synthesized.

* ``PR_CREATION_TIME``: Not read, but synthesized.

* ``PR_DEPARTMENT_NAME``: [Before Gromox 2.42] Not read, but copied from the
  ``groups.title`` column of the user's group_id. ("groups" in SQL refer to
  departments, a feature to create hierarchies in the address book). [Since
  Gromox 2.42] Departments were abandoned and reading the property via MAPI
  yields no value. [Since Gromox 2.44] Special treatment has ceased. MAPI
  clients now see the same value as it is in SQL.

* ``PR_DISPLAY_TYPE``: Not read, but synthesized based on PR_DISPLAY_TYPE_EX.

* ``PR_DISPLAY_TYPE_EX``: Indicates the mailbox type and user icon.
  Set to ``0`` (``DT_MAILUSER`` in source code) for regular users.
  Set to ``1`` (``DT_DISTLIST``) for mailing lists / groups.
  Set to ``6`` (``DT_REMOTE_MAILUSER``) for contact objects.
  Set to ``7`` (``DT_ROOM``) for room resources.
  Set to ``8`` (``DT_EQUIPMENT``) for equipment resources.
  No other values are supported. The ABP synthesizes a suitable
  PR_DISPLAY_TYPE_EX value for MAPI clients built from this SQL row.

* ``PR_EMAIL_ADDRESS``: Not read, but synthesized from username.

* ``PR_EMS_AB_DISPLAY_NAME_PRINTABLE``: Not read, but copied from
  PR_DISPLAY_NAME.

* ``PR_EMS_AB_HOME_MDB``: Not read, but synthesized.

* ``PR_EMS_AB_NETWORK_ADDRESS``: Not read, but synthesized.

* ``PR_EMS_AB_PROXY_ADDRESSES``: Not read, but synthesized based on the
  ``aliases`` SQL table.

* ``PR_EMS_AB_THUMBNAIL_PHOTO``: Not read, but copied from the store property
  PR_EMS_AB_THUMBNAIL_PHOTO in the user store (exchange.sqlite3).

* ``PR_OBJECT_TYPE``: Not read, but synthesized based on PR_DISPLAY_TYPE_EX.

* ``PR_OFFICE_LOCATION``: Not read from the user object, but copied from the
  ``domain.address`` column of the user's domain.

* ``PR_SEND_RICH_INFO``: If the property is absent, the ABP will synthesize it,
  with value ``1``.

* ``PR_SMTP_ADDRESS``: If and only if the object is a contact object
  (see PR_DISPLAY_TYPE_EX), this property is used to indicate the e-mail
  address for this contact. Otherwise, it is synthesized from the username.

* ``PR_TEMPLATEID``: Not read, but synthesized based on PR_DISPLAY_TYPE_EX.

* ``PR_TRANSMITTABLE_DISPLAY_NAME``: Not read, but copied from
  PR_DISPLAY_NAME.

The following properties have their value passed verbatim to MAPI clients, but
the properties do have semantics or warrants remarks from our side.

* ``PR_EMS_AB_ROOM_CAPACITY``: This property is only of informational value; no
  decisions in code paths are made based on the value.

* ``PR_SCHDINFO_AUTO_ACCEPT_APPTS``: [Originally, this property was used in
  OXOPFFB configuratino messages. Gromox repurposed the property to be set on
  user objects.] If set to ``0``, meeting requests will not be automatically
  accepted by the server system (but they may still be added to the calendar as
  tentative appointments). If set to ``1``, meeting requests will be accepted
  (subject to availability and other constraints).

* ``PR_SCHDINFO_BOSS_WANTS_COPY``: [Originally OXOPFFB.] (Proposed) If set to
  ``1``, any delegate operations will put the boss (the delegator, the
  representee) in Cc.

* ``PR_SCHDINFO_DISALLOW_RECURRING_APPTS``: [Originally OXOPFFB.] If set to
  ``1``, any meeting requests involving a recurrence are declined.

* ``PR_SCHDINFO_DISALLOW_OVERLAPPING_APPTS``: [Originally OXOPFFB.] If set to
  ``1``, any meeting requests involving a scheduling conflict are declined.

All other property values have no extra meaning and are passed through.

The SQL ``user_properties`` table has a ``propval_bin`` and a ``propval_str``
column; if ``propval_bin`` is non-NULL, that value is used, otherwise
``propval_str`` is. Conceptually, both propval_bin and propval_str are stored
in a std::string in memory. Now, depending on the proptag, decoding of that
std::string's content is performed according to the following actions, which
also sets a standard for the data format in those columns:

* PT_SHORT/PT_LONG/PT_I8: The input form must be an integer. The ``strtoul``
  function is used (which works for signed and unsigned numbers).
* PT_SYSTIME: The input form must be a mapitime integer (hectonanoseconds since
  the Windows epoch); same handling as PT_I8. The earlier option of using
  ``yyyy-mm-dd`` in the propval_str column is no longer supported.


Display Type value correlation
==============================

The following table lists the different Exchange objects that can be created,
and what values the GAB objects exhibit in ``PR_DISPLAY_TYPE``,
``PR_DISPLAY_TYPE_EX``, ``PR_OBJECT_TYPE`` and the ``EMSAB_ENTRYID::type``
fields.

Thing                  DT       DTX         OT  etype
=====================  =======  ==========  ==  =====
GAL container          0x20000  -           4   -
"All Address Lists"    0x30000  -           4   -
"Outlook Addres Book"  0x50000  -           4   -
Normal user            0        0x40000000  6   0
Shared mailbox         0        0           6   0
User without EX mbox   0        unset       6   6
Distribution group     1        1           8   1
Dynamic dist.group     3        3           6   3
Security group         1        0x40000009  8   1
Room                   0        7           6   0
Equipment              0        8           6   0
Mail user              0        6           6   6
Mail contact           6        6           6   6
Personal DistList      5        -           8   -
=====================  =======  ==========  ==  =====

``PR_OBJECT_TYPE`` tells whether to use ``IID_IMailUser` or ``IID_IDistList``
with e.g. ``IMAPIContainer::OpenEntry``.

(AB objects of type 5 (DT_PRIVATE_DISTLIST) do not have EMSAB_ENTRYID::etype,
because they use CONTAB_ENTRYID instead.)
