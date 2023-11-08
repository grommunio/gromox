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

* ``PR_ADDRTYPE``: not read / synthesized

* ``PR_COMPANY_NAME``: Not read from the user object, but copied from the
  ``domain.title`` column of the user's domain.

* ``PR_CREATION_TIME``: not read / synthesized

* ``PR_DEPARTMENT_NAME``: not read / copied from the ``groups.title``
  column of the user's group_id. ("groups" in SQL refer to departments, a
  feature to create hierarchies in the address book).

* ``PR_DISPLAY_TYPE``: not read / synthesized based on PR_DISPLAY_TYPE_EX

* ``PR_DISPLAY_TYPE_EX``: Indicates the mailbox type and user icon.
  Set to ``0`` (``DT_MAILUSER`` in source code) for regular users.
  Set to ``1`` (``DT_DISTLIST``) for mailing lists / groups.
  Set to ``6`` (``DT_REMOTE_MAILUSER``) for contact objects.
  Set to ``7`` (``DT_ROOM``) for room resources.
  Set to ``8`` (``DT_EQUIPMENT``) for equipment resources.
  No other values are supported. The ABP synthesizes a suitable
  PR_DISPLAY_TYPE_EX value for MAPI clients built from this SQL row.

* ``PR_EMAIL_ADDRESS``: not read / synthesized from username

* ``PR_EMS_AB_DISPLAY_NAME_PRINTABLE``: not read / copied from PR_DISPLAY_NAME

* ``PR_EMS_AB_HOME_MDB``: not read / synthesized

* ``PR_EMS_AB_NETWORK_ADDRESS``: not read / synthesized

* ``PR_EMS_AB_PROXY_ADDRESSES``: not read / synthesized based on the
  ``aliases`` SQL table.

* ``PR_EMS_AB_THUMBNAIL_PHOTO``: not read / copied from the store property
  PR_EMS_AB_THUMBNAIL_PHOTO in the user store (exchange.sqlite3).

* ``PR_OBJECT_TYPE``: not read / synthesized based on PR_DISPLAY_TYPE_EX

* ``PR_OFFICE_LOCATION``: Not read from the user object, but copied from the
  ``domain.address`` column of the user's domain.

* ``PR_SEND_RICH_INFO``: If the property is absent, the ABP will synthesize it,
  with value ``1``.

* ``PR_SMTP_ADDRESS``: If and only if the object is a contact object
  (see PR_DISPLAY_TYPE_EX), this property is used to indicate the e-mail
  address for this contact. Otherwise, it is synthesized from the username.

* ``PR_TEMPLATEID``: not read / synthesized based on
  PR_DISPLAY_TYPE_EX

* ``PR_TRANSMITTABLE_DISPLAY_NAME``: not read / copied from
  PR_DISPLAY_NAME

The following properties have their value passed verbatim to MAPI clients, but
the properties do have semantics or warrants remarks from our side.

* ``PR_EMS_AB_ROOM_CAPACITY``: This property is only of informational value; no
  decisions in code paths are made based on the value.

* ``PR_SCHDINFO_BOSS_WANTS_COPY`` (proposed extension): If set to ``1``, any
  delegate operations will put the boss (the delegator, the representee) in Cc.
  [Originally, this property was used in OXOPFFB configuration messages. Gromox
  repurposed the property to be set on user objects.]

* ``PR_SCHDINFO_DISALLOW_RECURRING_APPTS`` (proposed extension): If set to
  ``1``, Rooms and Equipment (Resource mailboxes) will respond to, and decline,
  any Meeting Requests with a Recurrence Pattern. [Originally OXOPFFB-specific,
  repurposed as a user property by Gromox.]

* ``PR_SCHDINFO_DISALLOW_OVERLAPPING_APPTS`` (proposed extension): If set to
  ``1``, Rooms and Equipment (Resource mailboxes) will respond and decline
  Meeting Requests that conflict with an existing appointment. When the value
  is ``0``, insatisfiable requests will get no response. (Satisfiable requests
  will get accepted.) [Originally OXOPFFB-specific, repurposed as a user
  property by Gromox.]

All other property values have no extra meaning and are passed through.
