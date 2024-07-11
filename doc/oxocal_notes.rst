..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2024 grommunio GmbH

Random notes on Calendaring/OXOCAL/OXCICAL
==========================================

Summary
-------

* PR_SENT_REPRESENTING of IPM.Schedule messages always contains the organizer,
  never a delegator (delegate permission check thus needs to special-case this)
* PR_RECIPIENT_FLAGS bit 0x40 is present in a sentitems message the first time a
  non-recipOriginal entity is mailed
* PR_RECIPIENT_FLAGS bit 0x200 is present for explicitly invited participants
* New values for PR_RECIPIENT_TRACKSTATUS are only in the organizer's calendar
  item, in organizer's sent items, and in participants inbox items, but never
  propagated to participants' calendar items.


Tryout: Base meeting
--------------------

When a draft meeting request is created with OL2019, the MAPI message in
boss\IPM_SUBTREE\Calendar will have these significant properties:

* PR_MESSAGE_CLASS=``IPM.Schedule.Meeting.Request``
* PR_SENDER=boss
* PR_SENT_REPRESENTING=boss
* PR_SUBJECT=``C-level meeting``
* PidLidSendMeetingAsIcal=0
* recipient #0:
	* PR_DISPLAY_NAME=boss
	* PR_RECIPIENT_FLAGS=recipSendable | recipOriginal
	* PR_RECIPIENT_TRACKSTATUS=respNone
* recipient #1:
	* PR_DISPLAY_NAME=user9
	* PR_RECIPIENT_FLAGS=recipSendable | 0x200
	* PR_RECIPIENT_TRACKSTATUS=respNone

The MAPI message in boss\IPM_SUBTREE\SentItems has:

* PidTagSentRepresentingFlags=0
* expectedly new blank recipient table plus
* recipient #0:
	* PR_DISPLAY_NAME=user9
	* PR_RECIPIENT_FLAGS=recipSendable | 0x200
	* PR_RECIPIENT_TRACKSTATUS=respNone
* otherwise pretty much the same

The RFC5322 representation of the boss sent item (obtained via IMAP here rather
than catching the SMTP conversation) indicates an inline scheduling item
(``Content-Disposition: inline`` is the default if no other disposition is
given)::

	From: boss
	To: user9
	X-MS-Has-Attach:
	Content-Type: multipart/alternative; boundary="--x"

	--x
	Content-Type: text/plain

	--x
	Content-Type: text/calendar; charset="utf-8"; method=REQUEST

	...
	BEGIN:VEVENT
	ORGANIZER;CN=boss:MAILTO:boss@localhost
	ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=user9:MAILTO:user9@localhost
	...

The user9 inbox message has an equivalent IMAP representation (some boundary
strings are different). The 0x200 bit may find its way into the user9 inbox
message, but the details are unclear (possibly EXC2019 uses TNEF sending to
itself; replaying the RFC5322 via SMTP makes 0x200 go lost.) In any case, even
if the inbox message has bit 0x200, the user9 calendar item will not. Hence
the bit is inconsequential to participants.


Recipient flags
---------------

(Data structures shown herein reference the state after "Base meeting" left
off.) When boss invites another user, the boss calendar item is updated with a
new recipient:

* PR_DISPLAY_NAME=user16
* PR_RECIPIENT_FLAGS=recipSendable | 0x200

The boss sentitem message is mostly the same, but contains a new recipient
table with one new recipient:

* PR_DISPLAY_NAME=user16
* PR_RECIPIENT_FLAGS=recipSendable | 0x240

Further updates of any kind sent to user16 carry no 0x40. The 0x40 bit has the
same survival characteristics as 0x200 (see above). (Uninviting a user happens
via PR_MESSAGE_CLASS=IPM.Schedule.Meeting.Canceled.)

Corollary: 0x40 seems to indicate non-original participants that were just
contacted for the first time.

When a meeting is forwarded (either by organizer or participant), the calendar
item is updated with a new recipient:

* PR_DISPLAY_NAME=user16
* PR_RECIPIENT_FLAGS=recipSendable

Participants added via forwards do not contain 0x200.

Corollary: 0x200 indicates "invited".


Recipient status
----------------

When a participant accepts the meeting, the PR_RECIPIENT_TRACKSTATUS property
of the participant entry in the participant's calendar item is not modified.
Updates only occur to the organizer's calendar item recipient list as the
organizer receives responses. When the organizer sends updates, updated
PR_RECIPIENT_TRACKSTATUS values are conveyed, but participants still do not
update their calendar items with new values so received.

Corollary: PR_RECIPIENT_TRACKSTATUS is updated (only) in the organizer's
calendar item.


Organizer in PR_SENT_REPR
-------------------------

Let ``secretary`` be a delegate of ``boss`` (delegator). When secretary creates
a calendar item in the boss calendar, delegation properties and participants
are set as expected:

* PR_SENT_REPRESENTING=boss
* PR_SENDER=secretary
* recipient #0:
	* PR_DISPLAY_NAME=boss
	* PR_RECIPIENT_FLAG=recipOriginal | recipOrganizer
* recipient #1:
	* PR_DISPLAY_NAME=user0
	* PR_RECIPIENT_FLAG=recipOriginal
* recipient #2:
	* PR_DISPLAY_NAME=user9
	* PR_RECIPIENT_FLAG=recipOriginal

The sentitems message/user9 inbox message has:

* PR_SENT_REPRESENTING=boss
* PR_SENDER=secretary
* recipient #0:
	* PR_DISPLAY_NAME=user0
	* PR_RECIPIENT_FLAG=recipOriginal
* recipient #1:
	* PR_DISPLAY_NAME=user9
	* PR_RECIPIENT_FLAG=recipOriginal

Corollary: PR_SENT_REPRESENTING contains the organizer.

user9's calendar item will again have 3 recipients as above.
If user9 now forwards, the sentitems message has:

* PR_SENT_REPRESENTING=boss
* PR_SENDER=user9
* recipient #0:
	* PR_DISPLAY_NAME=user16
	* PR_RECIPIENT_FLAG=recipOriginal
* PidLidAppointmentUnsendableRecipients={binary blob}:
	* recipient #0:
		* PR_DISPLAY_NAME=user0
		* PR_RECIPIENT_FLAG=recipOriginal
	* recipient #:
		* PR_DISPLAY_NAME=user9
		* PR_RECIPIENT_FLAG=recipOriginal

Note how participants are conveyed via PidLidAppointmentUnsendableRecipients,
and the organizer via PR_SENT_REPRESENTING.


X-MS-OLK-SENDER
---------------

The X-MS-OLK-SENDER iCal field is generated from PR_SENDER, but only if:

* using the "forward as iCal" operation in Outlook
* sender of this forward is actually a permitted delegate of the *organizer*

What happens:

* Outlook perfoms MAPI-to-iCal conversion
* iCal file added to a IPM.Note draft message as a MAPI attachment
* when sent, EXC2019 performs conversion of the draft to RFC5322 and emits a
  text/calendar MIME part with ``Content-Disposition: attachment``
* on reception there is no automatic server-side or client-side processing
  because it is ``attachment``
* client-side autoprocessing by OL once attachment is opened, then
  X-MS-OLK-SENDER is used as this iCal file is transferred to a new MAPI
  calendar item in one's calendar folder

What happens with regular forward operation:

* a new IPM.Scheduling draft message is generated from the forwarded
  IPM.Scheduling calendar item
* when sent, EXC2019 performs conversion of the draft to RFC5322+iCal and emits
  a text/calendar MIME part with ``Content-Disposition: inline``
* on reception, X-MS-OLK-SENDER is ignored during EXC2019 server-side
  autoprocessing because, so our thought goes, the information is already
  provided by the From: line
* on client-side reading, X-MS-OLK-SENDER is ignored during OL client-side
  autoprocessing because, so our thought goes, the information is already
  providd by PR_SENDER
* All behavior is conforming, as the spec says "SHOULD"
