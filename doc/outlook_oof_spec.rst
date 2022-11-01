..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2020 Jan Engelhardt

Observations on Outlook's Out Of Office Handling

version 2020-03-31

written up by Jan Engelhardt


OOF dialog
==========

When setting up an OOF timespan in Outlook, it will consider OOF to be "on" and
show the OOF config button with yellow background only if the *current* time is
within the timespan. As time progresses forward and the OOF period has begun,
Outlook will not update itself; some event (e.g. incoming mail) needs to happen
before it turns yellow.

This OOF state is written to the ``PR_OOF_STATE`` property on the store object
when the OOF dialog config is applied, and it will not be updated even after
the OOF yellow background shows.

Exchange Server evaluates almost nothing of this at all. It ignores
``PR_OOF_STATE``, and ignores the ``PR_BODY`` texts stored in the FAI message.
Editing the FAI messages' ``PR_BODY`` will not change the automatic reply body.
Changing e.g. the ``PR_MESSAGE_CLASS`` however will make Exchange stop sending
the reply, even if it is changed back afterwards.

Internet search suggests that OOF is set using the EWS API instead.

MAPI only gets gratitious copies, and only of certain information, making it
practically useless.


OOF levels
==========

OL offers four stiff levels:

* ``OOF_DISABLED``
* ``OOF_INTERNAL``: internal members (this organization) only
* ``OOF_CONTACTS``: internal, and user's contacts
* ``OOF_EXTERNAL``: internal, and externals

There is no way to, for example, enable OOF for just externals.


Rule 1
======

When the OOF level is ``>= OOF_INTERNAL``, this rule will be created
(in ``PR_RULES_TABLE``, but not ``PR_RW_RULES_STREAM``)::

	PR_RULE_NAME="Microsoft.Exchange.OOF.InternalSenders.Global"
	PR_RULE_PROVIDER="Microsoft Exchange OOF Assistant"
	PR_RULE_ACTIONS={
		lpActions->ulVersion = 0x00000001 = EDK_RULES_VERSION
		lpActions->cActions = 0x00000001
		lpActions->lpAction[0x00000000]:
		lpAction->acttype = 0x00000004 = OP_OOF_REPLY
		lpAction->lpRes: 
		lpRes was NULL
		lpAction->ulFlags = 0x00000000 = 
		lpAction->actReply.lpEntryId:
		cb: 70 lpb: 00000000EA01816B84555A47AB5BE61FE0BBB21E070066E7E68ED3C93F4DA3C31C8011FD60FC000000A8B1550000325AA2D15223B0449E3A8B4C7F5959B00001664AB6140000
			=> references PR_ENTRYID of FAI message
		actReply.guidReplyTemplate = {BD9B44ED-D910-4E11-99DA-D2B0FCA0CA30} = Unknown GUID
			=> references PR_REPLY_TEMPLATE_ID of FAI message
		lpAction->ulActionFlavor = 0x00000000 = OP_OOF_REPLY
		lpAction->lpPropTagArray = NULL
	}
	PR_RULE_CONDITION=NULL
	PR_RULE_STATE=ST_KEEP_OOF_HIST | ST_CLEAR_OOF_HIST | 0x100

FAI message::

	PR_MESSAGE_CLASS="IPM.Note.Rules.OofTemplate.Microsoft"
	PR_ENTRYID=<as specified in actReply.lpEntryId>
	PR_REPLY_TEMPLATE_ID=<as specified in guidReplyTemplate>

This rule has no conditions stored whatsoever.


Rule 2
======

When the OOF level is ``>= OOF_CONTACTS``, this rule will be created::

	PR_RULE_NAME="Microsoft.Exchange.OOF.AllExternalSenders.Global"
	PR_RULE_PROVIDER="Microsoft Exchange OOF Assistant"
	PR_RULE_ACTIONS={
	{
		lpActions->ulVersion = 0x00000001 = EDK_RULES_VERSION
		lpActions->cActions = 0x00000001
		lpActions->lpAction[0x00000000]:
		lpAction->acttype = 0x00000004 = OP_OOF_REPLY
		lpAction->lpRes: NULL
		lpAction->ulFlags = 0x00000000 = 
		lpAction->actReply.lpEntryId:
		cb: 70 lpb: 00000000EA01816B84555A47AB5BE61FE0BBB21E070066E7E68ED3C93F4DA3C31C8011FD60FC000000A8B1550000325AA2D15223B0449E3A8B4C7F5959B000016B2EF60B0000
		<entryid of a FAI message>
		actReply.guidReplyTemplate = {DF9FE98E-A4E7-4EDF-990C-DF172ECFBC4D} = Unknown GUID
		<PR_REPLY_TEMPLATE of said FAI message>
		lpAction->ulActionFlavor = 0x00000000 = OP_OOF_REPLY
		lpAction->lpPropTagArray = NULL
	}
	PR_RULE_CONDITION=NULL
	PR_RULE_STATE=ST_KEEP_OOF_HIST | 0x100

FAI message::

	PR_MESSAGE_CLASS="IPM.Note.Rules.ExternalOofTemplate.Microsoft"
	PR_ENTRYID=<as specified in actReply.lpEntryId>
	PR_REPLY_TEMPLATE_ID=<as specified in guidReplyTemplate>
