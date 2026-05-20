Problem statement
=================

When another mailbox's calendar is opened in a *cached mode* profile with
Outlook, appointments are loaded initially, but then disappear after the blink
of an eye. A message is dropped in the "Sync Failures" folder:

```
Synchronizing Mailbox 'myown@company.de'
Synchronizing server changes in folder 'SharedMbox - Calendar'
Error synchronizing folder [80040803-30141506-0-533]
The file xyz.ost cannot be opened because too
many other files are open. [blah blah]
```

Oddly, the issue

* only affects the Calendar folder (PR_IPM_APPOINTMENT_ENTRYID)
* not e.g. Tasks or Notes (i.e. others in the set of common shared folders)
* nor secondary calendar folders (other folders with PR_CONTAINER_CLASS IPF.Calendar)
* nor any other regular folder

* only affects stores opened ad-hoc (e.g. ribbon bar ▶ Calendar ▶ Open
  Calendar ▶ From Addressbook)
* does not occur with with stores which have been added to the MAPI profile
  store table explicitly via MAPI profile settings ▶ Change ▶ More Settings ▶
  Advanced ▶ Open these additional mailboxes
* does not seem to occur with stores implicitly added through AutoDiscover
  automapping (secondary_store_hints)

* only occurs when the MAPI profile has the checkbox "Download shared folders"
  enabled (this is the default case)


Debug ROPs
==========

Conveniently stopping/delaying execution of gromox-emsmdb with a debugger also
stops/delays execution inside the Exchange connector (emsmdb32.dll) on the
Windows side.

Analysis of the ROP commands issued by OL shows that, after having obtained
MAPI messages representing the appointments, a final GetPropertiesSpecific call
is performed on the calendar folder. After that call has completed, OL decides
to nuke the folder contents on the client side.

With fault injection, we can make the server return a failure code for that
particular GetPropertiesSpecific call, at which point the appointments stay.
This suggests that there is something wrong with the property values of that
folder. But this makes no sense, because the properties are fine for when the
second store is explicitly added to the MAPI profile.


Debug MSPST
===========

The layout of the 80040803-30141506-0-533 error code is described in
doc/error_codes.rst. Through decompilation, 0x30141506 has been found in the
PST driver (mspst32.dll). That driver is using the folder's
PR_PARENT_SOURCE_KEY property value to perform a lookup in some internal
datastructure, but failing to find a result. In conseuqence, it returns code
0x30141506.


Workaround
==========

By indicating to the MAPI client that PR_PARENT_SOURCE_KEY is not present, that
lookup will not happen and Outlook will not execute the particular code path
that inspects PR_PARENT_SOURCE_KEY and erroneously finds it to be "invalid".

It turns out there are two ways of doing this:
1. rejecting any request for the PR_PARENT_SOURCE_KEY *propval*
2. omitting PR_PARENT_SOURCE_KEY from the *proptags* list
