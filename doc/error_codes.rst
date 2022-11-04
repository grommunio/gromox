..
        SPDX-License-Identifier: CC-BY-SA-4.0 or-later
        SPDX-FileCopyrightText: 2021-2022 grommunio GmbH

Error decoder tool
==================

Useful utility from `MSDN
<https://learn.microsoft.com/en-us/windows/win32/debug/system-error-code-lookup-tool>`_.

```
$ ./Err_6.4.5.exe 0x80070057
# for hex 0x80070057 / decimal -2147024809
  COR_E_ARGUMENT                         corerror.h
# An argument does not meet the contract of the method.
  DDERR_INVALIDPARAMS                    ddraw.h
  DIERR_INVALIDPARAM                     dinput.h
  DSERR_INVALIDPARAM                     dsound.h
  STIERR_INVALID_PARAM                   stierr.h
  DRM_E_INVALIDARG                       windowsplayready.h
  E_INVALIDARG                           winerror.h
# One or more arguments are invalid
#
# as an HRESULT: Severity: FAILURE (1), FACILITY_WIN32 (0x7), Code 0x57
#
# for hex 0x57 / decimal 87
  ERROR_INVALID_PARAMETER               winerror.h
# The parameter is incorrect
```

The Gromox source tree comes with a bunch of error mnemonics and they can be
greped for (`git grep -e 80070057`), but it only carries few and topical to
MAPI.


Synchronization Log
===================

```
18:14:35 Synchronizer Version 16.0.5197
18:14:35 Synchronizing Mailbox 'User Name'
18:14:35 Synchronizing local changes in folder 'Kalender'
18:14:35 Uploading to server '63545368-4067-726f-6d6d-756e1f000000@locally.de'
18:14:35 Error synchronizing message 'Test-in-shared-cal'
18:14:35 		 [80070057-501-80070057-322]
18:14:35 		 The client operation failed.
18:14:35 		 Microsoft Exchange Information Store
18:14:35 		 For more information on this failure, click the URL below:
18:14:35 		 http://www.microsoft.com/support/prodredirect/outlook2000_us.asp?err=80070057-501-80070057-322
18:14:35 Moved a message that failed synchronization to 'Lokale Fehler'. Message subject -> 'Test-in-shared-cal'. You can view  this message in your offline folder only.
18:14:35 Downloading from server '63545368-4067-726f-6d6d-756e1f000000@locally.de'
18:14:35 Done
```

Components of the sync error number vector:

# local side: operation return code (MAPI)
# local side: unsure - some error code, or possibly a length
# remote side: operation return code (e.g. ROP)
# remote side: unsure - some error code (Exchange Storage Engine or DoRpc function call?), or possibly the length of the RPC

The synchronization log messages contain a URL that has long been defunct but
never updated. (outlook2000_us.asp is really telling.)


Send and Receive dialog
=======================

```
x of y Tasks have completed successfully.

Task 'Synchronizing subscribed folders for abc@def.de` reported error
(0x80048002) : 'This task was cancelled before it was completed.'

Task '...' reported error (0x800CCC0D) : 'Cannot find the email server.
Verify the server information in your account properties.'

Task '...' reported error (0x80042108) : 'Outlook is unable to connect to your
incoming )POP3) e-mail server. If you continue to receive this message, contact
your server administartor or Internet service provider (ISP).'

Fehler (0x80190194) beim Ausführen der Aufgabe "abc@def.de": "Ein unerwarteter
Fehler ist aufgetreten."

Fehler (0x80200011) beim Ausführen der Aufgabe "abc@def.de": "Fehler beim
Ausführen der Operation."
```

The error decoder is a hit-and-miss in this regard. 80190194 was recognized,
800ccc0d was not.
