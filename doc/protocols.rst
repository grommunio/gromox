..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2024 grommunio GmbH

Protocols
=========

When there "protocols" are being talked about, many readers will first and
foremost think of data formats (e.g. for data transferred over network, or at
rest in files) and state transitions (what clients and servers ought to do and
when).

Groupware components are not required to specifically know/implement all
protocols. The calendaring protocol MS-OXOCAL for example could be considered
mostly a client-client protocol. OXOCAL specifies what properties a MAPI client
needs to set on a message object so that it is treated as an "appointment" by
other MAPI clients. The server can just treat the details as opaque data.
Another example is MS-OXOABKT: A server does not have to implement any logic
for this protocol, because it can treat the data in question as opaque, just
like a file transfer program does not need to care whether an image is JPEG or
PNG.


Standards list
==============

The logical MAPI data model (`MAPI concepts
<https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/mapi-concepts>`_)
of stores, folders, messages, attachments, recipients and properties is central
to everything. On top of the concepts, concrete formats and action protocols
are defined. The relevant material is plenty and spread out over many volumes,
such as the Outlook MAPI reference, Exchange Server Protocols, and the Internet
RFCs.

Generously speaking, Gromox implements parts of at least

* `Exchange protocols
  <https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprotlp>`_:
  OXCDATA, OXDSCLI, OXCFOLD, OXCFXICS, OXCICAL, OXCMAIL, OXCMAPIHTTP plus
  mandatory but undocumented encodings, OXOMSG, OXCNOTIF, OXNSPI, OXCPERM,
  OXCPRPT, OXCROPS, OXCRPC, OXCSTOR, OXCTABL, OXMSG, OXOABK, OXOABKT, OXOCAL,
  OXOCNTC, OXODLGT, OXOMSG, OXORULE, OXOSFLD, OXOSMIME, OXPROPS, OXTNEF, OXVCARD,
  OXABREF, OXOCFG, OXRTFCP, OXWAVLS, OXWOOF, OXWSCDATA, OXWSCONT, OXWSCORE,
  OXWSFOLD, OXWSMSG, OXWSMTGS, OXWSPOST, OXWSRSLNM, OXWSSYNC, OXWSTASK, (DCERPC
  C706)
* `Windows protocols
  <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp>`_:
  CFB, DTYP, ERREF, LCID, PST, RPCE, RPCH, UCODEREF
* Internet protocols
  * 7230/7233/7617/9112 (HTTP)
  * 2595/2971/6154/7888/9501 (IMAP)
  * 1939/2595 (POP3)
  * 2821/2920/3027/5248/5321 (SMTP)
  * 2045/2046/2047/2049/5322 (Internet Mail and MIME)
  * 5545 (iCalendar)
  * 6350 (vCard)
  * 4122 (GUIDs — caveats see doc/glossary.rst)


Transports
==========

ROP - Remote Operations Protocol
--------------------------------

Normative reference: [MS-OXCROPS].

OXCROPS defines a binary protocol for mailbox actions, such as "Create Folder",
"Delete Folder", "Load Message", "Create Message/Appointment", etc. "ROP" can
also stand for just "remote operation" (i.e. one), and this is the main
colloquial use; the protocol instead is generally talked about using "OXCROPS".

At Gromox, we have come to known of the *existence* of 172 ROPs so far, though
a fair amount have fallen out of use long before Gromox existed, and those
historic ones are not present in official Microsoft documentation. Gromox only
handles 125 request types, and a few of those are just stub functions without
any serious logic — sometimes, you just have to (adequately) signal the
function is no longer implemented.


EMSMDB
------

Normative reference: [MS-OXCRPC].

OXCRPC defines a binary protocol for what could be best described as "session
actions". This literally includes e.g. "Connect", "Process some ROPs",
"Disconnect". The term "RPC" (remote procedure call) may be in colloquial use
to refer to one such action.

Technically, RPC is a shorthand term to denote (on the client side) a
function that converts its arguments to another representation for
transmission over a network, then waiting for an answer and unpacking
that back.

At Gromox, we have come to known of the *existence* of 15 RPCs so far, though
many have fallen out of use already. Gromox handles 6 request types only, which
seems sufficient for contemporary interaction with the groupware server.

There is one important RPC called ``ecDoRpcExt2``. Multiple ROPs (see above)
can be packed into one RPC for bulk processing to improve network latency.


MSRPC
-----

Normative references: [C706], [MS-RPCE].

EMSMDB was originally specified for use with MSRPC.

MSRPC is a slight derivative of DCE/RPC. There is no particular one transport
specified for RPC. RPC packets could be output directly onto Layer 2 (e.g. as
Ethernet frames after adding suitable Ethernet headers), which is why RPC
itself contains, in a sense, a rudimentary reimplementation of Internet
Protocol. There are "interface", "endpoints" and even fragments.

RPC packets could also be output on top of TCP or UDP, and the port number 135
might ring a distant bell of history (because 138/139 may be used with file
services such as Samba).


RPC-over-HTTP
-------------

Normative references: [MS-RPCH].

For reasons of LAN security, those ports are often firewalled off. To
nevertheless enable Outlook clients on arbitrary machines to contact the
groupware server, Outlook 2010 comes with the RPC-over-HTTP protcol, marketed
as "Outlook Anywhere", which encapsulates MSRPC into HTTP. This uses two
concurrently active HTTP connections, and two unusual custom HTTP method names
that may not be understood by all proxies.

The layering now looks something like:

.. code-block:: text

	IPv4/v6
	  ┗━ TCP
	      ┗━ HTTP
	          ┗━ MSRPC protocol data unit (PDU)
	              ┗━ EMSMDB, op=ecDoRpcExt2
	                  ┣━ ropOpenFolder("INBOX")
	                  ┗━ ropReadMessage(no. 17 of just-opened folder)


MAPIHTTP
--------

Also known as MH in Gromox.

Normative references: [MS-OXCMAPIHTTP].

Outlook 2013 already introduced the next protocol, which does away with the
redundant MSRPC layer altogether, and moves EMSMDB (which is rather thin) into
HTTP headers.

.. code-block:: text

	IPv4/v6
	  ┗━ TCP
	      ┗━ HTTP POST /mapi/emsmdb, X-Request-Type=ecDoRpcExt2
	          ┣━ ropOpenFolder("INBOX")
	          ┗━ ropReadMessage(no. 17 of just-opened folder)
