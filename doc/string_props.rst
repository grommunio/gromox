C Application interfaces
========================

The MSMAPI C API and KGWC mapi4linux API have a ``struct SPropValue`` like so:

.. code-block:: c

   struct SPropValue {
       union _UPV {
           char *lpszA;
           wchar_t *lpszW;
       };
   };

The meaning of the narrow string characters is environment-/locale-dependent
(LC_CTYPE). This can be a single-byte encoding (e.g. cp1252), multi-byte
fixed-width encoding, or a multi-byte variable-width encoding (e.g. UTF-8).

The meaning of the wide string characters is platform-dependent. Under Windows,
wide chars (``wchar_t``) represent UTF-16 code units (not codepoints). On
Linux-glibc, wide chars represent UTF-32 code units.

Gromox does not have an MSMAPI/COM-like interface.


PHP Application interfaces
==========================

The PHP interpreter implements only one type of string: narrow.

For Gromox, it was deemed acceptable to unconditionally use UTF-8 for string
property values at all times, because PHP programs primarily interact with web
browsers rather than 8-bit command lines like Windows's ``cmd.exe``. With that
decision in mind, ``PT_STRING8`` and ``PT_UNICODE`` carry the same meaning,
which is similar to strings inside gromox-http. Also as a result of a historic
decision, all property types are switched from ``PT_UNICODE`` to ``PT_STRING8``
as properties go from php-mapi to the PHP program, and vice-versa in the other
direction (cf. ``proptag_to_phptag`` and ``phptag_to_proptag``).


Network protocols
=================

The Exchange protocols OXNSPI and OXCROPS transfer wide strings as UTF-16LE.
The protocols specify that both PT_STRING8 and PT_UNICODE can be transferred,
however, in practice, the emsmdb.dll connector modifies proptags during upload
(e.g. ``SetProps``) and transmits only PT_UNICODE-typed strings in modern
systems.

The Gromox EXMDB, ZRPC and MIDB protocols transfer strings as UTF-8. The use of
UTF-8 is convenient, because the data in SQLite DB is already UTF-8. Property
types are retained.

EWS and EAS use XML, so string values are transferred as UTF-8 (with XML
Character Entity Encoding as needed).


Servers
=======

Exchange stores string properties (presumably) as they come from the network.
(Since clients 

The EMSMDB/NSP network protocol handlers in Gromox convert from 8-bit/UTF-16LE
to UTF-8 as data is received. (Mnemonic: The ``EXT_PULL`` and ``EXT_PUSH``
classes are instantiated with flags=``EXT_FLAG_UTF16``.) The original property
type is generally retained so that the call sequence ``SetProperties`` plus
``GetPropList`` returns the same proptags as were entered. This UTF-8 data is
stored in SQLite as SQLITE_BLOBs. When data is read back by Outlook via
EMSMDB/NSP, strings are converted back to 8-bit/UTF-16 depending on the
requested property type.
