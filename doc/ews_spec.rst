..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2023 Jan Engelhardt

Observations on Exchange Server's EWS

version 2023-12-07

written up by Jan Engelhardt


Store Id (StoreId format)
=========================

.. code-block:: text

	// StoreId: <base64>
	00000000  2e 00 00 00 00 85 86 83  1a be d9 c1 41 94 c5 5d  |............A..]|
	00000010  3d 89 01 75 99 01 00 01  00 00 00 a5 18 7b 6f bc  |=..u.........{o.|
	00000020  dc ea 1e d0 3c 56 57 00  00 00 00 00 0f 00 00 01  |....<VW.........|
	00000030

	uint8_t group_length;
	{
		GUID provider_uid?;
		uint16_t ??;
		uint32_t ??;
		GUID store_guid;
		uint32_t ??;
	}
	uint8_t ??;


Store ID (HexEntryId)
=====================

.. code-block:: text

	00000000  00 00 00 00 85 86 83 1a  be d9 c1 41 94 c5 5d 3d  |...........A..]=|
	00000010  89 01 75 99 01 00 01 00  00 00 a5 18 7b 6f bc dc  |..u.........{o..|
	00000020  ea 1e d0 3c 56 57 00 00  00 00 00 0f 00 00        |...<VW........|
	0000002e

This is just the center portion of the StoreId form.


Store Id (EwsId base64 form)
============================

.. code-block:: text

	00000000  01 03 24 00 37 65 36 31  36 37 35 34 2d 32 37 38  |..$.7e616754-278|
	00000010  64 2d 34 39 62 62 00 2d  38 30 35 61 2d 30 66 37  |d-49bb.-805a-0f7|
	00000020  38 36 34 66 65 33 64 63  35 00 2e 00 00 03 85 86  |864fe3dc5.......|
	00000030  83 1a be d9 c1 41 94 c5  5d 3d 89 01 75 99 01 00  |.....A..]=..u...|
	00000040  01 00 00 01 a5 18 7b 6f  bc dc ea 1e d0 3c 56 57  |......{o.....<VW|
	00000050  00 00 03 0f 00 00 00                              |.......|
	00000057

Store Id (EwsLegacyId base64 form)
==================================

.. code-block:: text

	00000000  01 00 10 00 75 73 65 72  35 40 67 72 61 6d 6d 01  |....user5@gramm.|
	00000010  2e 6e 65 74 00 2e 00 00  03 85 86 83 1a be d9 c1  |.net............|
	00000020  41 94 c5 5d 3d 89 01 75  99 01 00 01 00 00 01 a5  |A..]=..u........|
	00000030  18 7b 6f bc dc ea 1e d0  3c 56 57 00 00 03 0f 00  |.{o.....<VW.....|
	00000040  00 00                                             |..|
	00000042

.. code-block:: c

	uint16_t something;
	uint16_t mbguidlen;
	char8_t mailbox_guid[mbguid_len+1];
	uint16_t length = 0x2e; /* this u16 included in the length value */
	uint16_t ??;
	uint8_t ??;
	GUID provider_uid;
	uint16_t ??;
	uint16_t ??;
	uint8_t ??[2];
	GUID store_guid;

Folder Id
=========

.. code-block:: text

	00000000  00 03 24 00 62 62 30 30  66 37 63 66 2d 30 62 39  |..$.bb00f7cf-0b9|
	00000010  34 2d 34 66 61 62 2d 38  65 66 35 2d 32 33 31 66  |4-4fab-8ef5-231f|
	00000020  30 62 63 34 30 34 31 36  00 2e 00 00 00 00 00 a2  |0bc40416........|
	00000030  1e 44 9a 4e 3c d7 4b 98  f2 0f 97 5e 57 37 f0 01  |.D.N<.K....^W7..|
	00000040  00 1e de f0 7f 30 72 25  41 8b 15 34 c4 66 23 92  |.....0r%A..4.f#.|
	00000050  52 00 00 23 67 48 67 00  00                       |R..#gHg..|
	00000059

.. code-block:: c

	uint16_t something;
	uint16_t mbguidlen;
	char8_t mailbox_guid[mbguid_len+1];
	uint16_t eid_length = 0x2e;
	/* rest is the usual FOLDER_ENTRYID structure (cf. mapi_types.hpp) */


Message Id
==========

.. code-block:: text

	00000000  00 03 24 00 62 62 30 30  66 37 63 66 2d 30 62 39  |..$.bb00f7cf-0b9|
	00000010  34 2d 34 66 61 62 2d 38  65 66 35 2d 32 33 31 66  |4-4fab-8ef5-231f|
	00000020  30 62 63 34 30 34 31 36  00 46 00 00 00 00 00 a2  |0bc40416.F......|
	00000030  1e 44 9a 4e 3c d7 4b 98  f2 0f 97 5e 57 37 f0 07  |.D.N<.K....^W7..|
	00000040  00 1e de f0 7f 30 72 25  41 8b 15 34 c4 66 23 92  |.....0r%A..4.f#.|
	00000050  52 00 00 00 00 01 0f 00  00 1e de f0 7f 30 72 25  |R............0r%|
	00000060  41 8b 15 34 c4 66 23 92  52 00 00 23 67 4f 7f 00  |A..4.f#.R..#gO..|
	00000070  00                                                |.|
	00000071

.. code-block:: c

	uint16_t something;
	uint16_t mbguidlen;
	char8_t mailbox_guid[mbguid_len+1];
	uint16_t eid_length = 0x46;
	/* rest is the usual MESSAGE_ENTRYID structure (cf. mapi_types.hpp) */


Change Key
==========

.. code-block:: text

	00000000  01 00 00 00                                       |....|
	00000004

	00000000  01 00 00 00 16 00 00 00  1e de f0 7f 30 72 25 41  |............0r%A|
	00000010  8b 15 34 c4 66 23 92 52  00 00 23 66 1c 8c        |..4.f#.R..#f..|
	0000001e

	00000000  09 00 00 00                                       |....|
	00000004

	00000000  09 00 00 00 16 00 00 00  1e de f0 7f 30 72 25 41  |............0r%A|
	00000010  8b 15 34 c4 66 23 92 52  00 00 23 66 04 93        |..4.f#.R..#f..|
	0000001e

	00000000  0f 00 00 00 16 00 00 00  ee 4e 3b 86 8d 1c 5f 40  |.........N;..._@|
	00000010  85 73 42 30 21 88 f1 53  00 00 1e 50 00 0d        |.sB0!..S...P..|
	0000001e

.. code-block:: c

	uint32_t type;
	uint32_t changekey_len = 0x16;
	/* rest is the usual PR_CHANGE_KEY format */
	GUID dbguid;
	uint8_t cn[6]; /* big-endian 48-bit integer */

type=1 for folders, type=9 for messages, type=15 for calendar items.
CK may be just 4 bytes in case no CK exists (or so).


Subscription Ids
================

.. code-block:: text

	00000000  1a 00 73 72 76 2d 65 78  63 68 61 6e 67 65 2d 30  |..srv-exchange-0|
	00000010  31 2e 67 72 61 6d 6d 6d  2e 6e 65 74 10 00 00 00  |1.grammm.net....|
	00000020  23 ec 54 d2 16 4a 59 44  8c 8f 36 c5 07 2d d5 8b  |#.T..JYD..6..-..|
	00000030  95 5c e8 88 06 f7 db 08  10 00 00 00 cf f7 00 bb  |.\..............|
	00000040  94 0b ab 4f 8e f5 23 1f  0b c4 04 16              |...O..#.....|
	0000004c

.. code-block:: c

	uint16_t svlength;
	char8_t servername[svlength];
	uint32_t some_len = 16;
	GUID some_guid;
	uint64_t timestamp;
	uint32_t mailbox_guid_len = 16;
	GUID mailbox_guid; /* sense as per glossary.rst */

The GUIDs are of type RFC 4122 §4.1.3, hence guid byte #7's high nibble is
always '4', guid byte #8's has always the 0x80 bit set, and guid byte #8 is
generally between 0x80..0xbf.

The timestamp is in 100-nanosecond intervals since January 1 year 1 AD.
(0x08dbf70688e85c95/10000000/86400/365.25 = 2022.88, date of execution is
2023-12-07, so like 2023.93, the remaining .05 difference is probably
unaccounted leap day stuff).
