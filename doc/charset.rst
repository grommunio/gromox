=========================
Where is my character set
=========================


RTF
===

(Uncompressed) RTF is always made of chars. (Whether it is 7- or 8-bit, ASCII
or ASCII+, we will defer to the spec. For programming purposes, it is
henceforth "chars".) There are some commands which affect the interpretation of
subsequent chars.

``\pc``, ``\ansi``, and a bunch of others declare the character set to apply to
subsequent RTF data. Under cp437, a 0x80 byte means U+00C7; under cp1252, a
0x80 byte means U+20AC. It is possible to write literal bytes using an escape
code instead, e.g. ``\'80`` to the same effect.

The usefulness of ``\ansicpg1252`` is in question, since the "cousin" command
``\ansicpg1251`` appears not to have changed the rendition of a document with
extended chars in a smoketest.

Characters outside the ASCII and/or codepage can be expressed with Unicode
codepoints like so: ``\u199 ?`` (U+00C7) and ``\u8364 ?`` (U+20AC). ``?`` is a
substitution character, intended for when the text needs downconversion to a
narrower set of characters. The subtituend can literally be the question mark
(and often is), but other characters work too. ``\u225 a`` would offer ``a`` as
a substitution for ``á``.

It has been observed that Outlook would also generate the sequence
``\uc2\u28450\'f9\'d3``. The origin of the F9D3 sequence is unknown, and it is
different across documents for the same Unicode codepoint, which suggests it
may be a per-document custom "character set".


HTML
====

The character set for a HTML document is given by a sideband mechanism, i.e.

	* the Content-Type header as part of a HTTP response,
	* the Content-Type header as part of a RFC5322 mail,
	* the PR_INTERNET_CPID property as part of a MAPI message

Only when no sideband mechanism exists should the ``<meta
http-equiv="Content-Type" content="...">`` tag inside the document have effect,
if any. (Outlook's fallback mechanism is to actually use the RPC/session
character set.) However, to get to <meta>, a parser needs to make an assumption
about the character set, and ASCII/chars is a sensible starting choice.

A problem arises when the sideband data is not carried along when the HTML data
is replicated, i.e. transmitted or stored somewhere else, such as a file. This
can lead to subsequent decoding problems, especially when the <meta> tag value
disagreed with the Content-Type value in the first place.

HTML may express logical characters in a number of ways, such as _HTML
Entities_ like ``&euro;``, or via Unicode codepoints ``&#8364;``.


Plaintext
=========

The character set for PR_BODY_A data as is given by PR_INTERNET_CPID.

As a consequence, PR_BODY_A and PR_HTML should always have the same character
set to avoid garbled displaying.

The character set for PR_BODY_W data is Unicode. The encoding is wchar_t
in Windows MAPI, UTF-16LE over the network, and Gromox stores it as UTF-8 on
disk.


Rendition
=========

When Gromox's autosynthesis of HTML/RTF is disabled, Outlook only has
the plaintext form available and runs its own conversion to richtext.
In doing so, it will use the standard system font (usually Segoe UI),
breaking expectations of character width in some mails.


Wire format
===========

As if there were not enough places that switch between 8-bit and Unicode:

EMSMDB clients pass a preferred 8-bit codepage to the server when they
establish their RPC connection (ecDoConnectEx).

The ROPs ropOpenMessage, ropCreateMessage, openEmbeddesMessage have a
codepage argument with which the in-memory message object
will operate under a possibly different codepage.

The ROP ropGetPropertiesSpecific has a "want_unicode" argument.

For PR_BODY_A, PR_INTERNET_CPID is used. Perhaps the per-connection/per-MO
codepage only plays a role for other properties like PR_SUBJECT_A?
