Gromox
======

Gromox is the central groupware server component of grommunio. It is capable of
serving as a replacement for Microsoft Exchange and compatibles. Connectivity
options include RPC/HTTP (Outlook Anywhere), MAPI/HTTP, IMAP, POP3, an
SMTP-speaking LDA, and a PHP module with a MAPI function subset. Components can
scale-out over multiple hosts.

|shield-agpl| |shield-release|_ |shield-cov|_ |shield-loc|

.. |shield-agpl| image:: https://img.shields.io/badge/license-AGPL--3.0-green
.. |shield-release| image:: https://shields.io/github/v/tag/grommunio/gromox
.. _shield-release: https://github.com/grommunio/gromox/tags
.. |shield-cov| image:: https://img.shields.io/coverity/scan/gromox
.. _shield-cov: https://scan.coverity.com/projects/gromox
.. |shield-loc| image:: https://img.shields.io/github/languages/code-size/grommunio/gromox

Gromox is modular and consists of a set of components and programs to provide
its feature set. This repository includes a number of manual pages, for which a
rendered version is at `docs.grommunio.com
<https://docs.grommunio.com/man/gromox.7.html>`_.

Instructions for compilation are in `doc/install.rst <doc/install.rst>`_.

Gromox relies on other components to provide a sensibly complete mail system,

* Admin API/CLI (Management):
  `grommunio Admin API/CLI <https://github.com/grommunio/admin-api>`_
* Admin Web Interface (Management):
  `grommunio Admin Web <https://github.com/grommunio/admin-web>`_
* User Web Interface (Web UI):
  `grommunio Web <https://github.com/grommunio/grommunio-web>`_
* Exchange ActiveSync (EAS) (Mobile Devices):
  `grommunio Sync <https://github.com/grommunio/grommunio-sync>`_
* CalDAV & CardDAV (Interoperability with Clients):
  `grommunio DAV <https://github.com/grommunio/grommunio-dav>`_
* a mail transfer agent like Postfx, Exim, ad more
* mail security solutions like rspamd and others (commercial ones included)

The grommunio Appliance ships these essentials and has a ready-to-run
installation of Gromox.


Support
=======

Support is available through grommunio GmbH and its partners.
See https://grommunio.com/ for details. A community forum is
at `<https://community.grommunio.com/>`_.

The source code repository and technical issue tracker can be found at
`<https://github.com/grommunio/gromox>`_.

For direct contact and supplying information about a security-related
responsible disclosure, contact `dev@grommunio.com <dev@grommunio.com>`_.


Standards and protocols
=======================

Gromox follows a number of protocols as described by the `Microsoft Exchange
Server Protocol Documents
<https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprotlp>`_ —
OXCDATA, OXDSCLI, OXCFOLD, OXCFXICS, OXCICAL, OXCMAIL, OXCMAPIHTTP (plus yet
undocumented encodings), OXCMSG, OXCNOTIF, OXNSPI, OXCPERM, OXCPRPT, OXCROPS,
OXCRPC, OXCSTOR, OXCTABL, OXMSG, OXOABK, OXOABKT, OXOCAL, OXOCNTC, OXODLGT,
OXOMSG, OXORULE, OXOSFLD, OXOSMIME, OXPROPS, OXTNEF, OXVCARD, and (partially)
OXABREF, OXOCFG, OXRTFCP, OXWOOF, PST, as well as parts of the specifications
of DCERPC/C7086, RPCE and RPCH.


Contributing
============

* https://docs.github.com/en/get-started/quickstart/contributing-to-projects
* Alternatively, upload commits to a git store of your choosing, or export the
  series as a patchset using `git format-patch
  <https://git-scm.com/docs/git-format-patch>`_, then convey the git
  link/patches through our direct contact address (above).

Coding style
------------

When in Rome, do as the Romans do.
