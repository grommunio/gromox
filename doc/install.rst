..
	SPDX-License-Identifier: CC-BY-SA-4.0 or-later
	SPDX-FileCopyrightText: 2021-2022 grommunio GmbH

Dependency installation
=======================

A pre-built version of Gromox is readily available by way of the grommunio Linux
distribution. If you choose to build from source nevertheless, a number of
dependencies are needed:

* autotools
* C++17/C++20 compiler
* cURL library
* fmt >= 8
* jsoncpp
* libHX >= 4.12
* libiconv (OpenBSD only)
* libvmime >= 0.9.2.160 (commit c6904bd7cf03f6cca92cf0d15aec02e7850e0276)
* libxml2 (we use this for HTML parsing)
* libzstd
* MariaDB Connector/C or compatible
* OpenLDAP or similar headers
* OpenSSL or compatible
* perl5
* SQLite3
* tinyxml2 >= 8 (we use this for all things XML)
* zlib

Optional deps:

* libc/libresolv with "res_nquerydomain" & "ns_initparse" functions
* libolecf
* libpff
* Linux-PAM
* PHP 7/8 headers

When the grommunio repository is known to zypper, one can request to install
the dependencies of the SRPM, which conveniently brings in everything that was
used to build Gromox in the first place. By extension, the same mechanism can
be used for other source repositories such as libexmdbpp.

.. code-block::

	# zypper si -d gromox
	Loading repository data...
	Reading installed packages...
	Resolving package dependencies...

	The following 62 NEW packages are going to be installed:
	  autoconf automake binutils [...]
	Overall download size: 70.8 MiB. Already cached: 0 B. After the operation,
	additional 284.5 MiB will be used.
	Continue? [y/n/v/...? shows all options] (y):


Source build procedure
======================

The procedure is the well-established autotools run. Note that the default
install prefix is /usr, not /usr/local.

For true developers, the ``qconf`` helper script may be used as a typing
shortcut and to configure the paths such that just-built program binaries, from
within the source directory, would work with a (pre-existing) Gromox
installation from the grommunio distribution.

The rest of the documentation assumes that Gromox was configured with
``--prefix=/usr --sysconfdir=/etc --localstatedir=/var``.

(For FreeBSD/OpenBSD, you may need to pass extra parameters, e.g.
``CPPFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib
--with-php-config=/usr/local/bin/php-config-8.1`` to configure.)

ASAN notes
----------

The following additional developer options are available:

* --with-asan: shorthand for enabling Address Sanitizer
* --with-ubsan: shorthand for enabling UB Sanitizer

Due to a problem in libtool <= 2.4.7 (debbugs.gnu.org/56839) and
ASAN (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=103930), it is
necessary to also call ``make`` with the sanitizer libs (asan, ubsan or both,
depending on choice) if they are shared libraries (usually gcc), plus
to-intercept libraries: ``make
LIBS="-lasan -lubsan -lcrypt"``


Optional runtime components
===========================

* A FastCGI server that can execute PHP >= 7.4,
  to enable AutoDiscover and Free/Busy Scheduling Assistant functions.

* PHP command-line interface,
  to enable the scheduled/delayed message sending function.

* A mail transfer agent, for the ability to receive messages from, and send
  messages to, remote SMTP servers on the Internet. Spam handling should also
  occur in the MTA chain.

* w3m, for improved HTML-to-text conversion.

* If tinkering with databases, the ``sqlite3`` and ``mysql``
  command-line clients may prove useful.

* If tinkering with coredumps, the ``zstd`` utility for decompressing
  files from ``/var/lib/systemd/coredump`` will help.


Minimal configuration
=====================

IPv6
----

The IPv6 kernel module needs to be available/enabled and the ``::1``
address must exist on the loopback device.


SQL database
------------

A MariaDB/MySQL database is used to store (and replicate, if so needed later)
users, groups and other objects like distribution lists. The default database
name Gromox's mysql_adaptor plugin will use is ``email``, hence you would
create that as a blank database. The default database access users is root with
no password, which fits the default installation of MariaDB too. Any deviations
will have to be specified in ``/etc/gromox/mysql_adaptor.cfg`` and
``/etc/gromox/autodiscover.ini``; the corresponding manpage is
mysql_adaptor(4gx) and autodiscover(4gx). The database can then be populated
using ``gromox-dbop -C``.

Gromox only requires SELECT,UPDATE permissions on this database as it does not
create or delete users. The grommunio Administration Backend is in charge of user
management, and this role will need more permissions.


TLS certificates
----------------

Have a PEM-encoded certificate and key ready. The cert file should contain any
necessary sections of the certificate chain (in case those CAs are not already
available by way of ``/etc/ssl/certs``). openSSL generally allows having the
cert and the key in the same file, if you wish to do so. Add to
``/etc/gromox/http.cfg``::

	http_listen_tls_port = 443
	http_support_tls = true
	http_certificate_path = /etc/gromox/mydomain.pem
	http_private_key_path = /etc/gromox/mydomain.key

The Gromox Autodiscover handler `forces`__ a HTTPS redirect, which is why a
certificate should indeed be set up. Then, since you already have the
certificates, you could also use them in e.g. the SMTP server's configuration.

__ https://github.com/grommunio/gromox/blob/master/exch/php/ews/autodiscover.php#L24


Hostname
--------

If the kernel hostname is different from the hostname used to access the
service(s), then ``autodiscover.ini`` needs the ``hostname=...`` line so that
Autodiscover can construct the correct TLS upgrade redirect URLs to itself, for
an external user.


x500_org_name
-------------

Do not bother changing this config directive's default value.

In various daemons, the ``x500_org_name`` config directive influences the DN
used in muidEMSAB entryids. In Exchange, the DN would be derived from the
Active Directory hierarchy or something — feel free to google for “X500 DN
Exchange” and cringe —, but as far as MAPI is concerned, the value is
arbitrary. The x500_org_name ought not be changed after initial installation as
it will invalidate participants of e-mail messages, calendar events, etc.


Users & /run
------------

Gromox services place their sockets into /run; for this to work, they need
permission on a suitable directory. ``data/tmpfiles-gromox.conf`` is a
systemd-tmpfiles fragment that will accomplish this appropriately.

Gromox services run in a privilege-reduced context. To that end,
``data/sysusers-gromox.conf`` is a systemd-sysusers fragment that will ensure
the user identities are available.

(Gromox RPM packages will do this on their own already)


php-fpm config
--------------

Parts of Gromox are implemented in PHP and need both php-fpm and php-cli. A
sample fragment for FPM is available in ``data/fpm-gromox.conf.sample``.

The choice of ``/run/gromox/php-fpm.sock`` in there coincides with the built-in
default config for mod_fastcgi(4gx).


SMTP
----

exchange_emsmdb.cfg and zcore.cfg implicitly default to using localhost:25 as
outgoing SMTP. At the same time, gromox-delivery-queue listens on port 25 by
default, but it is only the local delivery agent (LDA). Therefore, running with
implied defaults only gets you a system that can send mail to itself. To enable
Internet mail or to add spam filtration, you will have reconfigure
gromox-delivery-queue (edit smtp.cfg) to listen on port 24 rather than 25, and
install a full MTA like Postfix with configuration directives similar to::

	virtual_mailbox_domains = mydomain.de myotherdomain.com
	virtual_transport = lmtp:localhost:24


Running from the source checkout
--------------------------------

It is possible to run Gromox daemons from the source checkout. Heed the
following notes.

Gromox daemons switch to unprivileged mode, and after doing so, will still need
access to the build directory to access shared libraries. If any path component
of the build directory is missing search (execute) permission, the
daemon may be unable to start up. This happens predominantly when someone tries
to build Gromox as root (not a great idea) in ``/root`` (has mode 0700).

Gromox programs default to look for files in the installed system, i.e.
``/etc/gromox`` and ``/usr/share/gromox``. If nothing else is needed,
running daemons in place of their system counterparts is possible
with no edits to configuration, e.g.::

	systemctl stop gromox-http
	./http

To test updates to data files such as ``folder_names.txt``, the
modifications will either have to be copied to corresponding path in
``/usr/share/gromox``; else, you can set up and run the daemon with
an alternate config, e.g.:

.. code-block:: sh

	cp /etc/gromox/http.cfg http.cfg
	echo data_file_path=/root/gromox/data >>http.cfg
	./http -c http.cfg


Service start
-------------

``systemctl start <...>``

* ``gromox-http`` — at the very least, the main process needs to be started. This is sufficient for e.g. Outlook to open and browse mailboxes.
* ``gromox-adaptor`` — caches SQL data and generates work files used by other daemons
* ``gromox-zcore`` — the zcore process is needed by anything using php-mapi (grommuniom-web, grommunio-sync, ...)
* ``gromox-delivery-queue`` — LMTP/SMTP frontend of the local delivery agent (for incoming mail)
* ``gromox-delivery`` — Dequeueing backend of the local delivery agent
* ``gromox-imap`` — for ye Thunderbird
