Source build procedure
======================

A pre-built version of Gromox is readily available by way of the grammm Linux
distribution. If you choose to build from source nevertheless, a number of
dependencies are needed:

* autotools
* C++17 compiler
* gumbo-parser
* jsoncpp
* libHX
* Linux-PAM
* MariaDB Connector/C or compatible
* OpenSSL or compatible
* PHP 7/8 headers
* SQLite3
* zlib

The procedure is the well-established autotools run. Note that the default
prefix is /usr, not /usr/local.

For true developers, the ``qconf`` helper script may be used as a typing
shortcut and to configure the paths such that just-built program binaries, from
within the source directory, would work with a (pre-existing) Gromox
installation from the grammm distribution.

The rest of the documentation assumes that Gromox was configured with
``--prefix=/usr --sysconfdir=/etc --localstatedir=/var``.


Runtime desirables
==================

* A FastCGI server that can execute PHP >= 7.4,
  to enable AutoDiscover and Free/Busy Scheduling Assistant functions.

* PHP command-line interface,
  to enable the scheduled/delayed message sending function.

* A mail transfer agent, for the ability to receive messages from, and send
  messages to, remote SMTP servers on the Internet. Spam handling should also
  occur in the MTA chain.

* w3m, for improved HTML-to-text conversion.


Minimal configuration
=====================

SQL database
------------

A MariaDB/MySQL database is used to store (and replicate, if so needed later)
users, groups and other objects like distribution lists. The default database
name Gromox's mysql_adaptor plugin will use is ``email``, hence you would
create that as a blank database. The default database access users is root with
no password, which fits the default installation of MariaDB too. Any deviations
will have to be specified in ``/etc/gromox/mysql_adaptor.cfg``; the
corresponding manpage is mysql_adaptor(4gx). The database can then be populated
using ``gromox-dbop -C``.

Gromox only requires SELECT,UPDATE permissions on this database as it does not
create or delete users. The grammm Administration Backend is in charge of user
management, and this role will need more permissions.


SSL certificates
----------------

Have a PEM-encoded certificate and key ready. The cert file should contain any
necessary sections of the certificate chain (in case those CAs are not already
available by way of ``/etc/ssl/certs``). openSSL generally allows having the
cert and the key in the same file, if you wish to do so. Add to
`/etc/gromox/http.cfg`:

```
listen_ssl_port = 443
http_support_ssl = true
http_certificate_path = /etc/gromox/mydomain.pem
http_private_key_path = /etc/gromox/mydomain.key
```

The Gromox Autodiscover handler `forces`__ a HTTPS redirect, which is why a
certificate should indeed be set up. Then, since you already have the
certificates, you could also use them in e.g. ``smtp.cfg``.

__ https://github.com/grammm-dev/gromox/blob/master/exch/php/ews/autodiscover.php#L24


x500_org_name
-------------

Do not bother changing this config directive's default value.

In various daemons, the ``x500_org_name`` config directive influences the DN
used in muidEMSAB entryids. In Exchange, the DN would be derived from the
ActiveDirectory hierarchy or something — feel free to google for “X500 DN
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
outgoing SMTP. gromox-smtp listens on port 25 by default, but it is only the
LDA, so such setup would only allow to send mail locally. To enable Internet
mail or to add spam filtration, you will have reconfigure gromox-smtp to listen
on port 24 rather than 25, and install a full MTA like Postfix with
configuration directives similar to:

```
virtual_mailbox_domains = mydomain.de myotherdomain.com
virtual_transport = smtp:localhost:24
```


Service start
-------------

``systemctl start <...>``

* ``gromox-http`` — at the very least, the main process needs to be started. This is sufficient for e.g. Outlook to open and browse mailboxes.
* ``gromox-adaptor`` — caches SQL data and generates work files used by other daemons
* ``gromox-zcore`` — the zcore process is needed by anything using php-mapi (grammmm-web, grammm-sync, ...)
* ``gromox-smtp`` — SMTP half of the local delivery agent (for incoming mail)
* ``gromox-delivery`` — Dequeueing half of the local delivery agent
* ``gromox-imap`` — for ye Thunderbird
