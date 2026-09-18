====================================
Per-domain outbound SMTP smart-hosts
====================================

Purpose
=======

The ``domain_smtp_gateway`` table, created as part of schema version GX-134,
lets administrators define a per-domain outbound relay ("smart host"),
optionally with credentials and an encryption mode. Each domain of a grommunio
installation can route its outgoing
mail through its own relay (for example a provider smarthost such as
Mailgun or Sendgrid) instead of the global relayhost.

Design
======

Gromox itself does not connect to smarthosts. Outbound mail is always
handed to the configured ``outgoing_smtp_url`` (default:
``sendmail://localhost``, i.e. the local MTA such as Postfix). The MTA
evaluates the ``domain_smtp_gateway`` table with *sender-dependent*
lookups, so that the relay is selected by the envelope sender's domain.
This keeps queueing, retry, TLS policy, DSN generation and logging in
one place (the MTA) instead of duplicating a full SMTP client stack
inside gromox.

Table layout (``domain_smtp_gateway``):

==================  =====================================================
Column              Meaning
==================  =====================================================
``domain_id``       Primary key, foreign key to ``domains.id``
``host``            Relay hostname or IP
``port``            Relay TCP port (default 25)
``encryption``      ``none``; ``starttls`` (STARTTLS, certificate
                    verified); ``starttls_unverified`` (STARTTLS,
                    no certificate verification); ``tls`` (implicit
                    TLS, certificate verified, e.g. port 465)
``username``        Optional SASL username (no AUTH if empty)
``password``        Optional SASL password
``enabled``         1 = route this domain via the relay
``description``     Free-form note
==================  =====================================================

The grommunio admin API/CLI/web provide the management interface for
this table. Gromox only creates and updates the table schema.


Postfix wiring example
======================

Postfix can query the table live through MySQL maps. Three maps are
needed; none of them affects mail of domains without a gateway row
(such senders keep using the global ``relayhost``).

main.cf::

    sender_dependent_default_transport_maps =
        mysql:/etc/postfix/grommunio-domain-gateway-transport.cf
    smtp_sasl_password_maps =
        lmdb:/etc/postfix/sasl_passwd,
        mysql:/etc/postfix/grommunio-domain-gateway-auth.cf
    smtp_tls_policy_maps =
        mysql:/etc/postfix/grommunio-domain-gateway-tls-policy.cf

The sender-dependent ``smtp_sasl_password_maps`` lookup order (sender
address, sender domain, then nexthop) ensures gateway credentials only
apply to senders of gateway domains. Because the ``verify`` and
``secure`` TLS levels check certificates against trust anchors, the
``smtp_tls_CAfile`` variable is automatically set to the system
certificate ``/etc/ssl/ca-bundle.pem``

``grommunio-domain-gateway-transport.cf``::

	user = grommunio
	password = ...
	hosts = localhost
	dbname = grommunio
	query = SELECT CONCAT(
	            CASE g.encryption WHEN 'tls' THEN 'gwdsgw_ssl'
	                              WHEN 'none' THEN 'smtp'
	                              ELSE 'gwdsgw_starttls' END,
	            ':[', g.host, ']:', g.port)
	        FROM domain_smtp_gateway g
	        JOIN domains d ON d.ID = g.domain_id
	        WHERE d.domain_status = 0
	          AND d.domainname = _utf8mb4'%d' COLLATE utf8mb4_general_ci
	          AND g.enabled = 1

``grommunio-domain-gateway-auth.cf``::

	user = grommunio
	password = ...
	hosts = localhost
	dbname = grommunio
	query = SELECT CONCAT_WS(':', g.username, g.password)
	        FROM domain_smtp_gateway g
	        JOIN domains d ON d.ID = g.domain_id
	        WHERE d.domain_status = 0
	          AND d.domainname = _utf8mb4'%d' COLLATE utf8mb4_general_ci
	          AND g.enabled = 1
	          AND g.username IS NOT NULL AND g.username <> ''

``grommunio-domain-gateway-tls-policy.cf`` — Postfix looks
``smtp_tls_policy_maps`` up by nexthop (``[host]:port``), while the
table stores the bare host, hence the ``SUBSTRING_INDEX``
normalization. Hosts used by any active domain with encryption
``starttls`` or ``tls`` are pinned to the ``secure`` level; hosts only
used with ``starttls_unverified`` have no entry and stay at the
transport's ``encrypt`` level::

	user = grommunio
	password = ...
	hosts = localhost
	dbname = grommunio
	query = SELECT CONCAT('secure match=', g.host)
	        FROM domain_smtp_gateway g
	        JOIN domains d ON d.ID = g.domain_id
	        WHERE d.domain_status = 0
	          AND g.enabled = 1
	          AND g.encryption IN ('starttls', 'tls')
	          AND g.host = SUBSTRING_INDEX(SUBSTRING_INDEX('%s', ']', 1), '[', -1)
	        LIMIT 1

``master.cf`` entries for the STARTTLS and implicit-TLS transports are::

	gwdsgw_starttls unix -  -  n  -  -  smtp
	  -o smtp_tls_security_level=encrypt
	gwdsgw_ssl     unix -  -  n  -  -  smtp
	  -o smtp_tls_wrappermode=yes
	  -o smtp_tls_security_level=encrypt

Note that Postfix's ``encrypt`` level does not verify the relay
certificate. The ``smtp_tls_policy_maps`` entry above is what
distinguishes the modes: for ``starttls`` and ``tls`` the connection
to the relay is escalated to the ``secure`` level, so the relay
certificate is verified (chain and hostname); ``starttls_unverified``
keeps ``encrypt`` and works without a verifiable certificate.

The policy is keyed by relay host, not by domain: if several domains
share a relay host with differing ``encryption`` values, the strictest
mode applies to that host, and connections to a host that doubles as
an MX target of another domain are verified as well.
