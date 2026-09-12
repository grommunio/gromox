====================================
Per-domain outbound SMTP smart-hosts
====================================

Purpose
=======

The ``domain_smtp_gateway`` table (created by dbop as schema version 134)
lets administrators define a per-domain outbound relay ("smart-host"),
optionally with credentials and an encryption mode. Each domain of a grommunio installation can route its outgoing
mail through its own relay (for example a provider smarthost such as
Mailgun or Sendgrid) instead of the global relayhost.

Design
======

gromox itself does not connect to smart-hosts. Outbound mail is always
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
``encryption``      ``none``, ``starttls``, ``starttls_unverified``
                    or ``tls`` (implicit TLS, e.g. port 465)
``username``        Optional SASL username (no AUTH if empty)
``password``        Optional SASL password
``enabled``         1 = route this domain via the relay
``description``     Free-form note
==================  =====================================================

The grommunio admin API/CLI/web provide the management interface for
this table; gromox only creates and migrates the schema.

Postfix wiring example
======================

Postfix can query the table live through MySQL maps. Two maps are
needed; neither affects mail of domains without a gateway row (such
senders keep using the global ``relayhost``).

main.cf::

    sender_dependent_default_transport_maps =
        mysql:/etc/postfix/grommunio-domain-gateway-transport.cf
    smtp_sasl_password_maps =
        lmdb:/etc/postfix/sasl_passwd,
        mysql:/etc/postfix/grommunio-domain-gateway-auth.cf

The sender-dependent ``smtp_sasl_password_maps`` lookup order (sender
address, sender domain, then nexthop) ensures gateway credentials only
apply to senders of gateway domains.

grommunio-domain-gateway-transport.cf::

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

grommunio-domain-gateway-auth.cf::

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

master.cf entries for the STARTTLS and implicit-TLS transports::

    gwdsgw_starttls unix -  -  n  -  -  smtp
      -o smtp_tls_security_level=encrypt
    gwdsgw_ssl     unix -  -  n  -  -  smtp
      -o smtp_tls_wrappermode=yes
      -o smtp_tls_security_level=encrypt

Note that Postfix's ``encrypt`` level does not verify the relay
certificate; to enforce verification, add a ``smtp_tls_policy_maps``
entry for the relay host. ``starttls`` and ``starttls_unverified`` are
therefore equivalent under this wiring unless such a policy is present.
