"""

This plugin automates the process of completing a dns-01 challenge by creating,
and subsequently removing, TXT records using the VitalQIP Rest API.


Named Arguments
---------------

===================================    ======================================
``--dns-qip-credentials``              QIP Remote API credentials_
                                       INI file. (Required)
``--dns-qip-propagation-seconds``      The number of seconds to wait for DNS
                                       to propagate before asking the ACME
                                       server to verify the DNS record.
                                       (Default: 120)
===================================    ======================================


Credentials
-----------

Use of this plugin requires a configuration file containing VitalQIP Remote API
credentials.

.. code-block:: ini
   :name: creds.ini
   :caption: Example credentials file:

   # VitalQIP API credentials used by Certbot
   certbot_dns_qip:dns_qip_username = myremoteuser
   certbot_dns_qip:dns_qip_password = verysecureremoteuserpassword
   certbot_dns_qip:dns_qip_endpoint = https://localhost:8443/
   certbot_dns_qip:dns_qip_organisation = exampleorg

The path to this file can be provided interactively or using the
``--dns-qip-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would a password. Users who
   can read this file can use these credentials to issue arbitrary API calls on
   your behalf. Users who can cause Certbot to run using these credentials can
   complete a ``dns-01`` challenge to acquire new certificates or revoke
   existing certificates for associated domains, even if those domains aren't
   being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).

Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --authenticator certbot-dns-qip:dns-qip \\
     --dns-qip-credentials ~/.secrets/certbot/creds.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --authenticator certbot-dns-qip:dns-qip \\
     --dns-qip-credentials ~/.secrets/certbot/qip.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 240 seconds
             for DNS propagation

   certbot certonly \\
     --authenticator certbot-dns-qip:dns-qip \\
     --dns-qip-credentials ~/.secrets/certbot/creds.ini \\
     --dns-qip-propagation-seconds 240 \\
     -d example.com

"""
