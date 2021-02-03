# Certbot QIP DNS Plugin

VitalQIP DNS Authenticator plugin for Certbot

This plugin automates the process of completing a dns-01 challenge by creating, and subsequently removing, TXT records using the VitalQIP Remote API.

## Using plugin with certbot to query QIP

### Installation

Clone the repo and pip install:

```sh
pip install -e <path to repo>
```

### Named Arguments

To start using DNS authentication for QIP, pass the following arguments on
certbot's command line:

|Arguments                                |Description|
|-----------------------------------------|-----------|
|`--authenticator certbot-dns-qip:dns-qip`|Select the authenticator plugin (Required)|
|`--certbot-dns-qip:dns-qip-credentials`|QIP Remote User credentials INI file. (Required)|
|`--certbot-dns-qip:dns-qip-propagation-seconds`| waiting time for DNS to propagate before asking the ACME server to verify the DNS record.(Default: 10, Recommended: >= 600)|

### Credentials

An example ``creds.ini`` file:

```ini

   certbot_dns_qip:dns_qip_username = myremoteuser
   certbot_dns_qip:dns_qip_password = verysecureremoteuserpassword
   certbot_dns_qip:dns_qip_endpoint = https://localhost:8443/
   certbot_dns_qip:dns_qip_organisation = exampleorg
```

The path to this file can be provided interactively or using the `--certbot-dns-qip:dns-qip-credentials` command-line argument. Certbot records the path to this file for use during renewal, but does not store the file's contents.

### Request certificate using Certbot CLI

```sh
certbot certonly --authenticator certbot-dns-qip:dns-qip --certbot-dns-qip:dns-qip-credentials /tmp/creds.ini -d example.com
```

## Testing

Run tests for plugin using:

```sh
pip install -r requirements.txt
pytest -v
```

### Plugin development

When developing and testing functionality of the plugin, you will need to have a local certbot virtual env running. Below are the steps needed to set up:

1. Clone certbot from [github.com/certbot/certbot](https://github.com/certbot/certbot)
1. Cd into cloned repo
1. Run below commands to set up virtual environment and install:
    1. `python tools/venv3.py`
    1. `source venv3/bin/activate`
    1. `pip install -e ../path-to-plugin-repo`
    1. Test if plugin installs correctly using `certbot_test plugins` and check the list.
