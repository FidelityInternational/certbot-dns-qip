"""DNS Authenticator for VitalQIP."""
import json
import logging
import time

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for VitalQIP

    This Authenticator uses the VitalQIP Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using VitalQIP for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add)
        add("credentials", help="VitalQIP credentials INI file.")

    def more_info(self):
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the VitalQIP Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "QIP credentials INI file",
            {
                "endpoint": "URL of the QIP Remote API.",
                "username": "Username for QIP Remote API.",
                "password": "Password for QIP Remote API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_qip_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_qip_client().del_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _get_qip_client(self):
        return _QIPClient(
            self.credentials.conf("endpoint"),
            self.credentials.conf("username"),
            self.credentials.conf("password"),
        )

class _QIPClient(object):
    """
    Encapsulates all communication with the ISPConfig Remote REST API.
    """

    def __init__(self, endpoint, username, password):
        logger.debug("creating qipclient")
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.session = requests.Session()
        # remove for prod release
        self.session.verify = False

    def _login(self):
        if "Authentication" in self.session.headers.keys():
            return
        logger.debug("logging in")
        logindata = {"username": self.username, "password": self.password}
        resp = self._api_request("login", logindata)
        if "Authentication" not in resp.headers.keys():
            raise errors.PluginError("HTTP Error during login. No 'Authentication' header found")
        token = resp.headers["Authentication"]
        logger.debug(f"session token is {token}")
        self.session.headers.update({'Authentication': token})

    def _api_request(self, action, data):
        url = self._get_url(action)
        logger.debug(f"Data: {data}")
        resp = self.session.get(url, json=data)
        logger.debug(f"API Request to URL: {url}")
        if 200 < resp.status_code > 201:
            raise errors.PluginError(f"HTTP Error during request {resp.status_code}")
        if action == "login":
            return resp
        try:
            result = resp.json()
        except json.decoder.JSONDecodeError:
            raise errors.PluginError(f"API response with non JSON: {resp.text}")
        return result
        
    def _get_url(self, action):
        return "{0}{1}".format(self.endpoint, action)

    def _get_server_id(self, zone_id):
        zone = self._api_request("dns_zone_get", {"primary_id": zone_id})
        return zone["server_id"]

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the VitalQIP API
        """
        self._login()
        zone_id, zone_name = self._find_managed_zone_id(domain, record_name)
        if zone_id is None:
            raise errors.PluginError("Domain not known")
        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        o_record_name = record_name
        record_name = record_name.replace(zone_name, "")[:-1]
        logger.debug(
            "using record_name: %s from original: %s", record_name, o_record_name
        )
        record = self.get_existing_txt(zone_id, record_name, record_content)
        if record is not None:
            if record["data"] == record_content:
                logger.info("already there, id {0}".format(record["id"]))
                return
            else:
                logger.info("update {0}".format(record["id"]))
                self._update_txt_record(
                    zone_id, record["id"], record_name, record_content, record_ttl
                )
        else:
            logger.info("insert new txt record")
            self._insert_txt_record(zone_id, record_name, record_content, record_ttl)

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the VitalQIP API
        """
        self._login()
        zone_id, zone_name = self._find_managed_zone_id(domain, record_name)
        if zone_id is None:
            raise errors.PluginError("Domain not known")
        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        o_record_name = record_name
        record_name = record_name.replace(zone_name, "")[:-1]
        logger.debug(
            "using record_name: %s from original: %s", record_name, o_record_name
        )
        record = self.get_existing_txt(zone_id, record_name, record_content)
        if record is not None:
            if record["data"] == record_content:
                logger.debug("delete TXT record: %s", record["id"])
                self._delete_txt_record(record["id"])

    def _prepare_rr_data(self, zone_id, record_name, record_content, record_ttl):
        server_id = self._get_server_id(zone_id)
        data = {
            "client_id": None,
            "rr_type": "TXT",
            "params": {
                "server_id": server_id,
                "name": record_name,
                "active": "Y",
                "type": "TXT",
                "data": record_content,
                "zone": zone_id,
                "ttl": record_ttl,
                "update_serial": False,
                "stamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            },
        }
        return data

    def _insert_txt_record(self, zone_id, record_name, record_content, record_ttl):
        data = self._prepare_rr_data(zone_id, record_name, record_content, record_ttl)
        logger.debug("insert with data: %s", data)
        self._api_request("dns_txt_add", data)

    def _update_txt_record(
        self, zone_id, primary_id, record_name, record_content, record_ttl
    ):
        data = self._prepare_rr_data(zone_id, record_name, record_content, record_ttl)
        data["primary_id"] = primary_id
        logger.debug("update with data: %s", data)
        self._api_request("dns_txt_update", data)

    def _delete_txt_record(self, primary_id):
        data = {"primary_id": primary_id}
        logger.debug("delete with data: %s", data)
        self._api_request("dns_txt_delete", data)

    def _find_managed_zone_id(self, domain, record_name):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The ID of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """

        zone_dns_name_guesses = [record_name] + dns_common.base_domain_name_guesses(domain)

        for zone_name in zone_dns_name_guesses:
            # get the zone id
            try:
                logger.debug("looking for zone: %s", zone_name)
                zone_id = self._api_request("dns_zone_get_id", {"origin": zone_name})
                return zone_id, zone_name
            except errors.PluginError:
                pass
        return None, None

    def get_existing_txt(self, zone_id, record_name, record_content):
        """
        Get existing TXT records from the RRset for the record name.

        If an error occurs while requesting the record set, it is suppressed
        and None is returned.

        :param str zone_id: The ID of the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').

        :returns: TXT record value or None
        :rtype: `string` or `None`

        """
        self._login()
        read_zone_data = {"zone_id": zone_id}
        zone_data = self._api_request("dns_rr_get_all_by_zone", read_zone_data)
        for entry in zone_data:
            if (
                entry["name"] == record_name
                and entry["type"] == "TXT"
                and entry["data"] == record_content
            ):
                return entry
        return None
