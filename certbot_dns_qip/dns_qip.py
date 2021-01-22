"""DNS Authenticator for VitalQIP."""
import json
import logging
import time
import sys

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from urllib.parse import urlparse, urljoin

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
            self.credentials.conf("organsation"),
        )

class _QIPClient(object):
    """
    Encapsulates all communication with the ISPConfig Remote REST API.
    """

    def __init__(self, endpoint, username, password, organsation):
        logger.debug("creating qipclient")
        e = urlparse(endpoint)
        if e.scheme == "":
            raise errors.PluginError("No scheme (http/https) found in provided endpoint")
        self.endpoint = e
        self.username = username
        self.password = password
        self.organsation = organsation
        self.session = requests.Session()
        self.session.headers.update({'accept': 'application/json'})
        self.session.headers.update({'Content-Type': 'application/json'})
        # remove for prod release
        self.session.verify = False

    def _login(self):
        if "Authentication" in self.session.headers.keys():
            return
        logger.debug("logging in")
        logindata = {"username": self.username, "password": self.password}
        resp = self._api_request("POST", "/api/login", logindata)
        if "Authentication" not in resp.headers.keys():
            raise errors.PluginError("HTTP Error during login. No 'Authentication' header found")
        token = resp.headers["Authentication"]
        logger.debug(f"session token is {token}")
        self.session.headers.update({'Authentication': f"Token {token}"})

    def _api_request(self, method, action, data={}, query={}):
        url = self._get_url(action)
        # logger.debug(f"Data: {data}")
        resp = self.session.request(method, url, json=data, params=query)
        logger.debug(f"API Request to URL: {url}")
        if action == "api/v1/FIL/zone.json" and resp.status_code == 404:
            return resp.text
        if resp.status_code < 200 or resp.status_code > 201:
            raise errors.PluginError(f"HTTP Error during request {resp.status_code}")
        if action == "/api/login":
            return resp
        result = {}
        if resp.text != "":
            try:
                result = resp.json()
            except json.decoder.JSONDecodeError:
                raise errors.PluginError(f"API response with non JSON: {resp.text}")
        return result

    def _get_url(self, action):
        return f"{self.endpoint.geturl()}{action}"

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
        record = self.get_existing_txt(record_name)
        print('zzzzzzzzzzzzzz')
        print(record)
        print(record_content)
        if record is not None:
            if record["data1"] == record_content:
                logger.info(f"already there, id {record['owner']}")
                return
            else:
                logger.info(f"update {record['owner']}")
                self._update_txt_record(record, record_content, record_ttl)
        else:
            logger.info("insert new txt record")
            self._insert_txt_record(record_name, record_content, record_ttl, domain)

        sys.exit(0)

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the VitalQIP API
        """
        return
        # self._login()
        # zone_id, zone_name = self._find_managed_zone(domain)
        # if zone_id is None:
        #     raise errors.PluginError("Domain not known")
        # logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        # o_record_name = record_name
        # record_name = record_name.replace(zone_name, "")[:-1]
        # logger.debug(
        #     "using record_name: %s from original: %s", record_name, o_record_name
        # )
        # record = self.get_existing_txt(record_name)
        # if record is not None:
        #     if record["data"] == record_content:
        #         logger.debug("delete TXT record: %s", record["id"])
        #         self._delete_txt_record(record["id"])

    def _prepare_rr_data(self, old_record, record_content, record_ttl):
        updated_record = old_record.copy()
        updated_record["data1"] = record_content
        updated_record["ttl"] = record_ttl

        update_body = {'oldRRRec': old_record, 'updatedRRRec': updated_record}

        return update_body

    def _insert_txt_record(self, record_name, record_content, record_ttl, domain):
        logger.debug(f"insert with data: {record_content}")
        zone_name = self._find_managed_zone(domain)
        payload = {"owner": record_name, "classType": "IN", "rrType": "TXT", "data1": record_content, "publishing": "ALWAYS", "ttl": record_ttl, "infraType": "ZONE", "infraFQDN": zone_name}
        self._login()
        self._api_request("POST", "api/v1/FIL/rr", data=payload)

    def _update_txt_record(self, old_record, record_content, record_ttl):
        data = self._prepare_rr_data(old_record, record_content, record_ttl)
        logger.debug("update with data: {data}")
        self._login()
        self._api_request("PUT", "api/v1/FIL/rr", data)

    def _delete_txt_record(self, primary_id):
        return
        # # data = {"primary_id": primary_id}
        # logger.debug("delete with data: %s", data)
        # self._api_request("dns_txt_delete", data)

    def _find_managed_zone(self, domain):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The ID of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """
        if len(domain.split('.')) == 1:
            raise errors.PluginError(f"No zone found")
        self._login()
        zones = self._api_request("GET", "api/v1/FIL/zone.json", query={"name": domain})
        if "DNS Zone not found" in zones:
            domain = '.'.join(domain.split('.')[1:])
            return self._find_managed_zone(domain)
        else:
            for zone in zones["list"]:
                if zone["name"] == domain:
                    return zone["name"]

    def get_existing_txt(self, record_name):
        """
        Get existing TXT records from the RRset for the record name.

        If an error occurs while requesting the record set, it is suppressed
        and None is returned.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').

        :returns: TXT record object or None
        :rtype: `Object` or `None`
        """
        self._login()
        query = {"name": record_name, "getDefaultRRs": "true"}
        try:
            records = self._api_request("GET", "api/v1/FIL/rr.json", query=query)
        except:
            return None
        for record in records['list']:
            if record['rrType'] == 'TXT':
                return record
        return None
