"""Tests for certbot_dns_qip.dns_qip."""

import unittest

import unittest.mock as mock
import json
import requests_mock

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

FAKE_USER = "remoteuser"
FAKE_PW = "password"
FAKE_ENDPOINT = "http://endpoint"
FAKE_ORG = "fake-org"
FAKE_TOKEN = "fake-token"

class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_qip.dns_qip import Authenticator

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "qip_username": FAKE_USER,
                "qip_password": FAKE_PW,
                "qip_endpoint": FAKE_ENDPOINT,
                "qip_organisation": FAKE_ORG,
            },
            path,
        )

        super(AuthenticatorTest, self).setUp()
        self.config = mock.MagicMock(
            qip_credentials=path, qip_propagation_seconds=0
        )  # don't wait during tests

        self.auth = Authenticator(self.config, "qip")

        self.mock_client = mock.MagicMock()
        self.auth._get_qip_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

class QIPClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42

    def setUp(self):
        from certbot_dns_qip.dns_qip import _QIPClient

        self.adapter = requests_mock.Adapter()
        self.client = _QIPClient(FAKE_ENDPOINT, FAKE_USER, FAKE_PW, FAKE_ORG)
        self.client.session.mount("http://", self.adapter)

    def _register_response(
        self, method, action, response=None, message=None, additional_matcher=None, request_headers={}, response_headers={}, **kwargs
    ):
        self.adapter.register_uri(
            method,
            f"{FAKE_ENDPOINT}{action}",
            text=response,
            additional_matcher=additional_matcher,
            request_headers=request_headers,
            headers=response_headers,
            **kwargs
        )

    # def test_add_txt_record(self):
    #     self._register_response("POST", "/api/login", response_headers={"Authentication": "asfnbajfdjbv"})
    #     self._register_response("GET", f"/api/v1/{FAKE_ORG}/rr.json?name={self.record_name}&getDefaultRRs=true", request_headers={"Authentication": "asfnbajfdjbv"})
    #     self.client.add_txt_record(
    #         DOMAIN, self.record_name, self.record_content, self.record_ttl
    #     )

    def test_del_txt_record(self):
        self._register_response("POST", "/api/login", response_headers={"Authentication": FAKE_TOKEN})
        search_txt_response = {
            "list": [{
                        "name": DOMAIN,
                        "type": "DOMAIN",
                        "rr": {
                            "name": self.record_name,
                            "recordType": "TXT",
                            "data": self.record_content,
                        }
            }]
        }
        self._register_response("GET", f"/api/v1/{FAKE_ORG}/qip-search.json?name={self.record_name}&searchType=All&subRange=TXT", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_txt_response)
        search_zone_response = {
            "list": [
            {
                "name": DOMAIN,
                "defaultTtl": 3600,
                "email": "hostmaster@foo.bar",
                "expireTime": 604800,
                "negativeCacheTtl": 600,
                "refreshTime": 21600,
                "retryTime": 3600
            }]
        }
        self._register_response("GET", f"/api/v1/{FAKE_ORG}/zone.json?name={DOMAIN}", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_zone_response)
        self._register_response("DELETE", f"/api/v1/{FAKE_ORG}/rr/singleDelete?infraFQDN={DOMAIN}&infraType=ZONE&owner={self.record_name}", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, status_code=204)
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)
        assert(self.adapter.call_count) == 4

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
