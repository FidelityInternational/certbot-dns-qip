"""Tests for certbot_dns_qip.dns_qip."""

from typing import Deque
import unittest
import pytest
from contextlib import contextmanager

import unittest.mock as mock
import json
import requests_mock

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from certbot_dns_qip.dns_qip import _QIPClient

FAKE_USER = "remoteuser"
FAKE_PW = "password"
FAKE_ENDPOINT = "http://endpoint"
FAKE_ORG = "fake-org"
FAKE_TOKEN = "fake-token"
FAKE_RECORD = "foo"
FAKE_RECORD_CONTENT = "bar"
FAKE_RECORD_TTL = 42

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

@pytest.fixture()
def adapter():
    return requests_mock.Adapter()

@pytest.fixture()
def client(adapter):
    client = _QIPClient(FAKE_ENDPOINT, FAKE_USER, FAKE_PW, FAKE_ORG)
    client.session.mount("http://", adapter)
    return client

@contextmanager
def does_not_raise():
    yield

def record(record_type):
    if record_type == None:
       return None
    return {
            "name": DOMAIN,
            "type": "DOMAIN",
            "rr": {
                "name": FAKE_RECORD,
                "recordType": record_type,
                "data": FAKE_RECORD_CONTENT,
            }
        }

def _register_response(adapter, method, action, response=None, additional_matcher=None, request_headers={}, response_headers={}, **kwargs):
    adapter.register_uri(
        method,
        f"{FAKE_ENDPOINT}{action}",
        text=response,
        additional_matcher=additional_matcher,
        request_headers=request_headers,
        headers=response_headers,
        **kwargs
    )

@pytest.mark.parametrize("record_type, update_record_data, call_count, calls, search_status_code", [
    ("TXT", None, 2, [f"/api/login", f"/api/v1/{FAKE_ORG}/qip-search.json"], 200),
    ("TXT", "foobarbaz", 3, [f"/api/login", f"/api/v1/{FAKE_ORG}/qip-search.json", f"/api/v1/{FAKE_ORG}/rr"], 200),
    (None, None, 4, [f"/api/login", f"/api/v1/{FAKE_ORG}/qip-search.json", f"/api/v1/{FAKE_ORG}/zone.json", f"/api/v1/{FAKE_ORG}/rr"], 500)
], ids=[
    "Record already exists, do nothing",
    "Record exists but with incorrect data, updating existing txt record with correct data",
    "Record doesn't exist, adding new txt record"
])
def test_add_txt_record(adapter, client, record_type, update_record_data, call_count, calls, search_status_code):
    rr = record(record_type)
    if update_record_data is not None:
        rr["rr"]["data"] = update_record_data
    search_response = {
        "list": [rr]
    }
    search_zone_response = {
        "list": [{"name": DOMAIN}]
    }
    _register_response(adapter, "POST", "/api/login", response_headers={"Authentication": FAKE_TOKEN})
    _register_response(adapter, "GET", f"/api/v1/{FAKE_ORG}/qip-search.json?name={FAKE_RECORD}&searchType=All&subRange=TXT", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_response, status_code=search_status_code)
    _register_response(adapter, "PUT", f"/api/v1/{FAKE_ORG}/rr", request_headers={"Authentication": f'Token {FAKE_TOKEN}'})
    _register_response(adapter,"GET", f"/api/v1/{FAKE_ORG}/zone.json?name={DOMAIN}", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_zone_response)
    _register_response(adapter, "POST", f"/api/v1/{FAKE_ORG}/rr", request_headers={"Authentication": f'Token {FAKE_TOKEN}'})
    client.add_txt_record(DOMAIN, FAKE_RECORD, FAKE_RECORD_CONTENT, FAKE_RECORD_TTL)
    for i, call in enumerate(calls):
        assert adapter.request_history[i].path == call
    assert adapter.call_count == call_count

def test_del_txt_record(adapter, client):
    _register_response(adapter, "POST", "/api/login", response_headers={"Authentication": FAKE_TOKEN})
    search_txt_response = {
        "list": [{
            "name": DOMAIN,
            "type": "DOMAIN",
            "rr": {
                "name": FAKE_RECORD,
                "recordType": "TXT",
                "data": FAKE_RECORD_CONTENT
            }
        }]
    }
    _register_response(adapter, "GET", f"/api/v1/{FAKE_ORG}/qip-search.json?name={FAKE_RECORD}&searchType=All&subRange=TXT", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_txt_response)
    search_zone_response = {
        "list": [{
            "name": DOMAIN,
            "defaultTtl": 3600,
            "email": "hostmaster@foo.bar",
            "expireTime": 604800,
            "negativeCacheTtl": 600,
            "refreshTime": 21600,
            "retryTime": 3600
        }]
    }
    _register_response(adapter,"GET", f"/api/v1/{FAKE_ORG}/zone.json?name={DOMAIN}", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_zone_response)
    _register_response(adapter,"DELETE", f"/api/v1/{FAKE_ORG}/rr/singleDelete?infraFQDN={DOMAIN}&infraType=ZONE&owner={FAKE_RECORD}", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, status_code=204)
    client.del_txt_record(DOMAIN, FAKE_RECORD, FAKE_RECORD_CONTENT, FAKE_RECORD_TTL)
    assert(adapter.call_count) == 4

def test_login_already_authenticated(client, adapter):
    client.session.headers.update({'Authentication': f"Token {FAKE_TOKEN}"})
    assert adapter.called == False

@pytest.mark.parametrize("response_headers, expectation", [
    ({"Authentication": FAKE_TOKEN}, does_not_raise()),
    ({}, pytest.raises(errors.PluginError))
], ids=[
    "Happy 200 response with token in response headers",
    "Not so happy 200 response without token in response headers"
])
def test_login_authentication(client, adapter, response_headers, expectation):
    _register_response(adapter, "POST", "/api/login", response_headers=response_headers)
    with expectation:
        client._login()
        assert adapter.called == True
        assert adapter.request_history[0].body == json.dumps({"username": FAKE_USER, "password": FAKE_PW}).encode('utf-8')
        assert client.session.headers["Authentication"] == f"Token {FAKE_TOKEN}"

@pytest.mark.parametrize("method, path, query, request_data, response_body, request_headers, response_headers, response_json, status_code, expectation", [
    ("GET", "/foo", "baz=bar", None, None, {}, {"foo": "bar"}, None, 200, does_not_raise()),
    ("POST", "/login", "", None, None, {}, {}, None, 200, does_not_raise()),
    ("GET", "/foo/bar", "", None, None, {}, {}, None, 500, pytest.raises(errors.PluginError)),
    ("GET", "/foo/bar", "", None, "Non JSON response", {}, {}, None, 200, pytest.raises(errors.PluginError))
], ids=[
    "Happy 200 response for GET",
    "Happy 200 response for POST",
    "UnHappy 500 response for POST - raises an exception",
    "Sort of happy 200 response for GET with non JSON body - raises an exception as it can't unmarshal response"
])
def test_api_request(adapter, client, method, path, query, request_data, response_body, request_headers, response_headers, response_json, status_code, expectation):
    _register_response(adapter, method, f"{path}?{query}", response=response_body, request_headers=request_headers, response_headers=response_headers, json=response_json, status_code=status_code)
    with expectation as e:
        resp = client._api_request(method, path, data=request_data, query=query)
        assert adapter.request_history[0].method == method
        assert adapter.request_history[0].path == path
        assert adapter.request_history[0].query == query
        assert adapter.request_history[0].body == request_data
        assert adapter.request_history[0].headers["Content-Type"] == "application/json"
        assert adapter.request_history[0].headers["accept"] == "application/json"
        for key, value in request_headers.items():
            assert adapter.request_history[0].headers[key] == value
        if response_body is not None:
            assert resp == response_body
        if response_json is not None:
            assert resp == json.dumps(response_json)

@pytest.mark.parametrize("record_types, status_code, expected_response", [
    (["TXT"], 200, "TXT"),
    (["CNAME", "TXT"], 200, "TXT"),
    ({"error": f"Cannot find All where name = {FAKE_RECORD}"}, 404, None)
], ids=[
    "happy 200 response, returning a single record",
    "happy 200 response, multiple records returned",
    "unhappy 404 response, no records  matching record name"
])
def test_get_existing_txt(adapter, client, record_types, status_code, expected_response):
    client.session.headers.update({"Authentication": f"Token {FAKE_TOKEN}"})
    search_txt_response = {
        "list": []
    }
    for r_type in record_types:
        search_txt_response["list"].append(record(r_type))

    _register_response(adapter, "GET", f"/api/v1/{FAKE_ORG}/qip-search.json?name={FAKE_RECORD}&searchType=All&subRange=TXT", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_txt_response, status_code=status_code)
    rec = client.get_existing_txt(FAKE_RECORD)
    assert rec == record(expected_response)

def test_update_txt_record(adapter, client):
    _register_response(adapter, "PUT", f"/api/v1/{FAKE_ORG}/rr")
    client.session.headers.update({"Authentication": f"Token {FAKE_TOKEN}"})
    client._update_txt_record(record("TXT"), FAKE_RECORD_CONTENT, FAKE_RECORD_TTL)
    assert adapter.called == True
    assert json.loads(adapter.request_history[0].body)["updatedRRRec"]["data1"] == FAKE_RECORD_CONTENT
    assert json.loads(adapter.request_history[0].body)["updatedRRRec"]["ttl"] == FAKE_RECORD_TTL

@pytest.mark.parametrize("qip_response, status_code, expectation", [
    ({"name": DOMAIN}, 200, does_not_raise()),
    ({"error": f"DNS Zone not found: [{DOMAIN}]"}, 404, pytest.raises(errors.PluginError)),
    ({"foo": "bar"}, 200, pytest.raises(errors.PluginError)),
    ({"list": [{"foo": "bar"}]}, 200, pytest.raises(errors.PluginError))
    ], ids=[
        "200 response, zone found",
        "404 response, no zone found with that name",
        "200 response, bad QIP response without list key",
        "200 response, bad QIP response without name key"
    ]
)
def test_find_managed_zone(adapter, client, qip_response, status_code, expectation):
    search_zone_response = {
        "list": [qip_response]
    }
    _register_response(adapter,"GET", f"/api/v1/{FAKE_ORG}/zone.json?name={DOMAIN}", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_zone_response, status_code=status_code)
    client.session.headers.update({"Authentication": f"Token {FAKE_TOKEN}"})
    with expectation:
        zone_name = client._find_managed_zone(DOMAIN)
        assert zone_name == DOMAIN

def test_insert_txt_record(adapter, client):
    search_zone_response = {
        "list": [{"name": DOMAIN}]
    }
    _register_response(adapter,"GET", f"/api/v1/{FAKE_ORG}/zone.json?name={DOMAIN}", request_headers={"Authentication": f'Token {FAKE_TOKEN}'}, json=search_zone_response)
    _register_response(adapter, "POST", f"/api/v1/{FAKE_ORG}/rr", request_headers={"Authentication": f'Token {FAKE_TOKEN}'})
    client.session.headers.update({"Authentication": f"Token {FAKE_TOKEN}"})
    client._insert_txt_record(FAKE_RECORD, FAKE_RECORD_CONTENT, FAKE_RECORD_TTL, DOMAIN)
    received_body = json.loads(adapter.request_history[1].body)
    assert received_body["owner"] == FAKE_RECORD
    assert received_body["data1"] == FAKE_RECORD_CONTENT
    assert received_body["ttl"] == FAKE_RECORD_TTL
    assert received_body["infraFQDN"] == DOMAIN
