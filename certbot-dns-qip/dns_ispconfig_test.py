"""Tests for certbot_dns_qip.dns_qip."""

import unittest

import unittest.mock
import json
import requests_mock

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

FAKE_USER = "remoteuser"
FAKE_PW = "password"
FAKE_ENDPOINT = "mock://endpoint"

def test_foo():
    pass

# class AuthenticatorTest(
#     test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
# ):
#     def setUp(self):
#         pass
if __name__ == "__main__":
    unittest.main()  # pragma: no cover
