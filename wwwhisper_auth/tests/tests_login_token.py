# wwwhisper - web access control.
# Copyright (C) 2016-2023 Jan Wrobel <jan@mixedbit.org>

# pylint: disable=missing-module-docstring

from django.test import TestCase
from wwwhisper_auth.login_token import generate_login_token
from wwwhisper_auth.login_token import generate_login_url
from wwwhisper_auth.login_token import load_login_token
from wwwhisper_auth.models import SitesCollection

class LoginTokenTest(TestCase):

    def setUp(self):
        self.sites = SitesCollection()
        # For each test case, test site must exist, so it can be set
        # by SetSiteMiddleware
        self.site = self.sites.create_item('FirstSite')
        self.site_other = self.sites.create_item('SecondSite')

    def test_load_valid_token(self):
        token = generate_login_token(self.site, 'alice@example.org')
        email = load_login_token(self.site, token)
        self.assertEqual('alice@example.org', email)

    def test_load_invalid_token(self):
        token = generate_login_token(self.site, 'alice@example.org')
        self.assertIsNone(load_login_token(self.site, token + 'x'))

    def test_load_valid_token_for_different_site(self):
        token = generate_login_token(self.site, 'alice@example.org')
        self.assertIsNone(load_login_token(self.site_other, token))

    def test_generate_login_url(self):
        url = generate_login_url(self.site,
                                 'alice@example.org',
                                 root_url='https://example.com',
                                 next_path='/foo/bar')
        encoded_path = 'next=%2Ffoo%2Fbar'
        regexp = ('https://example.com/wwwhisper/auth/login#' + encoded_path +
                  '&token=.{100,}')
        self.assertRegex(url, regexp)
