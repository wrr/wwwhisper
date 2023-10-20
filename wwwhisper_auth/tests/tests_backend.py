# wwwhisper - web access control.
# Copyright (C) 2016-2023 Jan Wrobel <jan@mixedbit.org>

from django.http import HttpRequest
from django.test import TestCase

from wwwhisper_auth.backend import AuthenticationError, VerifiedEmailBackend
from wwwhisper_auth.login_token import generate_login_token
from wwwhisper_auth.models import SitesCollection

TEST_USER_EMAIL = 'foo@example.com'

class VerifiedEmailBackendTest(TestCase):

    def setUp(self):
        self.sites = SitesCollection()
        self.site = self.sites.create_item('SomeSite')
        self.backend = VerifiedEmailBackend()

    def user_token(self):
        return generate_login_token(self.site, TEST_USER_EMAIL)

    def test_token_valid(self):
        user = self.site.users.create_item(TEST_USER_EMAIL)
        auth_user = self.backend.authenticate(
            HttpRequest(), self.site, self.user_token())
        self.assertEqual(user, auth_user)

    def test_token_invalid(self):
        _user = self.site.users.create_item(TEST_USER_EMAIL)
        self.assertRaisesRegex(AuthenticationError,
                               'Token invalid or expired',
                               self.backend.authenticate,
                               HttpRequest(),
                               self.site,
                               self.user_token() + 'x')

    def test_token_for_different_site(self):
        other_site = self.sites.create_item('OtherSite')
        other_site.users.create_item(TEST_USER_EMAIL)
        self.site.users.create_item(TEST_USER_EMAIL)
        token = generate_login_token(other_site, TEST_USER_EMAIL)
        self.assertRaisesRegex(AuthenticationError,
                               'Token invalid or expired',
                               self.backend.authenticate,
                               HttpRequest(),
                               self.site,
                               token)

    def test_no_such_user(self):
        self.assertRaisesRegex(AuthenticationError,
                               'Token invalid or expired',
                               self.backend.authenticate,
                               HttpRequest(),
                               self.site,
                               self.user_token())
