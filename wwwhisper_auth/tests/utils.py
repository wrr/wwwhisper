# wwwhisper - web access control.
# Copyright (C) 2012-2023 Jan Wrobel <jan@mixedbit.org>

"""Utilities to simplify testing."""

from django.test import TestCase
from django.test.client import Client
from wwwhisper_auth.models import SitesCollection
from wwwhisper_auth.models import SINGLE_SITE_ID


TEST_SITE = 'https://foo.example.org:8080'

class HttpTestCase(TestCase):
    """A base class for test cases that make HTTP requests."""

    def setUp(self):
        self.client = Client()
        self.sites = SitesCollection()
        # For each test case, test site must exist, so it can be set
        # by SetSiteMiddleware
        self.site = self.sites.create_item(SINGLE_SITE_ID)
        self.site.aliases.create_item(TEST_SITE)

    def post(self, url, args):
        return self.client.post(
            url, args, 'application/json; charset=UTF-8',
            HTTP_SITE_URL=TEST_SITE)

    """ To be used for views that are not contacted via Ajax. """
    def post_form(self, url, args):
        return self.client.post(url, args)

    def get(self, url, **extra_headers):
        return self.client.get(url, HTTP_SITE_URL=TEST_SITE, **extra_headers)

    def put(self, url, args=None):
        if args is None:
            return self.client.put(url, HTTP_SITE_URL=TEST_SITE)
        return self.client.put(
            url, data=args,
            content_type='application/json;  charset=UTF-8',
            HTTP_SITE_URL=TEST_SITE)


    def delete(self, url):
        return self.client.delete(url, HTTP_SITE_URL=TEST_SITE)
