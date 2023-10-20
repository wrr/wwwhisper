# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

from django.http import HttpRequest, HttpResponse
from django.test import TestCase
from django.test.client import RequestFactory

from wwwhisper_auth import http
from wwwhisper_auth.middleware import SecuringHeadersMiddleware
from wwwhisper_auth.middleware import ProtectCookiesMiddleware
from wwwhisper_auth.middleware import SetSiteMiddleware
from wwwhisper_auth.middleware import SiteUrlMiddleware
from wwwhisper_auth.models import SitesCollection
from wwwhisper_auth.models import SINGLE_SITE_ID

def get_response(_request):
    return HttpResponse()

class SetSiteMiddlewareTest(TestCase):
    def test_site_set_if_exists(self):
        site = SitesCollection().create_item(SINGLE_SITE_ID)
        middleware = SetSiteMiddleware(get_response)
        r = HttpRequest()
        self.assertEqual(200, middleware(r).status_code)
        self.assertEqual(SINGLE_SITE_ID, r.site.site_id)

    def test_site_not_set_if_missing(self):
        middleware = SetSiteMiddleware(get_response)
        r = HttpRequest()
        self.assertEqual(200, middleware(r).status_code)
        self.assertIsNone(r.site)

class SiteUrlMiddlewareTest(TestCase):
    def setUp(self):
        self.middleware = SiteUrlMiddleware(get_response)
        self.factory = RequestFactory()
        sites_collection = SitesCollection()
        self.site_url = 'https://foo.example.com'
        self.site = sites_collection.create_item(SINGLE_SITE_ID)
        self.site.aliases.create_item(self.site_url)

    def get(self, site_url, path=''):
        request = self.factory.get(path)
        request.site = self.site
        request.META['HTTP_SITE_URL'] = site_url
        return request

    def test_allowed_site_url_https(self):
        request = self.get(self.site_url)
        response = self.middleware(request)
        self.assertEqual(200, response.status_code)
        self.assertEqual(self.site_url, request.site_url)
        self.assertEqual('foo.example.com', request.get_host())
        self.assertTrue(request.https)
        self.assertTrue(request.is_secure())

    def test_allowed_site_url_http(self):
        url = 'http://bar.example.com'
        self.site.aliases.create_item(url)
        request = self.get(url)
        response = self.middleware(request)
        self.assertEqual(200, response.status_code)
        self.assertEqual(url, request.site_url)
        self.assertEqual('bar.example.com', request.get_host())
        self.assertFalse(request.https)
        self.assertFalse(request.is_secure())

    def test_allowed_site_url_with_port(self):
        url = 'http://bar.example.com:123'
        self.site.aliases.create_item(url)
        request = self.get(url);
        response = self.middleware(request)
        self.assertEqual(200, response.status_code)
        self.assertEqual(url, request.site_url)
        self.assertEqual('bar.example.com:123', request.get_host())
        self.assertFalse(request.https)
        self.assertFalse(request.is_secure())

    def test_not_allowed_site_url(self):
        request = self.get('https://bar.example.com')
        response = self.middleware(request)
        self.assertIsNotNone(response)
        self.assertEqual(400, response.status_code)
        self.assertRegex(response.content, b'Invalid request URL')

    def test_not_allowed_site_url2(self):
        request = self.get('https://foo.example.com:80')
        response = self.middleware(request)
        self.assertIsNotNone(response)
        self.assertEqual(400, response.status_code)
        self.assertRegex(response.content, b'Invalid request URL')

    def test_missing_site_url(self):
        request = self.get(None)
        response = self.middleware(request)
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content, b'Missing Site-Url header')

    def test_invalid_site_url(self):
        request = self.get('foo.example.org')
        response = self.middleware(request)
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content, b'Site-Url has incorrect format')

    def test_allowed_site_with_explicit_port(self):
        # Request with correct explicit port should be accepted, port
        # should be removed.
        request = self.get(self.site_url + ':443')
        response = self.middleware(request)
        self.assertEqual(200, response.status_code)
        self.assertEqual(self.site_url, request.site_url)
        self.assertEqual('foo.example.com', request.get_host())
        self.assertTrue(request.https)
        self.assertTrue(request.is_secure())

    def test_not_allowed_http_site_redirects_to_https_if_exists(self):
        request = self.get('http://foo.example.com', '/')
        response = self.middleware(request)
        self.assertIsNotNone(response)
        self.assertEqual(302, response.status_code)
        self.assertEqual('https://foo.example.com/', response['Location'])

    def test_not_allowed_http_site_redirects_to_https_if_exists2(self):
        request = self.get('http://foo.example.com', '/bar?baz=true')
        response = self.middleware(request)
        self.assertIsNotNone(response)
        self.assertEqual(302, response.status_code)
        self.assertEqual('https://foo.example.com/bar?baz=true',
                         response['Location'])

    def test_https_redirects_for_auth_request(self):
        request = self.get(
            'http://foo.example.com',
            '/wwwhisper/auth/api/is-authorized/?path=/foo/bar/baz')
        response = self.middleware(request)
        self.assertIsNotNone(response)
        self.assertEqual(302, response.status_code)
        self.assertEqual('https://foo.example.com/foo/bar/baz',
                         response['Location'])

    def test_https_redirects_for_auth_request2(self):
        request = self.get(
            'http://foo.example.com',
            '/wwwhisper/auth/api/is-authorized/?path=/foo/bar/baz?x=y&z=1')
        response = self.middleware(request)
        self.assertIsNotNone(response)
        self.assertEqual(302, response.status_code)
        self.assertEqual('https://foo.example.com/foo/bar/baz?x=y&z=1',
                         response['Location'])

def get_response_with_cookie(_request):
    response = http.HttpResponseNoContent()
    response.set_cookie('session', value='foo', secure=None)
    return response

class ProtectCookiesMiddlewareTest(TestCase):

    def test_secure_flag_set_for_https_request(self):
        middleware = ProtectCookiesMiddleware(get_response_with_cookie)
        request = HttpRequest()
        request.https = True

        response = middleware(request)
        self.assertTrue(response.cookies['session']['secure'])

    def test_secure_flag_not_set_for_http_request(self):
        middleware = ProtectCookiesMiddleware(get_response_with_cookie)
        request = HttpRequest()
        request.https = False

        response = middleware(request)
        self.assertFalse(response.cookies['session']['secure'])


class SecuringHeadersMiddlewareTest(TestCase):

    def test_different_origin_framing_not_allowed(self):
        middleware = SecuringHeadersMiddleware(get_response)
        response = middleware(HttpRequest())
        self.assertEqual('SAMEORIGIN', response['X-Frame-Options'])
        self.assertEqual('nosniff', response['X-Content-Type-Options'])
