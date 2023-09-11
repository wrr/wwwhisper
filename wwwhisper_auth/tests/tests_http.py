# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

from django.conf import settings
from django.conf.urls import url
from django.http import HttpResponse
from django.test import TestCase, override_settings
from django.test.client import Client
from wwwhisper_auth.http import accepts_html
from wwwhisper_auth.http import RestView
from wwwhisper_auth.http import HttpResponseNotAuthenticated
from wwwhisper_auth.tests.utils import HttpTestCase
from wwwhisper_auth.tests.utils import TEST_SITE

class TestView(RestView):
    def get(self, request):
        return HttpResponse(status=267)

    def post(self, request, ping_message):
        return HttpResponse(ping_message, status=277)

class TestView2(RestView):
    def get(self, request, url_arg):
        return HttpResponse(url_arg, status=288)

    def post(self, request, url_arg):
        return HttpResponse(url_arg, status=298)

urlpatterns = [
    url(r'^testview/$', TestView.as_view()),
    url(r'^testview2/(?P<url_arg>[a-z]+)/$', TestView2.as_view())]

@override_settings(ROOT_URLCONF='wwwhisper_auth.tests.tests_http')
class RestViewTest(HttpTestCase):

    def test_method_dispatched(self):
        response = self.get('/testview/')
        self.assertEqual(267, response.status_code)

    def test_method_with_json_argument_in_body_dispatched(self):
        response = self.post('/testview/', {'ping_message' : 'hello world'})
        self.assertEqual(277, response.status_code)
        self.assertEqual(response.content, b'hello world')

    def test_method_with_missing_json_argument_in_body_dispatched(self):
        response = self.post('/testview/', {})
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content, b'Invalid request arguments')

    def test_method_with_incorrect_json_argument_in_body(self):
        response = self.post('/testview/', {'pong_message' : 'hello world'})
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content, b'Invalid request arguments')

    def test_method_with_incorrectly_formated_json_argument_in_body(self):
        response = self.client.post('/testview/',
                                    "{{ 'ping_message' : 'hello world' }",
                                    'application/json ;  charset=UTF-8',
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                                    HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content,
                         b'Failed to parse the request body as a json object.')

    def test_incorrect_method(self):
        response = self.delete('/testview/')
        self.assertEqual(405, response.status_code)
        # 'The response MUST include an Allow header containing a list
        # of valid methods for the requested resource.' (rfc2616)
        self.assertCountEqual(['GET', 'POST', 'HEAD', 'OPTIONS'],
                              response['Allow'].split(', '))

    def test_method_with_argument_in_url_dispatched(self):
        response = self.get('/testview2/helloworld/')
        self.assertEqual(288, response.status_code)
        self.assertEqual(b'helloworld', response.content)


    def test_argument_in_body_cannot_overwrite_argument_in_url(self):
        response = self.post('/testview2/helloworld/',
                             {'url_arg': 'hello-world'})
        self.assertEqual(400, response.status_code)
        self.assertEqual(
            response.content, b'Invalid argument passed in the request body.')

    def test_content_type_validation(self):
        response = self.client.post(
            '/testview/', '{"ping_message" : "hello world"}', 'text/json',
            HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(400, response.status_code)
        self.assertRegex(response.content, b'Invalid Content-Type')

        response = self.client.post(
            '/testview/', '{"ping_message" : "hello world"}',
            'application/json; charset=UTF-16',
            HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(400, response.status_code)
        self.assertRegex(response.content, b'Invalid Content-Type')

        # Content-Type header should be case-insensitive.
        response = self.client.post(
            '/testview/', '{"ping_message" : "hello world"}',
            'application/JSON; charset=UTF-8',
            HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(277, response.status_code)

    def test_csrf_protection(self):
        self.client = Client(enforce_csrf_checks=True)

        # No CSRF tokens.
        response = self.client.get('/testview/', HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content, b'CSRF token missing or incorrect.')

        # Too short CSRF tokens.
        self.client.cookies[settings.CSRF_COOKIE_NAME] = 'a'
        response = self.client.get('/testview/', HTTP_X_CSRFTOKEN='a',
                                   HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content, b'CSRF token missing or incorrect.')

        # Not matching CSRF tokens.
        self.client.cookies[settings.CSRF_COOKIE_NAME] = \
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
        response = self.client.get(
            '/testview/', HTTP_X_CSRFTOKEN='xxxxxxxxxxxxxxxOxxxxxxxxxxxxxxxx',
            HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(400, response.status_code)
        self.assertEqual(response.content, b'CSRF token missing or incorrect.')

        # Matching CSRF tokens.
        self.client.cookies[settings.CSRF_COOKIE_NAME] = 64*'x'
        response = self.client.get(
            '/testview/', HTTP_X_CSRFTOKEN=64*'x',
            HTTP_SITE_URL=TEST_SITE)
        self.assertEqual(267, response.status_code)

    def test_caching_disabled_for_rest_view_results(self):
        response = self.get('/testview/')
        self.assertTrue(response.has_header('Cache-Control'))
        control = response['Cache-Control']
        # index throws ValueError if not found.
        control.index('no-cache')
        control.index('no-store')
        control.index('must-revalidate')
        control.index('max-age=0')


class AcceptHeaderUtilsTest(TestCase):
    def test_accepts_html(self):
        self.assertTrue(accepts_html('text/html'))
        self.assertTrue(accepts_html('text/*'))
        self.assertTrue(accepts_html('*/*'))
        self.assertTrue(accepts_html('audio/*, text/plain, text/*'))
        self.assertTrue(accepts_html(
                'text/*;q=0.3, text/html;q=0.7, text/html;level=1, ' +
                'text/html;level=2;q=0.4, */*;q=0.5'))

        self.assertFalse(accepts_html('text/plain'))
        self.assertFalse(accepts_html('audio/*'))
        self.assertFalse(accepts_html('text/x-dvi; q=0.8, text/x-c'))
        self.assertFalse(accepts_html(None))

class HttpResponseTest(TestCase):

    def test_not_authenticated_response_deletes_logged_in_cookie(self):
        response = HttpResponseNotAuthenticated()
        logged_in_cookie = response.cookies[settings.LOGGED_IN_COOKIE_NAME]
        self.assertEqual('', logged_in_cookie.value)
        self.assertEqual('Strict', logged_in_cookie['samesite'])
        self.assertEqual('/', logged_in_cookie['path'])
        self.assertEqual(0, logged_in_cookie['max-age'])
