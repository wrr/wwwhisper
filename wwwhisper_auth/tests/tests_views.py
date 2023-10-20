# wwwhisper - web access control.
# Copyright (C) 2012-2023 Jan Wrobel <jan@mixedbit.org>

import json
import urllib.parse

from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend
from django.core import mail
from django.test import override_settings

from wwwhisper_auth.login_token import generate_login_token
from wwwhisper_auth.tests.utils import HttpTestCase
from wwwhisper_auth.tests.utils import TEST_SITE

class FailingEmailBackend(BaseEmailBackend):
    def send_messages(self, _messages):
        return 0

class RaisingEmailBackend(BaseEmailBackend):
    def send_messages(self, messages):
        raise Exception('Send failed')

class AuthTestCase(HttpTestCase):
    def setUp(self):
       settings.EMAIL_BACKEND = \
            'django.core.mail.backends.locmem.EmailBackend'
       settings.TOKEN_EMAIL_FROM = 'verify@wwwhisper.io'
       super().setUp()

    def tearDown(self):
        if mail.outbox:
           mail.outbox = []

    def login(self, email, site=None):
        if site is None:
            site = self.site
        token = generate_login_token(site, email)
        self.assertTrue(self.client.login(site=site, token=token))
        # Login needs to set user_id in session.
        user = site.users.find_item_by_email(email)
        self.assertIsNotNone(user)
        # Session must be stored in a temporary variable, otherwise
        # updating does not work.
        s = self.client.session
        s['user_id'] = user.id
        s.save()

class AuthTest(AuthTestCase):
    def test_is_authorized_requires_path_parameter(self):
        response = self.get('/wwwhisper/auth/api/is-authorized/?pat=/foo')
        self.assertEqual(400, response.status_code)

    def test_is_authorized_if_not_authenticated(self):
        _location = self.site.locations.create_item('/foo/')
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/')
        self.assertEqual(401, response.status_code)
        self.assertTrue(response.has_header('WWW-Authenticate'))
        self.assertFalse(response.has_header('User'))
        self.assertEqual('VerifiedEmail', response['WWW-Authenticate'])
        self.assertEqual(response['Content-Type'], "text/plain; charset=utf-8")
        self.assertEqual(b'Authentication required.', response.content)

    def test_is_authorized_if_not_authorized(self):
        self.site.users.create_item('foo@example.com')
        self.login('foo@example.com')
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/')
        # For an authenticated user 'User' header should be always returned.
        self.assertEqual(403, response.status_code)
        self.assertEqual('foo@example.com', response['User'])
        self.assertEqual(response['Content-Type'], "text/plain; charset=utf-8")
        self.assertEqual(b'User not authorized.', response.content)

    def test_is_authorized_if_authorized(self):
        user = self.site.users.create_item('foo@example.com')
        location = self.site.locations.create_item('/foo/')
        location.grant_access(user.uuid)
        self.login('foo@example.com')
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/')
        self.assertEqual(200, response.status_code)
        self.assertEqual('0', response['Content-Length'])
        self.assertEqual('foo@example.com', response['User'])

    def test_is_authorized_if_user_of_other_site(self):
        site2 = self.sites.create_item('somesite')
        _user = site2.users.create_item('foo@example.com')
        _location = self.site.locations.create_item('/foo/')
        self.login('foo@example.com', site2)
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/')
        self.assertEqual(401, response.status_code)

    def test_is_authorized_if_open_location(self):
        location = self.site.locations.create_item('/foo/')
        location.grant_open_access()
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/')
        self.assertFalse(response.has_header('User'))
        self.assertEqual(200, response.status_code)
        self.assertEqual('0', response['Content-Length'])

    def test_is_authorized_if_open_location_and_authenticated(self):
        _user = self.site.users.create_item('foo@example.com')
        self.login('foo@example.com')
        location = self.site.locations.create_item('/foo/')
        location.grant_open_access()
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/')
        self.assertEqual(200, response.status_code)
        self.assertEqual('foo@example.com', response['User'])

    def test_is_authorized_if_invalid_path(self):
        user = self.site.users.create_item('foo@example.com')
        location = self.site.locations.create_item('/foo/')
        location.grant_access(user.uuid)
        self.login('foo@example.com')

        response = self.get(
            '/wwwhisper/auth/api/is-authorized/?path=/bar/../foo/')
        self.assertEqual(400, response.status_code)
        self.assertRegex(response.content,
                         b'Path should be absolute and normalized')

        response = self.get('/wwwhisper/auth/api/is-authorized/?path=.')
        self.assertEqual(400, response.status_code)
        self.assertRegex(response.content,
                         b'Path should be absolute and normalized')

    def test_is_authorized_decodes_path(self):
        location = self.site.locations.create_item('/f/')
        location.grant_open_access()
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=%2F%66%2F')
        self.assertEqual(200, response.status_code)

        response = self.get('/wwwhisper/auth/api/is-authorized/?path=%2F%66')
        self.assertEqual(401, response.status_code)

    def test_is_authorized_collapses_slashes(self):
        location = self.site.locations.create_item('/f/')
        location.grant_open_access()
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=///f/')
        self.assertEqual(200, response.status_code)

    def test_is_authorized_does_not_allow_requests_with_user_header(self):
        user = self.site.users.create_item('foo@example.com')
        location = self.site.locations.create_item('/foo/')
        location.grant_access(user.uuid)
        self.login('foo@example.com')
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/',
                            HTTP_USER='bar@example.com')
        self.assertEqual(400, response.status_code)

    def test_caching_disabled_for_auth_request_results(self):
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/')
        self.assertTrue(response.has_header('Cache-Control'))
        control = response['Cache-Control']
        # index throws ValueError if not found.
        control.index('no-cache')
        control.index('no-store')
        control.index('must-revalidate')
        control.index('max-age=0')

    # Make sure HTML responses are returned when request accepts HTML.

    def test_is_authorized_if_not_authenticated_html_response(self):
        _location = self.site.locations.create_item('/foo/')
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/',
                            HTTP_ACCEPT='text/plain, text/html')
        self.assertEqual(401, response.status_code)
        self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')
        self.assertRegex(response.content, b'<body')

        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/',
                            HTTP_ACCEPT='text/plain')
        self.assertEqual(401, response.status_code)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')

    def test_is_authorized_if_not_authenticated_custom_html_response(self):
        self.site.update_skin(
            title='Foo', header='Bar', message='Baz', branding=False)
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/',
                            HTTP_ACCEPT='*/*')
        self.assertEqual(401, response.status_code)
        self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')
        self.assertRegex(response.content, b'<title>Foo</title>')
        self.assertRegex(response.content, b'<h1>Bar</h1>')
        self.assertRegex(response.content, b'class="lead">Baz')

    def test_is_authorized_if_not_authorized_html_response(self):
        self.site.users.create_item('foo@example.com')
        self.login('foo@example.com')
        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/',
                            HTTP_ACCEPT='*/*')
        self.assertEqual(403, response.status_code)
        self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')
        self.assertRegex(response.content, b'<body')

        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/foo/',
                            HTTP_ACCEPT='text/plain, audio/*')
        self.assertEqual(403, response.status_code)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')

class LogoutTest(AuthTestCase):
    def test_authentication_requested_after_logout(self):
        _user = self.site.users.create_item('foo@example.com')
        self.login('foo@example.com')

        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/bar/')
        # Not authorized
        self.assertEqual(403, response.status_code)

        response = self.post('/wwwhisper/auth/api/logout/', {})
        self.assertEqual(204, response.status_code)

        # Should delete the 'logged-in' cookie
        logged_in_cookie = response.cookies[settings.LOGGED_IN_COOKIE_NAME]
        self.assertEqual('', logged_in_cookie.value)


        response = self.get('/wwwhisper/auth/api/is-authorized/?path=/bar/')
        # Not authenticated
        self.assertEqual(401, response.status_code)
        # Also each 401 response should delete the 'logged-in' cookie
        logged_in_cookie = response.cookies[settings.LOGGED_IN_COOKIE_NAME]
        self.assertEqual('', logged_in_cookie.value)


class WhoAmITest(AuthTestCase):
    def test_whoami_returns_email_of_logged_in_user(self):
        self.site.users.create_item('foo@example.com')

        # Not authorized.
        response = self.get('/wwwhisper/auth/api/whoami/')
        self.assertEqual(401, response.status_code)

        self.login('foo@example.com')
        response = self.get('/wwwhisper/auth/api/whoami/')
        self.assertEqual(200, response.status_code)
        parsed_response_body = json.loads(response.content)
        self.assertEqual('foo@example.com', parsed_response_body['email'])

        logged_in_cookie = response.cookies[settings.LOGGED_IN_COOKIE_NAME]
        self.assertEqual('y', logged_in_cookie.value)
        self.assertTrue(logged_in_cookie['secure'])
        self.assertEqual('Strict', logged_in_cookie['samesite'])
        self.assertEqual('/', logged_in_cookie['path'])
        self.assertFalse(logged_in_cookie['httponly'])
        self.assertEqual(settings.LOGGED_IN_COOKIE_AGE,
                         logged_in_cookie['max-age'])

    def test_whoami_for_user_of_differen_site(self):
        other_site = self.sites.create_item('othersite')
        other_site.users.create_item('foo@example.com')
        self.login('foo@example.com', other_site)
        # Not authorized.
        # Request is run for self.site, but user belongs to other_site.
        response = self.get('/wwwhisper/auth/api/whoami/')
        self.assertEqual(401, response.status_code)

        # Should delete the 'logged-in' cookie.
        logged_in_cookie = response.cookies[settings.LOGGED_IN_COOKIE_NAME]
        self.assertEqual('', logged_in_cookie.value)

class CsrfTokenTest(AuthTestCase):

    def test_token_returned_in_cookie(self):
        response = self.get('/wwwhisper/auth/api/csrftoken/')
        self.assertEqual(204, response.status_code)
        self.assertTrue(
            len(response.cookies[settings.CSRF_COOKIE_NAME].coded_value) > 20)

    # Ensures that ProtectCookiesMiddleware is applied.
    def test_csrf_cookie_http_only(self):
        response = self.get('/wwwhisper/auth/api/csrftoken/')
        self.assertTrue(response.cookies[settings.CSRF_COOKIE_NAME]['secure'])

class SendTokenTest(AuthTestCase):
    def test_email_sent(self):
        self.site.users.create_item('alice@example.org')
        response = self.post('/wwwhisper/auth/api/send-token/',
                             {'email': 'alice@example.org', 'path': '/foo/bar'})
        self.assertEqual(204, response.status_code)
        self.assertEqual(1, len(mail.outbox))
        msg = mail.outbox[0]
        self.assertEqual(f'{TEST_SITE} access token', msg.subject)
        self.assertEqual(1, len(msg.to))
        self.assertEqual('verify@wwwhisper.io', msg.from_email)
        self.assertEqual('alice@example.org', msg.to[0])
        path = urllib.parse.urlencode({'next': '/foo/bar'})
        regexp = (TEST_SITE + '/wwwhisper/auth/login#' + path +
                  '&token=.{100,}\n')
        self.assertRegex(msg.body, regexp)

    def test_email_not_sent_for_unknown_user(self):
        response = self.post('/wwwhisper/auth/api/send-token/',
                             {'email': 'alice@example.org', 'path': '/foo/bar'})
        self.assertEqual(204, response.status_code)
        self.assertEqual(0, len(mail.outbox))

    def test_email_address_is_none(self):
        response = self.post('/wwwhisper/auth/api/send-token/',
                             {'email': None, 'path': '/'})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Email not set.', response.content)

    def test_email_has_invalid_format(self):
        response = self.post('/wwwhisper/auth/api/send-token/',
                             {'email': 'alice', 'path': '/'})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Email has invalid format.', response.content)

    def test_tricky_redirection_replaced(self):
        self.site.users.create_item('alice@example.org')
        response = self.post('/wwwhisper/auth/api/send-token/',
                             {'email': 'alice@example.org', 'path': '/foo/../'})
        self.assertEqual(204, response.status_code)
        msg = mail.outbox[0]
        # Login ignores '/foo/../' and redirects to '/'.
        path = urllib.parse.urlencode({'next': '/'})
        regexp = (TEST_SITE + '/wwwhisper/auth/login#' + path +
                  '&token=.{100,}\n')
        self.assertRegex(msg.body, regexp)

    @override_settings(
        EMAIL_BACKEND='wwwhisper_auth.tests.tests_views.FailingEmailBackend')
    def test_send_token_fails(self):
        self.site.users.create_item('alice@example.org')
        response = self.post('/wwwhisper/auth/api/send-token/',
                             {'email': 'alice@example.org', 'path': '/'})
        self.assertEqual(500, response.status_code)
        self.assertEqual(
            b'Email delivery problem. ' +
            b'Check the entered address or try again in a few minutes.',
            response.content)

    @override_settings(
        EMAIL_BACKEND='wwwhisper_auth.tests.tests_views.RaisingEmailBackend')
    def test_send_token_fails2(self):
        self.site.users.create_item('alice@example.org')
        response = self.post('/wwwhisper/auth/api/send-token/',
                             {'email': 'alice@example.org', 'path': '/'})
        self.assertEqual(500, response.status_code)
        self.assertEqual(
            b'Email delivery problem. ' +
            b'Check the entered address or try again in a few minutes.',
            response.content)

class LoginTest(AuthTestCase):
    def setUp(self):
        super(AuthTestCase, self).setUp()

    def test_login_fails_if_token_missing(self):
        response = self.post('/wwwhisper/auth/api/login/', {})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Invalid request arguments', response.content)

    def test_login_fails_if_token_null(self):
        response = self.post('/wwwhisper/auth/api/login/', {'token': None})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Token missing.', response.content)

    def test_login_fails_if_token_invalid(self):
        response = self.post('/wwwhisper/auth/api/login/', {'token': 'xyz'})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Token invalid or expired.', response.content)

    def test_login_fails_if_token_for_different_site(self):
        other_site = self.sites.create_item('othersite')
        other_site.users.create_item('foo@example.org')
        self.site.users.create_item('foo@example.org')
        token = generate_login_token(other_site, 'foo@example.org')
        response = self.post('/wwwhisper/auth/api/login/', {'token': token})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Token invalid or expired.', response.content)

    def test_login_succeeds_if_known_user(self):
        self.site.users.create_item('foo@example.org')
        token = generate_login_token(self.site, 'foo@example.org')
        response = self.post('/wwwhisper/auth/api/login/', {'token': token})
        self.assertEqual(204, response.status_code)

        logged_in_cookie = response.cookies[settings.LOGGED_IN_COOKIE_NAME]
        self.assertEqual('y', logged_in_cookie.value)
        self.assertTrue(logged_in_cookie['secure'])
        self.assertEqual('Strict', logged_in_cookie['samesite'])
        self.assertEqual('/', logged_in_cookie['path'])
        self.assertFalse(logged_in_cookie['httponly'])
        self.assertEqual(settings.LOGGED_IN_COOKIE_AGE,
                         logged_in_cookie['max-age'])

    def test_login_fails_if_unknown_user(self):
        token = generate_login_token(self.site, 'foo@example.org')
        response = self.post('/wwwhisper/auth/api/login/', {'token': token})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Token invalid or expired.', response.content)

    def test_successful_login_invalidates_token(self):
        self.site.users.create_item('foo@example.org')
        token = generate_login_token(self.site, 'foo@example.org')
        response = self.post('/wwwhisper/auth/api/login/', {'token': token})
        self.assertEqual(204, response.status_code)
        response = self.post('/wwwhisper/auth/api/login/', {'token': token})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b'Token invalid or expired.', response.content)

class SessionCacheTest(AuthTestCase):
    def test_user_cached_in_session(self):
        user = self.site.users.create_item('foo@example.com')

        token = generate_login_token(self.site, 'foo@example.com')
        response = self.post('/wwwhisper/auth/api/login/', {'token': token})
        self.assertEqual(204, response.status_code)

        s = self.client.session
        user_id = s['user_id']
        self.assertIsNotNone(user_id)
        self.assertEqual(user_id, user.id)
