# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

from django.test import TestCase
from wwwhisper_auth.url_utils import collapse_slashes
from wwwhisper_auth.url_utils import contains_fragment
from wwwhisper_auth.url_utils import contains_params
from wwwhisper_auth.url_utils import contains_query
from wwwhisper_auth.url_utils import decode
from wwwhisper_auth.url_utils import is_canonical
from wwwhisper_auth.url_utils import validate_redirection_target
from wwwhisper_auth.url_utils import validate_site_url
from wwwhisper_auth.url_utils import remove_default_port
from wwwhisper_auth.url_utils import strip_query

class PathTest(TestCase):

    def test_is_canonical(self):
        self.assertTrue(is_canonical('/'))
        self.assertTrue(is_canonical('/foo/bar'))
        self.assertTrue(is_canonical('/foo/bar/'))
        self.assertTrue(is_canonical('/foo/bar/  '))


        self.assertFalse(is_canonical(''))
        self.assertFalse(is_canonical('foo'))
        self.assertFalse(is_canonical('//'))
        self.assertFalse(is_canonical(' /'))
        self.assertFalse(is_canonical(' //'))
        self.assertFalse(is_canonical('//foo'))
        self.assertFalse(is_canonical('/foo/bar/..'))
        self.assertFalse(is_canonical('/foo//bar'))
        self.assertFalse(is_canonical('/foo/bar//'))
        self.assertFalse(is_canonical('/foo/bar/./foo'))

    def test_collapse_slashes(self):
        self.assertEqual(collapse_slashes('/'), '/')
        self.assertEqual(collapse_slashes('/foo/'), '/foo/')
        self.assertEqual(collapse_slashes('/foo'), '/foo')

        self.assertEqual(collapse_slashes('//'), '/')
        self.assertEqual(collapse_slashes('///'), '/')
        self.assertEqual(collapse_slashes('///foo//////bar//'), '/foo/bar/')
        self.assertEqual(collapse_slashes('///foo// ///bar//'), '/foo/ /bar/')

    def test_decode(self):
        self.assertEqual('/foo bar#', decode('/foo%20bar%23'))
        self.assertEqual('/FoO', decode('%2F%46%6f%4F'))
        self.assertEqual('/', decode('/'))
        self.assertEqual('/foo', decode('/foo'))
        self.assertEqual('/foo/', decode('/foo/'))

    def test_strip_query(self):
        self.assertEqual('/foo/', strip_query('/foo/?bar=abc'))
        self.assertEqual('/foo', strip_query('/foo?'))
        self.assertEqual('/foo', strip_query('/foo?bar=abc?baz=xyz'))

    def test_contains_fragment(self):
        self.assertTrue(contains_fragment('/foo#123'))
        self.assertTrue(contains_fragment('/foo#'))
        # Encoded '#' should not be treated as fragment separator.
        self.assertFalse(contains_fragment('/foo%23'))

    def test_contains_query(self):
        self.assertTrue(contains_query('/foo?'))
        self.assertFalse(contains_query('/foo'))

    def test_contains_params(self):
        self.assertTrue(contains_params('/foo;'))
        self.assertFalse(contains_params('/foo'))

class RedirectionTargetTest(TestCase):

    def test_validate_redirection_target(self):
        self.assertTrue(validate_redirection_target('/'))
        self.assertTrue(validate_redirection_target('/foo'))
        self.assertTrue(validate_redirection_target('/foo/'))
        self.assertTrue(validate_redirection_target('/foo/?bar=baz'))
        self.assertTrue(validate_redirection_target('/foo?bar=baz/../'))

        self.assertFalse(validate_redirection_target(''))
        self.assertFalse(validate_redirection_target('/' + 'f' * 200))
        self.assertFalse(validate_redirection_target('http://example.org/'))
        self.assertFalse(validate_redirection_target('example.org/'))
        self.assertFalse(validate_redirection_target('/foo\n'))
        self.assertFalse(validate_redirection_target('/foo/../bar'))
        self.assertFalse(validate_redirection_target(''))

class SiteUrlTest(TestCase):

    def assertInvalid(self, result, errorRegexp):
        self.assertEqual(False, result[0])
        self.assertRegex(result[1], errorRegexp)

    def assertValid(self, result):
        self.assertEqual((True, None), result)

    def test_validation(self):
        self.assertInvalid(
            validate_site_url('example.com'), 'missing scheme')
        self.assertInvalid(
            validate_site_url('ftp://example.com'), 'incorrect scheme')
        self.assertInvalid(
            validate_site_url('http://'), 'missing domain')
        self.assertInvalid(
            validate_site_url('http://example.com/foo'), 'contains path')
        self.assertInvalid(
            validate_site_url('http://example.com/'), 'contains path')
        self.assertInvalid(
            validate_site_url('http://example.com?a=b'), 'contains query')
        self.assertInvalid(
            validate_site_url('http://example.com#boo'), 'contains fragment')
        self.assertInvalid(
            validate_site_url('http://alice@example.com'), 'contains username')
        self.assertInvalid(
            validate_site_url('http://:pass@example.com'), 'contains password')

        self.assertValid(validate_site_url('http://example.com'))
        self.assertValid(validate_site_url('http://example.com:80'))
        self.assertValid(validate_site_url('https://example.com'))
        self.assertValid(validate_site_url('https://example.com:123'))

    def test_remove_default_port(self):
        self.assertEqual('http://example.com',
                         remove_default_port('http://example.com'))
        self.assertEqual('http://example.com:56',
                         remove_default_port('http://example.com:56'))

        self.assertEqual('https://example.com',
                         remove_default_port('https://example.com:443'))
        self.assertEqual('http://example.com:443',
                         remove_default_port('http://example.com:443'))

        self.assertEqual('http://example.com',
                         remove_default_port('http://example.com:80'))
        self.assertEqual('https://example.com:80',
                         remove_default_port('https://example.com:80'))
