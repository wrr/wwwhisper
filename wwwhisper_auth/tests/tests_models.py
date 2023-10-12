# coding=utf-8

# wwwhisper - web access control.
# Copyright (C) 2012-2017 Jan Wrobel <jan@mixedbit.org>

from contextlib import contextmanager
from functools import wraps

from django.db import transaction
from django.forms import ValidationError
from django.test import TestCase

from wwwhisper_auth.models import LimitExceeded
from wwwhisper_auth.models import SitesCollection

FAKE_UUID = '41be0192-0fcc-4a9c-935d-69243b75533c'
TEST_SITE = 'https://example.com'
TEST_SITE2 = 'https://example.org'
TEST_USER_EMAIL = 'foo@bar.com'
TEST_LOCATION = '/pub/kika'

class ModelTestCase(TestCase):
    def setUp(self):
        self.sites = SitesCollection()
        self.site = self.sites.create_item(TEST_SITE)
        self.site2 = self.sites.create_item(TEST_SITE2)
        self.aliases = self.site.aliases
        self.locations = self.site.locations
        self.users = self.site.users

    @contextmanager
    def assert_site_modified(self, site):
        mod_id = site.mod_id
        yield
        self.assertNotEqual(mod_id, site.mod_id)
        self.assertEqual(site.mod_id, site.get_mod_id_ts())

    @contextmanager
    def assert_site_not_modified(self, site):
        mod_id = site.mod_id
        yield
        self.assertEqual(mod_id,  site.mod_id)

# Test testing infrastructure.
class SiteModifiedTest(ModelTestCase):
    def test_assert_site_modified(self):
        with self.assert_site_modified(self.site):
            self.site.site_modified()
        # Should not raise anything

    def test_assert_site_not_modified(self):
        with self.assert_site_not_modified(self.site):
            pass
        # Should not raise anything

    def test_assert_site_modified_raises(self):
        try:
            with self.assert_site_modified(self.site):
                pass
        except AssertionError as er:
            pass # Expected.
        else:
            self.fail('Assertion not raised')

    def test_assert_site_not_modified_raises(self):
        try:
            with self.assert_site_not_modified(self.site):
                self.site.site_modified()
        except AssertionError as er:
            pass # Expected.
        else:
            self.fail('Assertion not raised')

class SitesTest(ModelTestCase):
    def test_create_site(self):
        self.assertEqual(TEST_SITE, self.site.site_id)
        self.assertIsNotNone(self.site.locations.site)
        self.assertIsNotNone(self.site.users.site)

    def test_create_site_twice(self):
        self.assertRaisesRegex(ValidationError,
                               'Site .* already exists.',
                               self.sites.create_item,
                               TEST_SITE)

    def test_find_site(self):
        site2 = self.sites.find_item(TEST_SITE)
        self.assertIsNotNone(site2)
        self.assertEqual(self.site, site2)

    def test_delete_site(self):
        self.assertTrue(self.sites.delete_item(TEST_SITE))
        self.assertIsNone(self.sites.find_item(TEST_SITE))

    def test_default_skin(self):
        skin = self.site.skin()
        self.assertEqual('wwwhisper: Web Access Control', skin['title'])
        self.assertEqual('Protected site', skin['header'])
        self.assertRegex(skin['message'], 'Access to this site is')
        self.assertTrue(skin['branding'])

    def test_update_skin(self):
        with self.assert_site_modified(self.site):
            self.site.update_skin(title='BarFoo', header='', message='hello',
                                  branding=False)
        with self.assert_site_not_modified(self.site):
            skin = self.site.skin()
        self.assertEqual('BarFoo', skin['title'])
        self.assertEqual('Protected site', skin['header'])
        self.assertEqual('hello', skin['message'])
        self.assertFalse(skin['branding'])

        # If default value is used, it should not be saved to a db,
        # but it should still be returned in the skin dict.
        self.site.update_skin(title='wwwhisper: Web Access Control ', header='',
                              message='', branding=False)
        self.assertEqual('', self.site.title)
        self.assertEqual('wwwhisper: Web Access Control',
                         self.site.skin()['title'])

class UsersCollectionTest(ModelTestCase):
    def test_create_user(self):
        with self.assert_site_modified(self.site):
            user = self.users.create_item(TEST_USER_EMAIL)
        self.assertEqual(TEST_USER_EMAIL, user.email)
        self.assertEqual(TEST_SITE, user.site_id)

    def test_find_user_by_uuid(self):
        user1 = self.users.create_item(TEST_USER_EMAIL)
        with self.assert_site_not_modified(self.site):
            user2 = self.users.find_item(user1.uuid)
        self.assertIsNotNone(user2)
        self.assertEqual(user1, user2)

    def test_find_user_by_pk(self):
        user1 = self.users.create_item(TEST_USER_EMAIL)
        with self.assert_site_not_modified(self.site):
            user2 = self.users.find_item_by_pk(user1.id)
        self.assertIsNotNone(user2)
        self.assertEqual(user1, user2)

    def test_find_user_different_site(self):
        user1 = self.users.create_item(TEST_USER_EMAIL)
        self.assertIsNone(self.site2.users.find_item(user1.uuid))

    def test_delete_site_deletes_user(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        self.assertEqual(1, user.__class__.objects.filter(id=user.id).count())
        self.assertTrue(self.sites.delete_item(self.site.site_id))
        self.assertEqual(0, user.__class__.objects.filter(id=user.id).count())

    def test_find_user_by_email(self):
        self.assertIsNone(self.users.find_item_by_email(TEST_USER_EMAIL))
        user1 = self.users.create_item(TEST_USER_EMAIL)
        with self.assert_site_not_modified(self.site):
            user2 = self.users.find_item_by_email(TEST_USER_EMAIL)
        self.assertIsNotNone(user2)
        self.assertEqual(user1, user2)

    def test_find_user_by_email_different_site(self):
        self.users.create_item(TEST_USER_EMAIL)
        self.assertIsNone(self.site2.users.find_item_by_email(TEST_USER_EMAIL))

    def test_find_user_by_email_is_case_insensitive(self):
        user1 = self.users.create_item('foo@bar.com')
        user2 = self.users.find_item_by_email('FOo@bar.com')
        self.assertIsNotNone(user2)
        self.assertEqual(user1, user2)

    def test_delete_user(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        with self.assert_site_modified(self.site):
            self.assertTrue(self.users.delete_item(user.uuid))
        self.assertIsNone(self.users.find_item(user.uuid))

    def test_create_user_twice(self):
        with transaction.atomic():
            self.users.create_item(TEST_USER_EMAIL)
        # Integrity error raised during duplicate user creation makes
        # it impossible to run any other query within the same
        # test. transaction.atomic() blocks fix this issue.
        with transaction.atomic():
            self.assertRaisesRegex(ValidationError,
                                   'User already exists',
                                   self.users.create_item,
                                   TEST_USER_EMAIL)

        # Make sure user lookup is case insensitive.
        with transaction.atomic():
            self.users.create_item('uSeR@bar.com')
        with transaction.atomic():
            with self.assert_site_not_modified(self.site):
                self.assertRaisesRegex(ValidationError,
                                       'User already exists',
                                       self.users.create_item,
                                       'UsEr@bar.com')

    def test_create_user_twice_for_different_sites(self):
        self.users.create_item(TEST_USER_EMAIL)
        with self.assert_site_not_modified(self.site):
            with self.assert_site_modified(self.site2):
                self.site2.users.create_item(TEST_USER_EMAIL)
        # Should not raise

    def test_delete_user_twice(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        self.assertTrue(self.users.delete_item(user.uuid))
        self.assertFalse(self.users.delete_item(user.uuid))

    def test_delete_user_different_site(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        self.assertFalse(self.site2.users.delete_item(user.uuid))

    def test_get_all_users(self):
        user1 = self.users.create_item('foo@example.com')
        user2 = self.users.create_item('bar@example.com')
        user3 = self.site2.users.create_item('baz@example.com')
        self.assertEqual(2, self.users.count())
        self.assertEqual(1, self.site2.users.count())
        with self.assert_site_not_modified(self.site):
            self.assertCountEqual(
                ['foo@example.com', 'bar@example.com'],
                [u.email for u in self.users.all()])
        self.users.delete_item(user1.uuid)
        self.assertCountEqual(
            ['bar@example.com'],
            [u.email for u in self.users.all()])
        self.assertEqual(1, self.users.count())

    def test_get_all_users_when_empty(self):
        self.assertEqual(0, self.users.count())
        self.assertListEqual([], list(self.users.all()))

    def test_email_validation(self):
        """Test strings taken from BrowserId tests."""
        self.assertIsNotNone(self.users.create_item('x@y.z'))
        self.assertIsNotNone(self.users.create_item('x@y.z.w'))
        self.assertIsNotNone(self.users.create_item('x.v@y.z.w'))
        self.assertIsNotNone(self.users.create_item('x_v@y.z.w'))
        # Valid tricky characters.
        self.assertIsNotNone(self.users.create_item(
                r'x#!v$we*df+.|{}@y132.wp.a-s.012'))

        with self.assert_site_not_modified(self.site):
            self.assertRaisesRegex(ValidationError,
                                   'Invalid email format',
                                   self.users.create_item,
                                   'x')
            self.assertRaisesRegex(ValidationError,
                                   'Invalid email format',
                                   self.users.create_item,
                                   'x@y')
            self.assertRaisesRegex(ValidationError,
                                   'Invalid email format',
                                   self.users.create_item,
                                   '@y.z')
            self.assertRaisesRegex(ValidationError,
                                   'Invalid email format',
                                   self.users.create_item,
                                   'z@y.z@y.z')
            self.assertRaisesRegex(ValidationError,
                                   'Invalid email format',
                                   self.users.create_item,
                                   '')
            # Invalid tricky character.
            self.assertRaisesRegex(ValidationError,
                                   'Invalid email format',
                                   self.users.create_item,
                                   r'a\b@b.c.d')
            # Too long.
            self.assertRaisesRegex(ValidationError,
                                   'Invalid email format',
                                   self.users.create_item,
                                   'foo@bar.com.' + ('z' * 100) )

    def test_email_normalization(self):
        email = self.users.create_item('x@y.z').email
        self.assertEqual('x@y.z', email)

        email = self.users.create_item('aBc@y.z').email
        self.assertEqual('abc@y.z', email)

    def test_users_limit(self):
        limit = 10
        self.site.users_limit = limit
        for i in range(0, limit):
            self.users.create_item('foo%d@bar.com' % (i))
        self.assertRaisesRegex(LimitExceeded,
                               'Users limit exceeded',
                               self.users.create_item,
                               'foo10@bar.com')

    def test_login_user(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        with self.assert_site_modified(self.site):
            user.login_successful()

class LocationsCollectionTest(ModelTestCase):
    def test_create_location(self):
        with self.assert_site_modified(self.site):
            location = self.locations.create_item(TEST_LOCATION)
            self.assertEqual(TEST_LOCATION, location.path)
            self.assertEqual(TEST_SITE, location.site_id)

    def test_delete_site_deletes_location(self):
        location = self.locations.create_item(TEST_LOCATION)
        self.assertEqual(
            1, location.__class__.objects.filter(id=location.id).count())
        self.assertTrue(self.sites.delete_item(self.site.site_id))
        self.assertEqual(
            0, location.__class__.objects.filter(id=location.id).count())

    def test_find_location_by_uuid(self):
        location1 = self.locations.create_item(TEST_LOCATION)
        with self.assert_site_not_modified(self.site):
            location2 = self.locations.find_item(location1.uuid)
        self.assertIsNotNone(location2)
        self.assertEqual(location1.path, location2.path)
        self.assertEqual(location1.uuid, location2.uuid)

    def test_find_location_by_pk(self):
        location1 = self.locations.create_item(TEST_LOCATION)
        with self.assert_site_not_modified(self.site):
            location2 = self.locations.find_item_by_pk(location1.id)
        self.assertIsNotNone(location2)
        self.assertEqual(location1.path, location2.path)
        self.assertEqual(location1.uuid, location2.uuid)

    def test_delete_location(self):
        location = self.locations.create_item(TEST_LOCATION)
        self.assertIsNotNone(self.locations.find_item(location.uuid))
        with self.assert_site_modified(self.site):
            self.assertTrue(self.locations.delete_item(location.uuid))
        self.assertIsNone(self.locations.find_item(location.uuid))

    def test_create_location_twice(self):
        self.locations.create_item(TEST_LOCATION)
        with self.assert_site_not_modified(self.site):
            self.assertRaisesRegex(ValidationError,
                                   'Location already exists',
                                   self.locations.create_item,
                                   TEST_LOCATION)

    def test_create_location_twice_for_different_sites(self):
        self.locations.create_item(TEST_LOCATION)
        with self.assert_site_not_modified(self.site):
            with self.assert_site_modified(self.site2):
                self.site2.locations.create_item(TEST_LOCATION)

    def test_delete_location_twice(self):
        location = self.locations.create_item(TEST_LOCATION)
        self.assertTrue(self.locations.delete_item(location.uuid))
        self.assertFalse(self.locations.delete_item(location.uuid))

    def test_get_all_locations(self):
        location1 = self.locations.create_item('/foo')
        location2 = self.locations.create_item('/foo/bar')
        self.site2.locations.create_item('/foo/baz')
        self.assertEqual(2, self.locations.count())
        self.assertEqual(1, self.site2.locations.count())
        with self.assert_site_not_modified(self.site):
            self.assertCountEqual(['/foo/bar', '/foo'],
                                  [l.path for l
                                   in self.locations.all()])
        self.locations.delete_item(location1.uuid)
        self.assertCountEqual(['/foo/bar'],
                              [l.path for l
                               in self.locations.all()])
        self.assertEqual(1, self.locations.count())

    def test_get_all_locations_when_empty(self):
        self.assertEqual(0, self.locations.count())
        self.assertListEqual([], list(self.locations.all()))

    def test_grant_access(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.locations.create_item(TEST_LOCATION)
        with self.assert_site_not_modified(self.site):
            self.assertFalse(location.can_access(user))
        with self.assert_site_modified(self.site):
            (perm, created) = location.grant_access(user.uuid)
        self.assertTrue(created)
        self.assertIsNotNone(perm)
        self.assertTrue(location.can_access(user))

    def test_grant_access_for_not_existing_user(self):
        location = self.locations.create_item(TEST_LOCATION)
        self.assertRaisesRegex(LookupError,
                               'User not found',
                               location.grant_access,
                               FAKE_UUID)

    def test_grant_access_for_user_of_different_site(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.site2.locations.create_item(TEST_LOCATION)
        self.assertFalse(location.can_access(user))
        self.assertRaisesRegex(LookupError,
                               'User not found',
                               location.grant_access,
                               user.uuid)

    def test_grant_access_if_already_granted(self):
        location = self.locations.create_item(TEST_LOCATION)
        user = self.users.create_item(TEST_USER_EMAIL)
        (permission1, created1) = location.grant_access(user.uuid)
        self.assertTrue(created1)
        (permission2, created2) = location.grant_access(user.uuid)
        self.assertFalse(created2)
        self.assertEqual(permission1, permission2)
        self.assertEqual(TEST_USER_EMAIL, permission1.user.email)
        self.assertTrue(location.can_access(user))

    def test_grant_access_to_deleted_location(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.locations.create_item(TEST_LOCATION)
        self.assertTrue(self.locations.delete_item(location.uuid))
        self.assertRaises(ValidationError,
                          location.grant_access,
                          user.uuid)

    def test_revoke_access(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.locations.create_item(TEST_LOCATION)
        location.grant_access(user.uuid)
        self.assertTrue(location.can_access(user))
        with self.assert_site_modified(self.site):
            location.revoke_access(user.uuid)
        self.assertFalse(location.can_access(user))

    def test_revoke_not_granted_access(self):
        location = self.locations.create_item(TEST_LOCATION)
        user = self.users.create_item(TEST_USER_EMAIL)
        with self.assert_site_not_modified(self.site):
            self.assertRaisesRegex(LookupError,
                                   'User can not access location.',
                                   location.revoke_access,
                                   user.uuid)

    def test_revoke_access_to_deleted_location(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.locations.create_item(TEST_LOCATION)
        location.grant_access(user.uuid)
        self.assertTrue(self.locations.delete_item(location.uuid))
        self.assertRaisesRegex(LookupError,
                               'User can not access location.',
                               location.revoke_access,
                               user.uuid)

    def test_deleting_user_revokes_access(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.locations.create_item(TEST_LOCATION)
        self.assertFalse(location.can_access(user))
        location.grant_access(user.uuid)
        self.assertTrue(location.can_access(user))
        self.users.delete_item(user.uuid)
        self.assertFalse(location.can_access(user))

    def test_deleting_location_revokes_access(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.locations.create_item(TEST_LOCATION)
        self.assertFalse(location.can_access(user))
        location.grant_access(user.uuid)
        self.assertTrue(location.can_access(user))
        self.locations.delete_item(location.uuid)
        self.assertFalse(location.can_access(user))

    def test_revoke_access_for_not_existing_user(self):
        location = self.locations.create_item(TEST_LOCATION)
        self.assertRaisesRegex(LookupError,
                               'User not found',
                               location.revoke_access,
                               FAKE_UUID)

    def test_get_permission(self):
        location = self.locations.create_item(TEST_LOCATION)
        user1 = self.users.create_item(TEST_USER_EMAIL)
        self.assertRaisesRegex(LookupError,
                               'User can not access',
                               location.get_permission,
                               user1.uuid)
        location.grant_access(user1.uuid)
        self.assertIsNotNone(location.get_permission(user1.uuid))

        user2 = self.site2.users.create_item(TEST_USER_EMAIL)
        # User does not belong to the site.
        self.assertRaisesRegex(LookupError,
                               'User not found',
                               location.get_permission,
                               user2.uuid)

    def test_find_location_by_path(self):
        location = self.locations.create_item('/foo/bar')
        with self.assert_site_not_modified(self.site):
            self.assertEqual(location, self.locations.find_location('/foo/bar'))
            self.assertIsNone(self.site2.locations.find_location('/foo/bar'))

        self.assertEqual(
            location, self.locations.find_location('/foo/bar/'))
        self.assertIsNone(self.site2.locations.find_location('/foo/bar/'))

        self.assertEqual(
            location, self.locations.find_location('/foo/bar/b'))
        self.assertIsNone(self.site2.locations.find_location('/foo/bar/b'))

        self.assertEqual(
            location, self.locations.find_location('/foo/bar/baz'))
        self.assertIsNone(self.site2.locations.find_location('/foo/bar/baz'))

        self.assertEqual(
            location, self.locations.find_location('/foo/bar/baz/bar/'))
        self.assertIsNone(
            self.site2.locations.find_location('/foo/bar/baz/bar/'))

        self.assertIsNone(self.locations.find_location('/foo/ba'))
        self.assertIsNone(self.locations.find_location('/foo/barr'))
        self.assertIsNone(self.locations.find_location('/foo/foo/bar'))

    def test_more_specific_location_takes_precedence_over_generic(self):
        location1 = self.locations.create_item('/foo/bar')
        user = self.users.create_item('foo@example.com')
        location1.grant_access(user.uuid)

        location2 = self.locations.create_item('/foo/bar/baz')
        self.assertEqual(
            location1, self.locations.find_location('/foo/bar'))
        self.assertEqual(
            location1, self.locations.find_location('/foo/bar/ba'))
        self.assertEqual(
            location1, self.locations.find_location('/foo/bar/bazz'))

        self.assertEqual(
            location2, self.locations.find_location('/foo/bar/baz'))
        self.assertEqual(
            location2, self.locations.find_location('/foo/bar/baz/'))
        self.assertEqual(
            location2, self.locations.find_location('/foo/bar/baz/bam'))
        self.assertFalse(location2.can_access(user))

    def test_trailing_slash_respected(self):
        location = self.locations.create_item('/foo/bar/')
        self.assertIsNone(self.locations.find_location('/foo/bar'))

    def test_grant_access_to_root(self):
        location = self.locations.create_item('/')
        user = self.users.create_item('foo@example.com')
        location.grant_access(user.uuid)

        self.assertEqual(location, self.locations.find_location('/'))
        self.assertEqual(location, self.locations.find_location('/f'))
        self.assertEqual(
            location, self.locations.find_location('/foo/bar/baz'))

    def test_grant_open_access(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.locations.create_item(TEST_LOCATION)
        self.assertFalse(location.open_access_granted())
        self.assertFalse(location.can_access(user))

        with self.assert_site_modified(self.site):
            location.grant_open_access()
        with self.assert_site_not_modified(self.site):
            self.assertTrue(location.open_access_granted())
            self.assertTrue(location.can_access(user))

        with self.assert_site_modified(self.site):
            location.revoke_open_access()
        self.assertFalse(location.open_access_granted())
        self.assertFalse(location.can_access(user))

    def test_user_of_different_site_can_not_access_even_if_open_location(self):
        user = self.users.create_item(TEST_USER_EMAIL)
        location = self.site2.locations.create_item(TEST_LOCATION)
        location.grant_open_access()
        self.assertFalse(location.can_access(user))

    def test_has_open_location(self):
        self.assertFalse(self.locations.has_open_location())
        self.locations.create_item('/bar')
        self.assertFalse(self.locations.has_open_location())
        location = self.locations.create_item('/foo')
        location.grant_open_access()
        self.assertTrue(self.locations.has_open_location())
        self.assertFalse(self.site2.locations.has_open_location())
        location.revoke_open_access()
        self.assertFalse(self.locations.has_open_location())

    def test_get_allowed_users(self):
        location1 = self.locations.create_item('/foo/bar')
        location2 = self.locations.create_item('/foo/baz')

        user1 = self.users.create_item('foo@example.com')
        user2 = self.users.create_item('bar@example.com')
        user3 = self.users.create_item('baz@example.com')

        location1.grant_access(user1.uuid)
        location1.grant_access(user2.uuid)
        location2.grant_access(user3.uuid)

        with self.assert_site_not_modified(self.site):
            self.assertCountEqual(['foo@example.com', 'bar@example.com'],
                                  [u.email for u in location1.allowed_users()])
            self.assertCountEqual(['baz@example.com'],
                                  [u.email for u in location2.allowed_users()])

        location1.revoke_access(user1.uuid)
        self.assertCountEqual(['bar@example.com'],
                              [u.email for u in location1.allowed_users()])

    def test_get_allowed_users_when_empty(self):
        location = self.locations.create_item(TEST_LOCATION)
        self.assertEqual([], location.allowed_users())

    def test_location_path_validation(self):
        with self.assert_site_not_modified(self.site):
            self.assertRaisesRegex(ValidationError,
                                   'should be absolute and normalized',
                                   self.locations.create_item,
                                   '/foo/../bar')
            self.assertRaisesRegex(ValidationError,
                                   'should not contain parameters',
                                   self.locations.create_item,
                                   '/foo;bar')
            self.assertRaisesRegex(ValidationError,
                                   'should not contain query',
                                   self.locations.create_item,
                                   '/foo?s=bar')
            self.assertRaisesRegex(ValidationError,
                                   'should not contain fragment',
                                   self.locations.create_item,
                                   '/foo#bar')
            self.assertRaisesRegex(ValidationError,
                                   'should contain only ascii',
                                   self.locations.create_item,
                                    '/żbik')
            long_path = '/a' * int(self.locations.PATH_LEN_LIMIT / 2) + 'a'
            self.assertRaisesRegex(ValidationError,
                                   'too long',
                                   self.locations.create_item,
                                   long_path)

    """Path passed to create_location is expected to be saved verbatim."""
    def test_location_path_not_encoded(self):
        self.assertEqual(
            '/foo%20bar', self.locations.create_item('/foo%20bar').path)
        self.assertEqual(
            '/foo~', self.locations.create_item('/foo~').path)
        self.assertEqual(
            '/foo/bar!@7*', self.locations.create_item('/foo/bar!@7*').path)

    def test_locations_limit(self):
        limit = 10
        self.site.locations_limit = limit
        for i in range(0, limit):
            self.locations.create_item('/foo%d' % (i))
        self.assertRaisesRegex(LimitExceeded,
                               'Locations limit exceeded',
                               self.locations.create_item,
                               '/foo10')

class AliasesCollectionTest(ModelTestCase):

    def test_add_alias(self):
        with self.assert_site_modified(self.site):
            alias = self.aliases.create_item(TEST_SITE)
        self.assertEqual(TEST_SITE, alias.url)
        self.assertTrue(len(alias.uuid) > 20)

    def test_add_alias_invalid_url(self):
        self.assertRaisesRegex(ValidationError,
                               'missing scheme',
                               self.aliases.create_item,
                               'foo.example.com')

    def test_default_port_removed(self):
        with self.assert_site_modified(self.site):
            alias = self.aliases.create_item('http://example.org:80')
        self.assertEqual('http://example.org', alias.url)

    def test_normalized(self):
        with self.assert_site_modified(self.site):
            alias = self.aliases.create_item('  hTtp://eXamPlE.org')
        self.assertEqual('http://example.org', alias.url)


    def test_alias_must_be_unique(self):
        self.aliases.create_item('http://example.org:123')
        self.assertRaisesRegex(ValidationError,
                               'already exists',
                               self.aliases.create_item,
                               'http://example.org:123')

    def test_alias_must_be_unique_after_normalization(self):
        # There was a bug in wwwhisper that allowed to add a
        # duplicated alias, by appending a default port to it (default
        # port is automatically stripped from the alias). Such
        # duplicated aliases caused later assertion failures.
        self.aliases.create_item('http://example.org')
        with self.assert_site_not_modified(self.site):
            self.assertRaisesRegex(ValidationError,
                                   'already exists',
                                   self.aliases.create_item,
                                   'http://example.org:80')

    def test_alias_for_different_site_can_duplicate(self):
        alias = self.aliases.create_item('http://example.org:123')
        self.assertIsNotNone(alias)
        alias = self.site2.aliases.create_item('http://example.org:123')
        self.assertIsNotNone(alias)

    def test_find_alias_by_url(self):
        self.assertIsNone(self.aliases.find_item_by_url(TEST_SITE))
        alias1 = self.aliases.create_item(TEST_SITE)
        with self.assert_site_not_modified(self.site):
            alias2 = self.aliases.find_item_by_url(TEST_SITE)
        self.assertIsNotNone(alias2)
        self.assertEqual(alias1, alias2)

    def test_find_alias_by_url_different_site(self):
        self.aliases.create_item(TEST_SITE)
        self.assertIsNone(self.site2.aliases.find_item_by_url(TEST_SITE))

    def test_aliases_limit(self):
        limit = 10
        self.site.aliases_limit = limit
        for i in range(0, limit):
            self.aliases.create_item('http://foo%d.org' % (i))
        self.assertRaisesRegex(LimitExceeded,
                               'Aliases limit exceeded',
                               self.aliases.create_item,
                               'http://foo10.org')

    def test_alias_length_limit(self):
        long_url = 'https://%s.org' % ('x' * self.aliases.ALIAS_LEN_LIMIT)
        self.assertRaisesRegex(ValidationError,
                               'Url too long',
                               self.aliases.create_item,
                               long_url)
