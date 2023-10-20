# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

"""Data model for the site access control rules.

Each site has users, locations (paths) and permissions - rules that
define which user can access which locations. Sites are
isolated. Users and locations are associated with a single site and
are used only for this site. Site has also aliases: urls that can be
used to access the site, only requests from these urls are allowed.

Provides methods that map to REST operations that can be performed on
users, locations and permissions resources. Allows to retrieve
externally visible attributes of these resources, the attributes are
returned as a resource representation by REST methods.

Resources are identified by an externally visible UUIDs. Standard
primary key ids are not used for external identification purposes,
because those ids can be reused after object is deleted.

Makes sure entered emails and paths are valid.
"""

import functools
import logging
import re
import threading
import uuid as uuidgen

from django.contrib.auth.models import AbstractBaseUser
from django.db import connection
from django.db import models
from django.db import IntegrityError
from django.forms import ValidationError
from django.urls import reverse
from django.utils import timezone

from wwwhisper_auth import  url_utils
from wwwhisper_auth import  email_re

logger = logging.getLogger(__name__)

class LimitExceeded(Exception):
    pass

class ValidatedModel(models.Model):
    """Base class for all model classes.

    Makes sure all constraints are preserved before changed data is
    saved.
    """

    class Meta:
        """Disables creation of a DB table for ValidatedModel."""
        abstract = True
        # Needed because models are used from signal handlers, before
        # the application is loaded.
        app_label = 'wwwhisper_auth'

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

# Id used when wwwhisper servers just a single site.
SINGLE_SITE_ID = 'theone'

class Site(ValidatedModel):
    """A site to which access is protected.

    Site has locations, users and aliases.

    Attributes:
      site_id: Can be a domain or any other string.

      mod_id: Changed after any modification of site-related data (not
         only Site itself but also site's locations, permissions or
         users). Allows to determine when Django processes need to
         update cached data.
    """
    site_id = models.TextField(primary_key=True, db_index=True, editable=False)
    mod_id = models.IntegerField(default=0)

    # Default values for texts on a login page (used when custom texts
    # are set to empty values).
    _default_skin = {
        'title': 'wwwhisper: Web Access Control',
        'header': 'Protected site',
        'message': 'Access to this site is restricted, please verify your email:'
    }

    title = models.CharField(max_length=80, blank=True)
    header = models.CharField(max_length=100, blank=True)
    message = models.CharField(max_length=500, blank=True)
    branding = models.BooleanField(default=True)

    aliases_limit = None
    users_limit = None
    locations_limit = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Synchronizes mod id that can be read by a cache updating
        # thread.
        self.mod_id_lock = threading.Lock()

    def heavy_init(self):
        """Creates collections of all site-related data.

        This is a resource intensive operation that retrieves all site
        related data from the database. It is only performed if the site
        was modified since it was last retrieved.
        """
        self.locations = LocationsCollection(self)
        self.users = UsersCollection(self)
        self.aliases = AliasesCollection(self)

    def site_modified(self):
        """Increases the site modification id.

        This causes the site to be refreshed in web processes caches.
        """
        cursor = connection.cursor()
        cursor.execute(
            'UPDATE wwwhisper_auth_site '
            'SET mod_id = mod_id + 1 WHERE site_id = %s', [self.site_id])
        cursor.close()
        mod_id = self.mod_id_from_db()
        with self.mod_id_lock:
            self.mod_id = mod_id

    def skin(self):
        """Dictionary with settings that configure the site's login page."""
        # Dict comprehensions not used to support python 2.6.
        result = dict([(attr, getattr(self, attr) or self._default_skin[attr])
                       for attr in self._default_skin.keys()])
        result['branding'] = self.branding
        return result

    def update_skin(self, title, header, message, branding):
        for attr in self._default_skin.keys():
            arg = locals()[attr].strip()
            if arg == self._default_skin[attr]:
                arg = ''
            setattr(self, attr, arg)
        self.branding = branding
        self.save()
        self.site_modified()

    def get_mod_id_ts(self):
        """This method can be safely invoked by a non main thread"""
        with self.mod_id_lock:
            return self.mod_id

    def mod_id_from_db(self):
        """Retrieves from the DB a current modification identifier for the site.

        Returns None if the site no longer exists in the DB.
        """
        cursor = connection.cursor()
        cursor.execute(
            'SELECT mod_id FROM wwwhisper_auth_site WHERE site_id = %s',
            [self.site_id])
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            return None
        return row[0]

def modify_site(decorated_method):
    """Must decorate all methods that change data associated with the site.

    Makes sure site is marked as modified and other Django processes
    will retrieve new data from the DB instead of using cached data.
    """

    @functools.wraps(decorated_method)
    def wrapper(self, *args, **kwargs):
        result = decorated_method(self, *args, **kwargs)
        # If no exception.
        self.site.site_modified()
        return result
    return wrapper


class SitesCollection(object):
    def create_item(self, site_id, **kwargs):
        """Creates a new Site object.

        Args:
           site_id: A domain or other id of the created site.
        Raises:
           ValidationError if a site with a given id already exists.
        """
        site =  Site.objects.create(site_id=site_id, **kwargs)
        site.heavy_init()
        return site

    def find_item(self, site_id):
        site = _find(Site, site_id=site_id)
        if site is not None:
            site.heavy_init()
        return site

    def delete_item(self, site_id):
        site = self.find_item(site_id)
        if site is None:
            return False
        # Users, Locations and Permissions have foreign key to the Site
        # and are deleted automatically.
        site.delete()
        return True

class User(AbstractBaseUser):
    class Meta:
        app_label = 'wwwhisper_auth'
        unique_together = ('site', 'email')

    # Site to which the user belongs.
    site = models.ForeignKey(Site, related_name='+', on_delete=models.CASCADE)

    # Externally visible UUID of the user. Allows to identify a REST
    # resource representing the user.
    uuid = models.CharField(max_length=36, db_index=True,
                            editable=False, unique=True)
    email = models.EmailField(db_index=True)

    USERNAME_FIELD = 'uuid'
    REQUIRED_FIELDS = ['email', 'site']

    def attributes_dict(self):
        """Returns externally visible attributes of the user resource."""
        return _add_common_attributes(self, {'email': self.email})

    def get_absolute_url(self):
        return reverse('wwwhisper_user', kwargs={'uuid' : self.uuid})

    @modify_site
    def login_successful(self):
        """Must be called after successful login."""
        # Successful login updates User.last_login, cache refresh
        # needs to be forced for the login token to be invalidated.
        return

class Location(ValidatedModel):
    """A location for which access control rules are defined.

    Location is uniquely identified by its canonical path. All access
    control rules defined for a location apply also to sub-paths,
    unless a more specific location exists. In such case the more
    specific location takes precedence over the more generic one.

    For example, if a location with a path /pub is defined and a user
    foo@example.com is granted access to this location, the user can
    access /pub and all sub path of /pub. But if a location with a
    path /pub/beer is added, and the user foo@example.com is not
    granted access to this location, the user won't be able to access
    /pub/beer and all its sub-paths.

    Attributes:
      site: Site to which the location belongs.
      path: Canonical path of the location.
      uuid: Externally visible UUID of the location, allows to identify a REST
          resource representing the location.

      open_access: can be:
        disabled ('n') - only explicitly allowed users can access a location;
        enabled ('y') - everyone can access a location, no login is required;
        (the attribute is a char not a bool for historical
         reasons. 'a' mode used to be also supported that allowed
         everyone access but required authentication).

    """
    class Meta:
        app_label = 'wwwhisper_auth'
        unique_together = ('site', 'path')

    OPEN_ACCESS_CHOICES = (
        ('n', 'no open access'),
        ('y', 'open access'),
        )
    site = models.ForeignKey(Site, related_name='+', on_delete=models.CASCADE)
    path = models.TextField(db_index=True)
    uuid = models.CharField(max_length=36, db_index=True,
                            editable=False, unique=True)
    open_access = models.CharField(max_length=2, choices=OPEN_ACCESS_CHOICES,
                                   default='n')

    def permissions(self):
        # Does not run a query to get permissions if not needed.
        return self.site.locations.get_permissions(self.id)

    def __unicode__(self):
        return self.path

    def get_absolute_url(self):
        """Constructs URL of the location resource."""
        return reverse('wwwhisper_location', kwargs={'uuid' : self.uuid})

    @modify_site
    def grant_open_access(self):
        """Allows to access the location without authentication."""
        self.open_access = 'y'
        self.save()

    def open_access_granted(self):
        return self.open_access == 'y'

    @modify_site
    def revoke_open_access(self):
        self.open_access = 'n'
        self.save()

    def can_access(self, user):
        """Determines if a user can access the location.

        Returns:
            True if the user is granted permission to access the
            location or it the location is open.
        """
        # Sanity check (this should normally be ensured by the caller).
        if user.site_id != self.site_id:
            return False
        return (self.open_access_granted()
                or self.permissions().get(user.id) != None)

    @modify_site
    def grant_access(self, user_uuid):
        """Grants access to the location to a given user.

        Args:
            user_uuid: string UUID of a user.

        Returns:
            (new Permission object, True) if access to the location was
                successfully granted.
            (existing Permission object, False) if user already had
                granted access to the location.

        Raises:
            LookupError: A site to which location belongs has no user
                with a given UUID.
        """
        user = self.site.users.find_item(uuid=user_uuid)
        if user is None:
            raise LookupError('User not found')
        permission = self.permissions().get(user.id)
        created = False
        if permission is None:
            created = True
            permission = Permission.objects.create(
                http_location_id=self.id, user_id=user.id, site_id=self.site_id)
        return (permission, created)

    @modify_site
    def revoke_access(self, user_uuid):
        """Revokes access to the location from a given user.

        Args:
            user_uuid: string UUID of a user.

        Raises:
            LookupError: Site has no user with a given UUID or the
                user can not access the location.
        """
        permission = self.get_permission(user_uuid)
        permission.delete()

    def get_permission(self, user_uuid):
        """Gets Permission object for a given user.

        Args:
            user_uuid: string UUID of a user.

        Raises:
            LookupError: No user with a given UUID or the user can not
                access the location.
        """
        user = self.site.users.find_item(uuid=user_uuid)
        if user is None:
            raise LookupError('User not found.')
        permission = self.permissions().get(user.id)
        if permission is None:
            raise LookupError('User can not access location.')
        return permission

    def allowed_users(self):
        """"Returns a list of users that can access the location."""
        # The code could access permission.user like this:
        # [perm.user for perm in self.permissions().itervalues()]
        # but this involves a single DB query per allowed user, going
        # through cached site.users involves no queries.
        return [self.site.users.find_item_by_pk(user_id)
                for user_id in self.permissions().keys()]

    def attributes_dict(self):
        """Returns externally visible attributes of the location resource."""
        result = {
            'path': self.path,
            'allowedUsers': [
                user.attributes_dict() for user in self.allowed_users()
                ],
            }
        if self.open_access_granted():
            result['openAccess'] = True
        return _add_common_attributes(self, result)

class Permission(ValidatedModel):
    """Connects a location with a user that can access the location.

    Attributes:
        http_location: The location to which the Permission object gives access.
        user: The user that is given access to the location.
    """

    http_location = models.ForeignKey(Location, related_name='+',
                                      on_delete=models.CASCADE)
    site = models.ForeignKey(Site, related_name='+',
                             on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name='+',
                             on_delete=models.CASCADE)

    def __unicode__(self):
        return f'{self.http_location}, {self.user.email}'

    def get_absolute_url(self):
        """Constructs URL of the permission resource."""
        return reverse('wwwhisper_allowed_user',
                kwargs={'location_uuid' : self.http_location.uuid,
                        'user_uuid': self.user.uuid})

    def attributes_dict(self):
        """Returns externally visible attributes of the permission resource."""
        return _add_common_attributes(
            self, {'user': self.user.attributes_dict()})

class Alias(ValidatedModel):
    """One of urls that can be used to access the site.

    Attributes:
      site: Site to which the alias belongs.
      url: Has form http(s)://domain[:port], default ports (80 for http,
         443 for https) are always stripped.
      uuid: Externally visible UUID of the alias.
    """
    class Meta:
        app_label = 'wwwhisper_auth'
        unique_together = ('site', 'url')

    site = models.ForeignKey(Site, related_name='+', on_delete=models.CASCADE)
    url = models.TextField(db_index=True)
    uuid = models.CharField(max_length=36, db_index=True,
                            editable=False, unique=True)

    def get_absolute_url(self):
        return reverse('wwwhisper_alias', kwargs={'uuid' : self.uuid})

    def attributes_dict(self):
        return _add_common_attributes(self, {'url': self.url})


class Collection(object):
    """A common base class for managing a collection of resources.

    All resources in a collection belong to a common site and only
    this site can manipulate the resouces.

    Resources in the collection are of the same type and need to be
    identified by an UUID.

    Attributes (Need to be defined in subclasses):
        item_name: Name of a resource stored in the collection.
        model_class: Class that manages storage of resources.
    """

    def __init__(self, site):
        self.site = site
        self.update_cache()

    def update_cache(self):
        self._cached_items_dict = {}
        self._cached_items_list = []
        for item in self.model_class.objects.filter(site_id=self.site.site_id):
            self._cached_items_dict[item.id] = item
            self._cached_items_list.append(item)
            # Use already retrieved site, do not retrieve it again.
            item.site = self.site
        self.cache_mod_id = self.site.mod_id

    def is_cache_obsolete(self):
        return self.site.mod_id != self.cache_mod_id

    def all(self):
        if self.is_cache_obsolete():
            self.update_cache()
        return self._cached_items_list

    def all_dict(self):
        if self.is_cache_obsolete():
            self.update_cache()
        return self._cached_items_dict

    def count(self):
        return len(self.all())

    def get_unique(self, filter_fun):
        """Finds a unique item that satisfies a given filter.

        Returns:
           The item or None if not found.
        """
        return next((x for x in self.all() if filter_fun(x)), None)

    def find_item(self, uuid):
        return self.get_unique(lambda item: item.uuid == uuid)

    def find_item_by_pk(self, pk):
        return self.all_dict().get(pk, None)

    @modify_site
    def delete_item(self, uuid):
        """Deletes an item with a given UUID.

        Returns:
           True if the item existed and was deleted, False if not found.
        """
        item = self.find_item(uuid)
        if item is None:
            return False
        item.delete()
        return True

    def _do_create_item(self, *args, **kwargs):
        """Only to be called by subclasses.

        Raises ValidationError if the item can not be created because
        it violates UNIQUE constraints of the DB.
        """
        try:
            item = self.model_class.objects.create(
                site=self.site, uuid=str(uuidgen.uuid4()), **kwargs)
        except IntegrityError as e:
            # In most cases UNIQUE constraint violation is detected by
            # the Django process which results in ValidationError. But
            # due to transaction isolation level that is used some
            # violations are not detected by Django in which case
            # IntegrityError is raised by the DB engine (translated to
            # ValidationError for consistency).
            raise ValidationError(str(e))
        item.site = self.site
        return item

class UsersCollection(Collection):
    """Collection of users resources."""

    item_name = 'user'
    model_class = User
    # When increased DB schema also needs to be altered to accept
    # longer values (Django uses 75 limit for models.EmailField).
    EMAIL_LEN_LIMIT = 75

    @modify_site
    def create_item(self, email):
        """Creates a new User object for the site.

        There may be two different users with the same email but for
        different sites.

        Raises:
            ValidationError if the email is invalid or if a site
            already has a user with such email.
            LimitExceeded if the site defines a maximum number of
            users and adding a new one would exceed this number.
        """
        users_limit = self.site.users_limit
        if (users_limit is not None and self.count() >= users_limit):
            raise LimitExceeded('Users limit exceeded')

        if len(email) > self.EMAIL_LEN_LIMIT:
            raise ValidationError('Email too long')

        encoded_email = _encode_email(email)
        if encoded_email is None:
            raise ValidationError('Invalid email format.')
        # Django 1.8 correctly sets last_login field to NULL for newly
        # created users. Earlier Django versions set this field to
        # date_joined and had a 'not NULL' constraint on the
        # field. For compatibility with old databases, old behavior is
        # preserved, last_login is initally set to a date when user is
        # created.
        try:
            return self._do_create_item(email=encoded_email,
                                        last_login=timezone.now())
        except ValidationError:
            raise ValidationError('User already exists.')


    def find_item_by_email(self, email):
        encoded_email = _encode_email(email)
        if encoded_email is None:
            return None
        return self.get_unique(lambda user: user.email == encoded_email)

class LocationsCollection(Collection):
    """Collection of locations resources."""

    # Can be safely risen to whatever value is needed.
    PATH_LEN_LIMIT = 300

    # TODO: These should rather also be all caps.
    item_name = 'location'
    model_class = Location

    def update_cache(self):
        super().update_cache()
        # Retrieves permissions for all locations of the site with a
        # single query.
        self._cached_permissions = {}
        for p in Permission.objects.filter(site=self.site):
            self._cached_permissions.setdefault(
                p.http_location_id, {})[p.user_id] = p

    def get_permissions(self, location_id):
        """Returns permissions for a given location of the site."""
        if self.is_cache_obsolete():
            self.update_cache()
        return self._cached_permissions.get(location_id, {})

    @modify_site
    def create_item(self, path):
        """Creates a new Location object for the site.

        The location path should be canonical and should not contain
        parts that are not used for access control (query, fragment,
        parameters). Location should not contain non-ascii characters.

        Raises:
            ValidationError if the path is invalid or if a site
            already has a location with such path.
            LimitExceeded if the site defines a maximum number of
            locations and adding a new one would exceed this number.
        """

        locations_limit = self.site.locations_limit
        if (locations_limit is not None and self.count() >= locations_limit):
            raise LimitExceeded('Locations limit exceeded')

        if not url_utils.is_canonical(path):
            raise ValidationError(
                'Path should be absolute and normalized (starting with / '\
                    'without /../ or /./ or //).')
        if len(path) > self.PATH_LEN_LIMIT:
            raise ValidationError('Path too long')
        if url_utils.contains_fragment(path):
            raise ValidationError(
                "Path should not contain fragment ('#' part).")
        if url_utils.contains_query(path):
            raise ValidationError(
                "Path should not contain query ('?' part).")
        if url_utils.contains_params(path):
            raise ValidationError(
                "Path should not contain parameters (';' part).")
        try:
            path.encode('ascii')
        except UnicodeError:
            raise ValidationError(
                'Path should contain only ascii characters.')
        try:
            return self._do_create_item(path=path)
        except ValidationError:
            raise ValidationError('Location already exists.')


    def find_location(self, canonical_path):
        """Finds a location that defines access to a given path on the site.

        Args:
            canonical_path: The path for which matching location is searched.

        Returns:
            The most specific location with path matching a given path or None
            if no matching location exists.
        """
        canonical_path_len = len(canonical_path)
        longest_matched_location = None
        longest_matched_location_len = -1

        for location in self.all():
            probed_path = location.path
            probed_path_len = len(probed_path)
            trailing_slash_index = None
            if probed_path[probed_path_len - 1] == '/':
                trailing_slash_index = probed_path_len - 1
            else:
                trailing_slash_index = probed_path_len

            if (canonical_path.startswith(probed_path) and
                probed_path_len > longest_matched_location_len and
                (probed_path_len == canonical_path_len or
                 canonical_path[trailing_slash_index] == '/')) :
                longest_matched_location_len = probed_path_len
                longest_matched_location = location
        return longest_matched_location

    def has_open_location(self):
        for location in self.all():
            if location.open_access_granted():
                return True
        return False

class AliasesCollection(Collection):
    item_name = 'alias'
    model_class = Alias
    # RFC 1035
    ALIAS_LEN_LIMIT = 8 + 253 + 6

    @modify_site
    def create_item(self, url):
        aliases_limit = self.site.aliases_limit
        if (aliases_limit is not None and self.count() >= aliases_limit):
            raise LimitExceeded('Aliases limit exceeded')
        if len(url) > self.ALIAS_LEN_LIMIT:
            raise ValidationError('Url too long')

        url = url.strip().lower()
        (valid, error) = url_utils.validate_site_url(url)
        if not valid:
            raise ValidationError('Invalid url: ' + error)
        url = url_utils.remove_default_port(url)
        try:
            return self._do_create_item(url=url)
        except ValidationError:
            raise ValidationError('Alias with this url already exists')

    def find_item_by_url(self, url):
        return self.get_unique(lambda item: item.url == url)

def _uuid2urn(uuid):
    return 'urn:uuid:' + uuid

def _add_common_attributes(item, attributes_dict):
    """Inserts common attributes of an item to a given dict.

    Attributes that are common for different resource types are a
    'self' link and an 'id' field.
    """
    attributes_dict['self'] = item.get_absolute_url()
    if hasattr(item, 'uuid'):
        attributes_dict['id'] = _uuid2urn(item.uuid)
    return attributes_dict

def _find(model_class, **kwargs):
    """Finds a single item satisfying a given expression.

    Args:
        model_class: Model that manages stored items.
        **kwargs: Filtering expression, at most one element can satisfy it.
    Returns:
        An item that satisfies expression or None.
    """
    items = [item for item in model_class.objects.filter(**kwargs)]
    count = len(items)
    assert count <= 1
    if count == 0:
        return None
    return items[0]

def _encode_email(email):
    """Encodes and validates email address.

    Email is converted to a lower case not to require emails to be added
    to the access control list with the same capitalization that the
    user signs-in with.
    """
    encoded_email = email.lower()
    if not is_email_valid(encoded_email):
        return None
    return encoded_email

def is_email_valid(email):
    return re.match(email_re.EMAIL_VALIDATION_RE, email)
