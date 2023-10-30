# wwwhisper - web access control.
# Copyright (C) 2018-2023 Jan Wrobel <jan@mixedbit.org>

"""Creates initial DB entries for newly created wwwhisper app.

The entries are needed so the initial admin user can open the
wwwhisper admin app, create additional users and grant access to them.
"""

from django.apps import AppConfig
from django.forms import ValidationError
from django.conf import settings
from django.db.models import signals
from django.core.exceptions import ImproperlyConfigured

SITE_URL = getattr(settings, 'WWWHISPER_INITIAL_SITE_URL', None)

def _create_site():
    """Creates a site configured in settings.py."""
    from wwwhisper_auth import models as auth_models
    try:
        site =  auth_models.SitesCollection().create_item(
            auth_models.SINGLE_SITE_ID)
        site.aliases.create_item(SITE_URL)
        return site
    except ValidationError as ex:
        raise ImproperlyConfigured(f'Failed to create site {SITE_URL}') from ex

def _create_initial_locations(site):
    """Creates all locations listed in WWWHISPER_INITIAL_LOCATIONS setting."""
    locations_paths = getattr(settings, 'WWWHISPER_INITIAL_LOCATIONS', [])
    for path in locations_paths:
        try:
            site.locations.create_item(path)
        except ValidationError as ex:
            raise ImproperlyConfigured(
                f'Failed to create location {path}') from ex

def _create_initial_admins(site):
    """Creates all users listed in WWWHISPER_INITIAL_ADMINS setting."""
    emails = getattr(settings, 'WWWHISPER_INITIAL_ADMINS', [])
    for email in emails:
        try:
            _user = site.users.create_item(email)
        except ValidationError as ex:
            raise ImproperlyConfigured(
                f'Failed to create admin user {email}') from ex

def _grant_admins_access_to_all_locations(site):
    for user in site.users.all():
        for location in site.locations.all():
            location.grant_access(user.uuid)

# pylint: disable=unused-argument
def grant_initial_permission(sender, *args, **kwargs):
    """Configures initial permissions for wwwhisper protected site.

    Allows users with emails listed on WWWHISPER_INITIAL_ADMINS to
    access locations listed on WWWHISPER_INITIAL_LOCATIONS. The
    function is invoked when the wwwhisper database is created.
    Initial access rights is the only difference between users listed
    on WWWHISPER_INITIAL_ADMINS and other users. The admin application
    manages access to itself, so it can be used to add and remove
    users that can perform administrative operations.
    """
    if kwargs.get('interactive', True):
        site = _create_site()
        _create_initial_locations(site)
        _create_initial_admins(site)
        _grant_admins_access_to_all_locations(site)



class Config(AppConfig):
    name = 'wwwhisper_admin'

    def ready(self):
        if SITE_URL:
            # Invoke grant_initial_permission function defined in this module
            # when database is created
            signals.post_migrate.connect(
                grant_initial_permission,
                sender=self)
