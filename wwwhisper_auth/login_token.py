# wwwhisper - web access control.
# Copyright (C) 2016-2023 Jan Wrobel <jan@mixedbit.org>

"""Functions for generating and validating login tokens."""

import datetime
import urllib.parse

from django.conf import settings
from django.core import signing
from django.urls import reverse


def _datetime_to_timestamp(datetime_arg):
    """Returns float that has microseconds resolution"""
    # It does not matter what timezone and start time is used here.
    # It is only important that the output of this function increases
    # when datetime_arg increases.
    return (datetime_arg - datetime.datetime(2015,1,1)).total_seconds()


# TODO: tokens can no longer be generated for not existing users,
# update these functions to avoid duplicated users lookups.

def generate_login_token(site, email):
    """Returns a signed token to login a user with a given email.

    The token should be emailed to the user to verify that the user
    indeed owns the email.

    The token is valid only for the current site (it will be discarded
    if it is submitted to a different site protected by the same
    wwwhisper instance).

    The token allows only for one succesful login.
    """
    timestamp = 0
    user = site.users.find_item_by_email(email)
    if user is not None and user.last_login is not None:
        # Successul login changes user.last_login, which invalidates
        # all tokens generated for the user.
        timestamp = _datetime_to_timestamp(user.last_login)
    site_id = site.site_id
    token_data = {
        'site': site_id,
        'email': email,
        'timestamp': timestamp
    }
    return signing.dumps(token_data, salt=site_id, compress=True)

def load_login_token(site, token):
    """Verifies the login token.

    Returns email encoded in the token if the token is valid, None
    otherwise.
    """
    try:
        site_id= site.site_id
        token_data = signing.loads(
            token, salt=site_id, max_age=settings.AUTH_TOKEN_SECONDS_VALID)
        # site_id in the token seems like an overkill. site_id is
        # already used as salt which should give adequate protection
        # against using a token for sites different than the one for
        # which the token was generated.
        if token_data['site'] != site_id:
            return None
        email = token_data['email']
        timestamp = token_data['timestamp']
        user = site.users.find_item_by_email(email)
        if user is not None and user.last_login is not None:
            if _datetime_to_timestamp(user.last_login) != timestamp:
                return None
        elif timestamp != 0:
            return None
        return email
    except signing.BadSignature:
        return None

def generate_login_url(site, email, root_url, next_path):
    """Returns a login URL for a user with a given email.

    The returned URL will log the user in after it is opened in a
    browser. The URL points to the 'login-check-token' end point of
    the root_url, with token and next=next_path appended as hash
    parameters.
    """
    token = generate_login_token(site=site, email=email)
    params = urllib.parse.urlencode(dict(next=next_path, token=token), safe=':')
    return f'{root_url}{reverse("login-check-token")}#{params}'
