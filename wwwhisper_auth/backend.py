# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

"""Authentication backend used by wwwhisper_auth."""

from django.contrib.auth.backends import ModelBackend
from django.forms import ValidationError

from wwwhisper_auth import login_token
from wwwhisper_auth.models import LimitExceeded

class AuthenticationError(Exception):
    pass

class VerifiedEmailBackend(ModelBackend):
    """"Backend that authenticates the user using verified email"""

    def authenticate(self, request, site, site_url, token):
        """Token was a part of a login url that proves email ownership.

        Returns:
             Object that represents a user with the verified email
             encoded in the token or None.
        Raises:
            AuthenticationError: token is invalid, expired or
            generated for a different site.
        """
        verified_email = login_token.load_login_token(site, site_url, token)
        if verified_email is None:
            raise AuthenticationError('Token invalid or expired.')

        return site.users.find_item_by_email(verified_email)
