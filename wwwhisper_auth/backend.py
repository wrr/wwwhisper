# wwwhisper - web access control.
# Copyright (C) 2012-2023 Jan Wrobel <jan@mixedbit.org>

"""Authentication backend used by wwwhisper_auth."""

from django.contrib.auth.backends import ModelBackend

from wwwhisper_auth import login_token

class AuthenticationError(Exception):
    pass

class VerifiedEmailBackend(ModelBackend):
    """"Backend that authenticates the user using verified email"""

    def authenticate(self, request, site, token):
        """Token was a part of a login url that proves email ownership.

        Returns:
             Object that represents a user with the verified email
             encoded in the token or None.
        Raises:
            AuthenticationError: token is invalid, expired or
            generated for a different site.
        """
        verified_email = login_token.load_login_token(site, token)
        if verified_email is not None:
            user = site.users.find_item_by_email(verified_email)
            if user:
                # user can be None only if the user was deleted after the
                # token was generated.
                return user
        raise AuthenticationError('Token invalid or expired.')
