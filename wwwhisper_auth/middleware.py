# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse

from wwwhisper_auth import http
from wwwhisper_auth.models import SINGLE_SITE_ID
from wwwhisper_auth import url_utils

import wwwhisper_auth.site_cache
import logging

logger = logging.getLogger(__name__)

SECURE_PROXY_SSL_HEADER = getattr(settings, 'SECURE_PROXY_SSL_HEADER')[0]

class SetSiteMiddleware(object):
    """Associates a request with the only site that is in a db.

    The middleware is used for setups in which a single wwwhisper
    instance serves a single site (all standalone setups). In
    wwwhisper as a service setup, a single wwwhisper instance serves
    multiple sites.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.sites = wwwhisper_auth.site_cache.CachingSitesCollection()

    def __call__(self, request):
        request.site = self.sites.find_item(SINGLE_SITE_ID)
        return self.get_response(request)

class SiteUrlMiddleware(object):
    """Validates and sets site_url for the request.

    A Site-Url header must carry one of site's aliases otherwise a
    request is rejected. If Site-Url contains http://host_foo address
    which is not allowed but https://host_foo is allowed, redirect is
    returned.

    Sets X-Forwarded-Host to match Site-Url. X-Forwarded-Host is used
    by Django to generate redirects.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def _alias_defined(self, site, url):
        return site.aliases.find_item_by_url(url) is not None

    def _get_full_path(self, request):
        full_path = request.get_full_path()
        auth_request_prefix = reverse('auth-request') + '?path='
        if full_path.startswith(auth_request_prefix):
            full_path = full_path[len(auth_request_prefix):]
        return full_path

    def _needs_https_redirect(self, site, scheme, host):
        return scheme == 'http' and self._alias_defined(site, 'https://' + host)

    def _site_url_invalid(self, request, scheme, host):
        if self._needs_https_redirect(request.site, scheme, host):
            logger.debug('Request over http, redirecting to https')
            return redirect('https://' + host + self._get_full_path(request))
        msg = 'Invalid request URL, you can use wwwhisper admin to allow ' \
            'requests from this address.'
        logger.warning(msg)
        return http.HttpResponseBadRequest(msg)

    def __call__(self, request):
        url = request.META.get('HTTP_SITE_URL', None)
        if url is None:
            return http.HttpResponseBadRequest('Missing Site-Url header')
        url = url_utils.remove_default_port(url)
        parts = url.split('://', 1)
        if len(parts) != 2:
            return http.HttpResponseBadRequest('Site-Url has incorrect format')
        scheme, host = parts
        if not self._alias_defined(request.site, url):
            return self._site_url_invalid(request, scheme, host)
        request.site_url = url
        request.META[SECURE_PROXY_SSL_HEADER] = scheme
        request.META['HTTP_X_FORWARDED_HOST'] = host
        # TODO: use is_secure() instead
        request.https = (scheme == 'https')
        return self.get_response(request)


class ProtectCookiesMiddleware(object):
    """Sets 'secure' flag for all cookies if request is over https.

    The flag prevents cookies from being sent with HTTP requests.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # response.cookies is SimpleCookie (Python 'Cookie' module).
        for cookie in response.cookies.values():
            if request.https:
                cookie['secure'] = True
        return response


class SecuringHeadersMiddleware(object):
    """Sets headers that impede clickjacking + content sniffing related attacks.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-Frame-Options'] = 'SAMEORIGIN'
        response['X-Content-Type-Options'] = 'nosniff'
        return response
