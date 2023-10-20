# wwwhisper - web access control.
# Copyright (C) 2012-2015 Jan Wrobel <jan@mixedbit.org>

"""Utils to simplify REST style views.

Contains classes representing commonly used HTTP responses with
appropriate content types and encoding.
"""

import functools
import json
import logging
import re
import traceback

from django.conf import settings
from django.http import HttpResponse
from django.utils.crypto import constant_time_compare
from django.views.decorators.cache import patch_cache_control
from django.views.generic import View

from wwwhisper_auth import models

logger = logging.getLogger(__name__)

TEXT_MIME_TYPE = 'text/plain; charset=utf-8'
HTML_MIME_TYPE = 'text/html; charset=utf-8'
JSON_MIME_TYPE = 'application/json; charset=utf-8'
JS_MIME_TYPE = 'text/javascript; charset=UTF-8'

_accepts_html_re = re.compile('text/(html|\*)|(\*/\*)')

def accepts_html(accept_header):
    """Checks if the 'Accept' header accepts html response.

    Args:
       accept_header: A string, for example 'audio/*, text/plain, text/*'
    """
    return (accept_header is not None
            and _accepts_html_re.search(accept_header) is not None)

def set_logged_in_cookie(response):
    response.set_cookie(key=settings.LOGGED_IN_COOKIE_NAME,
                        value='y',
                        max_age=settings.LOGGED_IN_COOKIE_AGE,
                        path='/',
                        httponly=False,
                        samesite=settings.LOGGED_IN_COOKIE_SAMESITE)

def delete_logged_in_cookie(response):
    response.delete_cookie(key=settings.LOGGED_IN_COOKIE_NAME,
                           samesite=settings.LOGGED_IN_COOKIE_SAMESITE)

class HttpResponseOK(HttpResponse):
    """"Request succeeded.

    Response contains plain text.
    """

    def __init__(self, message):
        super().__init__(message,
                         content_type=TEXT_MIME_TYPE,
                         status=200)


class HttpResponseOKJson(HttpResponse):
    def __init__(self, attributes_dict):
        super().__init__(json.dumps(attributes_dict),
                         content_type=JSON_MIME_TYPE,
                         status=200)

class HttpResponseOKHtml(HttpResponse):
    def __init__(self, body):
        super().__init__(body,
                         content_type=HTML_MIME_TYPE,
                         status=200)

class HttpResponseOKJs(HttpResponse):
    def __init__(self, body):
        super().__init__(body,
                         content_type=JS_MIME_TYPE,
                         status=200)

class HttpResponseNoContent(HttpResponse):
    """Request succeeded, response body is empty."""

    def __init__(self):
        super().__init__(status=204)
        self.__delitem__('Content-Type')

class HttpResponseCreated(HttpResponse):
    """Request succeeded, a resource was created.

    Contains json representation of the created resource.
    """

    def __init__(self, attributes_dict):
        """
        Args:
            attributes_dict: A dictionary containing all attributes of
                the created resource. The attributes are serialized to
                json and returned in the response body
        """

        super().__init__(json.dumps(attributes_dict),
                         content_type=JSON_MIME_TYPE,
                         status=201)

class HttpResponseRedirect(HttpResponse):
    """See other resource.

    302 is used, but 303 or 307 should also work (for example oauth2,
    which depends heavily on redirections, uses 302 in examples but
    allows implementations to use other codes).
    """

    def __init__(self, location):
        super().__init__(content_type=JSON_MIME_TYPE,
                         status=302)
        self['Location'] = location

class HttpResponseNotAuthenticated(HttpResponse):
    """User is not authenticated.

    Request can be retried after successul authentication.
    """

    def __init__(self, html_response=None):
        """Sets WWW-Authenticate header required by the HTTP standard."""
        if html_response is None:
            body, content_type = 'Authentication required.', TEXT_MIME_TYPE
        else:
            body, content_type = html_response, HTML_MIME_TYPE
        super().__init__(body, content_type=content_type, status=401)
        self['WWW-Authenticate'] = 'VerifiedEmail'
        delete_logged_in_cookie(self)

class HttpResponseNotAuthorized(HttpResponse):
    """User is authenticated but is not authorized to access a resource."""

    def __init__(self, html_response=None):
        if html_response is None:
            body, content_type = 'User not authorized.', TEXT_MIME_TYPE
        else:
            body, content_type = html_response, HTML_MIME_TYPE
        super().__init__(body, content_type=content_type, status=403)

class HttpResponseBadRequest(HttpResponse):
    """Request invalid.

    The most generic error status, returned when none of the more
    specific statuses is appropriate.
    """

    def __init__(self, message):
        logger.debug(f'Bad request {message}')
        super().__init__(message, content_type=TEXT_MIME_TYPE, status=400)

class HttpResponseLimitExceeded(HttpResponse):
    """Too many resource are already created, a new one can not be added."""

    def __init__(self, message):
        logger.debug(f'Limit exceeded {message}')
        super().__init__(message, content_type=TEXT_MIME_TYPE, status=400)

class HttpResponseNotFound(HttpResponse):

    def __init__(self, message):
        logger.debug(f'Not found {message}')
        super().__init__(message, content_type=TEXT_MIME_TYPE, status=404)

class HttpResponseServiceUnavailable(HttpResponse):

    def __init__(self, message):
        logger.warning(f'Service unavailable {message}')
        super().__init__(message, content_type=TEXT_MIME_TYPE, status=503)

class HttpResponseInternalError(HttpResponse):

    def __init__(self, message):
        logger.warning(f'Internal error {message}')
        super().__init__(message, content_type=TEXT_MIME_TYPE, status=500)

def disallow_cross_site_request(decorated_method):
    """Drops a request if it has any indicators of a cross site request."""
    @functools.wraps(decorated_method)
    def wrapper(self, request, *args, **kwargs):
        # Validate CSRF token unless test environment disabled CSRF protection.
        if (not getattr(request, '_dont_enforce_csrf_checks', False)
            and not _csrf_token_valid(request)):
            return HttpResponseBadRequest(
                'CSRF token missing or incorrect.')
        return decorated_method(self, request, *args, **kwargs)
    return wrapper

def never_ever_cache(decorated_method):
    """Like Django @never_cache but sets more valid cache disabling headers.

    @never_cache only sets Cache-Control:max-age=0 which is not
    enough. For example, with max-axe=0 Firefox returns cached results
    of GET calls when it is restarted.
    """
    @functools.wraps(decorated_method)
    def wrapper(*args, **kwargs):
        response = decorated_method(*args, **kwargs)
        patch_cache_control(
            response, no_cache=True, no_store=True, must_revalidate=True,
            max_age=0)
        return response
    return wrapper

class RestView(View):
    """A common base class for all REST style views.

    Disallows all cross origin requests. Disables caching of
    responses. For POST and PUT methods, deserializes method arguments
    from a json encoded request body. If a specific method is not
    implemented in a subclass, or if it does not accept arguments
    passed in the body, or if some arguments are missing, an
    appropriate error is returned to the client.
    """

    @disallow_cross_site_request
    @never_ever_cache
    def dispatch(self, request, *args, **kwargs):
        """Dispatches a method to a subclass.

        kwargs contains arguments that are passed as a query string,
        for PUT and POST arguments passed in a json request body are
        added to kwargs, conflicting names result in an error.
        """
        method = request.method.lower()
        # Parse body as json object if it is not empty (empty body
        # contains '--BoUnDaRyStRiNg--')
        if ((method == 'post' or method == 'put')
            and request.body and request.body[0] != '-'):
            try:
                if not _utf8_encoded_json(request):
                    return HttpResponseBadRequest(
                        'Invalid Content-Type (only '
                        f"'{JSON_MIME_TYPE}' is acceptable).")

                json_args = json.loads(request.body)
                for k in json_args:
                    if k in kwargs:
                        return HttpResponseBadRequest(
                            'Invalid argument passed in the request body.')
                    else:
                        kwargs[k] = json_args[k]
                kwargs.update()
            except ValueError as err:
                logger.debug(
                    f'Failed to parse the request body a as json object: {err}')
                return HttpResponseBadRequest(
                    'Failed to parse the request body as a json object.')
        try:
            return super().dispatch(request, *args, **kwargs)
        except TypeError as err:
            trace = "".join(traceback.format_exc())
            logger.debug(
                f'Invalid arguments, handler not found: {err}\n{trace}')
            return HttpResponseBadRequest('Invalid request arguments')

def _csrf_token_valid(request):
    """Checks if a valid CSRF token is set in the request header.

    Django CSRF protection middleware is not used directly because it
    allows cross origin GET requests and does strict referer checking
    for HTTPS requests.

    GET request are believed to be safe because they do not modify
    state, but they do require special care to make sure the result is
    not leaked to the calling site. Under some circumstances resulting
    json, when interpreted as script or css, can possibly be
    leaked. The simplest protection is to disallow cross origin GETs.

    Strict referer checking for HTTPS requests is a protection method
    suggested in a study 'Robust Defenses for Cross-Site Request
    Forgery'. According to the study, only 0.2% of users block the
    referer header for HTTPS traffic. Many think the number is low
    enough not to support these users. The methodology used in the
    study had a considerable flaw, and the actual number of users
    blocing the header may be much higher.

    Because all protected methods are called with Ajax, for most
    clients a check that ensures a custom header is set is sufficient
    CSRF protection. No token is needed, because browsers disallow
    setting custom headers for cross origin requests. Unfortunately,
    legacy versions of some plugins did allow such headers. To protect
    users of these plugins a token needs to be used. The problem that
    is left is a protection of a user that is using a legacy plugin in
    a presence of an active network attacker. Such attacker can inject
    his token over HTTP, and exploit the plugin to send the token over
    HTTPS. The impact is mitigated if Strict Transport Security header
    is set (as recommended) for all wwwhisper protected sites (not
    perfect solution, because the header is supported only by the
    newest browsers).
    """
    # TODO: rename this header to WWWHISPER_CRSFTOKEN.
    header_token = request.META.get('HTTP_X_CSRFTOKEN', '')
    cookie_token = request.COOKIES.get(settings.CSRF_COOKIE_NAME, '')
    if (len(header_token) < 32 or
        not constant_time_compare(header_token, cookie_token)):
        return False
    return True

def _utf8_encoded_json(request):
    """Checks if content of the request is defined to be utf-8 encoded json.

    'Content-type' header should be set to 'application/json;
    charset=utf-8'.  The function allows whitespaces around the two
    segments an is case-insensitive.
    """
    content_type = request.META.get('CONTENT_TYPE', '')
    parts = content_type.split(';')
    if (len(parts) != 2 or
        parts[0].strip().lower() != 'application/json' or
        parts[1].strip().lower() != 'charset=utf-8'):
        return False
    return True
