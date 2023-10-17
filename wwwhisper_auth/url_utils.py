# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

"""Functions that operate on an HTTP resource path."""

import posixpath
import urllib.request, urllib.parse, urllib.error
import re

def strip_query(path):
    """Strips query from a path."""
    query_start = path.find('?')
    if query_start != -1:
        return path[:query_start]
    return path

def decode(path):
    """Decodes URL encoded characters in path."""
    return urllib.parse.unquote_plus(path)

def collapse_slashes(path):
    """Replaces repeated path separators ('/') with a single one."""
    return re.sub('//+', '/', path)

def is_canonical(path):
    """True if path is absolute and normalized.

    Canonical path is unique, i.e. two different such paths are never
    equivalent.
    """
    # Posix recognizes '//' as a normalized path, but it is not
    # canonical (it is the same as '/').
    if path == '' or not posixpath.isabs(path) or path.startswith('//'):
        return False
    # Normpath removes trailing '/'.
    normalized_path =  posixpath.normpath(path)
    if (normalized_path != path and normalized_path + '/' != path):
        return False
    return True

def contains_fragment(path):
    """True if path contains fragment id ('#' part)."""
    return path.count('#') != 0

def contains_query(path):
    """True if path contains query string ('?' part)."""
    return path.count('?') != 0

def contains_params(path):
    """True if path contains params (';' part)."""
    return path.count(';') != 0

# Path where successful login redirects is stored in email
# verification token, so should not be too long.
REDIRECTION_PATH_LIMIT = 200
def validate_redirection_target(path):
    """Checks if login can safely redirect to a path.

    For example, if instead of a path a full url is used (with a
    domain part), the redirect could leak a login token in the Referer
    header (not an obvious problem since token is intended to be one
    time, but better to prevent it).

    These are conservative checks. Discarding a valid path is not a
    distaster, because login then redirects to '/' and is still
    successful.
    """
    if len(path) > REDIRECTION_PATH_LIMIT:
        return False
    parsed_url = urllib.parse.urlparse(path)
    for attr in ['scheme', 'netloc', 'username', 'password']:
        val = getattr(parsed_url, attr, None)
        if  val is not None and val != '':
            return False
    # Filter new lines for additional protection from Location header
    # split into two headers (should be also prevented by Django).
    return (is_canonical(parsed_url.path) and
            not '\n' in path)

def validate_site_url(url):
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme == '':
        return (False, 'missing scheme (http:// or https://)')
    if parsed_url.scheme not in ('http', 'https'):
        return (False, 'incorrect scheme (should be http:// or https://)')
    if parsed_url.netloc == '':
        return (False, 'missing domain')

    for attr in ['path', 'username', 'query', 'params', 'fragment', 'password']:
        val = getattr(parsed_url, attr, None)
        if val is not None and val != '':
            return (False, 'contains ' + attr)
    return (True, None)

def remove_default_port(url):
    parts = url.split(':')
    if len(parts) != 3:
        return url
    scheme, rest, port = parts
    if ((scheme == 'https' and port == '443') or
        (scheme == 'http' and port == '80')):
        return f'{scheme}:{rest}'
    return url
