#!/usr/bin/env python

# wwwhisper - web access control.
# Copyright (C) 2012-2015 Jan Wrobel <jan@mixedbit.org>

"""Configures wwwhisper for a given site.

Creates site-specific Django settings files. Creates configuration
file for supervisor (http://supervisord.org/), which allows to
start wwwhisper application under the control of the supervisor
daemon. Initializes database to store access control list.
"""

import getopt
import os
import sys
import random
import subprocess

from urllib.parse import urlparse

SITES_DIR = 'sites'
DJANGO_CONFIG_DIR = 'django'
DJANGO_CONFIG_FILE = 'site_settings.py'
SUPERVISOR_CONFIG_DIR = 'supervisor'
SUPERVISOR_CONFIG_FILE= 'site.conf'
DB_DIR = 'db'
DB_NAME = 'acl_db'

WWWHISPER_USER = 'wwwhisper'
WWWHISPER_GROUP = 'www-data'
DEFAULT_INITIAL_LOCATIONS = ['/', '/wwwhisper/admin/']

def err_quit(errmsg):
    """Prints an error message and quits."""
    print(errmsg, file=sys.stderr)
    sys.exit(1)

def usage():
    print("""

Generates site-specific configuration files and initializes wwwhisper database.

--site-url, --admin-email and --location are only initial settings,
wwwhisper web application can be used to add/remove locations and
grant/revoke access to other users.

Usage:

  %(prog)s
      -s, --site-url A URL of a site to protect in a form
            scheme://domain(:port). Scheme can be https (recomended) or http.
            Port defaults to 443 for https and 80 for http.
      -a, --admin-email An email of a user that will be allowed to access
            initial locations. Multiple emails can be given with multiple
            -a directives.
      -l, --location A location that admin users will be able to access
            initially (defaults to /wwwhisper/admin/ and /). Multiple
            locations can be given with mutliple -l directives.
      -o, --output-dir A directory to store configuration (defaults to
            '%(config-dir)s' in the wwwhisper directory).
      -n, --no-supervisor Do not generate config file for supervisord.
""" % {'prog': sys.argv[0], 'config-dir': SITES_DIR})
    sys.exit(1)

def generate_secret_key():
    """Generates a secret key to be used with django setting file.

    Uses cryptographically secure generator. Displays a warning and
    generates a key that does not parse if the system does not provide
    a secure generator.
    """
    try:
        secure_generator = random.SystemRandom()
        allowed_chars='abcdefghijklmnopqrstuvwxyz'\
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'\
            '!@#$%^&*(-_=+'
        key_length = 50
        # This gives log2((26+26+10+14)**50) == 312 bits of entropy
        return ''.join(
            [secure_generator.choice(allowed_chars) for i in range(key_length)])
    except NotImplementedError:
        # The system does not support generation of secure random
        # numbers. Return something that raises parsing error and
        # points the user to a place where secret key needs to be
        # filled manually.
        message = ('Your system does not allow to automatically '
                   'generate secure secret keys.')
        print(('WARNING: You need to edit configuration file '
               'manually. ' + message), file=sys.stderr)
        return ('\'---' + message + ' Replace this text with a long, '
                'unpredictable secret string (at least 50 characters).')


def write_to_file(dir_path, file_name, file_content):
    """Writes a string to a file with a given name in a given directory.

    If the file does not exist it is created. Dies on error.
    """
    file_path = os.path.join(dir_path, file_name)
    try:
        with open(file_path, 'w') as destination:
            destination.write(file_content)
    except IOError as ex:
        err_quit('Failed to create file %s: %s.' % (file_path, ex))

def create_django_config_file(site_url, emails, locations, django_config_path,
                              db_path):
    """Creates a site specific Django configuration file.

    Settings that are common for all sites reside in the
    wwwhisper_service module.
    """

    settings = """# Don't share this with anybody.
SECRET_KEY = '%s'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '%s',
    }
}

WWWHISPER_INITIAL_SITE_URL = '%s'
WWWHISPER_INITIAL_ADMINS = (%s,)
WWWHISPER_INITIAL_LOCATIONS = (%s,)
""" % (generate_secret_key(),
       os.path.join(db_path, DB_NAME),
       site_url,
       ", ".join("'" + email + "'" for email in emails),
       ", ".join("'" + location + "'" for location in locations))
    write_to_file(django_config_path, '__init__.py', '')
    write_to_file(django_config_path, DJANGO_CONFIG_FILE, settings)

def default_port(scheme):
    """Returns default port for a given scheme (https or http) as string."""
    if scheme == "https":
        return "443"
    elif scheme == "http":
        return "80"
    assert False

def is_default_port(scheme, port):
    """Checks if a port (string) is default for a given scheme."""
    return default_port(scheme) == port

def create_supervisor_config_file(
    site_dir_name, wwwhisper_path, site_config_path, supervisor_config_path):
    """Creates site-specific supervisor config file.

    The file allows to start the wwwhisper application for the site.
    """
    settings = """[program:wwwhisper-%s]
command=%s/run_wwwhisper_for_site.sh -d %s
user=%s
group=%s
autorestart=true
stopwaitsecs=2
stopsignal=INT
stopasgroup=true
""" % (site_dir_name, wwwhisper_path, site_config_path, WWWHISPER_USER,
       WWWHISPER_GROUP)
    write_to_file(
        supervisor_config_path, SUPERVISOR_CONFIG_FILE, settings)

def parse_url(url):
    """Parses and validates a URL.

    URL needs to have scheme://hostname:port format, scheme and hostname
    are mandatory, port is optional. Converts scheme and hostname to
    lower case and returns scheme, hostname, port (as string) tupple.
    Dies if the URL is invalid.
    """

    err_prefix = 'Invalid site address - '
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme.lower()
    if scheme == '' or scheme not in ('https', 'http'):
        err_quit(err_prefix + 'scheme missing. '
                 'URL schould start with https:// (recommended) or http://')
    if parsed_url.hostname is None:
        err_quit(err_prefix + 'host name missing.'
                 'URL should include full host name (like https://foo.org).')
    if parsed_url.path  != '':
        err_quit(err_prefix + 'URL should not include resource path '
                 '(/foo/bar).')
    if parsed_url.params  != '':
        err_quit(err_prefix + 'URL should not include parameters (;foo=bar).')
    if parsed_url.query  != '':
        err_quit(err_prefix + 'URL should not include query (?foo=bar).')
    if parsed_url.fragment  != '':
        err_quit(err_prefix + 'URL should not include query (#foo).')
    if parsed_url.username != None:
        err_quit(err_prefix + 'URL should not include username (foo@).')

    hostname = parsed_url.hostname.lower()
    port = None
    if parsed_url.port is not None:
        port = str(parsed_url.port)
    else:
        port = default_port(scheme)

    return (scheme, hostname, port)

def main():
    site_url = None
    emails = []
    locations = []
    wwwhisper_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    output_path = os.path.join(wwwhisper_path, SITES_DIR)
    need_supervisor = True

    try:
        optlist, _ = getopt.gnu_getopt(
            sys.argv[1:],
            's:a:l:o:nh',
            ['site-url=',
             'admin-email=',
             'locations=',
             'output-dir=',
             'no-supervisor',
             'help'])

    except getopt.GetoptError as ex:
        print('Arguments parsing error: ', ex)
        usage()

    for opt, arg in optlist:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-s', '--site-url'):
            site_url = arg
        elif opt in ('-a', '--admin-email'):
            emails.append(arg)
        elif opt in ('-l', '--location'):
            locations.append(arg)
        elif opt in ('-o', '--output-dir'):
            output_path = arg
        elif opt in ('-n', '--no-supervisor'):
            need_supervisor = False
        else:
            assert False, 'unhandled option'


    if site_url is None:
        err_quit('--site-url is missing.')
    if not emails:
        err_quit('--admin-email is missing.')
    if not locations:
        locations += DEFAULT_INITIAL_LOCATIONS

    (scheme, hostname, port) = parse_url(site_url)
    site_url = scheme + '://' + hostname
    # URL should include the port number only if it is non-default.
    if not is_default_port(scheme, port):
        site_url += ":" + port
    # But settings directory name should always include the port.
    site_dir_name = '.'.join([scheme, hostname, port])

    site_config_path = os.path.join(output_path, site_dir_name)
    django_config_path = os.path.join(site_config_path, DJANGO_CONFIG_DIR)
    db_path = os.path.join(site_config_path, DB_DIR)
    supervisor_config_path = os.path.join(
        site_config_path, SUPERVISOR_CONFIG_DIR)
    try:
        os.umask(0o067)
        os.makedirs(site_config_path, 0o710)
        os.umask(0o077)
        os.makedirs(django_config_path)
        os.makedirs(db_path)
        if need_supervisor:
            os.makedirs(supervisor_config_path)
    except OSError as ex:
        err_quit('Failed to initialize configuration directory %s: %s.'
                 % (site_config_path, ex))

    create_django_config_file(
        site_url, emails, locations, django_config_path, db_path)

    if need_supervisor:
        create_supervisor_config_file(
            site_dir_name, wwwhisper_path, site_config_path,
            supervisor_config_path)

    manage_path = os.path.join(wwwhisper_path, 'manage.py')
    # Use Python from the virtual environment to run syncdb.
    exit_status = subprocess.call(
        ['/usr/bin/env', 'python', manage_path, 'migrate',
         '--run-syncdb', '--pythonpath=' + django_config_path])
    if exit_status != 0:
        err_quit('Failed to initialize wwwhisper database.');

    print('Site configuration successfully created.')

if __name__ == '__main__':
    main()
