# Django settings for wwwhisper_service project.

DEBUG = False
TEMPLATE_DEBUG = DEBUG


# If WWWHISPER_STATIC is set, wwwhisper serves static html resources
# needed for login and for the admin application (this is not needed
# if these resources are served directly by a frontend server).
WWWHISPER_STATIC = 'www_static'
# Serve all wwwhisper resources from /wwwhisper/ prefix (/wwwhisper/auth/,
# /wwwhisper/admin/)
WWWHISPER_PATH_PREFIX = 'wwwhisper/'
# Static files are also served from /wwwhisper/ prefix.
import wwwhisper_service.cdn_container
STATIC_URL = wwwhisper_service.cdn_container.CDN_CONTAINER + '/' + 'wwwhisper/'

import os
import sys

TESTING = sys.argv[1:2] == ['test']

if TESTING:
    from wwwhisper_service.test_site_settings import *
else:
    from site_settings import *

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
TOKEN_EMAIL_FROM = 'verify@wwwhisper.io'
AUTH_TOKEN_SECONDS_VALID = 60 * 30

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# Postgres backend requires this to be set.
TIME_ZONE = 'UTC'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = False

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = False

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = False

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
#        'LOCATION': 'unique-snowflake'
    }
}

if DEBUG:
    INTERNAL_IPS = ('127.0.0.1',)

SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True
# Site-Url from frontend server is validated by wwwhisper (checked
# against a list of aliases that are stored in the DB) and set in the
# X-Forwarded-Host. Host header is not used.
ALLOWED_HOSTS = ['*']

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

MIDDLEWARE = [
    #'wwwhisper_service.profile.ProfileMiddleware',
    # Must go before CommonMiddleware, to set a correct url to which
    # CommonMiddleware redirects.
    'wwwhisper_auth.middleware.SetSiteMiddleware',
    'wwwhisper_auth.middleware.SiteUrlMiddleware',
    'django.middleware.common.CommonMiddleware',
    # Must be placed before session middleware to alter session cookies.
    'wwwhisper_auth.middleware.ProtectCookiesMiddleware',
    'wwwhisper_auth.middleware.SecuringHeadersMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

# Don't use just sessionid, to avoid collision with apps protected by wwwhisper.
SESSION_COOKIE_NAME = 'wwwhisper-sessionid'
CSRF_COOKIE_NAME = 'wwwhisper-csrftoken'
CSRF_COOKIE_SAMESITE = 'Strict'

# Make the session valid for four weeks (discarding sessions after
# browser close is inconvenient with login tokens).
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 2419200
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# A helper cookie set together with the session cookie to indicate
# that the user is logged-in. Needed because the session cookie is
# http only and cannot be read from JavaScript.
#
# Lack of this cookie prevents wwwhisper iframe from being injected,
# so there are no /wwwhisper/auth/whoami requests for not logged-in
# visitors of open locations.
#
# No security important functionality should depend on this cookie
# being in the correct state (present for logged-in users, missing for
# not logged-in users).
LOGGED_IN_COOKIE_NAME = 'wwwhisper-in'
LOGGED_IN_COOKIE_AGE = 2419200
LOGGED_IN_COOKIE_SAMESITE = 'Strict'

ROOT_URLCONF = 'wwwhisper_service.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'wwwhisper_service.wsgi.application'

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
    'wwwhisper_auth',
    'wwwhisper_admin'
]

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
STATIC_ROOT = os.path.join(PROJECT_DIR, 'static') # needed by collectstatic

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(PROJECT_DIR, 'templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

AUTH_USER_MODEL = 'wwwhisper_auth.User'

AUTHENTICATION_BACKENDS = [
    'wwwhisper_auth.backend.VerifiedEmailBackend'
]

ABSOLUTE_URL_OVERRIDES = {
    'auth.user': lambda u: "/admin/api/users/%s/" % u.username,
}

handler = 'logging.StreamHandler' if not TESTING \
    else 'logging.NullHandler'
level = 'INFO' if not DEBUG else 'DEBUG'
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(name)s %(message)s'
            },
        # See http://docs.python.org/2/library/logging.html#logrecord-attributes
        'simple': {
            'format': '%(levelname)s %(name)s %(message)s'
            },
        },
    'handlers': {
        'console':{
            'level': level,
            'class': handler,
            'formatter': 'simple'
            },
        },
    'loggers': {
        'wwwhisper_service': {
            'handlers': ['console'],
            'propagate': True,
            'level': level,
            },
        'wwwhisper_auth': {
            'handlers': ['console'],
            'propagate': True,
            'level': level,
            },
        'wwwhisper_admin': {
            'handlers': ['console'],
            'propagate': True,
            'level': level,
            },
        'django.request': {
            'handlers': ['console'],
            'propagate': True,
            'level': level,
            },
        'django.db': {
            'handlers': ['console'],
            'propagate': True,
            'level': level,
            },
        }
    }

if not SECRET_KEY:
    raise ImproperlyConfigured('DJANGO_SECRET_KEY environment variable not set')
