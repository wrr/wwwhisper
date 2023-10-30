# wwwhisper - web access control.
# Copyright (C) 2012-2023 Jan Wrobel <jan@mixedbit.org>

"""Root entry for wwwhisper URLs dispatching configuration."""

import logging

from django.conf import settings
from django.conf.urls import include, url

from wwwhisper_auth.assets import read_asset, HtmlFileView, JsFileView

logger = logging.getLogger(__name__)

def _add_suffix(suffix):
    return f'^{settings.WWWHISPER_PATH_PREFIX}{suffix}'

def _url(path, *args, **kwargs):
    return url(_add_suffix(path), *args, **kwargs)

urlpatterns = [
    _url(r'auth/api/', include('wwwhisper_auth.urls')),
    _url(r'admin/api/', include('wwwhisper_admin.urls'))
]

# TODO(jw): remove branch, WWWHISPER_STATIC is now always set, even if
# wwwhisper is behind nginx which serves static files (this is needed
# for reverse('login-check-token') to work in
# wwwhisper_auth.views.SendToken.
if settings.WWWHISPER_STATIC is not None:
    logger.debug('wwwhisper configured to serve static files.')
    admin = read_asset(settings.WWWHISPER_STATIC, 'admin', 'index.html')
    overlay = read_asset(settings.WWWHISPER_STATIC, 'auth', 'overlay.html')
    iframe = read_asset(settings.WWWHISPER_STATIC, 'auth', 'iframe.js')
    logout = read_asset(settings.WWWHISPER_STATIC, 'auth', 'logout.html')
    login_check_token = read_asset(settings.WWWHISPER_STATIC, 'auth',
                              'login_check_token.html')
    goodbye = read_asset(settings.WWWHISPER_STATIC, 'auth', 'goodbye.html')

    urlpatterns += [
        _url('admin/$', HtmlFileView.as_view(asset=admin)),
        _url('auth/overlay.html$', HtmlFileView.as_view(asset=overlay)),
        _url('auth/iframe.js$', JsFileView.as_view(asset=iframe)),
        _url('auth/login$', HtmlFileView.as_view(asset=login_check_token),
             name='login-check-token'),
        _url('auth/logout$', HtmlFileView.as_view(asset=logout)),
        _url('auth/logout.html$', HtmlFileView.as_view(asset=logout)),
        _url('auth/goodbye$', HtmlFileView.as_view(asset=goodbye)),
        _url('auth/goodbye.html$', HtmlFileView.as_view(asset=goodbye))
    ]
