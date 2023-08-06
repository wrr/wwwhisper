# wwwhisper - web access control.
# Copyright (C) 2012-2018 Jan Wrobel <jan@mixedbit.org>

from django.conf import settings
from django.conf.urls import include, url
from django.conf import settings
from wwwhisper_auth.assets import Asset, HtmlFileView, JsFileView

import logging

logger = logging.getLogger(__name__)

def _add_suffix(suffix):
    return r'^%s%s' % (settings.WWWHISPER_PATH_PREFIX, suffix)

def _url(path, *args):
    return url(_add_suffix(path), *args)

urlpatterns = [
    _url(r'auth/api/', include('wwwhisper_auth.urls')),
    _url(r'admin/api/', include('wwwhisper_admin.urls'))
]

if settings.WWWHISPER_STATIC is not None:
    logger.debug('wwwhisper configured to serve static files.')
    admin = Asset(settings.WWWHISPER_STATIC, 'admin', 'index.html')
    overlay = Asset(settings.WWWHISPER_STATIC, 'auth', 'overlay.html')
    iframe = Asset(settings.WWWHISPER_STATIC, 'auth', 'iframe.js')
    logout = Asset(settings.WWWHISPER_STATIC, 'auth', 'logout.html')
    goodbye = Asset(settings.WWWHISPER_STATIC, 'auth', 'goodbye.html')

    urlpatterns += [
        _url('admin/$', HtmlFileView.as_view(asset=admin)),
        _url('auth/overlay.html$', HtmlFileView.as_view(asset=overlay)),
        _url('auth/iframe.js$', JsFileView.as_view(asset=iframe)),
        _url('auth/logout$', HtmlFileView.as_view(asset=logout)),
        _url('auth/logout.html$', HtmlFileView.as_view(asset=logout)),
        _url('auth/goodbye$', HtmlFileView.as_view(asset=goodbye)),
        _url('auth/goodbye.html$', HtmlFileView.as_view(asset=goodbye))
    ]

