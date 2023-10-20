# wwwhisper - web access control.
# Copyright (C) 2013-2023 Jan Wrobel <jan@mixedbit.org>

import os

from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django.views.generic import View
from wwwhisper_auth import http


def read_asset(prefix, *args):
    """Read a static file to be returned by requests."""
    assert prefix
    with open(os.path.join(prefix, *args), encoding='utf-8') as asset_file:
        return asset_file.read()

class StaticFileView(View):
    """An abstract view to serve a single static file."""

    asset = None

    @method_decorator(cache_control(private=True, max_age=60 * 60 * 5))
    def get(self, _request):
        return self.do_get(self.asset)

    def do_get(self, _asset):
        raise NotImplementedError

class HtmlFileView(StaticFileView):
    """A view to serve a single HTML file."""

    def do_get(self, asset):
        return http.HttpResponseOKHtml(asset)

class JsFileView(StaticFileView):
    """A view to serve a single JS file."""

    def do_get(self, asset):
        return http.HttpResponseOKJs(asset)
