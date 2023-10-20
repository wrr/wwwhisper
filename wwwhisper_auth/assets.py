# wwwhisper - web access control.
# Copyright (C) 2013-2023 Jan Wrobel <jan@mixedbit.org>

import os

from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django.views.generic import View
from wwwhisper_auth import http


class Asset:
    """Stores a static file to be returned by requests."""

    def __init__(self, prefix, *args):
        assert prefix
        with open(os.path.join(prefix, *args), encoding='utf-8') as asset_file:
            self.body = asset_file.read()


class StaticFileView(View):
    """ A view to serve a single static file."""

    asset = None

    @method_decorator(cache_control(private=True, max_age=60 * 60 * 5))
    def get(self, _request):
        return self.do_get(self.asset.body)

class HtmlFileView(StaticFileView):

    def do_get(self, body):
        return http.HttpResponseOKHtml(body)

class JsFileView(StaticFileView):

    def do_get(self, body):
        return http.HttpResponseOKJs(body)
