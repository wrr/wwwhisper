# wwwhisper - web access control.
# Copyright (C) 2013-2022 Jan Wrobel <jan@mixedbit.org>

import os

from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django.views.decorators.cache import cache_page
from django.views.generic import View
from wwwhisper_auth import http


class Asset:
    """Stores a static file to be returned by requests."""

    def __init__(self, prefix, *args):
        assert prefix is not None
        self.body = open(os.path.join(prefix, *args)).read()


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
