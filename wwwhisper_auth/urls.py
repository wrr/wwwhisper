# wwwhisper - web access control.
# Copyright (C) 2012-2023 Jan Wrobel <jan@mixedbit.org>

"""Urls exposed by the wwwhisper_auth application.

is-authorized/ URL does not need to be exposed by the HTTP server to
the outside world, other views need to be externally accessible.
"""

from django.urls import re_path

from wwwhisper_auth.views import Auth, CsrfToken, Login, Logout, WhoAmI
from wwwhisper_auth.views import SendToken

urlpatterns = [
    re_path(r'^csrftoken/$', CsrfToken.as_view()),
    re_path(r'^send-token/$', SendToken.as_view()),
    re_path(r'^login/$', Login.as_view()),
    re_path(r'^logout/$', Logout.as_view()),
    re_path(r'^whoami/$', WhoAmI.as_view()),
    re_path(r'^is-authorized/$', Auth.as_view(), name='auth-request')
]
