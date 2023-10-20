# wwwhisper - web access control.
# Copyright (C) 2012-2023 Jan Wrobel <jan@mixedbit.org>

"""Urls exposed by the wwwhisper_auth application.

is-authorized/ URL does not need to be exposed by the HTTP server to
the outside world, other views need to be externally accessible.
"""

from django.conf.urls import url
from wwwhisper_auth.views import Auth, CsrfToken, Login, Logout, WhoAmI
from wwwhisper_auth.views import SendToken

urlpatterns = [
    url(r'^csrftoken/$', CsrfToken.as_view()),
    url(r'^send-token/$', SendToken.as_view()),
    url(r'^login/$', Login.as_view()),
    url(r'^logout/$', Logout.as_view()),
    url(r'^whoami/$', WhoAmI.as_view()),
    url(r'^is-authorized/$', Auth.as_view(), name='auth-request')
]
