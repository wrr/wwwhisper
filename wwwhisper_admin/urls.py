# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

"""Urls exposed by the wwwhisper_admin application."""

from django.conf.urls import url
from wwwhisper_admin.views import CollectionView, ItemView, SkinView
from wwwhisper_admin.views import OpenAccessView, AllowedUsersView

urlpatterns = [
    url(r'^users/$',
        CollectionView.as_view(collection_name='users')),
    url(r'^users/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection_name='users'),
        name='wwwhisper_user'),
    url(r'^locations/$',
        CollectionView.as_view(collection_name='locations')),
    url(r'^locations/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection_name='locations'),
        name='wwwhisper_location'),
    url(r'^locations/(?P<location_uuid>[0-9a-z-]+)/allowed-users/' +
        '(?P<user_uuid>[0-9a-z-]+)/$',
        AllowedUsersView.as_view(),
        name='wwwhisper_allowed_user'),
    url(r'^locations/(?P<location_uuid>[0-9a-z-]+)/open-access/$',
        OpenAccessView.as_view()),
    url(r'^aliases/$',
        CollectionView.as_view(collection_name='aliases')),
    url(r'^aliases/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection_name='aliases'),
        name='wwwhisper_alias'),
    url(r'^skin/$', SkinView.as_view())
]
