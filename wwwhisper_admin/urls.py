# wwwhisper - web access control.
# Copyright (C) 2012-2022 Jan Wrobel <jan@mixedbit.org>

"""Urls exposed by the wwwhisper_admin application."""

from django.urls import re_path

from wwwhisper_admin.views import CollectionView, ItemView, SkinView
from wwwhisper_admin.views import OpenAccessView, AllowedUsersView

urlpatterns = [
    re_path(r'^users/$',
        CollectionView.as_view(collection_name='users')),
    re_path(r'^users/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection_name='users'),
        name='wwwhisper_user'),
    re_path(r'^locations/$',
        CollectionView.as_view(collection_name='locations')),
    re_path(r'^locations/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection_name='locations'),
        name='wwwhisper_location'),
    re_path(r'^locations/(?P<location_uuid>[0-9a-z-]+)/allowed-users/' +
        '(?P<user_uuid>[0-9a-z-]+)/$',
        AllowedUsersView.as_view(),
        name='wwwhisper_allowed_user'),
    re_path(r'^locations/(?P<location_uuid>[0-9a-z-]+)/open-access/$',
        OpenAccessView.as_view()),
    re_path(r'^aliases/$',
        CollectionView.as_view(collection_name='aliases')),
    re_path(r'^aliases/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection_name='aliases'),
        name='wwwhisper_alias'),
    re_path(r'^skin/$', SkinView.as_view())
]
