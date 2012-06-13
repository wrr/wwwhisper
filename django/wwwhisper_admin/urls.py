from django.conf.urls.defaults import patterns, include, url
from django.contrib.auth.models import User
from views import CollectionView, ItemView
from views import OpenAccessView, AllowedUsersView
from wwwhisper_auth.models import LocationsCollection, UsersCollection

users_collection = UsersCollection()
locations_collection = LocationsCollection()

urlpatterns = patterns(
    'wwwhisper_admin.views',
    url(r'^users/$',
        CollectionView.as_view(collection=users_collection)),
    url(r'^users/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection=users_collection)),
    url(r'^locations/$',
        CollectionView.as_view(collection=locations_collection)),
    url(r'^locations/(?P<uuid>[0-9a-z-]+)/$',
        ItemView.as_view(collection=locations_collection),
        name='wwwhisper_location'),
    url(r'^locations/(?P<location_uuid>[0-9a-z-]+)/allowed-users/' +
        '(?P<user_uuid>[0-9a-z-]+)/$',
        AllowedUsersView.as_view(locations_collection=locations_collection),
        name='wwwhisper_allowed_user'),
    url(r'^locations/(?P<location_uuid>[0-9a-z-]+)/open-access/$',
        OpenAccessView.as_view(locations_collection=locations_collection)),
    )
