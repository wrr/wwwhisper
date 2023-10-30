# wwwhisper - web access control.
# Copyright (C) 2012-2015 Jan Wrobel <jan@mixedbit.org>

"""Views that allow to manage access control list.

Expose REST interface for adding/removing locations and users and for
granting/revoking access to locations.
"""

import functools
import logging

from django.forms import ValidationError

from wwwhisper_auth import http
from wwwhisper_auth.models import LimitExceeded

logger = logging.getLogger(__name__)

def _full_path(request):
    return request.path

def set_collection(decorated_function):
    @functools.wraps(decorated_function)
    def wrapper(self, request, **kwargs):
        self.collection = getattr(request.site, self.collection_name)
        return decorated_function(self, request, **kwargs)
    return wrapper

class CollectionView(http.RestView):
    """Generic view over a collection of resources.

    Allows to get json representation of all resources in the
    collection and to add new resources to the collection.

    Attributes:
        collection_name: Name of the collection that view represents.
    """

    collection_name = None

    @set_collection
    def post(self, _request, **kwargs):
        """Ads a new resource to the collection.

        Args:
            **kwargs: holds collection dependent arguments that are
              used to create the resource.
        Returns json representation of the added resource."""
        try:
            created_item = self.collection.create_item(**kwargs)
        except ValidationError as ex:
            # ex.messages is a list of errors.
            return http.HttpResponseBadRequest(', '.join(ex.messages))
        except LimitExceeded as ex:
            return http.HttpResponseLimitExceeded(str(ex))

        attributes_dict = created_item.attributes_dict()
        response = http.HttpResponseCreated(attributes_dict)
        response['Location'] = attributes_dict['self']
        response['Content-Location'] = attributes_dict['self']
        return response

    @set_collection
    def get(self, request):
        """Returns json representation of all resources in the collection."""
        items_list = [item.attributes_dict()
                      for item in self.collection.all()]
        return http.HttpResponseOKJson({
                'self' : _full_path(request),
                self.collection_name: items_list
                })

class ItemView(http.RestView):
    """Generic view over a single resource stored in a collection.

    Allows to get json representation of the resource and to delete
    the resource.

    Attributes:
        collection_name: Name of the collection that view uses to retrieve
           the resource.
    """

    collection_name = None

    @set_collection
    def get(self, _request, uuid):
        """Returns json representation of a resource with a given uuid."""
        if item := self.collection.find_item(uuid):
            return http.HttpResponseOKJson(item.attributes_dict())
        return http.HttpResponseNotFound(
            f'{self.collection.item_name.capitalize()} not found')


    @set_collection
    def delete(self, _request, uuid):
        """Deletes a resource with a given uuid."""
        deleted = self.collection.delete_item(uuid)
        if not deleted:
            return http.HttpResponseNotFound(
                f'{self.collection.item_name.capitalize()} not found')
        return http.HttpResponseNoContent()

class OpenAccessView(http.RestView):
    """Manages resources that define if a location is open.

    An open location can be accessed without authentication.
    """

    @staticmethod
    def _attributes_dict(request):
        """Attributes representing a resource to which a request is related."""
        return {
            'self' : _full_path(request)
        }

    def put(self, request, location_uuid):
        """Creates a resource that enables open access to a given location."""
        location = request.site.locations.find_item(location_uuid)
        if location is None:
            return http.HttpResponseNotFound('Location not found.')

        if location.open_access_granted():
            return http.HttpResponseOKJson(self._attributes_dict(request))

        location.grant_open_access()
        response =  http.HttpResponseCreated(self._attributes_dict(request))
        response['Location'] = _full_path(request)
        return response

    def get(self, request, location_uuid):
        """Check if a resource that enables open access to a location exists."""
        location = request.site.locations.find_item(location_uuid)
        if location is None:
            return http.HttpResponseNotFound('Location not found.')
        if not location.open_access_granted():
            return http.HttpResponseNotFound(
                'Open access to location disallowed.')
        return http.HttpResponseOKJson(self._attributes_dict(request))

    def delete(self, request, location_uuid):
        """Deletes a resource.

        Disables open access to a given location.
        """
        location = request.site.locations.find_item(location_uuid)
        if location is None:
            return http.HttpResponseNotFound('Location not found.')
        if not location.open_access_granted():
            return http.HttpResponseNotFound(
                'Open access to location already disallowed.')
        location.revoke_open_access()
        return http.HttpResponseNoContent()

class AllowedUsersView(http.RestView):
    """Manages resources that define which users can access locations."""

    def put(self, request, location_uuid, user_uuid):
        """Creates a resource.

        Grants access to a given location by a given user.
        """
        location = request.site.locations.find_item(location_uuid)
        if not location:
            return http.HttpResponseNotFound('Location not found.')
        try:
            (permission, created) = location.grant_access(user_uuid)
            attributes_dict = permission.attributes_dict()
            if created:
                response =  http.HttpResponseCreated(attributes_dict)
                response['Location'] = attributes_dict['self']
            else:
                response = http.HttpResponseOKJson(attributes_dict)
            return response
        except LookupError as ex:
            return http.HttpResponseNotFound(str(ex))

    def get(self, request, location_uuid, user_uuid):
        """Checks if a resource that grants access exists.

        This is not equivalent of checking if the user can access the
        location. If the location is open, but the user is not
        explicitly granted access, not found failure is returned.
        """
        location = request.site.locations.find_item(location_uuid)
        if location is None:
            return http.HttpResponseNotFound('Location not found.')
        try:
            permission = location.get_permission(user_uuid)
            return http.HttpResponseOKJson(permission.attributes_dict())
        except LookupError as ex:
            return http.HttpResponseNotFound(str(ex))

    def delete(self, request, location_uuid, user_uuid):
        """Deletes a resource.

        Revokes access to a given location by a given user. If the
        location is open, the user will still be able to access the
        location after this call succeeds.
        """
        location = request.site.locations.find_item(location_uuid)
        if not location:
            return http.HttpResponseNotFound('Location not found.')
        try:
            location.revoke_access(user_uuid)
            return http.HttpResponseNoContent()
        except LookupError as ex:
            return http.HttpResponseNotFound(str(ex))


class SkinView(http.RestView):
    """Configures the login page."""

    # pylint: disable=too-many-arguments
    def put(self, request, title, header, message, branding):
        try:
            request.site.update_skin(title=title, header=header,
                                     message=message, branding=branding)
        except ValidationError as ex:
            return http.HttpResponseBadRequest(
                'Failed to update login page: ' + ', '.join(ex.messages))
        return http.HttpResponseOKJson(request.site.skin())

    def get(self, request):
        return http.HttpResponseOKJson(request.site.skin())
