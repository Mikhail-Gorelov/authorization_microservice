from django.utils.functional import SimpleLazyObject
from rest_framework.permissions import BasePermission
from django.contrib.auth import get_user_model

User = get_user_model()


class IsAuthenticatedOrNot(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        if request.session.has_key('user_id') and User.objects.filter(pk=request.session.get('user_id')).exists():
            user = User.objects.get(pk=request.session['user_id'])
            request.user = user
        return bool(request.user and request.user.is_authenticated)
