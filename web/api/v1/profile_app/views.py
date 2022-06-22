from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

from api.v1.profile_app import serializers


class GetUserView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.GetUserSerializer

    def get_object(self):
        if self.request.user.is_anonymous:
            return None
        else:
            return self.request.user
