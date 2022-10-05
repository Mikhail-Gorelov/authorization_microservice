from rest_framework.generics import RetrieveAPIView, GenericAPIView, ListAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth import get_user_model

from api.v1.profile_app import serializers
from api.v1.profile_app.permissions import IsAuthenticatedOrNot
from main import models

User = get_user_model()


class GetUserView(RetrieveAPIView):
    permission_classes = (IsAuthenticatedOrNot,)
    serializer_class = serializers.GetUserSerializer

    def get_object(self):
        return self.request.user

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)


class ChangeUserPasswordView(GenericAPIView):
    permission_classes = (IsAuthenticatedOrNot,)
    serializer_class = serializers.ChangeUserPasswordSerializer

    def get_object(self):
        return self.request.user

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'status': 'success'})


class ChangeUserProfileView(GenericAPIView):
    permission_classes = (IsAuthenticatedOrNot,)
    serializer_class = serializers.ChangeUserProfileSerializer

    # parser_classes = [MultiPartParser]

    def get_object(self):
        return self.request.user

    def put(self, request):
        serializer = self.get_serializer(data=request.data, instance=self.get_object())
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ChangeBillingAddressView(GenericAPIView):
    permission_classes = (IsAuthenticatedOrNot,)
    serializer_class = serializers.ChangeAddressSerializer

    def get_object(self):
        if not self.request.user.default_billing_address:
            models.Address.objects.create(user=self.request.user, user_default_billing_address=self.request.user)
            self.request.user.save()
        return self.request.user.default_billing_address

    def put(self, request):
        serializer = self.get_serializer(data=request.data, instance=self.get_object())
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ChangeShippingAddressView(GenericAPIView):
    permission_classes = (IsAuthenticatedOrNot,)
    serializer_class = serializers.ChangeAddressSerializer

    def get_object(self):
        if not self.request.user.default_shipping_address:
            models.Address.objects.create(user=self.request.user, user_default_shipping_address=self.request.user)
            self.request.user.save()
        return self.request.user.default_shipping_address

    def put(self, request):
        serializer = self.get_serializer(data=request.data, instance=self.get_object())
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ListEmailsView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.ListEmailsSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        users = [i[0] for i in list(User.objects.filter(id__in=serializer.data['users']).values_list('email'))
                 if i[0] != '']
        return Response(users)
