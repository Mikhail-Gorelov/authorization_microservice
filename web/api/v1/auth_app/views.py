import logging

from django.http import Http404
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from rest_framework.permissions import AllowAny
from rest_framework.generics import get_object_or_404, CreateAPIView

from . import serializers
from rest_framework.generics import GenericAPIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response

from .services import AuthAppService

User = get_user_model()

logger = logging.getLogger(__name__)


class LoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


class SignUpView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.SignUpSerializer

class VerifyEmailView(GenericAPIView):
    permission_classes = (AllowAny,)

    def get_serializer(self, *args, **kwargs):
        return serializers.VerifyEmailSerializer(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.kwargs['email'] = serializer.validated_data['email']
        user = self.get_object()
        AuthAppService.confirm(user)
        return Response({'detail': _('ok')}, status=status.HTTP_200_OK)

    def get_object(self, queryset=None):
        email = self.kwargs['email']
        emailconfirmation = get_object_or_404(
            User,
            email=email
        )
        return emailconfirmation

class PasswordResetView(GenericAPIView):
    serializer_class = serializers.PasswordResetSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {'detail': _('Password reset e-mail has been sent.')},
            status=status.HTTP_200_OK,
        )
