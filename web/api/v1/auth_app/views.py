import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework.generics import CreateAPIView
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenVerifyView, TokenRefreshView

from . import serializers
from .services import AuthAppService

User = get_user_model()

logger = logging.getLogger(__name__)


class LoginEmailView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.LoginEmailSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.user
        handler = AuthAppService()
        handler.login(user)
        return handler.login(user)


class LoginPhoneView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.LoginPhoneSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.user
        handler = AuthAppService()
        handler.login(user)
        return handler.login(user)


class SignUpEmailView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.SignUpEmailSerializer


class SignUpPhoneView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.SignUpPhoneSerializer


class VerifyView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.VerifySerializer


class PasswordResetEmailView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PasswordResetEmailSerializer


class PasswordResetPhoneView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PasswordResetPhoneSerializer


class PasswordResetConfirmView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PasswordResetConfirmSerializer


class LogoutView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        handler = AuthAppService()
        response = handler.full_logout(request=request)
        return response


class VerifyJWTView(TokenVerifyView):
    permission_classes = (AllowAny,)


class RefreshJWTView(TokenRefreshView):
    permission_classes = (AllowAny,)
