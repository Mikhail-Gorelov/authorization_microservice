import logging
from django.dispatch import Signal
from django.conf import settings
from django.http import Http404
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.permissions import AllowAny
from rest_framework.generics import get_object_or_404, CreateAPIView
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

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


class VerifyEmailView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.VerifyEmailSerializer


class PasswordResetView(CreateAPIView):
    serializer_class = serializers.PasswordResetSerializer
    permission_classes = (AllowAny,)


class PasswordResetConfirmView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PasswordResetConfirmSerializer


class LogoutView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        response = self.full_logout(request)
        return response

    def full_logout(self, request):
        response = Response({"detail": _("Successfully logged out.")}, status=HTTP_200_OK)
        if cookie_name := getattr(settings, 'JWT_AUTH_COOKIE', None):
            response.delete_cookie(cookie_name)
        refresh_cookie_name = getattr(settings, 'JWT_AUTH_REFRESH_COOKIE', None)
        refresh_token = request.COOKIES.get(refresh_cookie_name)
        if refresh_cookie_name:
            response.delete_cookie(refresh_cookie_name)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except KeyError:
            response.data = {"detail": _("Refresh token was not included in request data.")}
            response.status_code = HTTP_401_UNAUTHORIZED
        except (TokenError, AttributeError, TypeError) as error:
            if hasattr(error, 'args'):
                if 'Token is blacklisted' in error.args or 'Token is invalid or expired' in error.args:
                    response.data = {"detail": _(error.args[0])}
                    response.status_code = HTTP_401_UNAUTHORIZED
                else:
                    response.data = {"detail": _("An error has occurred.")}
                    response.status_code = HTTP_500_INTERNAL_SERVER_ERROR

            else:
                response.data = {"detail": _("An error has occurred.")}
                response.status_code = HTTP_500_INTERNAL_SERVER_ERROR

        return response
