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


class VerifyEmailView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.VerifyEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': _('ok')}, status=status.HTTP_200_OK)


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


class PasswordResetConfirmView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {'detail': _('Password has been reset with the new password.')},
        )


class LogoutView(APIView):
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS')

    def get(self, request, *args, **kwargs):
        if getattr(settings, 'ACCOUNT_LOGOUT_ON_GET', False):
            response = self.logout(request)
        else:
            response = self.http_method_not_allowed(request, *args, **kwargs)

        return self.finalize_response(request, response, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.logout(request)

    def session_logout(self):
        user_logged_out = Signal()
        user = getattr(self.request, 'user', None)
        if not getattr(user, 'is_authenticated', True):
            user = None
        user_logged_out.send(sender=user.__class__, request=self.request, user=user)
        self.request.session.flush()
        if hasattr(self.request, 'user'):
            from django.contrib.auth.models import AnonymousUser
            self.request.user = AnonymousUser()

    def full_logout(self, request):
        response = Response({"detail": _("Successfully logged out.")}, status=HTTP_200_OK)
        if cookie_name := getattr(settings, 'JWT_AUTH_COOKIE', None):
            response.delete_cookie(cookie_name)
        refresh_cookie_name = getattr(settings, 'JWT_AUTH_REFRESH_COOKIE', None)
        refresh_token = request.COOKIES.get(refresh_cookie_name)
        if refresh_cookie_name:
            response.delete_cookie(refresh_cookie_name)
        if 'rest_framework_simplejwt.token_blacklist' in settings.INSTALLED_APPS:
            # add refresh token to blacklist
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

        else:
            message = _(
                "Neither cookies or blacklist are enabled, so the token "
                "has not been deleted server side. Please make sure the token is deleted client side."
            )
            response.data = {"detail": message}
            response.status_code = HTTP_200_OK
        return response

    def logout(self, request):
        self.session_logout()
        response = self.full_logout(request)
        return response
