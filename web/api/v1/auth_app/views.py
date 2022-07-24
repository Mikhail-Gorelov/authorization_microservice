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
# from dj_rest_auth.views import LoginView

from . import serializers
from .authentication_classes import AuthenticationByPhone
from .services import AuthAppService

User = get_user_model()

logger = logging.getLogger(__name__)


class LoginEmailView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.LoginEmailSerializer

    # def get_response(self):
    #     serializer_class = self.get_response_serializer()
    #
    #     if getattr(settings, 'REST_USE_JWT', False):
    #         from rest_framework_simplejwt.settings import (
    #             api_settings as jwt_settings,
    #         )
    #         access_token_expiration = (timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME)
    #         refresh_token_expiration = (timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME)
    #         return_expiration_times = getattr(settings, 'JWT_AUTH_RETURN_EXPIRATION', False)
    #
    #         data = {
    #             'user': self.user,
    #             'access_token': self.access_token,
    #             'refresh_token': self.refresh_token,
    #         }
    #
    #         if return_expiration_times:
    #             data['access_token_expiration'] = access_token_expiration
    #             data['refresh_token_expiration'] = refresh_token_expiration
    #
    #         serializer = serializer_class(
    #             instance=data,
    #             context=self.get_serializer_context(),
    #         )
    #     elif self.token:
    #         serializer = serializer_class(
    #             instance=self.token,
    #             context=self.get_serializer_context(),
    #         )
    #     else:
    #         return Response(status=status.HTTP_204_NO_CONTENT)
    #
    #     response = Response(serializer.data, status=status.HTTP_200_OK)
    #     if getattr(settings, 'REST_USE_JWT', False):
    #         from .jwt_auth import set_jwt_cookies
    #         set_jwt_cookies(response, self.access_token, self.refresh_token)
    #     return response
    #
    # def login(self):
    #     self.user = self.serializer.validated_data['user']
    #     token_model = get_token_model()
    #
    #     if getattr(settings, 'REST_USE_JWT', False):
    #         self.access_token, self.refresh_token = jwt_encode(self.user)
    #     elif token_model:
    #         self.token = create_token(token_model, self.user, self.serializer)
    #
    #     if getattr(settings, 'REST_SESSION_LOGIN', True):
    #         self.process_login()

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.user
        handler = AuthAppService()
        handler.login(user)
        return Response(serializer.data)


class LoginPhoneView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.LoginPhoneSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


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
        response = self.full_logout(request)
        return response

    def full_logout(self, request):
        response = Response({
            "detail": _("Successfully logged out.")
        },
            status=HTTP_200_OK)

        if request.session.has_key('user_id'):
            del request.session['user_id']
            return response

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


class VerifyJWTView(TokenVerifyView):
    permission_classes = (AllowAny,)


class RefreshJWTView(TokenRefreshView):
    permission_classes = (AllowAny,)
