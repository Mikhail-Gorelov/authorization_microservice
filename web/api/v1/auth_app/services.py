from dataclasses import dataclass
from urllib.parse import urljoin

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from main.decorators import except_shell
from src.celery import app

User = get_user_model()


@dataclass
class UserToken:
    access_token: str
    refresh_token: str


@dataclass
class UserTokenExpiration:
    access_token_expiration: str
    refresh_token_expiration: str


class AuthAppService:
    @staticmethod
    def is_email_exists(email: str) -> bool:
        return User.objects.filter(email=email).exists()

    @staticmethod
    def get_reset_url(uid, token):
        url = f'/Webshop/password-reset/{uid}/{token}'
        return settings.FRONTEND_SITE + str(url)

    @staticmethod
    def get_confirmation_url(user: User) -> str:
        url = f'/Webshop/confirm/{user.confirmation_key}'
        return urljoin(settings.FRONTEND_SITE, url)

    @staticmethod
    def get_confirmation_key(user: User) -> str:
        return user.confirmation_key

    @staticmethod
    def send_confirmation_email(user: User):
        data = {
            "subject": "Confirmation email",
            'template_name': 'auth_app/success_registration.html',
            "to_email": user.email,
            "context": {
                "activate_url": AuthAppService.get_confirmation_url(user),
                "full_name": user.full_name()
            }
        }
        app.send_task(
            name='email_sender.tasks.send_information_email',
            kwargs=data,
        )
        return data

    @staticmethod
    def send_confirmation_sms(user: User):
        activation_key = AuthAppService.get_confirmation_key(user)
        full_name = user.full_name()
        data = {
            "body": f"Hello {full_name}! Nice to see you in Webshop! Enter this key to activate your account: {activation_key}",
            "to": str(user.phone_number),
        }
        app.send_task(
            name='sms_sender.tasks.send_information_sms',
            kwargs=data,
        )
        return data

    @staticmethod
    def send_verify_email(email: str, user: User, url: str):
        data = {
            'subject': 'Your reset e-mail',
            'template_name': 'auth_app/reset_password_sent.html',
            'to_email': email,
            'context': {
                'user': user.get_full_name(),
                'reset_url': url,
            },
        }
        app.send_task(
            name='email_sender.tasks.send_information_email',
            kwargs=data,
        )
        return data

    @staticmethod
    def send_verify_sms(phone_number: str, user: User, url: str):
        full_name = user.full_name()
        data = {
            "body": f"Hello {full_name}! Nice to see you in Webshop! Follow this link to reset your account: {url}",
            "to": str(phone_number),
        }
        app.send_task(
            name='sms_sender.tasks.send_information_sms',
            kwargs=data,
        )
        return data

    @staticmethod
    @except_shell((User.DoesNotExist,))
    def get_user(email: str) -> User:
        return User.objects.get(email=email)

    @staticmethod
    @except_shell((User.DoesNotExist,))
    def get_user_by_phone(phone_number: str) -> User:
        return User.objects.get(phone_number=phone_number)

    def tokens_expiration_time(self):
        expiration_time = getattr(settings, 'JWT_AUTH_RETURN_EXPIRATION', False)

        if expiration_time:
            from rest_framework_simplejwt.settings import (
                api_settings as jwt_settings,
            )

            access_token_expiration = (timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME)
            refresh_token_expiration = (timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME)

            return UserTokenExpiration(
                access_token_expiration=access_token_expiration,
                refresh_token_expiration=refresh_token_expiration,
            )

    def generate_token(self, user: User):
        refresh = RefreshToken.for_user(user)

        return UserToken(
            access_token=refresh.access_token,
            refresh_token=refresh,
        )

    def set_jwt_cookies(self, response: Response, access_token: str, refresh_token: str):
        if getattr(settings, 'REST_USE_JWT', True):
            from .jwt_auth import set_jwt_cookies
            set_jwt_cookies(response, access_token, refresh_token)
        return response

    def login(self, user: User):
        tokens = self.generate_token(user)
        expiration_time = self.tokens_expiration_time()
        response_data = {
            'access_token': str(tokens.access_token),
            'refresh_token': str(tokens.refresh_token),
            'access_token_expiration': expiration_time.access_token_expiration,
            'refresh_token_expiration': expiration_time.refresh_token_expiration,
            'user': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name()
            }
        }
        response = Response(data=response_data)
        self.set_jwt_cookies(response=response, access_token=tokens.access_token, refresh_token=tokens.refresh_token)
        return response

    def delete_jwt_cookies(self, request: Request):
        response = Response({
            "detail": "Successfully logged out."
        }, status=HTTP_200_OK)
        if cookie_name := getattr(settings, 'JWT_AUTH_COOKIE', None):
            response.delete_cookie(cookie_name)
        refresh_cookie_name = getattr(settings, 'JWT_AUTH_REFRESH_COOKIE', None)
        refresh_token = request.COOKIES.get(refresh_cookie_name)
        if refresh_cookie_name:
            response.delete_cookie(refresh_cookie_name)
        return response, refresh_token

    def blacklist_refresh_token(self, response: Response, refresh_token: str):
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except KeyError:
            response.data = {"detail": "Refresh token was not included in request data."}
            response.status_code = HTTP_401_UNAUTHORIZED
        except (TokenError, AttributeError, TypeError) as error:
            if hasattr(error, 'args'):
                if 'Token is blacklisted' in error.args or 'Token is invalid or expired' in error.args:
                    response.data = {"detail": error.args[0]}
                    response.status_code = HTTP_401_UNAUTHORIZED
                else:
                    response.data = {"detail": "An error has occurred."}
                    response.status_code = HTTP_500_INTERNAL_SERVER_ERROR

            else:
                response.data = {"detail": "An error has occurred."}
                response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        return response

    def full_logout(self, request: Request):
        response, refresh_token = self.delete_jwt_cookies(request=request)
        return self.blacklist_refresh_token(response, refresh_token)
