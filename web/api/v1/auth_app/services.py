import os
import re
from urllib.parse import urljoin

from django.contrib.auth import get_user_model
from django.core import signing
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken

from main.decorators import except_shell
from rest_framework.request import Request
from rest_framework.response import Response
from dataclasses import dataclass
from src.celery import app
from main.services import MainService

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

    def login(self, user: User):
        tokens = self.generate_token(user)
