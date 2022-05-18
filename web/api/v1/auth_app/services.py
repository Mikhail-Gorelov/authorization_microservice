import os
import re
from urllib.parse import urljoin

from django.contrib.auth import get_user_model
from django.core import signing
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from main.decorators import except_shell
from rest_framework.request import Request
from rest_framework.response import Response

from src.celery import app
from main.services import MainService

User = get_user_model()


class AuthAppService:
    @staticmethod
    def is_email_exists(email: str) -> bool:
        return User.objects.filter(email=email).exists()

    @staticmethod
    def get_reset_url(uid, token):
        url = f'/password-reset?uidb64={uid}&token={token}'
        return settings.FRONTEND_SITE + str(url)

    @staticmethod
    def get_confirmation_url(user: User) -> str:
        url = f'/confirm?key={user.confirmation_key}'
        return urljoin(settings.FRONTEND_SITE, url)

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
    @except_shell((User.DoesNotExist,))
    def get_user(email: str) -> User:
        return User.objects.get(email=email)
