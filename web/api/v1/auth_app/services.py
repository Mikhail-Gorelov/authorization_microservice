import re
from urllib.parse import urljoin

from django.contrib.auth import get_user_model
from django.core import signing
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from auth_app import models

User = get_user_model()


class AuthAppService:
    @staticmethod
    def is_email_exists(email: str) -> bool:
        return User.objects.filter(email=email).exists()

    @staticmethod
    def get_confirmation_url(user: User) -> str:
        url = f'/confirm?key={user.confirmation_key}'
        return urljoin(settings.FRONTEND_SITE, url)

    @staticmethod
    def send_confirmation_email(user: User):
        data = {
            "subject": "Confirmation email",
            "to_email": user.email,
            "context": {
                "url": AuthAppService.get_confirmation_url(user),
                "full_name": user.full_name()
            }
        }
        return data

    @staticmethod
    def confirm(user: User) -> User:
        user.is_active = True
        user.save()
        return user
