from typing import TypeVar

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core import signing
from django.db import models
from django.utils.translation import gettext_lazy as _

from .managers import UserManager

UserType = TypeVar('UserType', bound='User')


class User(AbstractUser):

    username = None
    email = models.EmailField(_('Email address'), unique=True)

    USERNAME_FIELD: str = 'email'
    REQUIRED_FIELDS: list[str] = []

    objects = UserManager()

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self) -> str:
        return self.email

    def full_name(self) -> str:
        return super().get_full_name()

    @property
    def confirmation_key(self) -> str:
        return signing.dumps(self.pk)

    @classmethod
    def from_key(cls, key: str) -> 'User':
        try:
            pk = signing.loads(key, max_age=settings.EMAIL_CONFIRMATION_EXPIRE_SECONDS)
            user = cls.objects.get(pk=pk)
        except (cls.DoesNotExist, signing.BadSignature, signing.SignatureExpired,):
            user = None
        return user
