from typing import TypeVar
from phonenumber_field.modelfields import PhoneNumberField
from django.conf import settings
from django_countries.fields import CountryField
from django.contrib.auth.models import AbstractUser
from django.core import signing
from django.db import models
from django.utils.translation import gettext_lazy as _

from . import choices
from .managers import UserManager

UserType = TypeVar('UserType', bound='User')


class Address(models.Model):
    street_address = models.CharField(max_length=256, blank=True)
    city = models.CharField(max_length=256, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = CountryField()
    user = models.ForeignKey(
        "User", related_name="user_address", null=True, blank=True, on_delete=models.CASCADE
    )

    def __str__(self):
        return str(self.pk)

    class Meta:
        verbose_name = 'Address'
        verbose_name_plural = 'Addresses'


class User(AbstractUser):
    username = None
    email = models.EmailField(_('Email address'), unique=True, null=True, blank=True)
    phone_number = PhoneNumberField(null=True, blank=True, unique=True, default=None)
    gender = models.IntegerField(choices=choices.GenderChoice.choices, null=True)
    birthday = models.DateField(null=True, blank=True)
    avatar = models.ImageField(
        upload_to="user/", default="default_avatar.jpg"
    )
    updated = models.DateTimeField(auto_now=True, db_index=True)
    default_shipping_address = models.OneToOneField(
        Address, related_name="user_default_shipping_address", null=True, blank=True, on_delete=models.SET_NULL
    )
    default_billing_address = models.OneToOneField(
        Address, related_name="user_default_billing_address", null=True, blank=True, on_delete=models.SET_NULL
    )

    USERNAME_FIELD: str = 'email'
    REQUIRED_FIELDS: list[str] = []

    objects = UserManager()

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self) -> str:
        if self.email:
            return self.email
        else:
            return str(self.phone_number)

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
