from typing import TYPE_CHECKING, Any

from django.contrib.auth.base_user import BaseUserManager

if TYPE_CHECKING:
    from .models import UserType


class UserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email: str, password: str, **extra_fields: Any) -> 'UserType':
        """
        Create and save a User with the given email and password.
        """
        _email: str = self.normalize_email(email)
        user = self.model(email=_email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_user_by_phone(self, phone_number: str, password: str, **extra_fields: any) -> 'UserType':
        """
        Create and save a User with the given phone and password.
        """
        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email: str, password: str, **extra_fields: Any) -> 'UserType':
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields['is_staff'] = True
        extra_fields['is_superuser'] = True
        extra_fields['is_active'] = True
        return self.create_user(email, password, **extra_fields)
