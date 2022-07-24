from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
import re

User = get_user_model()


class AuthenticationByPhone(BaseBackend):
    def authenticate(self, request, phone_number=None, password=None):
        user = self.get_user(phone_number=phone_number)
        if not user:
            return None
        pwd_valid = user.check_password(password)
        if not pwd_valid:
            return None
        return user

    def get_user(self, phone_number):
        try:
            return User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return None
