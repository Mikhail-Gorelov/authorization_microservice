from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from typing import TYPE_CHECKING, Optional

from api.v1.auth_app.forms import PassResetForm
from api.v1.auth_app.services import AuthAppService

if TYPE_CHECKING:
    from main.models import UserType

User = get_user_model()


class UserLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', ]


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=7, write_only=True)

    def authenticate(self, **kwargs) -> Optional['UserType']:
        return authenticate(self.context['request'], **kwargs)

    def validate(self, attrs):
        self.user = self.authenticate(email=attrs['email'], password=attrs['password'])
        attrs['user'] = self.user
        if not self.user:
            raise serializers.ValidationError('Wrong credentials')
        return attrs

    @property
    def data(self):
        refresh = RefreshToken.for_user(self.user)
        return_expiration_times = getattr(settings, 'JWT_AUTH_RETURN_EXPIRATION', False)

        tokens = {
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }

        if return_expiration_times:
            from rest_framework_simplejwt.settings import (
                api_settings as jwt_settings,
            )

            access_token_expiration = (timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME)
            refresh_token_expiration = (timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME)

            tokens['access_token_expiration'] = access_token_expiration
            tokens['refresh_token_expiration'] = refresh_token_expiration

        tokens['user'] = UserLoginSerializer(self.user).data

        return tokens


class SignUpSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, min_length=7)
    password1 = serializers.CharField(write_only=True, min_length=7)

    def validate_email(self, email) -> str:
        if AuthAppService.is_email_exists(email):
            raise serializers.ValidationError(_("User is already registered with this e-mail address."))
        return email

    def validate(self, attrs: dict) -> dict:
        if attrs['password'] != attrs['password1']:
            raise serializers.ValidationError(_("Passwords does not match"))
        return attrs

    def save(self, **kwargs):
        del self.validated_data['password1']
        user = User.objects.create_user(**self.validated_data, is_active=False)
        AuthAppService.send_confirmation_email(user)
        return user


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.CharField()


class PasswordResetSerializer(serializers.Serializer):
    password_reset_form_class = PassResetForm
