from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode as uid_decoder
from typing import TYPE_CHECKING, Optional

from api.v1.auth_app.forms import PassResetForm, SetPasswordForm
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
    key = serializers.CharField()

    def validate_key(self, key: str):
        self.user = User.from_key(key)
        if not self.user:
            raise serializers.ValidationError("Invalid key")
        return key

    def save(self, **kwargs):
        self.user.is_active = True
        self.user.save(update_fields=['is_active'])


class PasswordResetSerializer(serializers.Serializer):
    password_reset_form_class = PassResetForm
    email = serializers.EmailField()

    def get_email_options(self):
        """Override this method to change default e-mail options"""
        return {}

    def validate_email(self, value):
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)
        return value

    def save(self):
        from django.contrib.auth.tokens import default_token_generator

        request = self.context.get('request')
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),
            'request': request,
            'token_generator': default_token_generator,
        }

        opts.update(self.get_email_options())
        self.reset_form.save(**opts)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
        Serializer for confirming a password reset attempt.
    """
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    set_password_form_class = SetPasswordForm

    _errors = {}
    user = None
    set_password_form = None

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        try:
            uid = force_str(uid_decoder(attrs['uid']))
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({'uid': ['Invalid value']})

        if not default_token_generator.check_token(self.user, attrs['token']):
            raise serializers.ValidationError({'token': ['Invalid value']})

        self.custom_validation(attrs)
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs,
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)

        return attrs

    def save(self):
        return self.set_password_form.save()
