import os
import re

from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from phonenumber_field.serializerfields import PhoneNumberField
from django.conf import settings
from django.contrib.auth import authenticate, login
from .authentication_classes import AuthenticationByPhone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from rest_framework import serializers, status
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.http import urlsafe_base64_decode as uid_decoder
from typing import TYPE_CHECKING, Optional
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from api.v1.auth_app.services import AuthAppService
from main import models
from main import choices
from src.celery import app

if TYPE_CHECKING:
    from main.models import UserType

User = get_user_model()


class UserLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', ]


class LoginEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=7, write_only=True)
    remember_me = serializers.BooleanField()

    def authenticate(self, **kwargs) -> Optional['UserType']:
        return authenticate(self.context['request'], **kwargs)

    def validate(self, attrs):
        self.user = self.authenticate(email=attrs['email'], password=attrs['password'])
        attrs['user'] = self.user
        if not self.user:
            raise serializers.ValidationError(_('Wrong credentials'), code=status.HTTP_400_BAD_REQUEST)
        return attrs

    @property
    def data(self):
        if self.validated_data['remember_me'] is True:
            self.context['request'].session['user_id'] = self.user.pk
            return_data = UserLoginSerializer(self.user).data
            return_data['session_id'] = self.context['request'].session.session_key
            return return_data
        else:
            if self.context['request'].session.has_key('user_id'):
                del self.context['request'].session['user_id']

        refresh = RefreshToken.for_user(self.user)
        return_expiration_times = getattr(settings, 'JWT_AUTH_RETURN_EXPIRATION', False)

        tokens = {
            'access_token': str(self.get_token(refresh.access_token)),
            'refresh_token': str(self.get_token(refresh)),
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

    def get_token(self, token):
        user_name = self.user.full_name()
        token['email'] = self.user.email
        token['phone_number'] = str(self.user.phone_number)
        token['full_name'] = user_name
        return token


class LoginPhoneSerializer(serializers.Serializer):
    phone_number = PhoneNumberField()
    password = serializers.CharField(min_length=7, write_only=True)
    remember_me = serializers.BooleanField()

    def validate(self, attrs):
        auth_by_phone = AuthenticationByPhone()
        self.user = auth_by_phone.authenticate(request=self.context['request'], phone_number=attrs['phone_number'],
                                               password=attrs['password'])
        attrs['user'] = self.user
        if not self.user:
            raise serializers.ValidationError(_('Wrong credentials'), code=status.HTTP_400_BAD_REQUEST)
        return attrs

    @property
    def data(self):
        if self.validated_data['remember_me'] is True:
            self.context['request'].session['user_id'] = self.user.pk
            return UserLoginSerializer(self.user).data
        else:
            if self.context['request'].session.has_key('user_id'):
                del self.context['request'].session['user_id']

        refresh = RefreshToken.for_user(self.user)
        return_expiration_times = getattr(settings, 'JWT_AUTH_RETURN_EXPIRATION', False)

        tokens = {
            'access_token': str(self.get_token(refresh.access_token)),
            'refresh_token': str(self.get_token(refresh)),
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

    def get_token(self, token):
        user_name = self.user.full_name()
        token['email'] = self.user.email
        token['phone_number'] = str(self.user.phone_number)
        token['full_name'] = user_name
        return token


class SignUpEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, min_length=7)
    password1 = serializers.CharField(write_only=True, min_length=7)

    def validate_email(self, email: str) -> str:
        if AuthAppService.is_email_exists(email):
            raise serializers.ValidationError(_("User is already registered with this e-mail address."))
        return email

    def validate(self, attrs: dict) -> dict:
        if attrs['password'] != attrs['password1']:
            raise serializers.ValidationError(_("Passwords does not match"), code=status.HTTP_400_BAD_REQUEST)
        return attrs

    def save(self, **kwargs):
        del self.validated_data['password1']
        user = User.objects.create_user(**self.validated_data, is_active=False)
        AuthAppService.send_confirmation_email(user)
        return user


class SignUpPhoneSerializer(serializers.Serializer):
    phone_number = PhoneNumberField()
    password = serializers.CharField(write_only=True, min_length=7)
    password1 = serializers.CharField(write_only=True, min_length=7)

    def validate(self, attrs: dict) -> dict:
        if User.objects.filter(phone_number=attrs['phone_number']).exists():
            raise serializers.ValidationError(_("The user with this number already exists"),
                                              code=status.HTTP_400_BAD_REQUEST)
        if attrs['password'] != attrs['password1']:
            raise serializers.ValidationError(_("Passwords does not match"), code=status.HTTP_400_BAD_REQUEST)
        return attrs

    def save(self, **kwargs):
        del self.validated_data['password1']
        user = User.objects.create_user_by_phone(**self.validated_data, is_active=False)
        # AuthAppService.send_confirmation_sms(user)
        print(user.confirmation_key)
        return user


class VerifySerializer(serializers.Serializer):
    key = serializers.CharField()

    def validate_key(self, key: str):
        self.user = User.from_key(key)
        if not self.user:
            raise serializers.ValidationError(_("Invalid key"), code=status.HTTP_400_BAD_REQUEST)
        return key

    def save(self, **kwargs):
        self.user.is_active = True
        self.user.save(update_fields=['is_active'])


class PasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def save(self, **kwargs):
        email = self.validated_data['email']
        user = AuthAppService.get_user(email=email)
        if not user:
            return
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        url = AuthAppService.get_reset_url(uid=uid, token=token)
        AuthAppService.send_verify_email(email=email, user=user, url=url)


class PasswordResetPhoneSerializer(serializers.Serializer):
    phone_number = PhoneNumberField()

    def save(self, **kwargs):
        phone_number = self.validated_data['phone_number']
        user = AuthAppService.get_user_by_phone(phone_number=phone_number)
        if not user:
            return
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        url = AuthAppService.get_reset_url(uid=uid, token=token)
        print(url)
        # AuthAppService.send_verify_sms(phone_number=phone_number, user=user, url=url)


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate_passwords(self, attrs):
        if attrs['new_password1'] != attrs['new_password2']:
            raise serializers.ValidationError('Passwords does not match')

        return attrs

    def validate_uid(self, uid: str):
        try:
            uid = force_str(uid_decoder(uid))
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError('Invalid uid')
        return uid

    def validate_token(self, token: str):
        if not default_token_generator.check_token(self.user, token):
            raise serializers.ValidationError('Invalid token')

        return token

    def save(self, **kwargs):
        self.user.set_password(self.validated_data['new_password1'])
        self.user.save(update_fields=['password'])
