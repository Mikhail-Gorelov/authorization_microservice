from typing import Optional
from django_countries.serializers import CountryFieldMixin
from rest_framework import serializers
from main import models
from django.contrib.auth import get_user_model, authenticate

from main.choices import GenderChoice

User = get_user_model()


class GetAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Address
        fields = ("street_address", "city", "postal_code", "country")


class GetUserSerializer(serializers.ModelSerializer):
    gender = serializers.SerializerMethodField('get_gender')
    avatar = serializers.SerializerMethodField('get_avatar')
    default_shipping_address = GetAddressSerializer()
    default_billing_address = GetAddressSerializer()

    def get_gender(self, obj):
        return obj.get_gender_display()

    def get_avatar(self, obj):
        return obj.avatar.url

    class Meta:
        model = User
        fields = (
            "id", "first_name", "last_name", "email",
            "phone_number", "gender", "birthday", "avatar",
            "default_shipping_address",
            "default_billing_address"
        )


class ChangeUserPasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, min_length=7)
    new_password1 = serializers.CharField(write_only=True, min_length=7)
    new_password2 = serializers.CharField(write_only=True, min_length=7)

    def authenticate(self, **kwargs) -> Optional['UserType']:
        return authenticate(self.context['request'], **kwargs)

    def validate_current_password(self, current_password: str) -> str:
        user = self.context['request'].user
        if user.email:
            self.user = self.authenticate(email=user.email, password=current_password)
        else:
            self.user = self.authenticate(phone_number=user.phone_number, password=current_password)
        if not self.user:
            raise serializers.ValidationError('Wrong current password')
        return current_password

    def validate(self, attrs: dict) -> dict:
        if attrs['new_password1'] != attrs['new_password2']:
            raise serializers.ValidationError("Passwords does not match")
        return attrs

    def save(self, **kwargs):
        self.user.set_password(self.validated_data['new_password1'])
        self.user.save(update_fields=['password'])


class ChangeUserProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    gender = serializers.ChoiceField(
        required=False,
        allow_blank=True,
        allow_null=True,
        choices=GenderChoice.choices)
    avatar = serializers.ImageField(
        required=False,
        allow_null=True,
    )
    birthday = serializers.DateField(
        required=False,
        allow_null=True,
        format="%d-%m-%Y",
        input_formats=["%d-%m-%Y", "%Y-%m-%d"]
    )

    class Meta:
        model = User
        fields = (
            "first_name", "last_name", "gender", "birthday", "avatar",
        )


class ChangeAddressSerializer(CountryFieldMixin, serializers.ModelSerializer):
    class Meta:
        model = models.Address
        fields = ("street_address", "city", "postal_code", "country")


class ListEmailsSerializer(serializers.Serializer):
    users = serializers.ListField(child=serializers.IntegerField())
