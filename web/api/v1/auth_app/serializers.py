from django.contrib.auth import authenticate
from rest_framework import serializers
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from main.models import UserType

# Create your serializers here.

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=7, write_only=True)

    def authenticate(self, **kwargs) -> Optional['UserType']:
        return authenticate(self.context['request'], **kwargs)

    def validate(self, attrs):
        user = self.authenticate(email=attrs['email'], password=attrs['password'])
        attrs['user'] = user
        if not user and attrs['email']:
            raise serializers.ValidationError('Banned')
        if not user:
            raise serializers.ValidationError('Wrong credentials')
        return attrs
