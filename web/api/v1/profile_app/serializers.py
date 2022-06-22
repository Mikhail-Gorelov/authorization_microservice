from rest_framework import serializers
from main import models
from django.contrib.auth import get_user_model

User = get_user_model()


class GetAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Address
        fields = ("street_address_1", "street_address_2", "city", "city_area", "postal_code", "country")

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
            "first_name", "last_name", "email", "phone_number", "gender", "birthday", "avatar",
            "default_shipping_address",
            "default_billing_address"
        )
