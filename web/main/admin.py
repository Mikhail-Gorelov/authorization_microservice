from django.conf import settings
from django.contrib import admin
from .models import Address
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _

User = get_user_model()


@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ('id', 'country')
    list_filter = ('country',)
    search_fields = ('country',)


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    ordering = ('-id',)
    list_display = ('email', 'phone_number', 'full_name', 'is_active')
    search_fields = ('first_name', 'last_name', 'email')

    fieldsets = (
        (_('Personal info'), {'fields': ('id', 'first_name', 'last_name', 'email', 'phone_number', 'avatar',
                                         'default_shipping_address', 'default_billing_address', 'gender', 'birthday')}),
        (_('Secrets'), {'fields': ('password',)}),
        (
            _('Permissions'),
            {
                'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
            },
        ),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (
            None,
            {
                'classes': ('wide',),
                'fields': ('email', 'password1', 'password2'),
            },
        ),
    )
    readonly_fields = ('id',)


title = settings.MICROSERVICE_TITLE

admin.site.site_title = title
admin.site.site_header = title
admin.site.site_url = '/'
admin.site.index_title = title

admin.site.unregister(Group)
