from django.urls import path
from . import views

app_name = 'profile_app'

urlpatterns = [
    path('user-profile/', views.GetUserView.as_view(), name='get_user'),
    path('user-profile/set-password/', views.ChangeUserPasswordView.as_view(), name='set-password'),
    path('user-profile/change/', views.ChangeUserProfileView.as_view(), name='change-profile'),
    path('email-list/', views.ListEmailsView.as_view(), name='email-list'),
    path('default-address/billing/change/', views.ChangeBillingAddressView.as_view(), name='change-billing-address'),
    path('default-address/shipping/change/', views.ChangeShippingAddressView.as_view(), name='change-shipping-address'),
]
