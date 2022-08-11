from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()

app_name = 'auth_app'

urlpatterns = [
    path('sign-in/email/', views.LoginEmailView.as_view(), name='sign-in-email'),
    path('sign-in/phone/', views.LoginPhoneView.as_view(), name='sign-in-phone'),
    path('sign-up/email/', views.SignUpEmailView.as_view(), name='sign-up-email'),
    path('sign-up/phone/', views.SignUpPhoneView.as_view(), name='sign-up-phone'),
    path('verify-user/', views.VerifyView.as_view(), name='verify-email'),
    path('password/reset/email/', views.PasswordResetEmailView.as_view(), name='password-reset-email'),
    path('password/reset/phone/', views.PasswordResetPhoneView.as_view(), name='password-reset-phone'),
    path('password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm-email'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('verify-jwt/', views.VerifyJWTView.as_view(), name='verify-jwt'),
    path('refresh-jwt/', views.RefreshJWTView.as_view(), name='refresh-jwt'),
]

urlpatterns += router.urls
