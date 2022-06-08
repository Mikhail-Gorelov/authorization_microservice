from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from . import views

router = DefaultRouter()

app_name = 'auth_app'

urlpatterns = [
    path('sign-in/', views.LoginView.as_view(), name='sign-in'),
    path('sign-up/email/', views.SignUpEmailView.as_view(), name='sign-up-email'),
    path('sign-up/phone/', views.SignUpPhoneView.as_view(), name='sign-up-email'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
    path('password/reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm-email'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('verify-jwt/', views.VerifyJWTView.as_view(), name='verify-jwt'),
    path('refresh-jwt/', TokenRefreshView.as_view(), name='refresh-jwt'),
    path('set-data-jwt/', views.SetDataJWTView.as_view(), name='set-data-jwt'),
    path('user/user/', views.GetUserView.as_view(), name='get_user')
]

urlpatterns += router.urls
