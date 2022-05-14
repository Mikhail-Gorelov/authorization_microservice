from django.urls import path
from django.views.generic import TemplateView
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()

app_name = 'auth_app'

urlpatterns = [
    path('sign-in/', views.LoginView.as_view(), name='sign-in'),
    path('sign-up/', views.SignUpView.as_view(), name='sign-up'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
    path('password/reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm-email'),
    path(
        'password-reset/<uidb64>/<token>/',
        TemplateView.as_view(template_name='auth_app/includes/reset_password_email_link.html'),
        name='password-reset-confirm',
    ),
    path('logout/', views.LogoutView.as_view(), name='logout')
]

urlpatterns += router.urls
