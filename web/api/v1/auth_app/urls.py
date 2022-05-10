from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()

urlpatterns = [
    path('sign-in/', views.LoginView.as_view(), name='sign-in'),
    path('sign-up/', views.SignUpView.as_view(), name='sign-up'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
    path('password-reset/', views.PasswordResetView.as_view(), name='password-reset')
]

urlpatterns += router.urls
