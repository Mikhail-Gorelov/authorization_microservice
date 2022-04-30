from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()

urlpatterns = [
    path('sign-in/', views.LoginView.as_view(), name='sign-in'),
]

urlpatterns += router.urls
