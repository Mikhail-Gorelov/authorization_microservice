from django.urls import path
from . import views

app_name = 'profile_app'

urlpatterns = [
    path('user-profile/', views.GetUserView.as_view(), name='get_user')
]
