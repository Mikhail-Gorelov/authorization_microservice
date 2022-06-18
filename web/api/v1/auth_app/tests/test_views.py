import pytest
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from rest_framework import status
from django.contrib.auth import get_user_model

User = get_user_model()

pytestmark = [pytest.mark.django_db]


def test_login(api_client):
    url = reverse('api:v1:auth_app:sign-in')
    data = {
        "email": "test@test.com",
        "password": "tester26"
    }
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.parametrize(
    ['data', 'status_code'],
    (
        (
            {'email': 'test@test.com', "password": "tester26"}, status.HTTP_200_OK
        ),
        (
            {'email': 'test@test.co', "password": "tester26"}, status.HTTP_400_BAD_REQUEST
        ),
        (
            {'email': 'test@test.com', "password": "tester2"}, status.HTTP_400_BAD_REQUEST
        ),
    )
)
def test_login_validate(api_client, data, status_code):
    url = reverse('api:v1:auth_app:sign-in')
    response = api_client.post(url, data)
    assert response.status_code == status_code


@pytest.mark.parametrize(
    ['data', 'status_code'],
    (
        (
            {'email': 'user100@test.com', "password": "stringstring", "password1": "stringstring"},
            status.HTTP_201_CREATED
        ),
        (
            {'email': 'lalala', "password": "stringstring", "password1": "stringstring"}, status.HTTP_400_BAD_REQUEST
        ),
        (
            {'email': 'user100@test.com', "password": "string", "password1": "string"}, status.HTTP_400_BAD_REQUEST
        ),
        (
            {'email': 'test@test.com', "password": "tester26", "password1": "tester26"}, status.HTTP_400_BAD_REQUEST
        ),
        (
            {'email': 'user100@test.com', "password": "string", "password1": "strings"}, status.HTTP_400_BAD_REQUEST
        ),
    )
)
def test_sign_up_email_validate(api_client, data, status_code):
    url = reverse('api:v1:auth_app:sign-up-email')
    response = api_client.post(url, data)
    assert response.status_code == status_code


@pytest.mark.parametrize(
    ['data', 'status_code'],
    (
        (
            {'phone_number': '+79032851213', "password": "stringstring", "password1": "stringstring"},
            status.HTTP_201_CREATED
        ),
        (
            {'phone_number': '12345', "password": "stringstring", "password1": "stringstring"},
            status.HTTP_400_BAD_REQUEST
        ),
        (
            {'phone_number': '+79032851213', "password": "string", "password1": "string"}, status.HTTP_400_BAD_REQUEST
        ),
        (
            {'phone_number': '+79032851213', "password": "stringstring", "password1": "stringstrings"},
            status.HTTP_400_BAD_REQUEST
        )
    )
)
def test_sign_up_phone_validate(api_client, data, status_code):
    url = reverse('api:v1:auth_app:sign-up-phone')
    response = api_client.post(url, data)
    assert response.status_code == status_code


@pytest.mark.django_db
def test_verify_email(api_client):
    user = User.objects.get(email="test@test.com")
    url = reverse('api:v1:auth_app:verify-email')
    response = api_client.post(url, {'key': user.confirmation_key})
    assert response.status_code == status.HTTP_201_CREATED


@pytest.mark.django_db
def test_verify_email_validate(api_client):
    user = User.objects.get(email="test@test.com")
    url = reverse('api:v1:auth_app:verify-email')
    response = api_client.post(url, {'key': f'{user.confirmation_key}-random'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_verify_jwt(api_client):
    url_login = reverse('api:v1:auth_app:sign-in')
    data = {
        "email": "test@test.com",
        "password": "tester26"
    }
    response_login = api_client.post(url_login, data)
    url_verify_jwt = reverse('api:v1:auth_app:verify-jwt')
    response = api_client.post(url_verify_jwt, {'token': response_login.data['access_token']})
    assert response.status_code == status.HTTP_200_OK


def test_verify_jwt_validate(api_client):
    url = reverse('api:v1:auth_app:verify-jwt')
    response = api_client.post(url, {'token': 'something_wrong'})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_refresh_jwt(api_client):
    url_login = reverse('api:v1:auth_app:sign-in')
    data = {
        "email": "test@test.com",
        "password": "tester26"
    }
    response_login = api_client.post(url_login, data)
    url_refresh_jwt = reverse('api:v1:auth_app:refresh-jwt')
    response = api_client.post(url_refresh_jwt, {'refresh': response_login.data['refresh_token']})
    assert response.status_code == status.HTTP_200_OK


def test_refresh_jwt_validate(api_client):
    url = reverse('api:v1:auth_app:refresh-jwt')
    response = api_client.post(url, {'refresh': 'something_wrong'})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_logout(api_client):
    url = reverse('api:v1:auth_app:logout')
    response = api_client.post(url)
    assert response.status_code == status.HTTP_200_OK


def test_logout_validate(client):
    url = reverse('api:v1:auth_app:logout')
    response = client.post(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_password_reset(api_client):
    url = reverse('api:v1:auth_app:password-reset')
    data = {
        'email': 'test@test.com'
    }
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_201_CREATED


def test_password_reset_validate(api_client):
    url = reverse('api:v1:auth_app:password-reset')
    data = {
        'email': 'something-wrong'
    }
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_password_reset_confirm(api_client):
    url_reset = reverse('api:v1:auth_app:password-reset')
    data_reset = {
        'email': 'test@test.com'
    }
    response_reset = api_client.post(url_reset, data_reset)
    user = User.objects.get(email=response_reset.data.get('email'))
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    data_confirm = {
        'new_password1': 'stringstring',
        'new_password2': 'stringstring',
        'uid': uid,
        'token': token
    }
    url_confirm = reverse('api:v1:auth_app:password-reset-confirm-email')
    response = api_client.post(url_confirm, data_confirm)
    assert response.status_code == status.HTTP_201_CREATED
