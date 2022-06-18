import pytest
from django.conf import settings


@pytest.fixture()
def api_client(client):
    client.defaults['HTTP_AUTHORIZATION'] = f'{settings.API_KEY_HEADER} {settings.API_KEY}'
    return client
