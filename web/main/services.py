from django.conf import settings
from microservice_request.services import ConnectionService

class MainService(ConnectionService):
    service = settings.NOTIFICATIONS_API_URL
