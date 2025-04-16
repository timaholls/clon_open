import datetime
from django.shortcuts import redirect
from django.urls import reverse
from django.http import JsonResponse, HttpResponse
from django.conf import settings
import logging
import re
from .models import BlockedIP

logger = logging.getLogger(__name__)

class IPBlockMiddleware:
    """
    Middleware для блокировки доступа по IP-адресу
    """
    def __init__(self, get_response):
        self.get_response = get_response
        # URL, которые не будут проверяться на блокировку
        self.exempt_urls = [
            r'^/static/',
            r'^/media/',
            r'^/admin/',  # Админка всегда доступна
        ]
        self.exempt_urls = [re.compile(url) for url in self.exempt_urls]

    def __call__(self, request):
        # Получаем IP-адрес клиента
        client_ip = self._get_client_ip(request)

        # Если IP в списке исключений, пропускаем проверку
        if client_ip in getattr(settings, 'IP_WHITELIST', []):
            return self.get_response(request)

        # Пропускаем проверку для определенных URL
        if any(pattern.match(request.path) for pattern in self.exempt_urls):
            return self.get_response(request)

        # Проверяем, заблокирован ли IP
        if BlockedIP.is_ip_blocked(client_ip):
            # Для API-запросов возвращаем JSON-ответ
            if request.path.startswith('/api/'):
                return JsonResponse({
                    'error': 'Access denied',
                    'message': 'Your IP address has been blocked',
                }, status=403)

            # Для обычных запросов возвращаем страницу блокировки
            return HttpResponse(
                '<html><body><h1>Access Denied</h1>'
                '<p>Your IP address has been blocked.</p>'
                '</body></html>',
                content_type='text/html',
                status=403
            )

        # Если IP не заблокирован, продолжаем обработку запроса
        return self.get_response(request)

    def _get_client_ip(self, request):
        """Получает IP-адрес клиента с учетом прокси"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')
