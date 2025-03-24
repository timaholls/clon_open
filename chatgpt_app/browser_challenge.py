import re  # Добавьте импорт модуля re
import logging
from django.http import HttpResponse, HttpResponseRedirect
from django.core.cache import cache
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string

logger = logging.getLogger(__name__)

class BrowserChallengeMiddleware:
    """
    Упрощенный middleware для проверки наличия JavaScript и cookies в браузере.
    """
    def __init__(self, get_response):
        self.get_response = get_response

        # URL пути, которые не требуют проверки (статика, медиа, админка)
        self.exempt_urls = [
            r'^/static/',
            r'^/media/',
            r'^/admin/',
            r'^/favicon\\.ico$',
        ]

        # Компилируем регулярные выражения для производительности
        self.exempt_urls = [re.compile(url) for url in self.exempt_urls]  # Скомпилируем регулярные выражения

        # Локальные хосты, которые освобождаются от некоторых проверок
        self.local_hosts = getattr(settings, 'LOCAL_HOSTS', ['localhost', '127.0.0.1'])

    def __call__(self, request):
        # Пропускаем проверку для исключённых URL
        if any(pattern.match(request.path) for pattern in self.exempt_urls):
            return self.get_response(request)

        # Получаем IP-адрес клиента
        client_ip = self._get_client_ip(request)

        # Если клиент уже прошёл проверку, продолжаем обработку запроса
        if self._client_verified(request, client_ip):
            logger.debug(f"Browser verification passed for IP {client_ip}, processing request to {request.path}")
            return self.get_response(request)

        logger.info(f"Starting browser verification for IP {client_ip}, path: {request.path}")

        # Отображаем страницу с JavaScript-проверкой
        context = {
            'redirect_url': request.path,
            'is_local': request.get_host().split(':')[0] in self.local_hosts,
        }

        html_content = render_to_string('browser_challenge.html', context)
        return HttpResponse(html_content)

    def _client_verified(self, request, client_ip):
        """Проверяет, прошёл ли клиент верификацию"""
        verification_cookie = request.COOKIES.get('browser_verified')
        if not verification_cookie:
            logger.debug(f"No verification cookie for IP {client_ip}")
            return False

        logger.debug(f"Verification successful for IP {client_ip}")
        return True

    def _get_client_ip(self, request):
        """Получение IP адреса клиента с учетом прокси"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
