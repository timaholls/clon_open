import re
import json
import time
import hashlib
import logging
from urllib.parse import urlparse
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

class CSRFStrictProtectionMiddleware:
    """
    Middleware для строгой проверки CSRF токенов и заголовков браузера
    """
    def __init__(self, get_response):
        self.get_response = get_response

        # URL пути, которые не требуют проверки (статика, медиа, админка)
        self.exempt_urls = [
            r'^/static/',
            r'^/media/',
            r'^/admin/',
            r'^/favicon\.ico$',
            r'^/browser-verify/',  # Добавляем URL для проверки браузера
        ]

        # Компилируем регулярные выражения для производительности
        self.exempt_urls = [re.compile(url) for url in self.exempt_urls]

        # Разрешённые методы запросов (по умолчанию)
        self.allowed_methods = getattr(settings, 'ALLOWED_REQUEST_METHODS', ['GET', 'POST'])

        # Проверка заголовков браузера
        self.check_browser_headers = getattr(settings, 'CHECK_BROWSER_HEADERS', True)
        self.browser_header_checks = getattr(settings, 'BROWSER_HEADER_CHECKS',
                                            ['Accept', 'Accept-Language', 'Accept-Encoding', 'User-Agent'])

        # Проверка Referer
        self.require_valid_referer = getattr(settings, 'REQUIRE_VALID_REFERER', True)
        self.allowed_referers = getattr(settings, 'ALLOWED_REFERERS', ['localhost', '127.0.0.1'])

        # Проверка User-Agent
        self.require_valid_user_agent = getattr(settings, 'REQUIRE_VALID_USER_AGENT', True)

        # Проверка отпечатка браузера
        self.browser_fingerprint_check = getattr(settings, 'BROWSER_FINGERPRINT_CHECK', True)

    def __call__(self, request):
        # Пропускаем проверку для исключённых URL
        if any(pattern.match(request.path) for pattern in self.exempt_urls):
            return self.get_response(request)

        # Проверяем метод запроса
        if request.method not in self.allowed_methods:
            return HttpResponse("Метод не разрешен", status=405)

        # Проверяем AJAX-запросы (они должны содержать CSRF token в заголовке X-CSRFToken)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
            if not csrf_token:
                logger.warning(f"CSRF token missing in AJAX request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "CSRF token missing"}, status=403)

        # Проверка Referer для защиты от CSRF
        if self.require_valid_referer and request.method == 'POST':
            referer = request.META.get('HTTP_REFERER', '')
            if not referer:
                logger.warning(f"Referer header missing in POST request from {self._get_client_ip(request)}")
                return HttpResponse("Forbidden - Referer required", status=403)

            # Проверяем, что Referer присутствует в списке разрешённых
            parsed_referer = urlparse(referer)
            referer_host = parsed_referer.netloc.split(':')[0]

            if referer_host not in self.allowed_referers:
                logger.warning(f"Invalid Referer: {referer} from {self._get_client_ip(request)}")
                return HttpResponse("Forbidden - Invalid Referer", status=403)

        # Проверка User-Agent
        if self.require_valid_user_agent:
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            if not user_agent:
                logger.warning(f"User-Agent header missing from {self._get_client_ip(request)}")
                return HttpResponse("Forbidden - User-Agent required", status=403)

        # Проверка заголовков браузера
        if self.check_browser_headers:
            missing_headers = []
            for header in self.browser_header_checks:
                header_key = f'HTTP_{header.upper().replace("-", "_")}'
                if header_key not in request.META:
                    missing_headers.append(header)

            if missing_headers:
                logger.warning(f"Missing browser headers: {missing_headers} from {self._get_client_ip(request)}")
                return HttpResponse("Forbidden - Browser headers required", status=403)

        # Проверка отпечатка браузера
        if self.browser_fingerprint_check and request.method == 'POST':
            browser_fingerprint = self._get_browser_fingerprint(request)
            session_fingerprint = request.session.get('browser_fingerprint')

            # Если нет отпечатка в сессии, сохраняем его
            if not session_fingerprint:
                request.session['browser_fingerprint'] = browser_fingerprint
            # Если отпечатки не совпадают, запрещаем запрос
            elif session_fingerprint != browser_fingerprint:
                logger.warning(f"Browser fingerprint mismatch from {self._get_client_ip(request)}")
                return HttpResponse("Forbidden - Browser fingerprint mismatch", status=403)

        # Генерируем CSRF токен, если его нет
        if 'csrftoken' not in request.COOKIES:
            get_token(request)

        # Проверка на наличие CSRF токена в POST запросах
        if request.method == 'POST' and not request.path.endswith(csrf_exempt.__name__):
            # Проверяем наличие CSRF токена в куках
            if 'csrftoken' not in request.COOKIES and 'csrfmiddlewaretoken' not in request.POST:
                logger.warning(f"CSRF token missing in POST request from {self._get_client_ip(request)}")
                return HttpResponse("Forbidden - CSRF token missing", status=403)

        # Продолжаем обработку запроса стандартным образом
        response = self.get_response(request)

        # Добавляем дополнительные заголовки безопасности
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Feature-Policy'] = "camera 'none'; microphone 'none'; geolocation 'none'"
        response['Permissions-Policy'] = "camera=(), microphone=(), geolocation=()"

        return response

    def _get_client_ip(self, request):
        """Получение IP адреса клиента с учетом прокси"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _get_browser_fingerprint(self, request):
        """Создание отпечатка браузера на основе заголовков запроса"""
        fingerprint_data = {}

        # Сбор данных из заголовков
        headers_to_check = [
            'HTTP_USER_AGENT',
            'HTTP_ACCEPT',
            'HTTP_ACCEPT_ENCODING',
            'HTTP_ACCEPT_LANGUAGE',
            'HTTP_SEC_CH_UA',
            'HTTP_SEC_CH_UA_PLATFORM',
            'HTTP_SEC_CH_UA_MOBILE',
        ]

        for header in headers_to_check:
            if header in request.META:
                fingerprint_data[header] = request.META[header]

        # Добавляем IP для дополнительной точности
        fingerprint_data['IP'] = self._get_client_ip(request)

        # Создаем хеш на основе собранных данных
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
