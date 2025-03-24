import re
import json
import hashlib
import logging
from urllib.parse import urlparse
from django.conf import settings
from django.middleware.csrf import get_token
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

class CSRFStrictProtectionMiddleware:
    """
    Улучшенная проверка CSRF с гибкой проверкой отпечатка браузера
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_urls = [
            r'^/static/',
            r'^/media/',
            r'^/admin/',
            r'^/favicon\.ico$',
            r'^/browser-verify/',
        ]
        self.exempt_urls = [re.compile(url) for url in self.exempt_urls]
        self.allowed_methods = getattr(settings, 'ALLOWED_REQUEST_METHODS', ['GET', 'POST'])
        self.check_browser_headers = getattr(settings, 'CHECK_BROWSER_HEADERS', True)
        self.browser_header_checks = getattr(settings, 'BROWSER_HEADER_CHECKS',
                                           ['Accept', 'Accept-Language', 'User-Agent'])
        self.require_valid_referer = getattr(settings, 'REQUIRE_VALID_REFERER', True)
        self.allowed_referers = getattr(settings, 'ALLOWED_REFERERS', [])
        self.require_valid_user_agent = getattr(settings, 'REQUIRE_VALID_USER_AGENT', True)
        self.browser_fingerprint_check = getattr(settings, 'BROWSER_FINGERPRINT_CHECK', True)

    def __call__(self, request):
        if any(pattern.match(request.path) for pattern in self.exempt_urls):
            return self.get_response(request)

        # Проверка метода запроса
        if request.method not in self.allowed_methods:
            return HttpResponse("Method Not Allowed", status=405)

        # Проверка AJAX-запросов
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
            if not csrf_token:
                logger.warning(f"CSRF token missing in AJAX request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "CSRF token missing"}, status=403)

        # Проверка Referer
        if self.require_valid_referer and request.method == 'POST':
            referer = request.META.get('HTTP_REFERER', '')
            if not referer:
                logger.warning(f"Referer missing from {self._get_client_ip(request)}")
                return HttpResponse("Forbidden - Referer required", status=403)
            parsed_referer = urlparse(referer)
            referer_host = parsed_referer.netloc.split(':')[0]
            if referer_host not in self.allowed_referers:
                logger.warning(f"Invalid Referer: {referer}")
                return HttpResponse("Forbidden - Invalid Referer", status=403)

        # Проверка User-Agent
        if self.require_valid_user_agent and not request.META.get('HTTP_USER_AGENT'):
            logger.warning(f"User-Agent missing from {self._get_client_ip(request)}")
            return HttpResponse("Forbidden - User-Agent required", status=403)

        # Проверка отпечатка браузера (обновленная логика)
        if self.browser_fingerprint_check and request.method == 'POST':
            browser_fingerprint = self._get_browser_fingerprint(request)
            session_fingerprint = request.session.get('browser_fingerprint')

            if not session_fingerprint:
                request.session['browser_fingerprint'] = browser_fingerprint
            else:
                # Разрешаем изменение отпечатка, если CSRF токен валиден
                if session_fingerprint != browser_fingerprint:
                    logger.info(f"Updating browser fingerprint for {self._get_client_ip(request)}")
                    request.session['browser_fingerprint'] = browser_fingerprint

        # Генерация CSRF токена
        if 'csrftoken' not in request.COOKIES:
            get_token(request)

        response = self.get_response(request)
        if hasattr(response, '__setitem__'):
            # Заголовки безопасности
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'
        return response

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')

    def _get_browser_fingerprint(self, request):
        """Гибкий отпечаток на основе стабильных параметров"""
        fingerprint_data = {
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'csrf_token': request.META.get('CSRF_COOKIE') or request.COOKIES.get('csrftoken', ''),
            'sec_ch_ua': request.META.get('HTTP_SEC_CH_UA', ''),
        }
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()