import re
import json
import hashlib
import logging
import secrets
import traceback  # Для отслеживания вызовов
from urllib.parse import urlparse
from django.conf import settings
from django.middleware.csrf import get_token
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .csrf_service import CSRFTokenService

logger = logging.getLogger(__name__)

class CSRFStrictProtectionMiddleware:
    """
    Улучшенная проверка CSRF с проверкой подлинности токенов через Redis
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_urls = [
            r'^/static/',
            r'^/media/',
            r'^/admin/',
            r'^/favicon\.ico$',
            r'^/browser-verify/',
            r'^/api/csrf/refresh/$',  # Эндпоинт для обновления CSRF-токена
        ]
        self.exempt_urls = [re.compile(url) for url in self.exempt_urls]
        self.allowed_methods = getattr(settings, 'ALLOWED_REQUEST_METHODS', ['GET', 'POST'])
        self.require_valid_referer = getattr(settings, 'REQUIRE_VALID_REFERER', True)
        self.allowed_referers = getattr(settings, 'ALLOWED_REFERERS', [])
        self.require_valid_user_agent = getattr(settings, 'REQUIRE_VALID_USER_AGENT', True)

        # Добавляем API URL паттерны для строгой проверки
        self.api_url_patterns = [
            r'^/api/',
        ]
        self.api_url_patterns = [re.compile(url) for url in self.api_url_patterns]

        # Добавляем паттерны для GET-запросов к API, которые нужно разрешить без проверки CSRF
        self.api_get_exempt_patterns = [
            r'^/api/conversations/',
            r'^/api/user/profile/',
            r'^/api/messages/',
        ]
        self.api_get_exempt_patterns = [re.compile(url) for url in self.api_get_exempt_patterns]

    def __call__(self, request):
        # Запись в лог начала обработки запроса
        logger.warning(f"CSRF PROTECTION START: {request.method} {request.path} from {self._get_client_ip(request)}")

        # Получаем трассировку стека для отслеживания вызовов
        stack_trace = ''.join(traceback.format_stack())
        logger.debug(f"CSRF Middleware call stack:\n{stack_trace}")

        # Пропускаем защищенные URL
        if any(pattern.match(request.path) for pattern in self.exempt_urls):
            logger.warning(f"CSRF EXEMPT URL: {request.path}")
            return self.get_response(request)

        # Пропускаем GET-запросы к специальным API эндпоинтам
        if request.method == 'GET':
            # Для обычных GET запросов - пропускаем
            if not any(pattern.match(request.path) for pattern in self.api_url_patterns):
                logger.warning(f"CSRF EXEMPT REGULAR GET METHOD: {request.path}")
                # Для GET-запросов генерируем CSRF-токен, если его нет
                if 'csrftoken' not in request.COOKIES:
                    response = self.get_response(request)
                    token = CSRFTokenService.generate_token(request)
                    response.set_cookie(
                        'csrftoken',
                        token,
                        max_age=getattr(settings, 'CSRF_TOKEN_EXPIRY', 24 * 60 * 60),
                        httponly=False,
                        secure=settings.CSRF_COOKIE_SECURE,
                        samesite=settings.CSRF_COOKIE_SAMESITE
                    )
                    return response
                return self.get_response(request)
            # Для GET запросов к разрешенным API - пропускаем без проверки
            elif any(pattern.match(request.path) for pattern in self.api_get_exempt_patterns):
                logger.warning(f"CSRF EXEMPT API GET METHOD: {request.path}")
                return self.get_response(request)

        # Проверка метода запроса
        if request.method not in self.allowed_methods:
            logger.warning(f"CSRF METHOD NOT ALLOWED: {request.method}")
            return HttpResponse("Method Not Allowed", status=405)

        # Строгая проверка для API запросов (не GET методы)
        if any(pattern.match(request.path) for pattern in self.api_url_patterns) and request.method != 'GET':
            logger.warning(f"CSRF API REQUEST: {request.path}")

            # Проверка наличия CSRF токена в заголовке
            csrf_header = request.META.get('HTTP_X_CSRFTOKEN')
            logger.warning(f"CSRF TOKEN IN HEADER: {'Present' if csrf_header else 'Missing'} - Value: {csrf_header}")

            if not csrf_header:
                logger.warning(f"X-CSRFToken header missing in API request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "X-CSRFToken header required"}, status=403)

            # Проверка наличия CSRF токена в куках (для совместимости)
            csrf_cookie = request.COOKIES.get('csrftoken')
            logger.warning(f"CSRF TOKEN IN COOKIE: {'Present' if csrf_cookie else 'Missing'} - Value: {csrf_cookie}")

            if not csrf_cookie:
                logger.warning(f"csrftoken cookie missing in API request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "csrftoken cookie required"}, status=403)

            # Строгая проверка подлинности токена
            is_valid = CSRFTokenService.validate_token(request, csrf_header)
            logger.warning(f"CSRF TOKEN VALIDATION RESULT: {'Valid' if is_valid else 'Invalid'} for token: {csrf_header}")

            if not is_valid:
                logger.warning(f"CSRF VALIDATION FAILED: Invalid CSRF token in API request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "Invalid CSRF token"}, status=403)
            else:
                logger.warning(f"CSRF VALIDATION SUCCEEDED: Valid token for {request.path}")

        # Проверка AJAX-запросов (не GET)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' and request.method != 'GET':
            logger.warning(f"CSRF AJAX REQUEST: {request.path}")

            csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
            if not csrf_token:
                logger.warning(f"CSRF token missing in AJAX request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "CSRF token missing"}, status=403)

            # Строгая проверка подлинности токена для AJAX
            is_valid = CSRFTokenService.validate_token(request, csrf_token)
            logger.warning(f"CSRF AJAX TOKEN VALIDATION RESULT: {'Valid' if is_valid else 'Invalid'}")

            if not is_valid:
                logger.warning(f"Invalid CSRF token in AJAX request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "Invalid CSRF token"}, status=403)

        # Проверка Referer для POST запросов
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

        # Продолжаем обработку запроса
        logger.warning(f"CSRF PASSED ALL CHECKS: {request.path}")
        response = self.get_response(request)

        # Записываем статус ответа для отладки
        logger.warning(f"CSRF RESPONSE STATUS: {response.status_code} for {request.path}")

        # После успешной обработки запроса можно обновить токен (опционально)
        # Это повысит безопасность, но усложнит логику на клиентской стороне
        if getattr(settings, 'CSRF_ROTATE_TOKENS', False) and request.method == 'POST':
            old_token = request.COOKIES.get('csrftoken', '')
            if old_token and hasattr(response, 'set_cookie'):
                new_token = CSRFTokenService.refresh_token(request, old_token)
                response.set_cookie(
                    'csrftoken',
                    new_token,
                    max_age=getattr(settings, 'CSRF_TOKEN_EXPIRY', 24 * 60 * 60),
                    httponly=False,
                    secure=settings.CSRF_COOKIE_SECURE,
                    samesite=settings.CSRF_COOKIE_SAMESITE
                )

        # Заголовки безопасности
        if hasattr(response, '__setitem__'):
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'

        logger.warning(f"CSRF PROTECTION END: {request.method} {request.path}")
        return response

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')
