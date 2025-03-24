import datetime
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth import get_user_model, login
from django.utils import timezone
import logging
import re
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from .models import AuthToken, BlockedIP

logger = logging.getLogger(__name__)
User = get_user_model()

class AuthTokenMiddleware:
    """
    Middleware to authenticate users via token.

    This middleware checks for a token in the request headers or session,
    and authenticates the user if the token is valid.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip authentication for authentication-related views and static files
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return self.get_response(request)

        # Skip authentication for authentication-related views
        if request.path in [reverse('login'), reverse('signup'),
                           '/api/login/', '/api/signup/']:
            return self.get_response(request)

        # Check if user is already authenticated
        if request.user.is_authenticated:
            # User is authenticated, continue with the request
            response = self.get_response(request)
            return response

        # Try to get token from session
        token_value = request.session.get('auth_token')

        # If not in session, try to get from authorization header
        if not token_value and 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Token '):
                token_value = auth_header.split(' ')[1]

        # If no token found, get from cookie
        if not token_value and 'auth_token' in request.COOKIES:
            token_value = request.COOKIES.get('auth_token')

        # If no token found, redirect to login
        if not token_value:
            # Prevent redirect loop by checking if we're already on login page
            if request.path == reverse('login'):
                return self.get_response(request)

            if request.path.startswith('/api/'):
                # If API request, return 401
                response = redirect(reverse('login'))
                response.status_code = 401
                return response
            else:
                # If browser request, redirect to login
                return redirect(reverse('login'))

        # Try to find token in database
        try:
            token = AuthToken.objects.get(token=token_value)

            # Check if token is expired
            if token.expires_at < timezone.now():
                # Delete expired token
                token.delete()

                # Clear session
                request.session.flush()

                # Prevent redirect loop by checking if we're already on login page
                if request.path == reverse('login'):
                    return self.get_response(request)

                return redirect(reverse('login'))

            # Token is valid, set user and login user
            request.user = token.user
            login(request, token.user)

            # Log successful authentication
            logger.debug(f"User {request.user.email} authenticated via token")

        except AuthToken.DoesNotExist:
            # Token not found, delete from session and cookies
            if 'auth_token' in request.session:
                del request.session['auth_token']

            # Prevent redirect loop by checking if we're already on login page
            if request.path == reverse('login'):
                return self.get_response(request)

            return redirect(reverse('login'))

        # Continue with the request
        response = self.get_response(request)
        return response


class APISecurityMiddleware:
    """
    Middleware для дополнительной проверки безопасности API запросов
    Проверяет наличие CSRF-токенов в заголовке и куках для API-запросов
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.api_url_pattern = re.compile(r'^/api/')
        self.exempt_urls = [
            r'^/api/login/',
            r'^/api/signup/',
            r'^/static/',
            r'^/media/',
            r'^/browser-verify/',
        ]
        self.exempt_urls = [re.compile(url) for url in self.exempt_urls]

    def __call__(self, request):
        # Проверка только для API запросов
        if self.api_url_pattern.match(request.path) and not any(pattern.match(request.path) for pattern in self.exempt_urls):
            # Проверка CSRF токена в заголовке и куках
            csrf_header = request.META.get('HTTP_X_CSRFTOKEN')
            csrf_cookie = request.COOKIES.get('csrftoken')

            # Проверяем наличие токена в заголовке
            if not csrf_header:
                logger.warning(f"API Security: X-CSRFToken header missing in API request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "CSRF protection: X-CSRFToken header is required"}, status=403)

            # Проверяем наличие токена в куках
            if not csrf_cookie:
                logger.warning(f"API Security: csrftoken cookie missing in API request from {self._get_client_ip(request)}")
                return JsonResponse({"error": "CSRF protection: csrftoken cookie is required"}, status=403)

        # Продолжаем обработку запроса
        return self.get_response(request)

    def _get_client_ip(self, request):
        """Получает IP адрес клиента"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')


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
