import logging
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class AuthTokenMiddleware(MiddlewareMixin):
    """
    Middleware для проверки авторизационных токенов
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def process_request(self, request):
        # Если запрос аутентифицирован через сессию Django, пропускаем проверку токена
        if request.user.is_authenticated:
            return None

        # Получаем токен из сессии
        auth_token = request.session.get('auth_token')

        if not auth_token:
            # Если токена нет в сессии, пропускаем (будет обрабатываться стандартной Django-аутентификацией)
            return None

        # Импортируем здесь, чтобы избежать циклического импорта
        from .models import AuthToken

        # Пробуем найти токен в базе данных
        try:
            token_obj = AuthToken.objects.get(token=auth_token)
            # Проверяем действительность токена
            if token_obj.is_valid():
                # Устанавливаем user в request
                request.user = token_obj.user
                # Обновляем информацию об аутентификации
                request._auth = token_obj
            else:
                # Токен истек, удаляем его из сессии
                if 'auth_token' in request.session:
                    del request.session['auth_token']
        except AuthToken.DoesNotExist:
            # Токен не найден, удаляем его из сессии
            if 'auth_token' in request.session:
                del request.session['auth_token']

        return None


class ContentSecurityPolicyMiddleware(MiddlewareMixin):
    """
    Middleware для установки Content Security Policy (CSP) заголовков
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Добавляем CSP заголовок
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' https://cdn.tailwindcss.com https://code.jquery.com https://cdn.jsdelivr.net 'unsafe-inline'",
            "style-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net 'unsafe-inline'",
            "img-src 'self' data: https://cdn.jsdelivr.net",
            "font-src 'self' https://cdn.jsdelivr.net",
            "connect-src 'self'",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests"
        ]

        response['Content-Security-Policy'] = "; ".join(csp_directives)

        # Добавляем другие заголовки безопасности
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

        return response