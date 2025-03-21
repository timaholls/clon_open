from functools import wraps
from django.http import JsonResponse
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)

def api_rate_limit(requests_per_minute=30):
    """
    Ограничивает количество запросов к API от одного пользователя/IP
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Если пользователь аутентифицирован, используем его ID
            if request.user.is_authenticated:
                cache_key = f'api_rate_limit:{request.user.id}'
            else:
                # Иначе используем IP
                cache_key = f'api_rate_limit:{_get_client_ip(request)}'

            # Получаем текущее количество запросов
            requests = cache.get(cache_key, 0)

            # Если превышен лимит
            if requests >= requests_per_minute:
                logger.warning(f"API rate limit exceeded for {cache_key}")
                return JsonResponse({
                    'error': 'Rate limit exceeded. Try again later.',
                    'status': 'error'
                }, status=429)

            # Увеличиваем счетчик
            cache.set(cache_key, requests + 1, 60)  # 60 секунд = 1 минута

            # Выполняем представление
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

def check_api_permissions(permission='is_authenticated'):
    """
    Проверяет права доступа к API
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if permission == 'is_authenticated' and not request.user.is_authenticated:
                return JsonResponse({
                    'error': 'Authentication required',
                    'status': 'error'
                }, status=401)

            if permission == 'is_staff' and not request.user.is_staff:
                return JsonResponse({
                    'error': 'Staff access required',
                    'status': 'error'
                }, status=403)

            if permission == 'is_superuser' and not request.user.is_superuser:
                return JsonResponse({
                    'error': 'Admin access required',
                    'status': 'error'
                }, status=403)

            # Проверка проверка Referer для защиты от CSRF
            if request.method != 'GET':
                referer = request.META.get('HTTP_REFERER', '')
                host = request.META.get('HTTP_HOST', '')

                if not referer or host not in referer:
                    logger.warning(f"Invalid referer: {referer} for host {host}")
                    return JsonResponse({
                        'error': 'Invalid referer',
                        'status': 'error'
                    }, status=403)

            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

def _get_client_ip(request):
    """Получение IP адреса клиента с учетом прокси"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
