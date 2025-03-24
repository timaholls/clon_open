"""
Сервис для управления CSRF-токенами с использованием Redis.
Генерирует и проверяет подлинность CSRF-токенов.
"""
import json
import logging
import hashlib
import secrets
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django_redis import get_redis_connection
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

class CSRFTokenService:
    """
    Сервис для генерации и проверки CSRF-токенов с хранением в Redis
    """
    # Префикс для ключей в Redis
    REDIS_PREFIX = 'csrf_token:'

    @classmethod
    def generate_token(cls, request):
        """
        Генерирует новый CSRF-токен для запроса

        Args:
            request: HTTP запрос Django

        Returns:
            str: Сгенерированный CSRF-токен
        """
        try:
            # Генерируем новый случайный токен
            token_value = secrets.token_hex(32)  # 64 символа в hex-формате

            # Получаем данные о пользователе и сессии
            user_id = None
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = request.user.id
            session_key = request.session.session_key
            if not session_key:
                request.session.save()
                session_key = request.session.session_key

            # Получаем информацию о клиенте
            client_ip = cls._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')

            # Собираем данные токена
            token_data = {
                'user_id': user_id,
                'session_key': session_key,
                'created_at': timezone.now().timestamp(),
                'client_ip': client_ip,
                'user_agent': user_agent,
            }

            # Индекс для сессии (для быстрого удаления всех токенов сессии)
            session_index_key = f"csrf_session_index:{session_key}"

            # Сохраняем токен в Redis через django-redis
            redis_key = f"{cls.REDIS_PREFIX}{token_value}"
            expiry = getattr(settings, 'CSRF_TOKEN_EXPIRY', 24 * 60 * 60)  # 24 часа по умолчанию

            # Используем pipeline для атомарной операции
            redis_conn = get_redis_connection("default")
            pipe = redis_conn.pipeline()

            # Сохраняем токен и обновляем индекс сессии
            token_data_json = json.dumps(token_data)
            pipe.set(redis_key, token_data_json, ex=expiry)
            pipe.sadd(session_index_key, token_value)
            pipe.expire(session_index_key, expiry)
            pipe.execute()

            logger.debug(f"Generated new CSRF token for session {session_key}")
            return token_value

        except RedisError as e:
            logger.error(f"Redis error during token generation: {str(e)}")
            # В случае ошибки Redis генерируем токен в памяти
            fallback_token = secrets.token_hex(32)

            # Сохраняем в обычном кеше
            request.session['csrf_fallback_token'] = fallback_token
            logger.warning(f"Using fallback token for session {session_key}")

            return fallback_token
        except Exception as e:
            logger.error(f"Unexpected error during token generation: {str(e)}")
            # В случае ошибки возвращаем случайный токен
            return secrets.token_hex(32)

    @classmethod
    def validate_token(cls, request, token):
        """
        Проверяет валидность CSRF-токена

        Args:
            request: HTTP запрос Django
            token: CSRF-токен для проверки

        Returns:
            bool: True если токен валиден, иначе False
        """
        # ОТЛАДОЧНАЯ ИНФОРМАЦИЯ
        all_headers = dict(request.headers)
        all_cookies = dict(request.COOKIES)

        logger.warning(f"CSRF TOKEN VALIDATION START for token: {token}")
        logger.debug(f"Request headers: {all_headers}")
        logger.debug(f"Request cookies: {all_cookies}")

        # Проверка существующих токенов для сессии
        session_key = request.session.session_key
        if session_key:
            valid_tokens = cls._get_session_tokens(request)
            if valid_tokens:
                logger.warning(f"Session {session_key[:10]}... has {len(valid_tokens)} valid tokens: {', '.join(t[:5]+'...' for t in valid_tokens)}")

                # Проверка, есть ли токен из запроса среди действительных токенов сессии
                token_prefix = token[:20] if token else ""
                token_found = any(t.startswith(token_prefix) for t in valid_tokens)
                logger.warning(f"Token {token_prefix}... {'found' if token_found else 'NOT FOUND'} in valid session tokens")

        if not token:
            logger.warning(f"CSRF validation failed: Token is empty")
            return False

        try:
            # Получаем IP клиента для логирования
            client_ip = cls._get_client_ip(request)

            # Логируем токен для отладки
            logger.warning(f"Validating token: {token[:20]}... from {client_ip}")

            # Проверка аварийного токена (если Redis недоступен)
            fallback_token = request.session.get('csrf_fallback_token')
            if fallback_token and fallback_token == token:
                logger.warning(f"Using fallback token validation for {client_ip}")
                return True

            # Получаем данные токена из Redis
            redis_key = f"{cls.REDIS_PREFIX}{token}"

            # Получаем информацию о запросе для логов
            user_id = 'anonymous'
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = request.user.id
            session_key = request.session.session_key or 'no_session'

            # Отладочный лог
            logger.warning(f"Looking up token in Redis: {redis_key} for user={user_id}, session={session_key[:10]}...")

            # ПРЯМАЯ ПРОВЕРКА НАЛИЧИЯ КЛЮЧА В REDIS И ПОЛУЧЕНИЕ ДАННЫХ НАПРЯМУЮ
            try:
                redis_conn = get_redis_connection("default")
                key_exists = redis_conn.exists(redis_key)
                logger.warning(f"Redis key {redis_key} exists: {key_exists}")

                # Если ключ существует, получаем данные напрямую из Redis
                if key_exists:
                    token_data_str = redis_conn.get(redis_key)
                    if token_data_str:
                        token_data = json.loads(token_data_str)
                    else:
                        logger.warning(f"Redis key exists but value is None for token: {token[:20]}...")
                        return False
                else:
                    logger.warning(f"CSRF token not found in Redis: {token[:20]}... for {client_ip}")
                    # Проверяем, есть ли ЛЮБОЙ действительный токен для этой сессии
                    valid_tokens = cls._get_session_tokens(request)
                    if valid_tokens:
                        logger.warning(f"Session has {len(valid_tokens)} valid tokens, but none match the provided one")
                        for valid_token in valid_tokens:
                            logger.warning(f"Valid token in session: {valid_token[:20]}...")
                    return False
            except Exception as e:
                logger.error(f"Error checking Redis key: {str(e)}")
                # В случае ошибки проверяем аварийный токен
                fallback_token = request.session.get('csrf_fallback_token')
                if fallback_token and fallback_token == token:
                    logger.warning(f"Using fallback token validation after Redis error for {client_ip}")
                    return True
                return False

            # Отладочная информация о токене
            logger.warning(f"Token data: session={token_data['session_key'][:10]}..., "
                          f"user_id={token_data['user_id']}, created={token_data['created_at']}")

            # Проверяем сессию
            if token_data['session_key'] != request.session.session_key:
                logger.warning(f"CSRF token session mismatch for {client_ip}. "
                              f"Token session: {token_data['session_key'][:10]}..., "
                              f"Request session: {request.session.session_key[:10]}...")
                return False

            # Проверяем пользователя (если авторизован)
            user_id = None
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = request.user.id
            if token_data['user_id'] != user_id:
                logger.warning(f"CSRF token user mismatch for {client_ip}. "
                              f"Token user: {token_data['user_id']}, "
                              f"Request user: {user_id}")
                return False

            # Проверяем IP (опционально)
            if getattr(settings, 'CSRF_VALIDATE_IP', False):
                client_ip = cls._get_client_ip(request)
                if token_data['client_ip'] != client_ip:
                    logger.warning(f"CSRF token IP mismatch. "
                                  f"Token IP: {token_data['client_ip']}, "
                                  f"Request IP: {client_ip}")
                    return False

            # Проверяем User-Agent (опционально)
            if getattr(settings, 'CSRF_VALIDATE_USER_AGENT', True):
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                if token_data['user_agent'] != user_agent:
                    logger.warning(f"CSRF token User-Agent mismatch for {client_ip}. "
                                  f"Token: {token_data['user_agent'][:30]}..., "
                                  f"Request: {user_agent[:30]}...")
                    return False

            # Проверяем TTL токена (если нужно ограничить время жизни)
            if getattr(settings, 'CSRF_CHECK_TTL', False):
                created_at = token_data.get('created_at', 0)
                max_age = getattr(settings, 'CSRF_TOKEN_EXPIRY', 24 * 60 * 60)
                current_time = timezone.now().timestamp()

                if (current_time - created_at) > max_age:
                    logger.warning(f"CSRF token expired for {client_ip}. "
                                  f"Created: {created_at}, Current: {current_time}, "
                                  f"Max age: {max_age}")
                    return False

            # Обновляем TTL токена при успешной валидации
            try:
                # Используем Redis напрямую для обновления TTL без изменения данных
                redis_conn = get_redis_connection("default")
                expiry = getattr(settings, 'CSRF_TOKEN_EXPIRY', 24 * 60 * 60)
                redis_conn.expire(redis_key, expiry)

                # Также обновляем сессионный индекс
                session_index_key = f"csrf_session_index:{request.session.session_key}"
                redis_conn.expire(session_index_key, expiry)
            except Exception as e:
                logger.warning(f"Could not update token TTL: {str(e)}")

            logger.warning(f"CSRF token validated successfully for {client_ip} - {token[:20]}...")
            return True

        except RedisError as e:
            logger.error(f"Redis error during token validation: {str(e)}")
            # При ошибке Redis проверяем аварийный токен
            fallback_token = request.session.get('csrf_fallback_token')
            if fallback_token and fallback_token == token:
                return True
            return False
        except Exception as e:
            logger.error(f"Error validating CSRF token: {str(e)}", exc_info=True)
            return False

    @classmethod
    def refresh_token(cls, request, old_token=None):
        """
        Обновляет CSRF-токен, удаляя старый

        Args:
            request: HTTP запрос Django
            old_token: Старый CSRF-токен (опционально)

        Returns:
            str: Новый CSRF-токен
        """
        try:
            # Удаляем старый токен, если он передан
            if old_token:
                redis_key = f"{cls.REDIS_PREFIX}{old_token}"
                cache.delete(redis_key)

            # Генерируем новый токен
            return cls.generate_token(request)
        except Exception as e:
            logger.error(f"Error refreshing CSRF token: {str(e)}")
            # В случае ошибки возвращаем случайный токен
            return secrets.token_hex(32)

    @classmethod
    def cleanup_tokens(cls, request):
        """
        Удаляет все токены для текущей сессии
        (используется при выходе пользователя)

        Args:
            request: HTTP запрос Django
        """
        try:
            session_key = request.session.session_key
            if not session_key:
                return

            # Получаем индекс сессии
            session_index_key = f"csrf_session_index:{session_key}"

            # Подключаемся к Redis напрямую для операций с множествами
            redis_conn = get_redis_connection("default")

            # Получаем все токены сессии
            token_values = redis_conn.smembers(session_index_key)

            if not token_values:
                return

            # Используем pipeline для атомарного удаления всех токенов
            pipe = redis_conn.pipeline()

            for token in token_values:
                redis_key = f"{cls.REDIS_PREFIX}{token.decode('utf-8')}"
                pipe.delete(redis_key)

            # Удаляем сам индекс
            pipe.delete(session_index_key)
            pipe.execute()

            logger.info(f"Cleaned up all CSRF tokens for session {session_key}")
        except Exception as e:
            logger.error(f"Error cleaning up CSRF tokens: {str(e)}")

    @classmethod
    def check_redis_connection(cls):
        """
        Проверяет соединение с Redis

        Returns:
            bool: True если соединение успешно, иначе False
        """
        try:
            redis_conn = get_redis_connection("default")
            return redis_conn.ping()
        except Exception as e:
            logger.error(f"Redis connection error: {str(e)}")
            return False

    @staticmethod
    def _get_client_ip(request):
        """Получает IP-адрес клиента с учетом прокси"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    @classmethod
    def _get_session_tokens(cls, request):
        """
        Получает список всех токенов для текущей сессии

        Args:
            request: HTTP запрос Django

        Returns:
            list: Список токенов
        """
        try:
            session_key = request.session.session_key
            if not session_key:
                return []

            # Получаем индекс сессии
            session_index_key = f"csrf_session_index:{session_key}"

            # Подключаемся к Redis напрямую для операций с множествами
            redis_conn = get_redis_connection("default")

            # Получаем все токены сессии
            token_values = redis_conn.smembers(session_index_key)

            if not token_values:
                return []

            return [token.decode('utf-8') for token in token_values]
        except Exception as e:
            logger.error(f"Error getting session tokens: {str(e)}")
            return []
