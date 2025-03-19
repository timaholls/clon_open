import re
import json
import time
import base64
import hashlib
import logging
from django.http import HttpResponse, HttpResponseRedirect
from django.core.cache import cache
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string

logger = logging.getLogger(__name__)

class BrowserChallengeMiddleware:
    """
    Middleware для проверки реального браузера через JavaScript-вызов
    """
    def __init__(self, get_response):
        self.get_response = get_response

        # URL пути, которые не требуют проверки (статика, медиа, админка)
        self.exempt_urls = [
            r'^/static/',
            r'^/media/',
            r'^/admin/',
            r'^/favicon\.ico$',
            r'^/browser-verify/',  # URL для подтверждения браузера
        ]

        # Компилируем регулярные выражения для производительности
        self.exempt_urls = [re.compile(url) for url in self.exempt_urls]

        # Таймаут для подтверждения браузера (в секундах)
        self.challenge_timeout = getattr(settings, 'BROWSER_CHALLENGE_TIMEOUT', 60)

    def __call__(self, request):
        # Пропускаем проверку для исключённых URL
        if any(pattern.match(request.path) for pattern in self.exempt_urls):
            return self.get_response(request)

        # Получаем IP-адрес клиента
        client_ip = self._get_client_ip(request)

        # Пропускаем проверку, если клиент уже прошел проверку
        if self._client_verified(request, client_ip):
            return self.get_response(request)

        # Обрабатываем запрос верификации браузера
        if request.path == '/browser-verify/' and request.method == 'POST':
            return self._handle_verification(request)

        # Если это AJAX-запрос, возвращаем код 403
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return HttpResponse('{"error": "Browser verification required"}',
                                content_type='application/json', status=403)

        # Генерируем уникальный ключ для этого клиента
        challenge_key = self._generate_challenge_key(request)
        challenge_hash = hashlib.sha256(challenge_key.encode()).hexdigest()

        # Сохраняем ключ в кэш
        cache_key = f"browser_challenge:{client_ip}"
        cache.set(cache_key, {
            'key': challenge_key,
            'hash': challenge_hash,
            'timestamp': time.time(),
            'path': request.path,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }, self.challenge_timeout * 2)

        # Отображаем страницу с JavaScript-проверкой
        context = {
            'challenge_key': challenge_key,
            'challenge_hash': challenge_hash,
            'redirect_url': request.path,
        }

        html_content = render_to_string('browser_challenge.html', context)
        return HttpResponse(html_content)

    def _client_verified(self, request, client_ip):
        """Проверяет, прошёл ли клиент верификацию"""
        # Проверка куки верификации
        verification_cookie = request.COOKIES.get('browser_verified')
        if not verification_cookie:
            return False

        # Проверка в кэше
        cache_key = f"browser_verified:{client_ip}"
        if not cache.get(cache_key):
            return False

        # Проверка отпечатка браузера
        browser_fingerprint = self._get_browser_fingerprint(request)
        stored_fingerprint = cache.get(f"browser_fingerprint:{client_ip}")

        if not stored_fingerprint or stored_fingerprint != browser_fingerprint:
            return False

        return True

    def _handle_verification(self, request):
        """Обрабатывает запрос верификации браузера"""
        client_ip = self._get_client_ip(request)

        try:
            # Получаем данные из запроса
            content_type = request.content_type
            if not content_type or 'application/json' not in content_type:
                logger.warning(f"Invalid content type in browser verification: {content_type}")
                return HttpResponse('{"error": "Invalid content type"}',
                                   content_type='application/json', status=400)

            try:
                data = json.loads(request.body)
            except json.JSONDecodeError as e:
                logger.warning(f"JSON decode error in browser verification: {str(e)}")
                return HttpResponse('{"error": "Invalid JSON"}',
                                   content_type='application/json', status=400)

            response_hash = data.get('hash')
            challenge_hash = data.get('challenge_hash')
            redirect_url = data.get('redirect_url', '/')
            browser_features = data.get('browser_features', {})

            # Получаем сохранённый вызов из кэша
            cache_key = f"browser_challenge:{client_ip}"
            challenge_data = cache.get(cache_key)

            if not challenge_data:
                logger.warning(f"No challenge data found for IP {client_ip}")
                return HttpResponse('{"error": "Challenge expired"}',
                                   content_type='application/json', status=400)

            # Проверяем hash из запроса
            if challenge_hash != challenge_data['hash']:
                logger.warning(f"Challenge hash mismatch for IP {client_ip}")
                return HttpResponse('{"error": "Invalid challenge"}',
                                   content_type='application/json', status=400)

            # Проверяем ответ клиента
            expected_hash = self._compute_response_hash(challenge_data['key'], browser_features)
            if response_hash != expected_hash:
                logger.warning(f"Invalid response hash from IP {client_ip}")
                return HttpResponse('{"error": "Verification failed"}',
                                   content_type='application/json', status=400)

            # Сохраняем отпечаток браузера
            browser_fingerprint = self._get_browser_fingerprint(request, browser_features)
            cache.set(f"browser_fingerprint:{client_ip}", browser_fingerprint, 60 * 60 * 24)  # 24 часа

            # Отмечаем клиента как прошедшего проверку
            cache.set(f"browser_verified:{client_ip}", True, 60 * 60 * 24)  # 24 часа

            # Создаем ответ с перенаправлением и куки
            response = HttpResponse('{"status": "ok", "redirect": "' + redirect_url + '"}',
                                    content_type='application/json')

            # Устанавливаем куки для проверки браузера
            response.set_cookie(
                'browser_verified',
                browser_fingerprint,
                max_age=60 * 60 * 24,  # 24 часа
                httponly=True,
                secure=settings.CSRF_COOKIE_SECURE,
                samesite='Lax'
            )

            return response

        except Exception as e:
            logger.error(f"Error processing browser verification: {str(e)}", exc_info=True)
            return HttpResponse('{"error": "Server error"}',
                               content_type='application/json', status=500)

    def _generate_challenge_key(self, request):
        """Генерирует уникальный ключ вызова для проверки браузера"""
        ip = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        timestamp = str(time.time())
        random_part = get_random_string(16)

        return base64.b64encode(f"{ip}|{user_agent}|{timestamp}|{random_part}".encode()).decode()

    def _compute_response_hash(self, challenge_key, browser_features):
        """Вычисляет ожидаемый ответ от браузера"""
        # Сортируем особенности браузера для получения стабильного хеша
        features_str = json.dumps(browser_features, sort_keys=True)
        combined = f"{challenge_key}|{features_str}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def _get_browser_fingerprint(self, request, browser_features=None):
        """Создание отпечатка браузера на основе заголовков и особенностей браузера"""
        fingerprint_data = {}

        # Сбор данных из заголовков
        headers_to_check = [
            'HTTP_USER_AGENT',
            'HTTP_ACCEPT',
            'HTTP_ACCEPT_ENCODING',
            'HTTP_ACCEPT_LANGUAGE',
        ]

        for header in headers_to_check:
            if header in request.META:
                fingerprint_data[header] = request.META[header]

        # Добавляем особенности браузера, если они есть
        if browser_features:
            fingerprint_data.update(browser_features)

        # Добавляем IP для дополнительной точности
        fingerprint_data['IP'] = self._get_client_ip(request)

        # Создаем хеш на основе собранных данных
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()

    def _get_client_ip(self, request):
        """Получение IP адреса клиента с учетом прокси"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
