import re
from django.conf import settings
from django.http import HttpResponse
from django.core.cache import cache
from django.utils.crypto import get_random_string

class BotProtectionMiddleware:
    """
    Middleware для защиты от ботов и парсинга
    """
    def __init__(self, get_response):
        self.get_response = get_response

        # Список паттернов ботов по User-Agent
        self.bot_patterns = [
            r'[Bb]ot',
            r'[Ss]pider',
            r'[Cc]rawler',
            r'[Ss]craper',
            r'[Pp]ython-requests',
            r'[Ss]elenium',
            r'[Pp]hantom[Jj][Ss]',
            r'[Pp]uppeteer',
            r'[Hh]eadless[Cc]hrome',
            r'[Ww]get',
            r'[Cc]url',
            r'[Ss]imple[Hh]ttp',
            r'[Aa]utomation',
            r'[Pp]arsing',
            r'[Pp]roxy'
        ]

        # Компилируем регулярные выражения заранее для производительности
        self.bot_regex = re.compile('|'.join(self.bot_patterns))

    def __call__(self, request):
        # Получаем IP пользователя
        ip = self._get_client_ip(request)

        # Проверка User-Agent на наличие ботов
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Пропускаем проверку для админки
        if request.path.startswith('/admin/'):
            return self.get_response(request)

        # Проверка на ботов по User-Agent
        if self.bot_regex.search(user_agent):
            return HttpResponse("Доступ запрещен", status=403)

        # Проверка на отсутствие User-Agent (часто используется ботами)
        if not user_agent:
            return HttpResponse("Доступ запрещен", status=403)

        # Проверка на Honeypot (если бот заполнил скрытое поле)
        if request.method == 'POST' and request.POST.get('website', ''):
            # Блокируем IP на 1 час
            cache.set(f"blocked_ip:{ip}", True, 3600)
            return HttpResponse("Доступ запрещен", status=403)

        # Проверка на блокировку IP
        if cache.get(f"blocked_ip:{ip}"):
            return HttpResponse("Доступ запрещен", status=403)

        # Проверка на превышение лимита создания аккаунтов
        if request.path == '/register/' and request.method == 'POST':
            account_count = cache.get(f"account_creation:{ip}", 0)
            max_accounts = getattr(settings, 'MAX_ACCOUNT_CREATION_PER_IP', 3)

            if account_count >= max_accounts:
                return HttpResponse("Превышен лимит создания аккаунтов", status=403)

        response = self.get_response(request)
        if hasattr(response, '__setitem__'):
            # Модифицируем заголовки ответа для усложнения парсинга
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response['Pragma'] = 'no-cache'
    
            # Добавляем случайный токен для усложнения кэширования
            response['ETag'] = get_random_string(16)

        return response

    def _get_client_ip(self, request):
        """Получение IP адреса клиента с учетом прокси"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip