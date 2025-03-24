import re
import logging
from django.http import HttpResponse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class SQLInjectionProtectionMiddleware(MiddlewareMixin):
    """
    Middleware для усиленной защиты от SQL-инъекций и других атак
    """

    def __init__(self, get_response=None):
        super().__init__(get_response)


class SQLInjectionProtectionMiddleware(MiddlewareMixin):
    """
    Middleware для защиты от SQL-инъекций и других атак (ослабленный вариант)
    """

    def __init__(self, get_response=None):
        super().__init__(get_response)

        # Ослабленные SQL-шаблоны

        self.sql_patterns = [
            r'(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|UNION)\s',
            r'(\s|^)(OR|AND)(\s+|\s*\()(\d+|\'.*?\'|\w+)\s*=\s*(\d+|\'.*?\'|\w+)',
            r'(\s|^)(--|#)',  # SQL комментарии
            r'(\s|^)/\*.*?\*/',  # Многострочные SQL комментарии
            r'(\s|^)\/\*.*?\*\/',  # Многострочные SQL комментарии

            r'1=1',  # Типичная конструкция для SQL-инъекций
            r'SLEEP\s*\(.*?\)',  # Time-based атаки
            r'BENCHMARK\s*\(.*?\)',
            r'WAITFOR\s+DELAY',
            r'PG_SLEEP\s*\(.*?\)',
            r'(\s|^)(EXEC|EXECUTE|DECLARE|CURSOR)',
            r'(\s|^)(LOAD_FILE|LOAD DATA|INTO OUTFILE|DUMPFILE)',

            r'(\s|^)(INFORMATION_SCHEMA|SCHEMA_NAME|TABLE_NAME)',  # Защита от схемы базы данных
            r'(\s|^)(CONCAT|GROUP_CONCAT|SUBSTR|SUBSTRING)',  # Чувствительные функции
            r'(\s|^)(ORDER BY|GROUP BY)\s+\d+',  # Blind SQL Injection
            r'(\s|^)(CASE WHEN|IF|IFNULL)\s',  # Условные операторы в SQL
        ]

        # Усиленные XSS-шаблоны
        self.xss_patterns = [
            r'<script.*?>',
            r'javascript:',
            r'onload=',
            r'onerror=',
            r'onclick=',
            r'(alert|confirm|prompt)\s*\(',
            r'eval\s*\(',
            r'document\.cookie',
            r'document\.write',
            r'<iframe',
            r'<embed',
            r'<object',
            r'<img[^>]+\bonerror=',
            r'<img[^>]+\bsrc=[^>]*?javascript:',
            r'<svg[^>]*?\bonload=',
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'&#x[0-9a-fA-F]+;',  # HTML hex encoding
            r'&#\d+;',  # HTML decimal encoding
        ]

        # Усиленные шаблоны LFI/RFI
        self.lfi_patterns = [
            r'\\.\\./',
            r'%2e%2e%2f',
            r'/etc/passwd',
            r'/etc/shadow',
            r'/etc/hosts',
            r'/proc/self/',
            r'file://',
            r'php://input',
            r'php://filter',
            r'data://text',
            r'expect://',
            r'phar://',
        ]

        # Усиленные шаблоны Command Injection
        self.cmd_patterns = [
            r'(\\s|^|\\||;|&)(wget|curl|bash|sh|ssh|telnet|nc|ncat)',
            r'(\\s|^|\\||;|&)(powershell|cmd\\.exe|cscript|wscript)',
            r'(\\||;|&|`)',
            r'\\$\\([^)]*\\)',  # $(command) syntax
            r'\\`[^`]*\\`',  # `command` syntax
            r'>\s*([\\w]+\\.\\w{1,5})',  # Перенаправление вывода
            r'\\.\\/[\\w\\.]+',  # Запуск локальных скриптов

            r'(alert|confirm|prompt)\s*\(',
            r'eval\s*\(',
        ]

        # Ослабленные шаблоны LFI/RFI
        self.lfi_patterns = [
            r'\.\./',
            r'%2e%2e%2f',
            r'/etc/passwd',
            r'file://',
        ]

        # Ослабленные шаблоны Command Injection
        self.cmd_patterns = [
            r'(\s|^|\||;|&)(wget|curl|bash|sh|ssh|telnet|nc|ncat)',
            r'(\s|^|\||;|&)(powershell|cmd\.exe|cscript|wscript)',
            r'(\||;|&)',
        ]

        # Компиляция регулярных выражений
        self.sql_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_patterns]
        self.xss_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        self.lfi_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.lfi_patterns]
        self.cmd_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.cmd_patterns]

    def process_request(self, request):
        # Пропускаем проверку для статики, медиа, favicon и страниц логина
        if request.path.startswith(('/static/', '/media/', '/favicon.ico', '/login/')):
            return None

        # Пропускаем проверку для админки
        if request.path.startswith('/admin/'):
            return None

        # Проверяем GET параметры
        for key, value in request.GET.items():
            if self._check_injection(value):
                self._log_attack(request, 'GET', key, value)
                return HttpResponse("Обнаружена потенциальная атака", status=403)

        # Проверяем POST параметры
        for key, value in request.POST.items():
            if key in ['content', 'html', 'text', 'description', 'body']:

                # Для полей с контентом используем только проверку на XSS
                if isinstance(value, str) and self._check_xss(value):
                    self._log_attack(request, 'POST (XSS in content)', key, value)
                    return HttpResponse("Обнаружена потенциальная XSS атака", status=403)
            elif isinstance(value, str) and self._check_injection(value):
                self._log_attack(request, 'POST', key, value)
                return HttpResponse("Обнаружена потенциальная атака", status=403)
                # Проверяем куки

            if isinstance(value, str) and self._check_injection(value):
                self._log_attack(request, 'POST', key, value)
                return HttpResponse("Обнаружена потенциальная атака", status=403)

        # Проверяем куки (без `User-Agent`)
        for key, value in request.COOKIES.items():
            if self._check_injection(value):
                self._log_attack(request, 'COOKIE', key, value)
                return HttpResponse("Обнаружена потенциальная атака", status=403)

        return None

    def _check_injection(self, value):
        """Проверка значения на наличие потенциальных инъекций"""
        if not isinstance(value, str):
            return False

        for pattern in self.sql_regex + self.xss_regex + self.lfi_regex + self.cmd_regex:
            if pattern.search(value):
                return True

        return False

    def _check_xss(self, value):
        """Проверка только на XSS для полей с контентом"""
        if not isinstance(value, str):
            return False

        for pattern in self.xss_regex:
            if pattern.search(value):
                return True

        return False

    def _log_attack(self, request, method, key, value):
        """Логирование попытки атаки"""
        ip = self._get_client_ip(request)
        logger.warning(
            f"Possible attack detected! Method: {method}, Key: {key}, Value: {value}, IP: {ip}"
        )

    def _get_client_ip(self, request):
        """Получение IP адреса клиента с учетом прокси"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

        return x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')
