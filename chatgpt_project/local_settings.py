"""
Локальные настройки для разработки.
Этот файл не должен отслеживаться в системе контроля версий.
"""

# Включение режима отладки для разработки
DEBUG = True

# Список разрешенных хостов для разработки
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '*']

# Отключаем настройки безопасности для локальной разработки
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
ROOT_URLCONF = 'chatgpt_project.urls'
# Настройки ограничения запросов для разработки
RATE_LIMIT_REQUESTS = 200  # 200 запросов
RATE_LIMIT_PERIOD = 60     # за 60 секунд

# Включаем CAPTCHA для тестирования
CAPTCHA_ENABLED = True
