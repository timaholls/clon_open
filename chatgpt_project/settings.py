import os
from pathlib import Path
import secrets  # Импортируем для генерации криптографически стойких ключей
import logging

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# Заменяем ключ на случайно сгенерированный криптографически стойкий ключ
SECRET_KEY = secrets.token_hex(32)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False  # Включаем Debug для диагностики

import mimetypes
mimetypes.add_type("text/javascript", ".js", True)

# Список разрешенных хостов
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'bytegate.ru',
    '0.0.0.0',
]

# Настройки CSRF
CSRF_COOKIE_SECURE = True  # Отправлять cookie только по HTTPS
CSRF_COOKIE_HTTPONLY = False  # JavaScript должен иметь доступ для чтения токена
CSRF_COOKIE_SAMESITE = 'Lax'  # Защита от CSRF через межсайтовые запросы
CSRF_FAILURE_VIEW = 'django.views.csrf.csrf_failure'
CSRF_TRUSTED_ORIGINS = ['https://bytegate.ru', 'http://localhost:8000']
CSRF_USE_SESSIONS = False
CSRF_COOKIE_DOMAIN = None

# Дополнительные настройки безопасности CSRF
CSRF_TOKEN_EXPIRY = 24 * 60 * 60  # Срок действия CSRF токена (в секундах) - 24 часа
CSRF_STRICT_VERIFICATION = True   # Строгая проверка CSRF токенов (всегда включена)
CSRF_VALIDATE_IP = False          # Проверка IP при валидации токена (опционально)
CSRF_VALIDATE_USER_AGENT = True   # Проверка User-Agent при валидации (опционально)
CSRF_ROTATE_TOKENS = False        # Отключаем автоматическую ротацию токенов после каждого запроса
CSRF_CHECK_TTL = True             # Дополнительная проверка времени жизни токена

# Настройки Redis для CSRF токенов и кэширования
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = 'FOEo5oVgcko9LnoHNON9MRk+T/QRCG12'  # Пароль из установки Redis

# Настройки кэширования
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PASSWORD': REDIS_PASSWORD,  # Добавляем пароль для подключения
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',  # Добавляем сжатие данных для экономии памяти
            'IGNORE_EXCEPTIONS': True,  # Продолжать работу даже при проблемах с Redis
        },
        'KEY_PREFIX': 'csrf_django',  # Префикс для ключей, чтобы избежать конфликтов
    }
}

# Функция для обработки неудачной проверки CSRF
def csrf_failure(request, reason=""):
    from django.http import JsonResponse
    logger.error(f"CSRF FAILURE HANDLER: {request.path} - {reason}")
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'CSRF validation failed',
            'reason': reason
        }, status=403)
    else:
        from django.shortcuts import render
        return render(request, '403_csrf.html', {'reason': reason}, status=403)

# Переопределяем стандартный обработчик ошибок CSRF
CSRF_FAILURE_VIEW = csrf_failure

# API настройки безопасности
API_CSRF_STRICT = True  # Строгая проверка CSRF для API
API_REQUIRE_MATCHING_TOKEN = False  # Не требуем соответствия токенов в заголовке и куках

# Настройки для блокировки IP
IP_WHITELIST = [
    '127.0.0.1',
    'localhost',
    # Добавьте здесь IP-адреса, которые всегда должны иметь доступ
]

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'chatgpt_app',  # Custom ChatGPT app
]

MIDDLEWARE = [
    'chatgpt_app.middleware.IPBlockMiddleware',  # Блокировка IP должна быть первой
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # Отключаем стандартный CSRF middleware Django
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'chatgpt_app.middleware.AuthTokenMiddleware',  # Custom middleware for token auth
    # Используем наш middleware для строгой проверки CSRF
    'chatgpt_app.csrf_protection.CSRFStrictProtectionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'chatgpt_app.middleware.APISecurityMiddleware',  # Новый middleware для защиты API
    'chatgpt_app.rate_limit.RateLimitMiddleware',  # Middleware для ограничения количества запросов
    'chatgpt_app.bot_protection.BotProtectionMiddleware',  # Middleware для защиты от ботов
    'chatgpt_app.sql_injection_protection.SQLInjectionProtectionMiddleware',  # Новый middleware для защиты от SQL-инъекций
    'chatgpt_app.browser_challenge.BrowserChallengeMiddleware',  # Новый middleware для проверки браузера
]

# Настройки для работы с прокси
USE_X_FORWARDED_HOST = True  # Использовать X-Forwarded-Host заголовок
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')  # Считать запрос HTTPS если X-Forwarded-Proto = https

# Настройки ограничения запросов
RATE_LIMIT_REQUESTS = 60  # 60 запросов
RATE_LIMIT_PERIOD = 60    # за 60 секунд

# Настройки безопасности
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

SESSION_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000  # 1 год
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = False  # Отключаем перенаправление на HTTPS для локальной разработки

# Отключение фреймов для предотвращения clickjacking
X_FRAME_OPTIONS = 'DENY'

# CSRF настройки
CSRF_COOKIE_HTTPONLY = False  # Делаем куки доступными для JavaScript
CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'  # Стандартное имя заголовка
CSRF_TRUSTED_ORIGINS = [
    'https://localhost',
    'https://127.0.0.1',
    'https://bytegate.ru',
]  # Доверенные источники для CSRF

# Настройки проверки User-Agent, Referer и других заголовков
REQUIRE_VALID_REFERER = False  # Временно отключаем требование валидного Referer для отладки
ALLOWED_REFERERS = [
    'localhost',
    'bytegate.ru',
    '127.0.0.1',
]  # Список разрешенных Referer
REQUIRE_VALID_USER_AGENT = True  # Требовать валидный User-Agent
BROWSER_FINGERPRINT_CHECK = True  # Проверка отпечатка браузера

# Локальные хосты, которые освобождаются от HTTPS проверок
LOCAL_HOSTS = ['localhost', '127.0.0.1']

ROOT_URLCONF = 'chatgpt_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'chatgpt_project.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Authentication settings
AUTH_USER_MODEL = 'chatgpt_app.CustomUser'
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 10,  # Увеличиваем минимальную длину пароля
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Session settings
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_AGE = 60 * 60 * 12  # 12 часов вместо 7 дней
SESSION_COOKIE_HTTPONLY = True
SESSION_SAVE_EVERY_REQUEST = True  # Save the session to the database on every request


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = '/static/'  # Префикс URL для статики
STATIC_ROOT = '/root/clon_open/staticfiles'  # Для сбора статики, путь совпадает с nginx
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  # Где искать статику в разработке
]

# Create static directory if it doesn't exist
os.makedirs(os.path.join(BASE_DIR, 'static'), exist_ok=True)

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] {levelname} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'WARNING',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': 'django_csrf_debug.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'WARNING',
            'propagate': True,
        },
        'chatgpt_app.csrf_protection': {
            'handlers': ['console', 'file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'chatgpt_app.csrf_service': {
            'handlers': ['console', 'file'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

# Создаем директорию для логов если её нет
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

# Настройки для защиты от парсинга и ботов
CAPTCHA_ENABLED = True  # Флаг для включения капчи
MAX_ACCOUNT_CREATION_PER_IP = 3  # Ограничение на количество созданных учетных записей с одного IP
ALLOWED_REQUEST_METHODS = ['GET', 'POST']  # Разрешённые методы запросов
CHECK_BROWSER_HEADERS = True  # Проверка заголовков браузера
BROWSER_HEADER_CHECKS = ['Accept', 'Accept-Language', 'Accept-Encoding', 'User-Agent']  # Заголовки для проверки
BROWSER_CHALLENGE_TIMEOUT = 60  # Таймаут для проверки браузера в секундах
