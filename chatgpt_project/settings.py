import os
from pathlib import Path
import secrets  # Импортируем для генерации криптографически стойких ключей

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# Заменяем ключ на случайно сгенерированный криптографически стойкий ключ
SECRET_KEY = secrets.token_hex(32)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True  # Включаем Debug для диагностики

import mimetypes
mimetypes.add_type("text/javascript", ".js", True)

# Список разрешенных хостов
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'bytegate.ru',
    '0.0.0.0',
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
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'chatgpt_app.csrf_protection.CSRFStrictProtectionMiddleware',  # Новый middleware для строгой проверки CSRF
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'chatgpt_app.middleware.AuthTokenMiddleware',  # Custom middleware for token auth
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

CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000  # 1 год
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = False  # Отключаем перенаправление на HTTPS для локальной разработки

# Отключение фреймов для предотвращения clickjacking
X_FRAME_OPTIONS = 'DENY'

# CSRF настройки
CSRF_COOKIE_HTTPONLY = False  # Делаем куки доступными для JavaScript
CSRF_USE_SESSIONS = False  # Используем куки вместо сессий для CSRF токена
CSRF_COOKIE_NAME = 'csrftoken'  # Стандартное имя
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
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
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
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'chatgpt_app': {
            'handlers': ['console', 'file'],
            'level': 'INFO',  # Изменено с DEBUG на INFO для production
            'propagate': False,
        },
        'django.security': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
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
