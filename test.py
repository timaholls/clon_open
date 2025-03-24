"""
Тестовый скрипт для проверки генерации и валидации CSRF-токенов.
"""

import os
import sys
import django

# Настройка Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'chatgpt_project.settings')
django.setup()

# Импорты Django
from django.contrib.auth import get_user_model
from django.test.client import RequestFactory
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.auth.middleware import AuthenticationMiddleware

# Импорты проекта
from chatgpt_app.csrf_service import CSRFTokenService
from django.core.cache import cache
from django_redis import get_redis_connection

# Создаем запрос
factory = RequestFactory()
request = factory.get('/')

# Добавляем сессию
middleware = SessionMiddleware(get_response=lambda req: None)
middleware.process_request(request)
request.session.save()

# Выводим информацию о Redis
print("Проверка подключения к Redis:")
try:
    conn = get_redis_connection("default")
    ping_result = conn.ping()
    print(f"Redis ping: {ping_result}")
    print(f"Redis info: {conn.info()}")
except Exception as e:
    print(f"Ошибка подключения к Redis: {str(e)}")

# Генерируем CSRF-токен
print("\nГенерация CSRF-токена:")
try:
    token = CSRFTokenService.generate_token(request)
    print(f"Сгенерирован токен: {token}")

    # Проверяем наличие токена в Redis
    redis_key = f"csrf_token:{token}"
    token_exists = conn.exists(redis_key)
    print(f"Токен существует в Redis: {token_exists}")

    if token_exists:
        token_data = conn.get(redis_key)
        print(f"Данные токена: {token_data}")

    # Проверяем валидацию токена
    is_valid = CSRFTokenService.validate_token(request, token)
    print(f"Токен валиден: {is_valid}")

    # Проверяем валидацию недействительного токена
    fake_token = "fake_token_123456"
    is_fake_valid = CSRFTokenService.validate_token(request, fake_token)
    print(f"Поддельный токен валиден: {is_fake_valid}")

except Exception as e:
    print(f"Ошибка при работе с токенами: {str(e)}")

print("\nПроверка завершена.")
