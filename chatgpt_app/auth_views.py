from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.conf import settings
import json
import logging
import time
import re
# Функция для обновления CAPTCHA
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .captcha import Captcha
from .models import AuthToken
from .captcha import Captcha

logger = logging.getLogger(__name__)
User = get_user_model()

# Регулярное выражение для проверки надежности пароля
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$')

@csrf_exempt
def login_view(request):
    """Render the login page"""
    # If already logged in, redirect to the chat page
    if request.user.is_authenticated:
        return redirect('chat')

    ip = _get_client_ip(request)
    # Отслеживание попыток входа с IP
    login_attempts = cache.get(f"login_attempts:{ip}", 0)

    # Если превышен порог попыток, показываем капчу
    show_captcha = login_attempts >= 3 or getattr(settings, 'CAPTCHA_ENABLED', False)

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        captcha_input = request.POST.get('captcha')

        # Проверка Honeypot (скрытое поле, которое должно оставаться пустым)
        if request.POST.get('website', ''):
            logger.warning(f"Honeypot triggered from IP {ip}")
            # Блокируем IP на 1 час
            cache.set(f"blocked_ip:{ip}", True, 3600)
            return redirect('login')

        # Проверка капчи
        captcha_text = request.session.get('captcha_text')
        logger.info(f"Login CAPTCHA check: input='{captcha_input}', stored='{captcha_text}'")

        if not captcha_text or not Captcha.verify_captcha(captcha_input, captcha_text):
            logger.warning(f"Failed CAPTCHA attempt from IP {ip}")
            # Увеличиваем счетчик попыток
            cache.set(f"login_attempts:{ip}", login_attempts + 1, 3600)  # час

            # Генерируем новую капчу
            captcha_data = Captcha.generate_captcha()
            request.session['captcha_text'] = captcha_data['captcha_text']
            request.session.modified = True

            return render(request, 'chatgpt_app/login.html', {
                'error': 'Incorrect CAPTCHA. Please try again.',
                'captcha_image': captcha_data['captcha_image'],
                'email': email
            })

        # Добавляем задержку для защиты от брутфорса
        if login_attempts > 0:
            time.sleep(min(login_attempts * 0.5, 2.0))  # Максимум 2 секунды задержки

        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            # Сбрасываем счетчик попыток входа
            cache.delete(f"login_attempts:{ip}")

            # Generate auth token
            auth_token = AuthToken.generate_token(user)
            # Set token in session
            request.session['auth_token'] = auth_token.token
            # Log successful login
            logger.info(f"User {email} logged in successfully from IP {ip}")

            # Explicitly set the session to modified to ensure it's saved
            request.session.modified = True

            return redirect('chat')
        else:
            # Увеличиваем счетчик попыток
            cache.set(f"login_attempts:{ip}", login_attempts + 1, 3600)  # час

            # Генерируем новую капчу
            captcha_data = Captcha.generate_captcha()
            request.session['captcha_text'] = captcha_data['captcha_text']
            request.session.modified = True

            logger.warning(f"Failed login attempt for {email} from IP {ip}")
            return render(request, 'chatgpt_app/login.html', {
                'error': 'Invalid email or password',
                'captcha_image': captcha_data['captcha_image'],
                'email': email
            })

    # GET запрос - генерируем новую CAPTCHA только для отображения формы
    captcha_data = Captcha.generate_captcha()
    request.session['captcha_text'] = captcha_data['captcha_text']
    request.session.modified = True
    logger.info(f"Generated CAPTCHA for login form: {captcha_data['captcha_text']}")

    return render(request, 'chatgpt_app/login.html', {
        'captcha_image': captcha_data['captcha_image']
    })

@csrf_exempt
def signup_view(request):
    """Render the signup page"""
    # If already logged in, redirect to the chat page
    if request.user.is_authenticated:
        return redirect('chat')

    ip = _get_client_ip(request)

    # Проверка на превышение лимита создания аккаунтов с одного IP
    account_count = cache.get(f"account_creation:{ip}", 0)
    max_accounts = getattr(settings, 'MAX_ACCOUNT_CREATION_PER_IP', 3)

    if account_count >= max_accounts:
        return render(request, 'chatgpt_app/signup.html', {
            'error': 'Too many accounts created from your IP. Please try again later.'
        })

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        captcha_input = request.POST.get('captcha')

        # Проверка Honeypot (скрытое поле, которое должно оставаться пустым)
        if request.POST.get('website', ''):
            logger.warning(f"Honeypot triggered from IP {ip}")
            # Блокируем IP на 1 час
            cache.set(f"blocked_ip:{ip}", True, 3600)
            return redirect('login')

        # Проверка капчи
        captcha_text = request.session.get('captcha_text')
        logger.info(f"Signup CAPTCHA check: input='{captcha_input}', stored='{captcha_text}'")

        if not captcha_text or not Captcha.verify_captcha(captcha_input, captcha_text):
            logger.warning(f"Failed CAPTCHA attempt in signup from IP {ip}")
            # Генерируем новую капчу
            captcha_data = Captcha.generate_captcha()
            request.session['captcha_text'] = captcha_data['captcha_text']
            request.session.modified = True

            return render(request, 'chatgpt_app/signup.html', {
                'error': 'Incorrect CAPTCHA. Please try again.',
                'captcha_image': captcha_data['captcha_image'],
                'username': username,
                'email': email
            })

        # Проверка сложности пароля
        if not PASSWORD_REGEX.match(password):
            captcha_data = Captcha.generate_captcha()
            request.session['captcha_text'] = captcha_data['captcha_text']
            request.session.modified = True

            return render(request, 'chatgpt_app/signup.html', {
                'error': 'Password must be at least 8 characters and include letters, numbers, and special characters.',
                'captcha_image': captcha_data['captcha_image'],
                'username': username,
                'email': email
            })

        # Check if passwords match
        if password != password_confirm:
            captcha_data = Captcha.generate_captcha()
            request.session['captcha_text'] = captcha_data['captcha_text']
            request.session.modified = True

            return render(request, 'chatgpt_app/signup.html', {
                'error': 'Passwords do not match',
                'captcha_image': captcha_data['captcha_image'],
                'username': username,
                'email': email
            })

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            captcha_data = Captcha.generate_captcha()
            request.session['captcha_text'] = captcha_data['captcha_text']
            request.session.modified = True

            return render(request, 'chatgpt_app/signup.html', {
                'error': 'Email already exists',
                'captcha_image': captcha_data['captcha_image'],
                'username': username
            })

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        # Увеличиваем счетчик созданных аккаунтов с IP
        cache.set(f"account_creation:{ip}", account_count + 1, 86400 * 7)  # 7 дней

        # Log the user in
        login(request, user)

        # Generate auth token
        auth_token = AuthToken.generate_token(user)
        # Set token in session
        request.session['auth_token'] = auth_token.token

        # Explicitly set the session to modified to ensure it's saved
        request.session.modified = True

        logger.info(f"New user created: {email} from IP {ip}")

        return redirect('chat')

    # GET запрос - генерируем новую CAPTCHA только для отображения формы
    captcha_data = Captcha.generate_captcha()
    request.session['captcha_text'] = captcha_data['captcha_text']
    request.session.modified = True
    logger.info(f"Generated CAPTCHA for signup form: {captcha_data['captcha_text']}")

    return render(request, 'chatgpt_app/signup.html', {
        'captcha_image': captcha_data['captcha_image']
    })


@csrf_exempt
def logout_view(request):
    """Log the user out"""
    # Get the user
    user = request.user
    ip = _get_client_ip(request)

    # Временно отключаем CSRF для отладки
    # (Для продакшена этот декоратор нужно будет убрать)
    if not getattr(logout_view, '_csrf_exempt', False):
        logout_view._csrf_exempt = True

    # Для GET запроса просто показываем страницу подтверждения
    if request.method == 'GET':
        logger.info(
            f"Logout confirmation page requested by user {user.username if user.is_authenticated else 'anonymous'} from IP {ip}")
        return render(request, 'chatgpt_app/logout.html')

    # Для POST запроса выполняем выход и перенаправляем на страницу входа
    elif request.method == 'POST':
        # Логируем попытку выхода
        logger.info(f"Logout attempt with headers: {request.headers}")
        logger.info(f"CSRF Cookie: {request.COOKIES.get('csrftoken')}")

        # If the user is authenticated, log them out
        if user.is_authenticated:
            # Сохраняем информацию о пользователе для логирования после выхода
            username = user.username
            email = user.email

            # Delete auth token if exists
            auth_token = request.session.get('auth_token')
            if auth_token:
                try:
                    AuthToken.objects.filter(token=auth_token).delete()
                    logger.info(f"Auth token deleted for user {username}")
                except Exception as e:
                    logger.error(f"Error deleting auth token for user {username}: {str(e)}")

            # Clear session
            request.session.flush()

            # Log out user
            logout(request)

            logger.info(f"User {email} logged out successfully from IP {ip}")

            # Перенаправляем на страницу входа
            return redirect('login')
        else:
            # Если пользователь не аутентифицирован, просто перенаправляем на страницу входа
            logger.warning(f"Logout attempt for non-authenticated user from IP {ip}")
            return redirect('login')

    # Для других методов возвращаем ошибку
    else:
        logger.warning(f"Invalid method {request.method} for logout from IP {ip}")
        return HttpResponse("Method not allowed", status=405)


@csrf_exempt
@require_POST
def api_login(request):
    """API endpoint for login"""
    ip = _get_client_ip(request)

    # Проверка на блокировку IP
    if cache.get(f"blocked_ip:{ip}"):
        return JsonResponse({'error': 'Access denied'}, status=403)

    # Отслеживание попыток входа с IP
    login_attempts = cache.get(f"login_attempts:{ip}", 0)

    # Если превышен порог попыток, требуем капчу
    if login_attempts >= 3:
        return JsonResponse({'error': 'Too many failed attempts. Please use the web login page.'}, status=429)

    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and password are required'}, status=400)

        # Добавляем задержку для защиты от брутфорса
        if login_attempts > 0:
            time.sleep(min(login_attempts * 0.5, 2.0))  # Максимум 2 секунды задержки

        user = authenticate(request, email=email, password=password)

        if user is not None:
            # Сбрасываем счетчик попыток входа
            cache.delete(f"login_attempts:{ip}")

            # Generate auth token
            auth_token = AuthToken.generate_token(user)

            # Log in the user
            login(request, user)

            # Set token in session
            request.session['auth_token'] = auth_token.token
            request.session.modified = True

            return JsonResponse({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                },
                'token': auth_token.token,
                'expires_at': auth_token.expires_at.isoformat()
            })
        else:
            # Увеличиваем счетчик попыток
            cache.set(f"login_attempts:{ip}", login_attempts + 1, 3600)  # час

            logger.warning(f"Failed API login attempt for {email} from IP {ip}")
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in API login: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_POST
def api_signup(request):
    """API endpoint for signup"""
    ip = _get_client_ip(request)

    # Проверка на блокировку IP
    if cache.get(f"blocked_ip:{ip}"):
        return JsonResponse({'error': 'Access denied'}, status=403)

    # Проверка на превышение лимита создания аккаунтов с одного IP
    account_count = cache.get(f"account_creation:{ip}", 0)
    max_accounts = getattr(settings, 'MAX_ACCOUNT_CREATION_PER_IP', 3)

    if account_count >= max_accounts:
        return JsonResponse({'error': 'Too many accounts created from your IP'}, status=403)

    try:
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        captcha = data.get('captcha')
        captcha_id = data.get('captcha_id')

        if not username or not email or not password:
            return JsonResponse({'error': 'Username, email and password are required'}, status=400)

        # Проверка сложности пароля
        if not PASSWORD_REGEX.match(password):
            return JsonResponse({
                'error': 'Password must be at least 8 characters and include letters, numbers, and special characters.'
            }, status=400)

        # Всегда требуем капчу при API-регистрации
        if not captcha or not captcha_id:
            return JsonResponse({'error': 'CAPTCHA is required', 'require_captcha': True}, status=400)

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists'}, status=400)

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        # Увеличиваем счетчик созданных аккаунтов с IP
        cache.set(f"account_creation:{ip}", account_count + 1, 86400 * 7)  # 7 дней

        # Log in the user
        login(request, user)

        # Generate auth token
        auth_token = AuthToken.generate_token(user)

        # Set token in session
        request.session['auth_token'] = auth_token.token
        request.session.modified = True

        logger.info(f"New user created via API: {email} from IP {ip}")

        return JsonResponse({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'token': auth_token.token,
            'expires_at': auth_token.expires_at.isoformat()
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in API signup: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def _get_client_ip(request):
    """Получение IP адреса клиента с учетом прокси"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
