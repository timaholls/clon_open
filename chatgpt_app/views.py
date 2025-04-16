import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages
from .models import Conversation, Message, BlockedIP, MessageFile
from .csrf_service import CSRFTokenService
import json
import time
import logging
import hashlib
import secrets
import base64
from django.core.cache import cache
from django.views.decorators.cache import never_cache
from django.http import HttpResponse, Http404
from django.conf import settings
from openai import OpenAI

logger = logging.getLogger(__name__)

@login_required
def chat_view(request):
    # Получить conversation_id из query параметра или из сессии
    conversation_id = request.GET.get('conversation_id') or request.session.get('last_conversation_id')

    # Получить все разговоры пользователя
    conversations = Conversation.objects.filter(user=request.user).order_by('-updated_at')

    # Загрузить указанный разговор или первый, если не указан
    active_conversation = None
    if conversation_id:
        try:
            active_conversation = Conversation.objects.get(id=conversation_id, user=request.user)
            # Сохранить ID в сессии для восстановления после перезагрузки
            request.session['last_conversation_id'] = conversation_id
        except Conversation.DoesNotExist:
            # Если указанный разговор не существует, загрузить первый
            if conversations.exists():
                active_conversation = conversations.first()
                request.session['last_conversation_id'] = active_conversation.id
    elif conversations.exists():
        # Если ID не указан, загрузить первый разговор
        active_conversation = conversations.first()
        request.session['last_conversation_id'] = active_conversation.id

    # Генерируем новый CSRF-токен и сохраняем его в Redis
    csrf_token = CSRFTokenService.generate_token(request)

    context = {
        'conversations': conversations,
        'active_conversation': active_conversation,
    }

    response = render(request, 'chatgpt_app/chat.html', context)

    # Устанавливаем токен в куки
    response.set_cookie(
        'csrftoken',
        csrf_token,
        max_age=getattr(settings, 'CSRF_TOKEN_EXPIRY', 24 * 60 * 60),
        httponly=False,
        secure=settings.CSRF_COOKIE_SECURE,
        samesite=settings.CSRF_COOKIE_SAMESITE
    )

    return response



@login_required
@require_POST
def send_message(request):
    """API endpoint to send a message and get a response"""
    # Проверяем CSRF токен вручную
    csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
    if not csrf_token and 'csrfmiddlewaretoken' not in request.POST:
        return JsonResponse({'error': 'CSRF token missing or invalid'}, status=403)

    # Добавляем строгую проверку подлинности токена
    is_valid = CSRFTokenService.validate_token(request, csrf_token)
    if not is_valid:
        logger.warning(f"CSRF protection: Invalid token for user {request.user.username}")
        return JsonResponse({"error": "Invalid CSRF token"}, status=403)

    try:
        # Для JSON запросов
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            message_text = data.get('message')
            conversation_id = data.get('conversation_id')
            files_data = data.get('files', [])  # Получаем данные о файлах в формате base64
        # Для form-data запросов
        else:
            message_text = request.POST.get('message')
            conversation_id = request.POST.get('conversation_id')
            files_data = []
            # Обрабатываем загруженные файлы
            for file_key in request.FILES:
                uploaded_file = request.FILES[file_key]
                # Кодируем файл в base64 для последующей обработки
                file_content = base64.b64encode(uploaded_file.read()).decode('utf-8')
                files_data.append({
                    'name': uploaded_file.name,
                    'type': uploaded_file.content_type,
                    'size': uploaded_file.size,
                    'content': file_content
                })

        # Validate input
        if not message_text and not files_data:
            return JsonResponse({'error': 'Message or files are required'}, status=400)

        # Get or create conversation
        conversation = None
        is_new_conversation = False

        if conversation_id:
            try:
                conversation = Conversation.objects.get(id=conversation_id, user=request.user)
            except Conversation.DoesNotExist:
                # If conversation doesn't exist or doesn't belong to the user, create a new one
                conversation = Conversation.objects.create(
                    title="Новый чат",
                    user=request.user
                )
                is_new_conversation = True
        else:
            # Create a new conversation
            conversation = Conversation.objects.create(
                title="Новый чат",
                user=request.user
            )
            is_new_conversation = True

        # Create user message
        user_message = Message.objects.create(
            conversation=conversation,
            role='user',
            content=message_text or "Отправлены файлы",  # Если текста нет, указываем, что отправлены файлы
            sender_name=request.user.username
        )

        # Сохраняем загруженные файлы
        saved_files = []
        for file_data in files_data:
            if 'content' in file_data:
                # Декодируем файл из base64
                file_content = base64.b64decode(file_data['content'])
                
                # Создаем временный файл
                file_name = file_data.get('name', f"file_{len(saved_files)}")
                file_path = os.path.join(settings.MEDIA_ROOT, 'temp', file_name)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                
                # Создаем запись о файле в базе данных
                message_file = MessageFile(
                    message=user_message,
                    file_name=file_name,
                    file_type=file_data.get('type', 'application/octet-stream'),
                    file_size=file_data.get('size', len(file_content))
                )
                
                # Сохраняем файл в поле модели
                with open(file_path, 'rb') as f:
                    message_file.file.save(file_name, f)
                
                message_file.save()
                saved_files.append(message_file)
                
                # Удаляем временный файл
                if os.path.exists(file_path):
                    os.remove(file_path)

        # If this is the first message in the conversation, update the title
        if is_new_conversation or conversation.messages.count() <= 2:  # учитываем текущее сообщение и возможное системное
            conversation.update_title_from_message(message_text or "Новый чат с файлами")

        # Update conversation timestamp
        conversation.save()  # This will update the updated_at field

        # Получаем историю сообщений для контекста
        messages_history = []
        
        # Добавляем системное сообщение
        messages_history.append({
            "role": "system",
            "content": "Вы - ChatGPT, полезный и дружелюбный ассистент, который может анализировать изображения и документы."
        })
        
        # Получаем предыдущие сообщения из этого разговора
        previous_messages = conversation.messages.all().order_by('created_at')
        for prev_message in previous_messages:
            # Пропускаем системные сообщения, так как мы уже добавили системное сообщение выше
            if prev_message.role != 'system':
                # Создаем сообщение для API
                message_content = []
                
                # Добавляем текст сообщения, если он есть
                if prev_message.content:
                    message_content.append({
                        "type": "text",
                        "text": prev_message.content
                    })
                
                # Если это текущее сообщение пользователя, добавляем файлы
                if prev_message.id == user_message.id and saved_files:
                    for file in saved_files:
                        if file.file_type == 'image':
                            # Для изображений добавляем их в формате image_url
                            file_url = request.build_absolute_uri(file.file.url)
                            message_content.append({
                                "type": "image_url",
                                "image_url": {
                                    "url": file_url
                                }
                            })
                
                # Добавляем сообщение в историю
                messages_history.append({
                    "role": prev_message.role,
                    "content": message_content if len(message_content) > 1 else prev_message.content
                })

        # Настройка API ключа OpenAI
        try:
            # Создаем клиент OpenAI с API ключом из настроек
            client = OpenAI(api_key=settings.OPENAI_API_KEY)
            
            # Отправляем запрос к API OpenAI
            # Используем модель GPT-4 Vision для обработки изображений
            model = "gpt-4-vision-preview" if saved_files else "gpt-3.5-turbo"
            
            completion = client.chat.completions.create(
                model=model,
                messages=messages_history,
                max_tokens=1000 if saved_files else None  # Ограничиваем токены для vision модели
            )
            
            # Получаем ответ от модели
            assistant_message = completion.choices[0].message.content
            
        except Exception as api_error:
            logger.error(f"OpenAI API error: {str(api_error)}")
            # В случае ошибки API возвращаем сообщение об ошибке
            assistant_message = "Извините, произошла ошибка при обработке вашего запроса. Пожалуйста, попробуйте позже."

        # Create assistant message
        Message.objects.create(
            conversation=conversation,
            role='assistant',
            content=assistant_message,
            sender_name="ChatGPT"
        )

        # Подготавливаем информацию о файлах для ответа
        files_info = []
        for file in saved_files:
            files_info.append({
                'id': file.id,
                'name': file.file_name,
                'type': file.file_type,
                'size': file.file_size,
                'url': request.build_absolute_uri(file.file.url)
            })

        return JsonResponse({
            'message': assistant_message,
            'conversation_id': conversation.id,
            'conversation_title': conversation.title,
            'files': files_info
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in send_message: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def create_conversation(request):
    """API endpoint to create a new conversation"""
    try:
        # Проверка CSRF токена для API
        csrf_header = request.META.get('HTTP_X_CSRFTOKEN', '')
        csrf_cookie = request.COOKIES.get('csrftoken', '')

        # Проверка наличия токена в заголовке
        if not csrf_header:
            logger.warning(f"CSRF protection: X-CSRFToken header missing for user {request.user.username}")
            return JsonResponse({"error": "CSRF protection: X-CSRFToken header is required"}, status=403)

        # Проверка наличия токена в куках
        if not csrf_cookie:
            logger.warning(f"CSRF protection: csrftoken cookie missing for user {request.user.username}")
            return JsonResponse({"error": "CSRF protection: csrftoken cookie is required"}, status=403)

        # Добавляем строгую проверку подлинности токена
        is_valid = CSRFTokenService.validate_token(request, csrf_header)
        if not is_valid:
            logger.warning(f"CSRF protection: Invalid token for user {request.user.username}")
            return JsonResponse({"error": "Invalid CSRF token"}, status=403)

        # Create a new conversation
        conversation = Conversation.objects.create(
            title='Новый чат',
            user=request.user
        )

        return JsonResponse({
            'id': conversation.id,
            'title': conversation.title,
            'created_at': conversation.created_at.isoformat()
        })

    except Exception as e:
        logger.error(f"Error in create_conversation: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def delete_conversation(request, conversation_id):
    """API endpoint to delete a conversation"""
    try:
        # Проверка CSRF токена для API
        csrf_header = request.META.get('HTTP_X_CSRFTOKEN', '')
        csrf_cookie = request.COOKIES.get('csrftoken', '')

        # Проверка наличия токена в заголовке
        if not csrf_header:
            logger.warning(f"CSRF protection: X-CSRFToken header missing for user {request.user.username}")
            return JsonResponse({"error": "CSRF protection: X-CSRFToken header is required"}, status=403)

        # Проверка наличия токена в куках
        if not csrf_cookie:
            logger.warning(f"CSRF protection: csrftoken cookie missing for user {request.user.username}")
            return JsonResponse({"error": "CSRF protection: csrftoken cookie is required"}, status=403)

        # Добавляем строгую проверку подлинности токена
        is_valid = CSRFTokenService.validate_token(request, csrf_header)
        if not is_valid:
            logger.warning(f"CSRF protection: Invalid token for user {request.user.username}")
            return JsonResponse({"error": "Invalid CSRF token"}, status=403)

        conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)
        conversation.delete()

        return JsonResponse({'success': True})

    except Exception as e:
        logger.error(f"Error in delete_conversation: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def get_conversation_messages(request, conversation_id):
    """API endpoint to get all messages for a conversation"""
    try:
        # Проверка CSRF токена только для POST, PUT, DELETE
        if request.method:
            csrf_header = request.META.get('HTTP_X_CSRFTOKEN', '')
            csrf_cookie = request.COOKIES.get('csrftoken', '')

            # Проверка наличия токена в заголовке
            if not csrf_header:
                logger.warning(f"CSRF protection: X-CSRFToken header missing for user {request.user.username}")
                return JsonResponse({"error": "CSRF protection: X-CSRFToken header is required"}, status=403)

            # Проверка наличия токена в куках
            if not csrf_cookie:
                logger.warning(f"CSRF protection: csrftoken cookie missing for user {request.user.username}")
                return JsonResponse({"error": "CSRF protection: csrftoken cookie is required"}, status=403)

            # Добавляем строгую проверку подлинности токена
            is_valid = CSRFTokenService.validate_token(request, csrf_header)
            if not is_valid:
                logger.warning(f"CSRF protection: Invalid token for user {request.user.username}")
                return JsonResponse({"error": "Invalid CSRF token"}, status=403)

        # Важно: проверяем, что разговор принадлежит текущему пользователю
        conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)

        # Получаем сообщения, отсортированные по времени создания
        messages = conversation.messages.order_by('created_at')

        return JsonResponse({
            'conversation': {
                'id': conversation.id,
                'title': conversation.title,
            },
            'messages': [
                {
                    'id': message.id,
                    'role': message.role,
                    'content': message.content,
                    'sender_name': message.sender_name,
                    'created_at': message.created_at.isoformat()
                }
                for message in messages
            ]
        })

    except Exception as e:
        logger.error(f"Error in get_conversation_messages: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


def index_view(request):
    """Redirect to the chat view or login page depending on authentication"""
    # Проверяем подключение к Redis
    redis_connected = CSRFTokenService.check_redis_connection()
    if not redis_connected:
        logger.warning("Redis connection failed. Using fallback token mechanism.")

    if request.user.is_authenticated:
        return redirect('chat')
    else:
        return redirect('login')


@csrf_exempt
def browser_verify(request):
    """
    Обработчик для проверки браузера.
    Этот маршрут освобожден от CSRF проверки, так как используется при начальной валидации браузера.
    """
    if request.method != 'POST':
        return HttpResponse("Method not allowed", status=405)

    try:
        # Получаем IP адрес клиента
        client_ip = _get_client_ip(request)

        # Проверяем, является ли тело запроса JSON
        if not request.content_type or 'application/json' not in request.content_type:
            logger.warning(f"Invalid content type in browser verification: {request.content_type}")
            return JsonResponse({"error": "Invalid content type"}, status=400)

        try:
            # Получаем данные запроса
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error in browser verification: {str(e)}")
            return JsonResponse({"error": f"Invalid JSON: {str(e)}"}, status=400)

        response_hash = data.get('hash')
        challenge_hash = data.get('challenge_hash')
        redirect_url = data.get('redirect_url', '/')
        browser_features = data.get('browser_features', {})

        # Проверяем наличие всех необходимых данных
        if not all([response_hash, challenge_hash, redirect_url]):
            logger.warning(f"Missing required data in browser verification request from {client_ip}")
            return JsonResponse({"error": "Missing required data"}, status=400)

        # Получаем сохранённый вызов из кэша
        cache_key = f"browser_challenge:{client_ip}"
        challenge_data = cache.get(cache_key)

        if not challenge_data:
            logger.warning(f"No challenge data found for IP {client_ip}")
            return JsonResponse({"error": "Challenge expired"}, status=400)

        # Проверяем hash из запроса
        if challenge_hash != challenge_data['hash']:
            logger.warning(f"Challenge hash mismatch for IP {client_ip}")
            return JsonResponse({"error": "Invalid challenge"}, status=400)

        # Вычисляем ожидаемый хеш ответа
        challenge_key = challenge_data['key']
        features_str = json.dumps(browser_features, sort_keys=True)
        combined = f"{challenge_key}|{features_str}"
        expected_hash = hashlib.sha256(combined.encode()).hexdigest()

        # Проверяем ответ клиента
        if response_hash != expected_hash:
            logger.warning(f"Invalid response hash from IP {client_ip}")
            return JsonResponse({"error": "Verification failed"}, status=400)

        # Сохраняем отпечаток браузера
        fingerprint_data = {}
        for header in ['HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_ENCODING', 'HTTP_ACCEPT_LANGUAGE']:
            if header in request.META:
                fingerprint_data[header] = request.META[header]

        # Добавляем особенности браузера
        fingerprint_data.update(browser_features)
        fingerprint_data['IP'] = client_ip

        # Создаем хеш отпечатка
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        browser_fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()

        # Сохраняем в кэше
        cache.set(f"browser_fingerprint:{client_ip}", browser_fingerprint, 60 * 60 * 24)  # 24 часа
        cache.set(f"browser_verified:{client_ip}", True, 60 * 60 * 24)  # 24 часа

        # Создаем ответ с перенаправлением
        response_data = {
            "status": "ok",
            "redirect": redirect_url
        }

        response = JsonResponse(response_data)

        # Устанавливаем куки
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
        logger.error(f"Error in browser_verify: {str(e)}", exc_info=True)
        return JsonResponse({"error": "Server error"}, status=500)


def _get_client_ip(request):
    """Получение IP адреса клиента с учетом прокси"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@csrf_exempt
@require_GET
def refresh_csrf_token(request):
    """
    API эндпоинт для обновления CSRF-токена
    Этот эндпоинт освобожден от CSRF-защиты, так как используется
    для получения начального токена
    """
    try:
        # Проверяем подключение к Redis
        redis_connected = CSRFTokenService.check_redis_connection()
        if not redis_connected:
            logger.warning("Redis connection failed during token refresh. Using fallback token.")

        # Получаем старый токен, если есть
        old_token = request.COOKIES.get('csrftoken', '')

        # Генерируем новый токен
        new_token = CSRFTokenService.refresh_token(request, old_token)

        # Создаем ответ с установкой куки
        response = JsonResponse({
            'status': 'success',
            'message': 'CSRF token refreshed',
            'using_redis': redis_connected
        })

        response.set_cookie(
            'csrftoken',
            new_token,
            max_age=getattr(settings, 'CSRF_TOKEN_EXPIRY', 24 * 60 * 60),
            httponly=False,  # JavaScript должен иметь доступ для чтения
            secure=getattr(settings, 'CSRF_COOKIE_SECURE', True),
            samesite=getattr(settings, 'CSRF_COOKIE_SAMESITE', 'Lax')
        )

        return response
    except Exception as e:
        logger.error(f"Error refreshing CSRF token: {str(e)}")
        # Аварийная генерация токена при сбое
        emergency_token = secrets.token_hex(32)
        response = JsonResponse({
            'status': 'error',
            'message': 'Error refreshing token, using emergency token',
            'using_redis': False
        }, status=500)

        response.set_cookie(
            'csrftoken',
            emergency_token,
            max_age=3600,  # 1 час для аварийного токена
            httponly=False,
            secure=getattr(settings, 'CSRF_COOKIE_SECURE', True),
            samesite=getattr(settings, 'CSRF_COOKIE_SAMESITE', 'Lax')
        )

        return response


@never_cache  # Отключаем кеширование для статики
def serve_static_file(request, file_path):
    # Безопасный путь
    safe_path = os.path.normpath(file_path).lstrip('/')
    full_path = os.path.join(settings.STATIC_ROOT, safe_path)

    # Защита от directory traversal
    if not full_path.startswith(settings.STATIC_ROOT):
        raise Http404("Invalid path")

    # Проверка существования файла
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        raise Http404("File not found")

    # Определение MIME-типа
    content_type = 'text/plain'
    if full_path.endswith('.js'):
        content_type = 'application/javascript'
    elif full_path.endswith('.css'):
        content_type = 'text/css'
    elif full_path.endswith('.png'):
        content_type = 'image/png'
    elif full_path.endswith('.jpg') or full_path.endswith('.jpeg'):
        content_type = 'image/jpeg'

    # Чтение файла
    with open(full_path, 'rb') as f:
        content = f.read()

    return HttpResponse(content, content_type=content_type)

@login_required
def test_csrf_protection(request):
    """
    Тестовый эндпоинт для проверки CSRF-защиты
    """
    logger.warning(f"ТЕСТОВЫЙ ЭНДПОИНТ: Получен запрос {request.method} от {request.user.username}")

    # Проверяем токен в заголовке
    csrf_header = request.META.get('HTTP_X_CSRFTOKEN', '')
    logger.warning(f"ТЕСТОВЫЙ ЭНДПОИНТ: CSRF токен в заголовке: {csrf_header}")

    # Проверяем токен в куке
    csrf_cookie = request.COOKIES.get('csrftoken', '')
    logger.warning(f"ТЕСТОВЫЙ ЭНДПОИНТ: CSRF токен в куке: {csrf_cookie}")

    # Проверяем сессию
    session_key = request.session.session_key
    logger.warning(f"ТЕСТОВЫЙ ЭНДПОИНТ: Ключ сессии: {session_key}")

    # Проверяем Redis
    try:
        token_exists = CSRFTokenService.validate_token(request, csrf_header)
        logger.warning(f"ТЕСТОВЫЙ ЭНДПОИНТ: Токен валиден: {token_exists}")
    except Exception as e:
        logger.error(f"ТЕСТОВЫЙ ЭНДПОИНТ: Ошибка валидации токена: {str(e)}")

    # Возвращаем детали запроса
    response_data = {
        'user': request.user.username,
        'method': request.method,
        'path': request.path,
        'csrf_header_present': bool(csrf_header),
        'csrf_cookie_present': bool(csrf_cookie),
        'session_key': session_key,
        'tokens_match': csrf_header == csrf_cookie,
        'token_valid': token_exists if 'token_exists' in locals() else False,
        'headers': dict(request.headers),
        'cookies': {k: v for k, v in request.COOKIES.items() if k != 'sessionid'},  # Не показываем sessionid в ответе
    }

    return JsonResponse(response_data)

@staff_member_required
def block_ip_view(request, ip_address=None):
    """
    Представление для блокировки IP-адреса.
    Доступно только для администраторов.
    """
    if request.method == 'POST':
        ip_to_block = request.POST.get('ip_address') or ip_address
        reason = request.POST.get('reason', 'Manually blocked by admin')
        days = request.POST.get('days')

        # Проверяем корректность IP-адреса
        import re
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_to_block):
            from django.contrib import messages
            messages.error(request, f"Invalid IP address format: {ip_to_block}")
            return redirect('admin:index')

        # Определяем срок блокировки
        days_int = None
        if days and days.isdigit():
            days_int = int(days)

        # Блокируем IP
        BlockedIP.block_ip(ip_to_block, reason, days_int)

        # Если указан конкретный IP в URL, это блокировка через прямую ссылку
        if ip_address:
            # Добавляем сообщение об успешной блокировке
            from django.contrib import messages
            messages.success(request, f"IP {ip_address} has been blocked")
            return redirect('admin:index')

        # Иначе это форма блокировки из админки
        return JsonResponse({'status': 'success', 'message': f"IP {ip_to_block} has been blocked"})

    # Если это GET-запрос с указанным IP, блокируем его сразу
    if ip_address:
        # Блокируем IP
        BlockedIP.block_ip(ip_address, "Manually blocked by admin")

        # Добавляем сообщение об успешной блокировке
        from django.contrib import messages
        messages.success(request, f"IP {ip_address} has been blocked")
        return redirect('admin:index')

    # Для GET-запроса без IP возвращаем форму блокировки
    return render(request, 'admin/block_ip_form.html')

# Блокируем конкретный IP-адрес 94.241.175.200
@staff_member_required
def block_specific_ip(request):
    """
    Блокировка конкретного IP-адреса 94.241.175.200
    """
    ip_to_block = "94.241.175.200"
    reason = "Suspicious activity / Security threat"

    # Блокируем IP
    BlockedIP.block_ip(ip_to_block, reason)

    # Добавляем сообщение об успешной блокировке
    from django.contrib import messages
    messages.success(request, f"IP {ip_to_block} has been permanently blocked")

    # Перенаправляем на страницу администрирования
    return redirect('admin:index')
