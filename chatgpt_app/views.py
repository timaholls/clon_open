import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
import json
import time
import logging
import hashlib
from django.core.cache import cache
from django.views.decorators.cache import never_cache
from django.http import HttpResponse, Http404
from django.conf import settings
from .models import Conversation, Message

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

    context = {
        'conversations': conversations,
        'active_conversation': active_conversation,
    }

    return render(request, 'chatgpt_app/chat.html', context)


@login_required
@require_POST
def send_message(request):
    """API endpoint to send a message and get a response"""
    # Проверяем CSRF токен вручную
    csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
    if not csrf_token and 'csrfmiddlewaretoken' not in request.POST:
        return JsonResponse({'error': 'CSRF token missing or invalid'}, status=403)

    try:
        # Для JSON запросов
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            message = data.get('message')
            conversation_id = data.get('conversation_id')
        # Для form-data запросов
        else:
            message = request.POST.get('message')
            conversation_id = request.POST.get('conversation_id')

        # Validate input
        if not message:
            return JsonResponse({'error': 'Message is required'}, status=400)

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
            content=message,
            sender_name=request.user.username
        )

        # If this is the first message in the conversation, update the title
        if is_new_conversation or conversation.messages.count() <= 2:  # учитываем текущее сообщение и возможное системное
            conversation.update_title_from_message(message)

        # Update conversation timestamp
        conversation.save()  # This will update the updated_at field

        # Simulate a delay for the assistant response
        time.sleep(1)

        # Create a sample response
        assistant_message = "Тестовый ответ на ваше сообщение: " + message

        # Create assistant message
        Message.objects.create(
            conversation=conversation,
            role='assistant',
            content=assistant_message,
            sender_name="ChatGPT"
        )

        return JsonResponse({
            'message': assistant_message,
            'conversation_id': conversation.id,
            'conversation_title': conversation.title
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

        if not csrf_header or not csrf_cookie or csrf_header != csrf_cookie:
            logger.warning(f"CSRF protection: token mismatch or missing for user {request.user.username}")
            return JsonResponse({"error": "CSRF token validation failed"}, status=403)

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

        if not csrf_header or not csrf_cookie or csrf_header != csrf_cookie:
            logger.warning(f"CSRF protection: token mismatch or missing for user {request.user.username}")
            return JsonResponse({"error": "CSRF token validation failed"}, status=403)

        conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)
        conversation.delete()

        return JsonResponse({'success': True})

    except Exception as e:
        logger.error(f"Error in delete_conversation: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def get_conversation_messages(request, conversation_id):
    """API endpoint to get all messages for a conversation"""
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



# @csrf_exempt
# @never_cache  # Отключаем кеширование для статики
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
