import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from .models import Conversation, Message, BlockedIP, GptAssistant
import json
import logging
import hashlib
from django.core.cache import cache
from django.views.decorators.cache import never_cache
from django.http import HttpResponse, Http404
from django.conf import settings
import base64
from openai import OpenAI
import time

# Импорты для обработки различных форматов документов
import tempfile
import zipfile

try:
    import PyPDF2
    from docx import Document
    import xml.etree.ElementTree as ET
    from odf.opendocument import load
    from odf.text import P
    import pandas as pd

    DOCUMENT_LIBS_AVAILABLE = True
except ImportError:
    DOCUMENT_LIBS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Get API key from environment variables or settings
api_key = os.environ.get('OPENAI_API_KEY') or getattr(settings, 'OPENAI_API_KEY', None)

if not api_key:
    logger.error("OpenAI API key не настроен в переменных окружения или настройках")
    raise ValueError(
        "OpenAI API key is not configured. Please set OPENAI_API_KEY in your environment variables or settings.")

client = OpenAI(api_key=api_key)


@login_required
def index_view(request):
    """Main view for the application"""
    # If user has no conversations, redirect to chat view (new conversation)
    if not Conversation.objects.filter(user=request.user).exists():
        return redirect('chat')

    # Get the most recent conversation
    conversation = Conversation.objects.filter(user=request.user).order_by('-updated_at').first()
    return redirect('chat', conversation_id=conversation.id)

@login_required
def chat_view(request, conversation_id=None):
    """Chat view for the application"""
    conversations = Conversation.objects.filter(user=request.user).order_by('-updated_at')
    active_conversation = None

    if conversation_id:
        active_conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)

    # Получаем закрепленных ассистентов для отображения в примерах
    pinned_assistants = GptAssistant.objects.filter(is_pinned=True)

    return render(request, 'chatgpt_app/chat.html', {
        'conversations': conversations,
        'active_conversation': active_conversation,
        'pinned_assistants': pinned_assistants,  # Добавляем закрепленных ассистентов
    })


@login_required
@require_POST
def send_message_to_assistant(request):
    """API endpoint to send message to GPT Assistant"""
    try:
        # Parse JSON data from request
        data = json.loads(request.body)
        message_content = data.get('message', '').strip()
        conversation_id = data.get('conversation_id')
        assistant_id = data.get('assistant_id')
        has_attachment = data.get('has_attachment', False)
        attachment_data = data.get('attachment')

        # Validate the input
        if not message_content and not has_attachment:
            return JsonResponse({'error': 'Message or attachment is required'}, status=400)

        # Check if we need to create a new conversation
        if conversation_id:
            conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)
        else:
            # Получаем ассистента или используем None, если не найден
            assistant = None
            if assistant_id:
                try:
                    assistant = GptAssistant.objects.get(assistant_id=assistant_id)
                except GptAssistant.DoesNotExist:
                    return JsonResponse({'error': 'Assistant not found'}, status=404)

            # Создаем новую беседу с привязкой к ассистенту, если он был указан
            conversation = Conversation.objects.create(
                title="Новая беседа",
                user=request.user,
                assistant=assistant
            )

            if message_content:
                conversation.update_title_from_message(message_content)

        # Create user message
        user_message = Message.objects.create(
            conversation=conversation,
            role='user',
            content=message_content,
        )

        # Handle file attachment
        if has_attachment and attachment_data:
            try:
                file_data = attachment_data.get('data')
                file_name = attachment_data.get('name')

                if file_data and file_name:
                    # Extract the base64 data
                    if ',' in file_data:
                        _, file_data = file_data.split(',', 1)

                    # Decode the base64 data
                    binary_data = base64.b64decode(file_data)

                    # Create a temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file_name}") as temp:
                        temp.write(binary_data)
                        temp_path = temp.name

                    # Open and save the file to the Message model
                    with open(temp_path, 'rb') as f:
                        file_name = os.path.basename(file_name)
                        user_message.attachment.save(file_name, f)

                    # Remove the temporary file
                    os.unlink(temp_path)

                    # Detect attachment type
                    if file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg')):
                        user_message.attachment_type = 'image'
                    elif file_name.lower().endswith(('.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx', '.ppt', '.pptx')):
                        user_message.attachment_type = 'document'
                    else:
                        user_message.attachment_type = 'other'

                    user_message.attachment_name = file_name
                    user_message.has_attachment = True
                    user_message.save()

            except Exception as e:
                logger.error(f"Error processing attachment: {str(e)}")
                return JsonResponse({'error': f'Error processing attachment: {str(e)}'}, status=500)

        # Обновляем дату последней активности беседы
        conversation.save()  # Использует auto_now=True для updated_at

        try:
            # Проверяем, использует ли беседа GPT Assistant
            if conversation.assistant:
                assistant_id = conversation.assistant.assistant_id

                # Создаем новый thread для каждого запроса (или можно хранить id треда в беседе для продолжения)
                thread = client.beta.threads.create()

                # Добавляем сообщение пользователя
                client.beta.threads.messages.create(
                    thread_id=thread.id,
                    role="user",
                    content=message_content
                )

                # Запускаем ассистента
                run = client.beta.threads.runs.create(
                    thread_id=thread.id,
                    assistant_id=assistant_id,
                )

                # Ждем завершения задачи (polling)
                while True:
                    run_status = client.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
                    if run_status.status in ["completed", "failed"]:
                        break
                    time.sleep(1)

                # Получаем сообщения (ответ ассистента)
                messages = client.beta.threads.messages.list(thread_id=thread.id)

                # Находим ответ ассистента (последнее сообщение с ролью assistant)
                assistant_message = None
                for msg in messages.data:
                    if msg.role == "assistant":
                        assistant_message = msg.content[0].text.value
                        break

                if not assistant_message:
                    assistant_message = "Извините, произошла ошибка при получении ответа от ассистента."
            else:
                # Используем обычный GPT-4 для не-ассистентов
                try:
                    # Prepare messages for API call
                    messages_for_api = []

                    # Get previous messages for context (limit to last 20 for performance)
                    previous_messages = Message.objects.filter(conversation=conversation).order_by('created_at')[:20]

                    for msg in previous_messages:
                        messages_for_api.append({
                            "role": msg.role,
                            "content": msg.content
                        })

                    # Add current message if not already in the list
                    if not messages_for_api or messages_for_api[-1]["content"] != message_content:
                        messages_for_api.append({
                            "role": "user",
                            "content": message_content
                        })

                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=messages_for_api,
                        temperature=0.7,
                    )

                    assistant_message = response.choices[0].message.content
                    logger.info(f"Получен успешный ответ от OpenAI SDK, длина ответа: {len(assistant_message)} символов")
                except Exception as sdk_exc:
                    logger.error(f"OpenAI SDK error: {str(sdk_exc)}")
                    assistant_message = f"Извините, произошла ошибка при обработке вашего запроса. Пожалуйста, попробуйте позже."

        except Exception as e:
            logger.error(f"Error calling OpenAI API: {str(e)}")
            assistant_message = f"Извините, произошла ошибка при обработке вашего запроса. Пожалуйста, попробуйте позже."

            # Log the detailed error but don't expose it to the user
            logger.error(f"Detailed error: {str(e)}")

        # Create assistant message
        Message.objects.create(
            conversation=conversation,
            role='assistant',
            content=assistant_message,
            sender_name=conversation.assistant.name if conversation.assistant else "ChatGPT"
        )

        # Подготовим данные о вложении, если оно есть
        attachment_data = None
        if has_attachment and user_message.attachment:
            attachment_data = {
                'url': user_message.attachment.url,
                'name': user_message.attachment_name,
                'type': user_message.attachment_type
            }

        return JsonResponse({
            'message': assistant_message,
            'conversation_id': conversation.id,
            'conversation_title': conversation.title,
            'attachment': attachment_data
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in send_message_to_assistant: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def create_conversation(request):
    """API endpoint to create a new conversation"""
    try:
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
                    'created_at': message.created_at.isoformat(),
                    'has_attachment': message.has_attachment,
                    'attachment': {
                        'url': message.attachment.url if message.attachment else None,
                        'name': message.attachment_name,
                        'type': message.attachment_type
                    } if message.has_attachment else None
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


@login_required
@require_POST
def send_message(request):
    """API endpoint to send a message to regular GPT model"""
    try:
        # Parse JSON data from request
        data = json.loads(request.body)
        message_content = data.get('message', '').strip()
        conversation_id = data.get('conversation_id')
        has_attachment = data.get('has_attachment', False)
        attachment_data = data.get('attachment')

        # Validate the input
        if not message_content and not has_attachment:
            return JsonResponse({'error': 'Message or attachment is required'}, status=400)

        # Check if we need to create a new conversation
        if conversation_id:
            conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)
        else:
            # Create a new conversation without assistant (standard GPT)
            conversation = Conversation.objects.create(
                title="Новая беседа",
                user=request.user,
                assistant=None
            )

            if message_content:
                conversation.update_title_from_message(message_content)

        # Create user message
        user_message = Message.objects.create(
            conversation=conversation,
            role='user',
            content=message_content,
        )

        # Handle file attachment
        if has_attachment and attachment_data:
            try:
                file_data = attachment_data.get('data')
                file_name = attachment_data.get('name')

                if file_data and file_name:
                    # Extract the base64 data
                    if ',' in file_data:
                        _, file_data = file_data.split(',', 1)

                    # Decode the base64 data
                    binary_data = base64.b64decode(file_data)

                    # Create a temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file_name}") as temp:
                        temp.write(binary_data)
                        temp_path = temp.name

                    # Open and save the file to the Message model
                    with open(temp_path, 'rb') as f:
                        file_name = os.path.basename(file_name)
                        user_message.attachment.save(file_name, f)

                    # Remove the temporary file
                    os.unlink(temp_path)

                    # Detect attachment type
                    if file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg')):
                        user_message.attachment_type = 'image'
                    elif file_name.lower().endswith(('.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx', '.ppt', '.pptx')):
                        user_message.attachment_type = 'document'
                    else:
                        user_message.attachment_type = 'other'

                    user_message.attachment_name = file_name
                    user_message.has_attachment = True
                    user_message.save()

            except Exception as e:
                logger.error(f"Error processing attachment: {str(e)}")
                return JsonResponse({'error': f'Error processing attachment: {str(e)}'}, status=500)

        # Update conversation last activity time
        conversation.save()  # Uses auto_now=True for updated_at

        try:
            # Prepare messages for API call
            messages_for_api = []

            # Get previous messages for context (limit to last 20 for performance)
            previous_messages = Message.objects.filter(conversation=conversation).order_by('created_at')[:20]

            for msg in previous_messages:
                messages_for_api.append({
                    "role": msg.role,
                    "content": msg.content
                })

            # Add current message if not already in the list
            if not messages_for_api or messages_for_api[-1]["content"] != message_content:
                messages_for_api.append({
                    "role": "user",
                    "content": message_content
                })

            response = client.chat.completions.create(
                model="gpt-4o",
                messages=messages_for_api,
                temperature=0.7,
            )

            assistant_message = response.choices[0].message.content
            logger.info(f"Получен успешный ответ от OpenAI SDK, длина ответа: {len(assistant_message)} символов")
        except Exception as sdk_exc:
            logger.error(f"OpenAI SDK error: {str(sdk_exc)}")
            assistant_message = f"Извините, произошла ошибка при обработке вашего запроса. Пожалуйста, попробуйте позже."

        # Create assistant message
        Message.objects.create(
            conversation=conversation,
            role='assistant',
            content=assistant_message,
            sender_name="ChatGPT"
        )

        # Prepare attachment data if exists
        attachment_data = None
        if has_attachment and user_message.attachment:
            attachment_data = {
                'url': user_message.attachment.url,
                'name': user_message.attachment_name,
                'type': user_message.attachment_type
            }

        return JsonResponse({
            'message': assistant_message,
            'conversation_id': conversation.id,
            'conversation_title': conversation.title,
            'attachment': attachment_data
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in send_message: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
