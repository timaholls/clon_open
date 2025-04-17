import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from .models import Conversation, Message, BlockedIP
import json
import logging
import hashlib
from django.core.cache import cache
from django.views.decorators.cache import never_cache
from django.http import HttpResponse, Http404
from django.conf import settings
import base64
from openai import OpenAI

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


def extract_text_from_file(file_obj, file_name):
    """
    Извлекает текст из различных форматов файлов

    Args:
        file_obj: Объект файла (BytesIO или файлоподобный объект)
        file_name: Имя файла с расширением

    Returns:
        str: Извлеченный текст
    """
    if not DOCUMENT_LIBS_AVAILABLE:
        return f"[Документ {file_name} прикреплен, но необходимые библиотеки для его обработки не установлены]"

    # Проверка размера файла
    if hasattr(file_obj, 'size') and file_obj.size > settings.MAX_UPLOAD_SIZE:
        return f"[Файл {file_name} слишком большой. Максимальный размер: 10MB]"

    # Создаем временный файл
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        # Перемещаем указатель файла в начало, если это файлоподобный объект
        if hasattr(file_obj, 'seek'):
            file_obj.seek(0)
        # Записываем содержимое во временный файл
        temp_file.write(file_obj.read())
        temp_path = temp_file.name

    try:
        ext = os.path.splitext(file_name)[1].lower()

        if ext == ".txt":
            with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        elif ext == ".pdf":
            try:
                with open(temp_path, "rb") as f:
                    reader = PyPDF2.PdfReader(f)
                    return "\n".join(page.extract_text() for page in reader.pages if page.extract_text())
            except Exception as e:
                return f"[Ошибка при обработке PDF: {str(e)}]"

        elif ext == ".docx":
            try:
                doc = Document(temp_path)
                return "\n".join(p.text for p in doc.paragraphs if p.text)
            except Exception as e:
                return f"[Ошибка при обработке DOCX: {str(e)}]"

        elif ext == ".xml":
            try:
                tree = ET.parse(temp_path)
                root = tree.getroot()
                return "\n".join((elem.text or '').strip() for elem in root.iter() if elem.text)
            except Exception as e:
                return f"[Ошибка при обработке XML: {str(e)}]"

        elif ext == ".odt":
            try:
                text = ""
                odt_doc = load(temp_path)
                for paragraph in odt_doc.getElementsByType(P):
                    if paragraph.firstChild:
                        text += paragraph.firstChild.data + "\n"
                return text
            except Exception as e:
                return f"[Ошибка при обработке ODT: {str(e)}]"

        elif ext in [".xlsx", ".xls"]:
            try:
                df = pd.read_excel(temp_path, sheet_name=None)
                text = ""
                for sheet_name, sheet in df.items():
                    text += f"--- Лист: {sheet_name} ---\n"
                    text += sheet.to_string(index=False) + "\n"
                return text
            except Exception as e:
                return f"[Ошибка при обработке Excel: {str(e)}]"

        elif ext == ".csv":
            try:
                df = pd.read_csv(temp_path)
                return df.to_string(index=False)
            except Exception as e:
                return f"[Ошибка при обработке CSV: {str(e)}]"

        elif ext == ".zip":
            try:
                text = ""
                with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                    for name in zip_ref.namelist():
                        if name.endswith(('.txt', '.csv', '.xml')):
                            with zip_ref.open(name) as f:
                                content = f.read().decode("utf-8", errors="ignore")
                                text += f"\n--- Файл внутри архива: {name} ---\n{content}\n"
                return text if text else "[Архив не содержит текстовых файлов]"
            except Exception as e:
                return f"[Ошибка при обработке ZIP: {str(e)}]"

        else:
            return f"[Формат файла {ext} не поддерживается для извлечения текста]"

    except Exception as e:
        return f"[Ошибка при обработке файла: {str(e)}]"
    finally:
        # Удаляем временный файл
        if os.path.exists(temp_path):
            os.unlink(temp_path)


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

    response = render(request, 'chatgpt_app/chat.html', context)

    return response


@login_required
@require_POST
def send_message(request):
    """API endpoint to send a message and get a response"""
    # Проверяем CSRF токен вручную
    csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
    if not csrf_token and 'csrfmiddlewaretoken' not in request.POST:
        return JsonResponse({'error': 'CSRF token missing or invalid'}, status=403)

    try:
        # Логируем начало обработки запроса
        logger.info(f"Получен запрос на отправку сообщения от пользователя: {request.user.username}")

        # Проверка размера файла перед обработкой
        if request.META.get('CONTENT_LENGTH') and int(request.META.get('CONTENT_LENGTH')) > settings.MAX_UPLOAD_SIZE:
            logger.warning(f"Файл слишком большой: {request.META.get('CONTENT_LENGTH')} байт")
            return JsonResponse({
                'error': 'Файл слишком большой. Максимальный размер файла: 10MB.'
            }, status=413)

        # Определяем тип запроса - JSON или multipart (с файлами)
        has_attachment = False
        attachment_file = None
        attachment_type = None
        attachment_name = None
        message = None
        conversation_id = None

        # Обработка данных из разных типов запросов
        if request.content_type == 'application/json':
            # Для JSON запросов
            data = json.loads(request.body)
            message = data.get('message')
            conversation_id = data.get('conversation_id')
            logger.info(f"Получен JSON запрос: message={message}, conversation_id={conversation_id}")
        elif 'multipart/form-data' in request.content_type:
            # Для multipart/form-data запросов (с файлами)
            message = request.POST.get('message', '')
            conversation_id = request.POST.get('conversation_id')

            # Обработка прикрепленного файла
            if 'attachment' in request.FILES:
                attachment_file = request.FILES['attachment']

                # Определяем тип файла по MIME-типу или расширению
                content_type = attachment_file.content_type
                if content_type.startswith('image/'):
                    attachment_type = 'image'
                elif content_type.startswith(('application/', 'text/')):
                    attachment_type = 'document'
                else:
                    attachment_type = 'other'

                attachment_name = attachment_file.name
                has_attachment = True
                logger.info(f"Получен multipart запрос с вложением: type={attachment_type}, name={attachment_name}")
        else:
            # Для обычных form-data запросов
            message = request.POST.get('message')
            conversation_id = request.POST.get('conversation_id')
            logger.info(f"Получен form-data запрос: message={message}, conversation_id={conversation_id}")

        # Проверяем наличие сообщения или вложения
        if not message and not has_attachment:
            logger.warning("Запрос не содержит ни сообщения, ни вложения")
            return JsonResponse({'error': 'Message or attachment is required'}, status=400)

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
        user_message = Message(
            conversation=conversation,
            role='user',
            content=message if message else '',  # Пустая строка, если нет текста, но есть вложение
            sender_name=request.user.username
        )

        # Добавляем вложение, если оно есть
        if has_attachment and attachment_file:
            user_message.attachment = attachment_file
            user_message.attachment_type = attachment_type
            user_message.attachment_name = attachment_name
            user_message.has_attachment = True

        user_message.save()

        # If this is the first message in the conversation, update the title
        if is_new_conversation or conversation.messages.count() <= 2:  # учитываем текущее сообщение и возможное системное
            # Если есть текст, используем его для заголовка, иначе используем имя файла
            title_source = message if message else f"Файл: {attachment_name[:30]}"
            conversation.update_title_from_message(title_source)

        # Update conversation timestamp
        conversation.save()  # This will update the updated_at field

        try:
            # Получаем историю сообщений для контекста (ограничиваем последними 10)
            previous_messages = conversation.messages.filter(id__lt=user_message.id).order_by('-created_at')[:10]
            previous_messages = list(reversed(previous_messages))

            # Подготовим сообщения для API в зависимости от типа
            if has_attachment and attachment_type == 'image':
                # Если у нас есть изображение, используем модель GPT-4.1-vision
                logger.info("Подготовка запроса для анализа изображения через GPT-4.1-vision...")

                # Конвертируем изображение в формат base64
                attachment_file.seek(0)
                image_content = attachment_file.read()
                base64_image = base64.b64encode(image_content).decode('utf-8')

                # Определяем тип изображения по расширению или mime-типу
                image_extension = os.path.splitext(attachment_name)[1].lower().lstrip('.')
                if not image_extension or image_extension not in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
                    image_extension = 'jpeg'  # Используем jpeg как формат по умолчанию

                # Формируем запрос для модели vision
                messages_for_api = [
                    {
                        "role": "system",
                        "content": "Вы - помощник, который анализирует изображения и отвечает на вопросы о них. Давайте подробные и информативные ответы."
                    }
                ]

                # Добавляем предыдущие текстовые сообщения для контекста
                for prev_msg in previous_messages:
                    if prev_msg.role == 'user' or prev_msg.role == 'assistant':
                        messages_for_api.append({
                            "role": prev_msg.role,
                            "content": prev_msg.content
                        })

                # Формируем текущее сообщение пользователя с изображением
                user_content = [
                    {"type": "text", "text": message if message else "Что изображено на этой картинке? Опиши подробно."}
                ]

                # Добавляем изображение
                image_url = f"data:image/{image_extension};base64,{base64_image}"
                user_content.append({"type": "image_url", "image_url": {"url": image_url}})

                # Добавляем сообщение пользователя
                messages_for_api.append({
                    "role": "user",
                    "content": user_content
                })

            elif has_attachment and (attachment_type == 'document' or attachment_type == 'other'):
                # Для документов используем расширенную обработку и стандартный GPT-4
                logger.info("Подготовка запроса для анализа документов с расширенной обработкой...")

                # Извлекаем текст из документов с учетом их формата
                document_content = extract_text_from_file(attachment_file, attachment_name)

                # Ограничиваем размер документов для API
                max_doc_length = 12000  # Примерно 3000 токенов
                if len(document_content) > max_doc_length:
                    document_content = document_content[
                                       :max_doc_length] + "\n[Документ был обрезан из-за превышения допустимого размера]"

                # Формируем системное сообщение
                messages_for_api = [
                    {
                        "role": "system",
                        "content": "Вы - помощник, который анализирует документы и отвечает на вопросы о них. Давайте конкретные и содержательные ответы на основе содержимого документов."
                    }
                ]

                # Добавляем предыдущие сообщения для контекста
                for prev_msg in previous_messages:
                    if prev_msg.role == 'user' or prev_msg.role == 'assistant':
                        messages_for_api.append({
                            "role": prev_msg.role,
                            "content": prev_msg.content
                        })

                # Формируем запрос для анализа документов
                user_prompt = message if message else "Проанализируй содержимое этого документа и расскажи, что в нем написано. Предоставь структурированное резюме."
                user_content = f"{user_prompt}\n\nСодержимое документа ({attachment_name}):\n{document_content}"

                messages_for_api.append({
                    "role": "user",
                    "content": user_content
                })

            else:
                # Для обычных текстовых сообщений
                logger.info("Подготовка запроса для обычного текстового сообщения...")

                # Формируем системное сообщение
                messages_for_api = [
                    {
                        "role": "system",
                        "content": "Вы - полезный ассистент, который отвечает на вопросы пользователя."
                    }
                ]

                # Добавляем предыдущие сообщения для контекста
                for prev_msg in previous_messages:
                    if prev_msg.role == 'user' or prev_msg.role == 'assistant':
                        messages_for_api.append({
                            "role": prev_msg.role,
                            "content": prev_msg.content
                        })

                # Добавляем текущее сообщение пользователя
                messages_for_api.append({
                    "role": "user",
                    "content": message
                })

            # Логируем отправку запроса в OpenAI SDK
            logger.info(f"Отправка запроса к OpenAI SDK: {len(messages_for_api)} сообщений")
            try:
                if has_attachment and attachment_type == 'image':
                    # Vision (image_url) запрос
                    response = client.chat.completions.create(
                        model="gpt-4.1",
                        messages=messages_for_api,
                        max_tokens=3000
                    )
                else:
                    # Обычный текстовый или документ
                    response = client.chat.completions.create(
                        model="gpt-4.1",
                        messages=messages_for_api,
                        max_tokens=3000
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
            sender_name="ChatGPT"
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
        logger.error(f"Error in send_message: {str(e)}")
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
