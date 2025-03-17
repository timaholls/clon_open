from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
import json
import time
import logging

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
@csrf_exempt
@require_POST
def send_message(request):
    """API endpoint to send a message and get a response"""
    try:
        data = json.loads(request.body)
        message = data.get('message')
        conversation_id = data.get('conversation_id')

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
@csrf_exempt
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
@csrf_exempt
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
def get_conversation_messages(request, conversation_id):
    """API endpoint to get all messages for a conversation"""
    try:
        # Важно: проверяем, что разговор принадлежит текущему пользователю
        conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)

        # Получаем сообщения, отсортированные по времени создания
        messages = conversation.messages.order_by('created_at')
        print(messages)
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
