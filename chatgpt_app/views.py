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
    """
    Main chat view. Shows the chat interface and handles chat functionality.

    This view requires authentication. If the user is not authenticated,
    they will be redirected to the login page.
    """
    # Get all conversations for the current user
    conversations = Conversation.objects.filter(user=request.user).order_by('-updated_at')

    # Get the active conversation if provided
    active_conversation = None
    conversation_id = request.GET.get('conversation_id')

    if conversation_id:
        active_conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)
    elif conversations.exists():
        # Use the most recent conversation as the active one
        active_conversation = conversations.first()

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
        if conversation_id:
            try:
                conversation = Conversation.objects.get(id=conversation_id, user=request.user)
            except Conversation.DoesNotExist:
                # If conversation doesn't exist or doesn't belong to the user, create a new one
                conversation = Conversation.objects.create(
                    title=message[:50] + ('...' if len(message) > 50 else ''),
                    user=request.user
                )
        else:
            # Create a new conversation
            conversation = Conversation.objects.create(
                title=message[:50] + ('...' if len(message) > 50 else ''),
                user=request.user
            )

        # Create user message
        Message.objects.create(
            conversation=conversation,
            role='user',
            content=message
        )

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
            content=assistant_message
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
        conversation = get_object_or_404(Conversation, id=conversation_id, user=request.user)
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
