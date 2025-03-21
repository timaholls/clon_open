from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import secrets
import datetime
import hashlib


class CustomUser(AbstractUser):
    """
    Custom user model with additional fields
    """
    email = models.EmailField(_('email address'), unique=True)

    # Add additional fields as needed
    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email


class AuthToken(models.Model):
    """Token model for authentication"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='auth_tokens')
    token_hash = models.CharField(max_length=64, unique=True)  # Хеш токена для хранения
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"{self.user.email} - (Created: {self.created_at.strftime('%Y-%m-%d')})"

    def is_valid(self):
        return self.expires_at > timezone.now()

    @staticmethod
    def _hash_token(token):
        """Хеширует токен с помощью SHA-256"""
        return hashlib.sha256(token.encode()).hexdigest()

    @classmethod
    def generate_token(cls, user, expiry_days=7):
        # Delete any existing tokens for this user
        cls.objects.filter(user=user).delete()

        # Generate a new token
        token = secrets.token_hex(32)  # 64 character token
        token_hash = cls._hash_token(token)  # Хешируем токен
        expiry = timezone.now() + datetime.timedelta(days=expiry_days)

        # Create and return the token
        auth_token = cls.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expiry
        )

        # Возвращаем объект токена и сам токен для сохранения в сессии
        return auth_token, token

    @classmethod
    def verify_token(cls, token):
        """Проверяет токен и возвращает объект токена если валиден"""
        token_hash = cls._hash_token(token)
        try:
            auth_token = cls.objects.get(token_hash=token_hash)
            if auth_token.is_valid():
                return auth_token
            return None
        except cls.DoesNotExist:
            return None

class Conversation(models.Model):
    title = models.CharField(max_length=255)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='conversations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.user.username})"

    class Meta:
        ordering = ['-updated_at']

    def update_title_from_message(self, message_content):
        """Update conversation title based on message content"""
        # Разбиваем сообщение на слова
        words = message_content.split()

        # Берем первые три слова или меньше, если сообщение короче
        word_count = min(3, len(words))
        short_title = ' '.join(words[:word_count])

        # Добавляем многоточие, если сообщение длиннее
        if len(words) > word_count:
            short_title += '...'

        # Ограничиваем длину названия до 50 символов
        max_length = 50
        if len(short_title) > max_length:
            short_title = short_title[:max_length - 3] + '...'

        # Обновляем заголовок
        self.title = short_title
        self.save(update_fields=['title'])

        return self.title


class Message(models.Model):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
    ]

    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    # Добавь это поле:
    sender_name = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}"

    def save(self, *args, **kwargs):
        """Override save to automatically set sender_name based on role"""
        if not self.sender_name:
            if self.role == 'user':
                self.sender_name = self.conversation.user.username
            else:
                self.sender_name = "ChatGPT"
        super(Message, self).save(*args, **kwargs)