from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import secrets
import datetime


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
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"{self.user.email} - {self.token[:8]}..."

    def is_valid(self):
        return self.expires_at > timezone.now()

    @classmethod
    def generate_token(cls, user, expiry_days=7):
        # Delete any existing tokens for this user
        cls.objects.filter(user=user).delete()

        # Generate a new token
        token = secrets.token_hex(32)  # 64 character token
        expiry = timezone.now() + datetime.timedelta(days=expiry_days)

        # Create and return the token
        auth_token = cls.objects.create(
            user=user,
            token=token,
            expires_at=expiry
        )
        return auth_token


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
