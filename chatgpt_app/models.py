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
        return self.title

    class Meta:
        ordering = ['-updated_at']

    def get_first_message(self):
        """Get the first user message for generating a title"""
        first_message = self.messages.filter(role='user').first()
        if first_message:
            return first_message.content[:50]
        return "Новый чат"


class Message(models.Model):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
    ]

    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}"
