from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import secrets
import datetime
import os
import uuid

def get_file_path(instance, filename):
    """Генерирует уникальный путь для файла, сохраняя исходное расширение"""
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join('message_attachments', filename)


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


class GptAssistant(models.Model):
    """Модель для GPT ассистентов"""
    name = models.CharField(max_length=100, verbose_name="Название ассистента")
    assistant_id = models.CharField(max_length=100, unique=True, verbose_name="ID ассистента в OpenAI")
    description = models.TextField(verbose_name="Описание ассистента", blank=True, null=True)
    icon = models.CharField(max_length=50, default="ri-robot-line", verbose_name="Иконка")
    is_pinned = models.BooleanField(default=False, verbose_name="Закреплен в примерах")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "GPT ассистент"
        verbose_name_plural = "GPT ассистенты"
        ordering = ['-is_pinned', 'name']

    def __str__(self):
        return self.name


class Conversation(models.Model):
    title = models.CharField(max_length=255)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='conversations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Новое поле для связи с ассистентами
    assistant = models.ForeignKey(GptAssistant, on_delete=models.SET_NULL, null=True, blank=True, related_name='conversations')

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

    # Новые поля для файловых вложений
    has_attachment = models.BooleanField(default=False)
    attachment = models.FileField(upload_to=get_file_path, null=True, blank=True)
    attachment_type = models.CharField(max_length=20, blank=True, null=True,
                                     choices=[
                                         ('image', 'Image'),
                                         ('document', 'Document'),
                                         ('other', 'Other')
                                     ])
    attachment_name = models.CharField(max_length=255, blank=True, null=True)

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
                # Если беседа связана с ассистентом, используем его имя
                if self.conversation.assistant:
                    self.sender_name = self.conversation.assistant.name
                else:
                    self.sender_name = "ChatGPT"

        # Установка has_attachment если есть прикрепленный файл
        if self.attachment and not self.has_attachment:
            self.has_attachment = True

            # Определяем тип файла по расширению, если тип не указан
            if not self.attachment_type:
                filename = self.attachment.name.lower()
                if filename.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg')):
                    self.attachment_type = 'image'
                elif filename.endswith(('.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx', '.ppt', '.pptx')):
                    self.attachment_type = 'document'
                else:
                    self.attachment_type = 'other'

            # Сохраняем оригинальное имя файла, если не указано
            if not self.attachment_name and hasattr(self.attachment, 'name'):
                self.attachment_name = os.path.basename(self.attachment.name)

        super(Message, self).save(*args, **kwargs)


class BlockedIP(models.Model):
    """
    Модель для хранения заблокированных IP-адресов
    """
    ip_address = models.GenericIPAddressField(verbose_name="IP-адрес", unique=True)
    reason = models.TextField(verbose_name="Причина блокировки", blank=True)
    blocked_at = models.DateTimeField(verbose_name="Дата блокировки", auto_now_add=True)
    blocked_until = models.DateTimeField(verbose_name="Заблокирован до", null=True, blank=True)
    is_permanent = models.BooleanField(verbose_name="Постоянная блокировка", default=True)

    class Meta:
        verbose_name = "Заблокированный IP"
        verbose_name_plural = "Заблокированные IP"

    def __str__(self):
        return f"{self.ip_address} ({self.reason})"

    @classmethod
    def is_ip_blocked(cls, ip_address):
        """
        Проверяет, заблокирован ли IP-адрес
        """
        from django.utils import timezone

        # Проверяем, есть ли IP в базе заблокированных
        try:
            blocked = cls.objects.get(ip_address=ip_address)

            # Если блокировка постоянная, то IP заблокирован
            if blocked.is_permanent:
                return True

            # Если блокировка временная, проверяем срок
            if blocked.blocked_until and blocked.blocked_until > timezone.now():
                return True

            # Если срок истек, удаляем запись
            if blocked.blocked_until and blocked.blocked_until <= timezone.now():
                blocked.delete()
                return False

            return True
        except cls.DoesNotExist:
            return False

    @classmethod
    def block_ip(cls, ip_address, reason="", days=None):
        """
        Блокирует IP-адрес

        Args:
            ip_address: IP-адрес для блокировки
            reason: Причина блокировки
            days: Количество дней блокировки. None для постоянной блокировки.

        Returns:
            BlockedIP: Созданный или обновленный объект блокировки
        """
        from django.utils import timezone
        import datetime

        # Определяем дату окончания блокировки
        blocked_until = None
        is_permanent = True

        if days is not None:
            blocked_until = timezone.now() + datetime.timedelta(days=days)
            is_permanent = False

        # Создаем или обновляем запись о блокировке
        blocked_ip, created = cls.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': reason,
                'blocked_until': blocked_until,
                'is_permanent': is_permanent,
            }
        )

        return blocked_ip
