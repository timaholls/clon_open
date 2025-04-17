#!/usr/bin/env python
import os
import django
import sys

# Настройка окружения Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'chatgpt_project.settings')
django.setup()

from chatgpt_app.models import GptAssistant

def create_assistants():
    """
    Создает двух закрепленных ассистентов: Юридический бот и Консультант ИИ.
    Если ассистенты уже существуют, обновляет их данные.
    """
    # Юридический бот
    legal_bot, created = GptAssistant.objects.update_or_create(
        assistant_id="asst_legal_bot_id",  # Замените на реальный ID ассистента
        defaults={
            'name': 'Юридический бот',
            'description': 'Ассистент по юридическим вопросам и консультациям',
            'icon': 'ri-scales-line',
            'is_pinned': True
        }
    )

    if created:
        print(f"Создан новый ассистент: {legal_bot.name}")
    else:
        print(f"Обновлен существующий ассистент: {legal_bot.name}")

    # Консультант ИИ
    consultant_bot, created = GptAssistant.objects.update_or_create(
        assistant_id="asst_zqKi01mdvLeeNGXUf6cQ0GNQ",  # ID из примера
        defaults={
            'name': 'Консультант ИИ',
            'description': 'Ассистент для консультаций и помощи по различным вопросам',
            'icon': 'ri-robot-line',
            'is_pinned': True
        }
    )

    if created:
        print(f"Создан новый ассистент: {consultant_bot.name}")
    else:
        print(f"Обновлен существующий ассистент: {consultant_bot.name}")

    print("\nВсе ассистенты успешно созданы или обновлены!")
    print("\nСписок всех ассистентов:")
    for assistant in GptAssistant.objects.all().order_by('name'):
        print(f"- {assistant.name} (ID: {assistant.assistant_id}), закреплен: {'Да' if assistant.is_pinned else 'Нет'}")

if __name__ == "__main__":
    create_assistants()
