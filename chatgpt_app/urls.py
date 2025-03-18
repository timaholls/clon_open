from django.urls import path
from . import views
from . import auth_views
urlpatterns = [
    # Основные маршруты
    path('', views.index_view, name='index'),
    path('chat/', views.chat_view, name='chat'),

    # Аутентификация
    path('login/', auth_views.login_view, name='login'),
    path('signup/', auth_views.signup_view, name='signup'),
    path('logout/', auth_views.logout_view, name='logout'),

    # API маршруты
    path('api/login/', auth_views.api_login, name='api_login'),
    path('api/signup/', auth_views.api_signup, name='api_signup'),

    # Функции чата
    path('api/send_message/', views.send_message, name='send_message'),
    path('api/conversations/create/', views.create_conversation, name='create_conversation'),
    path('api/conversations/<int:conversation_id>/delete/', views.delete_conversation, name='delete_conversation'),
    path('api/conversations/<int:conversation_id>/messages/', views.get_conversation_messages, name='get_conversation_messages'),

    # CAPTCHA
    path('refresh-captcha/', auth_views.refresh_captcha, name='refresh_captcha'),
]
