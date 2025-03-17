from django.urls import path
from . import views
from . import auth_views

urlpatterns = [
    # Main views
    path('', views.index_view, name='index'),
    path('chat/', views.chat_view, name='chat'),

    # Authentication views
    path('login/', auth_views.login_view, name='login'),
    path('signup/', auth_views.signup_view, name='signup'),
    path('logout/', auth_views.logout_view, name='logout'),

    # API endpoints
    path('api/login/', auth_views.api_login, name='api_login'),
    path('api/signup/', auth_views.api_signup, name='api_signup'),

    # Message API endpoints
    path('api/send_message/', views.send_message, name='send_message'),
    path('api/conversations/create/', views.create_conversation, name='create_conversation'),
    path('api/conversations/<int:conversation_id>/delete/', views.delete_conversation, name='delete_conversation'),
    path('api/conversations/<int:conversation_id>/messages/', views.get_conversation_messages, name='get_conversation_messages'),
]
