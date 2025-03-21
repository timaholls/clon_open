from django.urls import path, re_path
from . import views
from . import auth_views

# API URLs для чата
chat_api_urls = [
    path('api/send_message/', views.send_message, name='send_message'),
    path('api/conversations/create/', views.create_conversation, name='create_conversation'),
    path('api/conversations/<int:conversation_id>/delete/', views.delete_conversation, name='delete_conversation'),
    path('api/conversations/<int:conversation_id>/messages/', views.get_conversation_messages, name='get_conversation_messages'),
]

# Auth API URLs
auth_api_urls = [
    path('api/login/', auth_views.api_login, name='api_login'),
    path('api/signup/', auth_views.api_signup, name='api_signup'),
]

# View URLs
view_urls = [
    path('', views.index_view, name='index'),
    path('chat/', views.chat_view, name='chat'),
    path('login/', auth_views.login_view, name='login'),
    path('signup/', auth_views.signup_view, name='signup'),
    path('logout/', auth_views.logout_view, name='logout'),
]

# Static files
static_urls = [
    re_path(r'^static/(?P<file_path>.*)$', views.serve_static_file, name='static_files'),
]

# Browser verification URLs
browser_urls = [
    path('browser_verify/', views.browser_verify, name='browser_verify'),
]

# Combine all URL patterns
urlpatterns = (
    view_urls +
    chat_api_urls +
    auth_api_urls +
    static_urls +
    browser_urls
)