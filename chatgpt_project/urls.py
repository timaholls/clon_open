"""URL configuration for chatgpt_project project."""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('chatgpt_app.urls')),
]

# Add static and media URLs in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    # Даже в production режиме добавляем маршруты для медиа-файлов
    # (в production это должно обрабатываться веб-сервером, но для тестирования это полезно)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
