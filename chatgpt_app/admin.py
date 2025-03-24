from django.contrib import admin
from django.utils import timezone
from .models import CustomUser, Conversation, Message, AuthToken, BlockedIP

class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_active', 'date_joined', 'last_login')
    search_fields = ('username', 'email')
    list_filter = ('is_active', 'is_staff', 'date_joined')
    ordering = ('-date_joined',)

class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'user', 'created_at', 'updated_at')
    search_fields = ('title', 'user__username')
    list_filter = ('created_at',)
    ordering = ('-updated_at',)

class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'conversation', 'role', 'sender_name', 'created_at')
    search_fields = ('content', 'conversation__title', 'sender_name')
    list_filter = ('role', 'created_at')
    ordering = ('-created_at',)

class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'expires_at', 'is_valid')
    search_fields = ('user__username', 'token')
    list_filter = ('created_at', 'expires_at')
    ordering = ('-created_at',)

    def is_valid(self, obj):
        return obj.expires_at > timezone.now()
    is_valid.boolean = True
    is_valid.short_description = 'Valid'

class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'blocked_at', 'blocked_until', 'is_permanent', 'is_active')
    search_fields = ('ip_address', 'reason')
    list_filter = ('is_permanent', 'blocked_at')
    ordering = ('-blocked_at',)
    actions = ['unblock_selected']

    def is_active(self, obj):
        if obj.is_permanent:
            return True
        return obj.blocked_until and obj.blocked_until > timezone.now()
    is_active.boolean = True
    is_active.short_description = 'Active'

    def unblock_selected(self, request, queryset):
        queryset.delete()
        self.message_user(request, f"{queryset.count()} IP-адресов разблокировано")
    unblock_selected.short_description = "Разблокировать выбранные IP-адреса"


# Register models
admin.site.register(CustomUser, UserAdmin)
admin.site.register(Conversation, ConversationAdmin)
admin.site.register(Message, MessageAdmin)
admin.site.register(AuthToken, AuthTokenAdmin)
admin.site.register(BlockedIP, BlockedIPAdmin)
