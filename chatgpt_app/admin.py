from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils import timezone
from .models import CustomUser, Conversation, Message, AuthToken


class CustomUserAdmin(UserAdmin):
    """Admin configuration for the CustomUser model"""
    list_display = ('username', 'email', 'is_staff', 'date_joined')
    search_fields = ('username', 'email')

    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'bio', 'avatar')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2'),
        }),
    )


class ConversationAdmin(admin.ModelAdmin):
    """Admin configuration for the Conversation model"""
    list_display = ('title', 'user', 'created_at', 'updated_at')
    list_filter = ('user', 'created_at')
    search_fields = ('title', 'user__username', 'user__email')
    date_hierarchy = 'created_at'


from django.contrib import admin
from .models import CustomUser, Conversation, Message, AuthToken


class MessageAdmin(admin.ModelAdmin):
    """Admin configuration for the Message model"""
    list_display = ('get_conversation_title', 'role', 'sender_name', 'preview_content', 'created_at')
    list_filter = ('role', 'sender_name', 'created_at', 'conversation__user')
    search_fields = ('content', 'sender_name', 'conversation__title', 'conversation__user__username')
    date_hierarchy = 'created_at'

    def get_conversation_title(self, obj):
        return obj.conversation.title

    get_conversation_title.short_description = 'Conversation'
    get_conversation_title.admin_order_field = 'conversation__title'

    def preview_content(self, obj):
        if len(obj.content) > 50:
            return obj.content[:50] + '...'
        return obj.content

    preview_content.short_description = 'Content'


class AuthTokenAdmin(admin.ModelAdmin):
    """Admin configuration for the AuthToken model"""
    list_display = ('user', 'token_preview', 'created_at', 'expires_at', 'is_valid')
    list_filter = ('created_at', 'expires_at')
    search_fields = ('user__username', 'user__email', 'token')
    date_hierarchy = 'created_at'

    def token_preview(self, obj):
        return obj.token[:10] + '...'

    token_preview.short_description = 'Token'

    def is_valid(self, obj):
        from django.utils import timezone
        return obj.expires_at > timezone.now()

    is_valid.boolean = True
    is_valid.short_description = 'Is Valid'


# Register models
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Conversation, ConversationAdmin)
admin.site.register(Message, MessageAdmin)
admin.site.register(AuthToken, AuthTokenAdmin)
