from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Conversation, Message, AuthToken

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    fieldsets = UserAdmin.fieldsets + (
        ('Extra Fields', {'fields': ('bio', 'avatar')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Extra Fields', {'fields': ('email', 'bio', 'avatar')}),
    )


class MessageInline(admin.TabularInline):
    model = Message
    extra = 0
    readonly_fields = ('created_at',)


class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'user', 'created_at', 'updated_at')
    list_filter = ('user', 'created_at')
    search_fields = ('title', 'user__username', 'user__email')
    readonly_fields = ('created_at', 'updated_at')
    inlines = [MessageInline]


class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'conversation', 'role', 'content_preview', 'created_at')
    list_filter = ('role', 'created_at', 'conversation__user')
    search_fields = ('content', 'conversation__title')
    readonly_fields = ('created_at',)

    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content


class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'created_at', 'expires_at', 'is_valid')
    list_filter = ('created_at', 'expires_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at',)

    def is_valid(self, obj):
        import datetime
        return obj.expires_at > datetime.datetime.now()
    is_valid.boolean = True


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Conversation, ConversationAdmin)
admin.site.register(Message, MessageAdmin)
admin.site.register(AuthToken, AuthTokenAdmin)
