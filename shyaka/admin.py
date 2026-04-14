from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile within User admin."""
    model = UserProfile
    fields = ('bio', 'date_created', 'date_updated')
    readonly_fields = ('date_created', 'date_updated')
    extra = 0


class UserAdmin(BaseUserAdmin):
    """Extended User admin with UserProfile inline."""
    inlines = (UserProfileInline,)


# Re-register UserAdmin with our extension
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile model."""
    list_display = ('user', 'date_created', 'date_updated')
    list_filter = ('date_created', 'date_updated')
    search_fields = ('user__username', 'user__email', 'bio')
    readonly_fields = ('date_created', 'date_updated')
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Profile', {
            'fields': ('bio',)
        }),
        ('Timestamps', {
            'fields': ('date_created', 'date_updated'),
            'classes': ('collapse',)
        }),
    )
