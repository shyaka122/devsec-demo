"""
URL configuration for shyaka (authentication service) app.
"""
from django.urls import path
from . import views

app_name = 'shyaka'

urlpatterns = [
    # Authentication endpoints (public)
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Protected endpoints (authenticated users)
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.profile, name='profile'),
    path('change-password/', views.change_password, name='change_password'),
    
    # Admin-only endpoints (admin users only)
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/users/', views.manage_users, name='manage_users'),
    path('admin/users/assign-role/', views.assign_user_role, name='assign_user_role'),
]
