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
    
    # Password reset endpoints (public) - secure account recovery workflow
    path('password-reset/', views.password_reset_request, name='password_reset_request'),
    path('password-reset/done/', views.password_reset_done, name='password_reset_done'),
    path('password-reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('password-reset/complete/', views.password_reset_complete, name='password_reset_complete'),
    
    # Protected endpoints (authenticated users)
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.profile, name='profile'),
    path('change-password/', views.change_password, name='change_password'),
    
    # File upload endpoints (authenticated users)
    path('upload-avatar/', views.upload_avatar, name='upload_avatar'),
    path('upload-document/', views.upload_document, name='upload_document'),
    path('documents/', views.document_list, name='document_list'),
    path('documents/<int:document_id>/download/', views.download_document, name='download_document'),
    path('documents/<int:document_id>/delete/', views.delete_document, name='delete_document'),
    
    # User profile endpoints with IDOR protection
    path('user/<int:user_id>/profile/', views.view_user_profile, name='view_user_profile'),
    path('user/<int:user_id>/profile/edit/', views.edit_user_profile, name='edit_user_profile'),
    
    # Admin-only endpoints (admin users only)
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/users/', views.manage_users, name='manage_users'),
    path('admin/users/assign-role/', views.assign_user_role, name='assign_user_role'),
]

