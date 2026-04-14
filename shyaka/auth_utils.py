"""
Authorization utilities for role-based access control.
Provides decorators and helper functions for enforcing authorization rules.
"""

from functools import wraps
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.contrib import messages


def get_user_role(user):
    """
    Determine the role of a user based on group membership.
    
    Returns:
        str: One of 'admin', 'staff', 'user', or 'anonymous'
    """
    if not user.is_authenticated:
        return 'anonymous'
    
    if user.is_superuser or user.groups.filter(name='admin').exists():
        return 'admin'
    
    if user.is_staff or user.groups.filter(name='staff').exists():
        return 'staff'
    
    return 'user'


def is_admin(user):
    """Check if user has admin role."""
    return get_user_role(user) == 'admin'


def is_staff(user):
    """Check if user has staff role."""
    return get_user_role(user) in ('admin', 'staff')


def is_authenticated_user(user):
    """Check if user is authenticated (any non-anonymous user)."""
    return user.is_authenticated


def require_role(*allowed_roles):
    """
    Decorator to restrict view access to users with specific roles.
    
    Args:
        allowed_roles: Variable length argument list of role names
                      ('admin', 'staff', 'user', 'anonymous')
    
    Example:
        @require_role('admin', 'staff')
        def admin_view(request):
            pass
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user_role = get_user_role(request.user)
            
            if user_role not in allowed_roles:
                if user_role == 'anonymous':
                    messages.error(request, 'You must be logged in to access this page.')
                    return redirect('shyaka:login')
                else:
                    messages.error(request, 'You do not have permission to access this page.')
                    return HttpResponseForbidden('Access Denied')
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_admin(view_func):
    """Decorator to restrict view access to admin users only."""
    @wraps(view_func)
    @login_required(login_url='shyaka:login')
    def wrapper(request, *args, **kwargs):
        if not is_admin(request.user):
            messages.error(request, 'Only administrators can access this area.')
            return HttpResponseForbidden('Access Denied')
        return view_func(request, *args, **kwargs)
    
    return wrapper


def require_staff(view_func):
    """Decorator to restrict view access to staff and admin users."""
    @wraps(view_func)
    @login_required(login_url='shyaka:login')
    def wrapper(request, *args, **kwargs):
        if not is_staff(request.user):
            messages.error(request, 'Only staff and administrators can access this area.')
            return HttpResponseForbidden('Access Denied')
        return view_func(request, *args, **kwargs)
    
    return wrapper
