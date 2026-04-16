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


def is_safe_redirect_url(url, request=None, allowed_relative_hosts=None):
    """
    Validate that a redirect URL is safe and not an open redirect attack.
    
    Security checks:
    - Rejects absolute URLs with external hosts (prevents redirect to attacker's site)
    - Only allows relative URLs (e.g., /profile/, /dashboard/)
    - Prevents protocol-relative URLs (e.g., //evil.com/malware)
    - Allows internal HTTPS/HTTP URLs if explicit host is whitelisted
    
    Args:
        url (str): The URL to validate
        request (HttpRequest, optional): Current request object (for getting current host)
        allowed_relative_hosts (list, optional): List of allowed hosts for absolute URLs
    
    Returns:
        bool: True if URL is safe to redirect to, False otherwise
    
    Examples:
        is_safe_redirect_url('/dashboard/')  # True - relative URL
        is_safe_redirect_url('//evil.com')   # False - protocol-relative
        is_safe_redirect_url('http://evil.com')  # False - external host
        is_safe_redirect_url('http://localhost/profile/')  # May be True (if whitelisted)
    """
    if not url:
        return False
    
    # URL should start with / for relative URLs or be valid scheme+host for same-origin
    # Reject protocol-relative URLs (//example.com/path)
    if url.startswith('//'):
        return False
    
    # Check for absolute URLs with external hosts
    if url.startswith('http://') or url.startswith('https://'):
        # For absolute URLs, we need to validate the host
        from urllib.parse import urlparse
        parsed = urlparse(url)
        parsed_host = parsed.netloc
        
        # If request provided, compare with current host
        if request:
            current_host = request.get_host()
            if parsed_host != current_host:
                return False  # Different host
        
        # If allowed hosts provided, check against whitelist
        if allowed_relative_hosts:
            if parsed_host not in allowed_relative_hosts:
                return False
        
        # If no request and no whitelist, reject absolute URLs (be conservative)
        if not request and not allowed_relative_hosts:
            return False
    
    # Relative URLs starting with / are safe
    # (They'll be served from same origin)
    if url.startswith('/'):
        return True
    
    # Allow named URL references (for link generation)
    # But reject anything else
    return False
