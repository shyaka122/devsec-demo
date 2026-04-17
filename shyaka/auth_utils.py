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
    
    Uses Django's url_has_allowed_host_and_scheme utility to validate redirect targets.
    
    Security checks:
    - Rejects protocol-relative URLs (//evil.com/malware) - can bypass HTTPS
    - Rejects absolute URLs with external hosts (prevents redirect to attacker's site)
    - Rejects non-HTTP(S) schemes like javascript:, data:, etc.
    - Only allows relative URLs (e.g., /profile/, /dashboard/) by default
    - Validates against ALLOWED_HOSTS from Django settings for absolute URLs
    
    Args:
        url (str): The URL to validate for redirect safety
        request (HttpRequest, optional): Current request object (for host validation)
        allowed_relative_hosts (list, optional): Additional hosts to allow (legacy param)
    
    Returns:
        bool: True if URL is safe to redirect to, False otherwise
    
    Examples:
        is_safe_redirect_url('/dashboard/')  # True - relative URL
        is_safe_redirect_url('//evil.com')   # False - protocol-relative
        is_safe_redirect_url('http://evil.com')  # False - external host
        is_safe_redirect_url('javascript:alert(1)')  # False - invalid scheme
        is_safe_redirect_url('data:text/html,<script>')  # False - invalid scheme
    
    Security Design:
    - Relative URLs are always safe (redirected within same origin)
    - Absolute URLs must match current request host OR be in ALLOWED_HOSTS
    - This prevents attackers from chaining open redirects with other attacks
    - Uses Django's standard approach from django.utils.http
    """
    if not url:
        return False
    
    # Reject protocol-relative URLs immediately
    # These can bypass HTTPS/HTTP scheme validation
    if url.startswith('//'):
        return False
    
    # Use Django's built-in validation for URLs with schemes
    # This validates both HTTP(S) URLs and rejects dangerous schemes
    from django.utils.http import url_has_allowed_host_and_scheme
    
    # Build list of allowed hosts
    allowed_hosts = []
    
    # Add current request host if available
    if request:
        allowed_hosts.append(request.get_host())
    
    # Add any explicitly allowed hosts
    if allowed_relative_hosts:
        allowed_hosts.extend(allowed_relative_hosts)
    
    # For relative URLs (starting with /), they're always safe
    # They're served from the same origin
    if url.startswith('/'):
        return True
    
    # For absolute URLs, use Django's standard validation
    # This checks scheme (only http/https allowed) and host validation
    if url.startswith('http://') or url.startswith('https://'):
        # Use Django's utility with our allowed hosts
        # If no allowed hosts specified, require request for validation
        if not allowed_hosts:
            return False
        return url_has_allowed_host_and_scheme(url, allowed_hosts=allowed_hosts)
    
    # Reject any other URLs (javascript:, data:, etc.)
    return False
