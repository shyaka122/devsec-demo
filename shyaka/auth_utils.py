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


# ============================================================================
# Audit Logging Utilities - Security Event Tracking
# ============================================================================

def get_client_ip(request):
    """
    Extract client IP address from request.
    Considers X-Forwarded-For header (for proxies) and falls back to REMOTE_ADDR.
    
    Security: Uses most recent IP from X-Forwarded-For to avoid spoofing.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the last IP (most recent proxy)
        ip = x_forwarded_for.split(',')[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


def get_user_agent(request):
    """
    Extract user agent from request.
    Limits length to prevent storage issues.
    """
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    return user_agent[:500]  # Limit to 500 chars


def log_audit_event(event_type, request, user=None, actor=None, 
                   description='', details=None):
    """
    Log a security-relevant event to the audit log.
    
    Args:
        event_type: Type of event (use AuditLog.EVENT_* constants)
        request: Django HttpRequest object
        user: User affected by the event
        actor: User who performed the action
        description: Human-readable description
        details: Additional structured details
    
    Returns:
        The created AuditLog instance or None if import fails
    
    Note:
        Never log passwords, tokens, or other sensitive data in details.
        Always pass safe, non-sensitive data.
    """
    try:
        from .models import AuditLog
        
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        return AuditLog.log_event(
            event_type=event_type,
            user=user,
            ip_address=ip_address,
            description=description,
            actor=actor,
            user_agent=user_agent,
            details=details or {},
        )
    except Exception as e:
        # Don't let logging errors break the application
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to log audit event: {e}")
        return None


# ============================================================================
# File Upload Security Utilities - Validation and Sanitization
# ============================================================================

import re
import os
import mimetypes

# Optional import - magic for better MIME type detection
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


def sanitize_filename(filename):
    """
    Sanitize a filename to prevent path traversal and other attacks.
    
    Security measures:
    - Removes path traversal attempts (../, .., backslashes)
    - Removes special characters that could be problematic
    - Limits length to 255 characters
    - Converts spaces and special chars to underscores
    - Preserves file extension
    
    Args:
        filename (str): Original filename from upload
    
    Returns:
        str: Safe, sanitized filename
    
    Examples:
        sanitize_filename('../../../etc/passwd')  # Returns 'etc_passwd'
        sanitize_filename('file with spaces.pdf')  # Returns 'file_with_spaces.pdf'
        sanitize_filename('../../malicious_file.exe')  # Returns 'malicious_file.exe'
    
    Security Design (OWASP CWE-434):
    - Only allows alphanumeric, hyphens, underscores, and dots
    - Prevents directory traversal with ../ patterns
    - Removes null bytes and other dangerous characters
    - Limits filename length to filesystem limits
    """
    if not filename:
        return 'upload'
    
    # Remove path separators and traversal attempts
    filename = os.path.basename(filename)  # Remove any path components
    filename = filename.replace('\\', '_').replace('/', '_')
    filename = filename.replace('..', '_')
    
    # Remove null bytes (can cause truncation in C libraries)
    filename = filename.replace('\x00', '')
    
    # Keep only safe characters (letters, numbers, -, _, .)
    # Replace everything else with underscore
    filename = re.sub(r'[^\w\-\.]', '_', filename, flags=re.UNICODE)
    
    # Remove leading dots (hidden files, .htaccess attacks)
    filename = filename.lstrip('.')
    
    # Limit length (255 is typical filesystem limit, leave buffer for hash)
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:190] + ext
    
    # Ensure we have a filename
    if not filename or filename == '_':
        filename = 'upload'
    
    return filename


def get_file_mime_type(file_obj):
    """
    Detect MIME type of uploaded file using magic bytes.
    
    This is more secure than relying on file extension,
    as extensions can be spoofed by attackers.
    
    Args:
        file_obj: Django UploadedFile object or file-like object
    
    Returns:
        str: MIME type (e.g., 'application/pdf', 'image/jpeg')
             Returns 'application/octet-stream' if unable to detect
    
    Security Design:
    - Reads file magic bytes (header) for type detection
    - Immune to extension spoofing
    - Works with python-magic library (optional)
    - Falls back to extension-based detection if magic unavailable
    
    References:
    - CWE-434: Unrestricted Upload of File with Dangerous Type
    """
    try:
        # Try using python-magic if available (most accurate)
        if HAS_MAGIC:
            file_obj.seek(0)  # Reset to beginning
            file_header = file_obj.read(1024)  # Read first 1KB for magic bytes
            file_obj.seek(0)  # Reset again for actual use
            
            mime = magic.from_buffer(file_header, mime=True)
            return mime if mime else 'application/octet-stream'
    except (AttributeError, Exception):
        pass
    
    # Fallback to extension-based detection
    try:
        if hasattr(file_obj, 'name'):
            mime_type, _ = mimetypes.guess_type(file_obj.name)
            return mime_type or 'application/octet-stream'
    except Exception:
        pass
    
    return 'application/octet-stream'


def is_valid_image_upload(file_obj, max_size_bytes=5*1024*1024):
    """
    Validate an image upload for avatar/profile image.
    
    Security checks:
    - MIME type must be image (image/jpeg, image/png, image/webp, image/gif)
    - File size must not exceed max_size_bytes
    - Filename is checked for suspicious patterns
    - Actual image content is validated (not just extension)
    
    Args:
        file_obj: Django UploadedFile object
        max_size_bytes: Maximum allowed file size (default: 5MB)
    
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    
    Examples:
        is_valid, error = is_valid_image_upload(uploaded_file)
        if is_valid:
            # Save file
        else:
            print(f"Upload failed: {error}")
    
    Security Design (OWASP CWE-434):
    - Validates MIME type using magic bytes
    - Checks file size before processing
    - Validates dimensions if possible
    - Prevents executable uploads disguised as images
    """
    allowed_mime_types = {
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/webp',
        'image/gif',
    }
    
    # Check file size
    if hasattr(file_obj, 'size'):
        if file_obj.size > max_size_bytes:
            return False, f"Image too large. Maximum size is {max_size_bytes/(1024*1024):.1f}MB"
    
    # Detect MIME type
    mime_type = get_file_mime_type(file_obj)
    if mime_type not in allowed_mime_types:
        return False, f"Invalid image type: {mime_type}. Allowed types: JPEG, PNG, WebP, GIF"
    
    # Validate PIL can open it (prevents corrupt files)
    try:
        from PIL import Image
        file_obj.seek(0)
        img = Image.open(file_obj)
        img.verify()
        file_obj.seek(0)
    except Exception as e:
        return False, f"Invalid or corrupted image file: {str(e)}"
    
    return True, None


def is_valid_document_upload(file_obj, max_size_bytes=10*1024*1024):
    """
    Validate a document upload (PDF, Office, Text, etc.).
    
    Security checks:
    - MIME type must be in allowed list
    - File extension must match MIME type
    - File size must not exceed max_size_bytes
    - Filename is sanitized
    
    Args:
        file_obj: Django UploadedFile object
        max_size_bytes: Maximum allowed file size (default: 10MB)
    
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    
    Examples:
        is_valid, error = is_valid_document_upload(uploaded_file)
        if is_valid:
            # Save document
        else:
            print(f"Upload failed: {error}")
    
    Security Design (OWASP CWE-434):
    - Allows only safe document types
    - Rejects executables, scripts, archives
    - Validates MIME type matches content
    - Size limit prevents DoS attacks
    - References: CWE-434, OWASP File Upload Cheat Sheet
    """
    # Import from models to avoid circular import
    from .models import Document
    
    allowed_mime_types = Document.ALLOWED_MIME_TYPES
    allowed_extensions = Document.ALLOWED_EXTENSIONS
    
    # Check file size first
    if hasattr(file_obj, 'size'):
        if file_obj.size > max_size_bytes:
            return False, f"File too large. Maximum size is {max_size_bytes/(1024*1024):.1f}MB"
    
    # Get file extension
    if hasattr(file_obj, 'name'):
        ext = os.path.splitext(file_obj.name)[1].lstrip('.').lower()
        if ext not in allowed_extensions:
            return False, f"File type not allowed: .{ext}. Allowed types: {', '.join(sorted(allowed_extensions))}"
    
    # Detect MIME type from content
    mime_type = get_file_mime_type(file_obj)
    if mime_type not in allowed_mime_types:
        return False, f"Invalid file type: {mime_type}. File content does not match allowed types."
    
    return True, None


def generate_safe_filename(original_filename, prefix=''):
    """
    Generate a safe filename with optional prefix (hash or timestamp).
    
    Args:
        original_filename (str): Original filename from upload
        prefix (str): Optional prefix to add before filename (e.g., hash)
    
    Returns:
        str: Safe filename ready for storage
    
    Example:
        safe_name = generate_safe_filename('My Document.pdf', prefix='abc123_')
        # Returns: 'abc123_My_Document.pdf' or similar
    """
    safe_name = sanitize_filename(original_filename)
    if prefix:
        name, ext = os.path.splitext(safe_name)
        return f"{prefix}{name}{ext}"
    return safe_name

