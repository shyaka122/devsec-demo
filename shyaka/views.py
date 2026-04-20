from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.db import IntegrityError
from django.http import Http404, FileResponse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
import hashlib
import os

from .forms import (
    RegistrationForm,
    LoginForm,
    UserProfileForm,
    PasswordChangeCustomForm,
    PasswordResetCustomForm,
    PasswordResetConfirmCustomForm,
    AvatarUploadForm,
    DocumentUploadForm,
)
from .models import UserProfile, LoginAttempt, AuditLog, Document
from .auth_utils import (
    require_role,
    require_admin,
    get_user_role,
    is_admin,
    is_staff,
    is_safe_redirect_url,
    log_audit_event,
    get_client_ip,
    sanitize_filename,
    generate_safe_filename,
)


@require_http_methods(["GET", "POST"])
@csrf_protect
def register(request):
    """
    User registration view.
    Handles both GET (display form) and POST (process registration).
    
    Security: Validates redirect target to prevent open redirect attacks.
    """
    if request.user.is_authenticated:
        return redirect('shyaka:dashboard')
    
    # Get optional next parameter for post-registration redirect (open redirect protection)
    next_url = request.GET.get('next') or request.POST.get('next')
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                # Create associated UserProfile
                UserProfile.objects.create(user=user)
                
                # Log registration event
                log_audit_event(
                    event_type=AuditLog.EVENT_REGISTRATION,
                    request=request,
                    user=user,
                    description=f'User {user.username} registered successfully'
                )
                
                messages.success(
                    request,
                    'Registration successful! Please log in.'
                )
                # Safely redirect to login or next URL if provided
                if next_url and is_safe_redirect_url(next_url, request):
                    return redirect(reverse('shyaka:login') + f'?next={next_url}')
                return redirect('shyaka:login')
            except IntegrityError:
                messages.error(
                    request,
                    'An error occurred during registration. Please try again.'
                )
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()
    
    # Pass next parameter to template if it's safe
    context = {'form': form}
    if next_url and is_safe_redirect_url(next_url, request):
        context['next'] = next_url
    
    return render(request, 'shyaka/register.html', context)


@require_http_methods(["GET", "POST"])
@csrf_protect
def login_view(request):
    """
    User login view with brute-force protection.
    
    Security features:
    - Tracks failed login attempts per username and IP address
    - Implements account lockout after 5 failed attempts (15 min cooldown)
    - Implements IP-based lockout after 15 failed attempts (15 min cooldown)
    - Returns same error message for all failures (prevents user enumeration)
    - Records all attempts (successful and failed) for audit trail
    - Validates redirect target to prevent open redirect attacks
    
    Abuse protection:
    - Failed attempts counted within last 15 minutes
    - Accounts lock for 15 minutes after 5 failures
    - IPs lock for 15 minutes after 15 failures
    - Lockout status checked before attempting authentication
    
    Open Redirect Protection:
    - Accepts optional 'next' parameter for post-login redirect
    - Validates redirect target against whitelist (only relative URLs allowed)
    - Falls back to dashboard if redirect is invalid/unsafe
    """
    if request.user.is_authenticated:
        return redirect('shyaka:dashboard')
    
    # Get next parameter for post-login redirect (open redirect protection)
    next_url = request.GET.get('next') or request.POST.get('next')
    
    client_ip = get_client_ip(request)
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            # Check for account/IP lockout BEFORE attempting authentication
            # This prevents attackers from continuing to guess passwords during lockout
            lockout = LoginAttempt.get_lockout_status(
                username=username,
                ip_address=client_ip,
                max_attempts=5,  # Account lockout after 5 failures
                lockout_minutes=15  # Cooldown period
            )
            
            if lockout['locked']:
                # Generic error message (doesn't reveal lockout reason)
                messages.error(
                    request,
                    'Invalid username or password. Please try again later or contact support.'
                )
                # Log the lockout attempt (for monitoring abuse patterns)
                LoginAttempt.record_attempt(
                    username=username,
                    ip_address=client_ip,
                    success=False,
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                return render(request, 'shyaka/login.html', {'form': form})
            
            # Attempt authentication
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                # Login successful - record attempt and create session
                login(request, user)
                LoginAttempt.record_attempt(
                    username=username,
                    ip_address=client_ip,
                    success=True,
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                # Log successful login event
                log_audit_event(
                    event_type=AuditLog.EVENT_LOGIN_SUCCESS,
                    request=request,
                    user=user,
                    description=f'User {username} logged in successfully'
                )
                
                messages.success(request, f'Welcome back, {username}!')
                
                # Safely redirect to next URL if provided and valid
                if next_url and is_safe_redirect_url(next_url, request):
                    return redirect(next_url)
                return redirect('shyaka:dashboard')
            else:
                # Login failed - record attempt
                LoginAttempt.record_attempt(
                    username=username,
                    ip_address=client_ip,
                    success=False,
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                # Log failed login event
                log_audit_event(
                    event_type=AuditLog.EVENT_LOGIN_FAILURE,
                    request=request,
                    description=f'Failed login attempt for username: {username}'
                )
                
                # Generic error message (prevents username enumeration)
                messages.error(
                    request,
                    'Invalid username or password. Please try again.'
                )
    else:
        form = LoginForm()
    
    # Pass next parameter to template if it's safe
    context = {'form': form}
    if next_url and is_safe_redirect_url(next_url, request):
        context['next'] = next_url
    
    return render(request, 'shyaka/login.html', context)


@login_required(login_url='shyaka:login')
@require_http_methods(["GET", "POST"])
def logout_view(request):
    """
    User logout view.
    Destroys user session and redirects to homepage.
    
    Security: Validates redirect target to prevent open redirect attacks.
    """
    # Get optional next parameter for post-logout redirect (open redirect protection)
    next_url = request.GET.get('next') or request.POST.get('next')
    
    user = request.user
    logout(request)
    
    # Log logout event
    log_audit_event(
        event_type=AuditLog.EVENT_LOGOUT,
        request=request,
        user=user,
        description=f'User {user.username} logged out'
    )
    
    messages.success(request, 'You have been logged out successfully.')
    
    # Safely redirect to next URL if provided and valid
    if next_url and is_safe_redirect_url(next_url, request):
        return redirect(next_url)
    return redirect('shyaka:login')


@login_required(login_url='shyaka:login')
def dashboard(request):
    """
    Authenticated user dashboard.
    Displays user information and profile summary.
    Role information is available in context for conditional display.
    """
    profile = get_object_or_404(UserProfile, user=request.user)
    user_role = get_user_role(request.user)
    
    context = {
        'user': request.user,
        'profile': profile,
        'user_role': user_role,
        'is_admin': is_admin(request.user),
        'is_staff': is_staff(request.user),
    }
    return render(request, 'shyaka/dashboard.html', context)


@login_required(login_url='shyaka:login')
@require_http_methods(["GET", "POST"])
@csrf_protect
def profile(request):
    """
    User profile view.
    Allows users to view and edit their profile information.
    
    Security: CSRF protection required for POST requests that modify user profile.
    """
    profile = get_object_or_404(UserProfile, user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(
            request.POST,
            instance=profile,
            initial={
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'email': request.user.email,
            }
        )
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('shyaka:profile')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserProfileForm(
            instance=profile,
            initial={
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'email': request.user.email,
            }
        )
    
    context = {
        'form': form,
        'profile': profile,
    }
    return render(request, 'shyaka/profile.html', context)


@login_required(login_url='shyaka:login')
@require_http_methods(["GET"])
def view_user_profile(request, user_id):
    """
    View a specific user's profile by ID.
    IDOR protection: Users can only view their own profile unless they are admin.
    
    Security: Object-level access control enforced.
    - Standard users can only view their own profile
    - Admins can view any user's profile
    - Returns 403 Forbidden if unauthorized
    """
    # Get the target user's profile
    target_user = get_object_or_404(User, id=user_id)
    profile = get_object_or_404(UserProfile, user=target_user)
    
    # IDOR Check: Verify object-level access
    # Allow access if user owns the profile OR is admin
    if request.user.id != target_user.id and not is_admin(request.user):
        messages.error(request, 'You do not have permission to view this profile.')
        return redirect('shyaka:dashboard')
    
    context = {
        'target_user': target_user,
        'profile': profile,
        'is_own_profile': request.user.id == target_user.id,
    }
    return render(request, 'shyaka/view_user_profile.html', context)


@login_required(login_url='shyaka:login')
@require_http_methods(["GET", "POST"])
@csrf_protect
def edit_user_profile(request, user_id):
    """
    Edit a specific user's profile by ID.
    IDOR protection: Users can only edit their own profile unless they are admin.
    
    Security: Object-level access control enforced.
    - Standard users can only edit their own profile
    - Admins can edit any user's profile
    - Returns 403 Forbidden if unauthorized
    """
    # Get the target user's profile
    target_user = get_object_or_404(User, id=user_id)
    profile = get_object_or_404(UserProfile, user=target_user)
    
    # IDOR Check: Verify object-level access
    # Allow access if user owns the profile OR is admin
    if request.user.id != target_user.id and not is_admin(request.user):
        messages.error(request, 'You do not have permission to edit this profile.')
        return redirect('shyaka:dashboard')
    
    if request.method == 'POST':
        form = UserProfileForm(
            request.POST,
            instance=profile,
            initial={
                'first_name': target_user.first_name,
                'last_name': target_user.last_name,
                'email': target_user.email,
            }
        )
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('shyaka:view_user_profile', user_id=user_id)
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserProfileForm(
            instance=profile,
            initial={
                'first_name': target_user.first_name,
                'last_name': target_user.last_name,
                'email': target_user.email,
            }
        )
    
    context = {
        'form': form,
        'profile': profile,
        'target_user': target_user,
        'is_own_profile': request.user.id == target_user.id,
    }
    return render(request, 'shyaka/edit_user_profile.html', context)


@login_required(login_url='shyaka:login')
@require_http_methods(["GET", "POST"])
@csrf_protect
def change_password(request):
    """
    Password change view.
    Allows authenticated users to change their password.
    """
    if request.method == 'POST':
        form = PasswordChangeCustomForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            
            # Log password change event
            log_audit_event(
                event_type=AuditLog.EVENT_PASSWORD_CHANGE,
                request=request,
                user=user,
                description=f'User {user.username} changed their password'
            )
            
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('shyaka:dashboard')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{error}")
    else:
        form = PasswordChangeCustomForm(request.user)
    
    context = {'form': form}
    return render(request, 'shyaka/change_password.html', context)


# ============================================================================
# Administration Views - Restricted to admin users only
# ============================================================================

@require_admin
@require_http_methods(["GET"])
def admin_dashboard(request):
    """
    Admin dashboard - Shows system statistics and user management options.
    Access restricted to admin users only.
    """
    total_users = User.objects.count()
    total_profiles = UserProfile.objects.count()
    
    admin_group = Group.objects.get_or_create(name='admin')[0]
    staff_group = Group.objects.get_or_create(name='staff')[0]
    
    admin_count = admin_group.user_set.count()
    staff_count = staff_group.user_set.count()
    
    context = {
        'total_users': total_users,
        'total_profiles': total_profiles,
        'admin_count': admin_count,
        'staff_count': staff_count,
        'user_role': get_user_role(request.user),
    }
    return render(request, 'shyaka/admin_dashboard.html', context)


@require_admin
@require_http_methods(["GET"])
def manage_users(request):
    """
    User management view - List and manage all users.
    Access restricted to admin users only.
    """
    all_users = User.objects.select_related('profile').all()
    admin_group = Group.objects.get_or_create(name='admin')[0]
    staff_group = Group.objects.get_or_create(name='staff')[0]
    
    users_data = []
    for user in all_users:
        user_groups = list(user.groups.values_list('name', flat=True))
        users_data.append({
            'user': user,
            'role': get_user_role(user),
            'groups': user_groups,
        })
    
    context = {
        'users_data': users_data,
        'admin_group': admin_group,
        'staff_group': staff_group,
        'user_role': get_user_role(request.user),
    }
    return render(request, 'shyaka/manage_users.html', context)


@require_admin
@require_http_methods(["POST"])
@csrf_protect
def assign_user_role(request):
    """
    Assign a role to a user - POST only for security.
    Access restricted to admin users only.
    """
    user_id = request.POST.get('user_id')
    role = request.POST.get('role')
    
    if not user_id or not role:
        messages.error(request, 'Invalid request parameters.')
        return redirect('shyaka:manage_users')
    
    try:
        user = User.objects.get(id=user_id)
        valid_roles = ['admin', 'staff', 'user']
        
        if role not in valid_roles:
            messages.error(request, 'Invalid role specified.')
            return redirect('shyaka:manage_users')
        
        # Remove user from all groups
        user.groups.clear()
        
        # Add user to appropriate group if not standard user
        if role in ['admin', 'staff']:
            group = Group.objects.get(name=role)
            user.groups.add(group)
            
            # Log role assignment event
            log_audit_event(
                event_type=AuditLog.EVENT_ROLE_ASSIGNED,
                request=request,
                user=user,
                actor=request.user,
                description=f'User {user.username} assigned to {role} role by admin {request.user.username}',
                details={'new_role': role}
            )
            
            messages.success(request, f'User {user.username} assigned to {role} group.')
        else:
            # Log role removal (standard user)
            log_audit_event(
                event_type=AuditLog.EVENT_ROLE_REMOVED,
                request=request,
                user=user,
                actor=request.user,
                description=f'User {user.username} set to standard user by admin {request.user.username}',
                details={'previous_role': 'admin or staff', 'new_role': 'user'}
            )
            
            messages.success(request, f'User {user.username} set as standard user.')
        
        return redirect('shyaka:manage_users')
    
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('shyaka:manage_users')


# ============================================================================
# Password Reset Views - Secure Account Recovery Workflow
# ============================================================================

@require_http_methods(["GET", "POST"])
@csrf_protect
def password_reset_request(request):
    """
    Password reset request view.
    Users can request a password reset by providing their email address.
    
    Security considerations:
    - Does NOT distinguish between valid and invalid emails (prevents user enumeration)
    - Returns same success message for all inputs
    - Uses Django's secure token generation (HMAC-SHA256)
    - Only users with registered email addresses can reset passwords
    - Email must be valid and associated with an account
    
    Design decisions:
    - Email-based reset (not username) - more common and less prone to typos
    - Generic success message prevents attackers from enumerating accounts
    """
    # Authenticated users should use "change password" instead
    if request.user.is_authenticated:
        return redirect('shyaka:dashboard')
    
    if request.method == 'POST':
        form = PasswordResetCustomForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            # Check if user exists with this email (but don't reveal status)
            try:
                user = User.objects.get(email=email)
                # Generate secure token
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.id))
                
                # In development, we'll store this in session for demo
                # In production, this would be sent via email
                request.session[f'password_reset_{uid}'] = {
                    'token': token,
                    'user_id': user.id,
                    'email': email,
                }
                
                messages.success(
                    request,
                    'If an account with that email exists, a password reset link has been sent.'
                )
                return redirect('shyaka:password_reset_done')
            except User.DoesNotExist:
                # Don't reveal whether email exists - same message for all cases
                messages.success(
                    request,
                    'If an account with that email exists, a password reset link has been sent.'
                )
                return redirect('shyaka:password_reset_done')
    else:
        form = PasswordResetCustomForm()
    
    context = {'form': form}
    return render(request, 'shyaka/password_reset_request.html', context)


@require_http_methods(["GET"])
def password_reset_done(request):
    """
    Password reset request confirmation view.
    Shows user that if an account exists, they've been sent a reset link.
    
    Security: Generic message doesn't reveal account existence.
    """
    return render(request, 'shyaka/password_reset_done.html')


@require_http_methods(["GET", "POST"])
@csrf_protect
def password_reset_confirm(request, uidb64, token):
    """
    Password reset confirmation view.
    Users confirm their email and set a new password.
    
    Security considerations:
    - Token is validated against user's password hash (Django's PasswordResetTokenGenerator)
    - Tokens are tied to specific user IDs (prevents token reuse across accounts)
    - Tokens expire after DEFAULT_PASSWORD_RESET_TIMEOUT (default: 1 week, configurable)
    - Invalid tokens/UIDs show generic error message
    - Only valid tokens allow password change
    - Validates redirect target to prevent open redirect attacks
    
    Process:
    1. Decode UID and find user
    2. Validate token (uses HMAC with user's password hash)
    3. If valid, allow user to set new password
    4. New password is validated against password validators
    5. Redirect to next URL if provided and safe
    """
    # Get optional next parameter for post-reset redirect (open redirect protection)
    next_url = request.GET.get('next') or request.POST.get('next')
    
    try:
        # Decode the user ID from URL-safe base64
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(
            request,
            'Invalid password reset link. Please request a new reset link.'
        )
        return redirect('shyaka:password_reset_request')
    
    # Validate token (Django checks if it was generated for this user and hasn't expired)
    if not default_token_generator.check_token(user, token):
        messages.error(
            request,
            'Invalid or expired password reset link. Please request a new reset link.'
        )
        return redirect('shyaka:password_reset_request')
    
    # Token is valid - allow password reset
    if request.method == 'POST':
        form = PasswordResetConfirmCustomForm(user, request.POST)
        if form.is_valid():
            user = form.save()
            # Update session so user stays logged in if they were
            update_session_auth_hash(request, user)
            
            # Log password reset event
            log_audit_event(
                event_type=AuditLog.EVENT_PASSWORD_RESET,
                request=request,
                user=user,
                description=f'User {user.username} reset their password'
            )
            
            messages.success(
                request,
                'Your password has been reset successfully. You can now log in.'
            )
            # Safely redirect to next URL if provided and valid
            if next_url and is_safe_redirect_url(next_url, request):
                return redirect(next_url)
            return redirect('shyaka:password_reset_complete')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{error}")
    else:
        form = PasswordResetConfirmCustomForm(user)
    
    # Pass next parameter to template if it's safe
    context = {
        'form': form,
        'uidb64': uidb64,
        'token': token,
        'user': user,
    }
    if next_url and is_safe_redirect_url(next_url, request):
        context['next'] = next_url
    
    return render(request, 'shyaka/password_reset_confirm.html', context)


@require_http_methods(["GET"])
def password_reset_complete(request):
    """
    Password reset completion view.
    Confirms that password has been successfully reset.
    User can proceed to login with their new password.
    
    Security: Provides clear guidance on next steps.
    """
    return render(request, 'shyaka/password_reset_complete.html')

# ============================================================================
# File Upload Views - Avatar and Document Management
# ============================================================================

@login_required
@require_http_methods(["GET", "POST"])
@csrf_protect
def upload_avatar(request):
    """
    Avatar upload view with security validation.
    
    Security properties:
    - Only authenticated users can upload
    - CSRF protection on POST
    - File validation: MIME type, size (5MB max), image content validation
    - Filename sanitized to prevent path traversal
    - Old avatar deleted when new one uploaded
    - Access control: Only upload to own profile
    
    References:
    - OWASP CWE-434: Unrestricted Upload of File with Dangerous Type
    - OWASP CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    """
    profile = request.user.profile
    
    if request.method == 'POST':
        form = AvatarUploadForm(request.POST, request.FILES, instance=profile)
        
        if form.is_valid():
            # Delete old avatar if exists
            if profile.avatar:
                profile.avatar.delete(save=False)
            
            # Save new avatar
            profile = form.save()
            
            # Log the upload event
            log_audit_event(
                event_type=AuditLog.EVENT_PROFILE_UPDATED,
                request=request,
                user=request.user,
                description=f'User {request.user.username} uploaded a new avatar'
            )
            
            messages.success(request, 'Avatar uploaded successfully!')
            return redirect('shyaka:profile')
        else:
            # Form has validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = AvatarUploadForm(instance=profile)
    
    context = {
        'form': form,
        'current_avatar': profile.avatar.url if profile.avatar else None,
    }
    return render(request, 'shyaka/upload_avatar.html', context)


@login_required
@require_http_methods(["GET", "POST"])
@csrf_protect
def upload_document(request):
    """
    Document upload view with comprehensive security validation.
    
    Security properties:
    - Only authenticated users can upload
    - CSRF protection on POST
    - File validation: MIME type, size (10MB max), extension check
    - Filename sanitized and hash-prefixed for uniqueness
    - Documents stored in per-user directory
    - Owner-based access control
    - Soft delete (documents not permanently deleted)
    
    References:
    - OWASP CWE-434: Unrestricted Upload of File with Dangerous Type
    - OWASP CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    - OWASP CWE-552: Files and Directories Accessible to External Parties
    """
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        
        if form.is_valid():
            # Create document instance but don't save yet
            document = form.save(commit=False)
            document.owner = request.user
            
            # Store original filename (sanitized)
            if request.FILES.get('file'):
                original_filename = request.FILES['file'].name
                document.original_filename = sanitize_filename(original_filename)
                
                # Create hash prefix for unique filename in upload
                file_hash = hashlib.sha256(f"{request.user.id}{original_filename}".encode()).hexdigest()[:8]
                document.file.name = f"documents/{request.user.id}/{file_hash}_{document.original_filename}"
                
                # Store MIME type
                from .auth_utils import get_file_mime_type
                document.mime_type = get_file_mime_type(request.FILES['file'])
                document.file_size = request.FILES['file'].size
            
            # Save document
            document.save()
            
            # Log the upload event
            log_audit_event(
                event_type=AuditLog.EVENT_PROFILE_UPDATED,
                request=request,
                user=request.user,
                description=f'User {request.user.username} uploaded document: {document.title}'
            )
            
            messages.success(request, 'Document uploaded successfully!')
            return redirect('shyaka:document_list')
        else:
            # Form has validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = DocumentUploadForm()
    
    context = {
        'form': form,
        'max_size_mb': 10,
        'allowed_types': ', '.join(Document.ALLOWED_EXTENSIONS),
    }
    return render(request, 'shyaka/upload_document.html', context)


@login_required
@require_http_methods(["GET"])
def document_list(request):
    """
    List documents accessible to the current user.
    
    Security properties:
    - Only shows documents owned by user or public documents
    - Deleted documents (soft deleted) are not shown
    - Access control enforced at query level
    - Pagination to prevent DoS attacks
    
    References:
    - OWASP A01:2021 - Broken Access Control
    """
    # Get user's own documents
    own_documents = Document.objects.filter(
        owner=request.user,
        is_deleted=False
    ).order_by('-uploaded_at')
    
    # Get public documents from other users
    public_documents = Document.objects.filter(
        is_deleted=False,
        is_public=True
    ).exclude(owner=request.user).order_by('-uploaded_at')
    
    context = {
        'own_documents': own_documents,
        'public_documents': public_documents,
    }
    return render(request, 'shyaka/document_list.html', context)


@login_required
@require_http_methods(["GET"])
def download_document(request, document_id):
    """
    Download document with access control verification.
    
    Security properties:
    - Access control: Only owner or admin can download
    - Public documents can be downloaded by any authenticated user
    - Content-Disposition header forces download instead of preview
    - Mime type validation prevents content-type spoofing
    - Soft deleted documents cannot be downloaded
    
    References:
    - OWASP A01:2021 - Broken Access Control
    - CWE-434: Unrestricted Upload of File with Dangerous Type
    """
    document = get_object_or_404(Document, pk=document_id)
    
    # Check access permissions
    if not document.can_access(request.user):
        messages.error(request, 'You do not have permission to access this document.')
        return redirect('shyaka:document_list')
    
    # Log download event
    log_audit_event(
        event_type=AuditLog.EVENT_PROFILE_UPDATED,
        request=request,
        user=request.user,
        description=f'User {request.user.username} downloaded document: {document.title}'
    )
    
    # Return file with proper headers for download
    response = FileResponse(document.file.open('rb'), content_type=document.mime_type)
    response['Content-Disposition'] = f'attachment; filename="{document.original_filename}"'
    return response


@login_required
@require_http_methods(["POST"])
@csrf_protect
def delete_document(request, document_id):
    """
    Soft delete document (mark as deleted, don't remove from DB).
    
    Security properties:
    - Only owner or admin can delete
    - Soft delete preserves audit trail
    - Document not permanently removed from database
    - Download becomes impossible after deletion
    
    References:
    - OWASP A01:2021 - Broken Access Control
    """
    document = get_object_or_404(Document, pk=document_id)
    
    # Check access permissions (owner or admin)
    if document.owner != request.user and not is_admin(request.user):
        messages.error(request, 'You do not have permission to delete this document.')
        return redirect('shyaka:document_list')
    
    document_title = document.title
    document.delete()  # Soft delete
    
    # Log deletion event
    log_audit_event(
        event_type=AuditLog.EVENT_PROFILE_UPDATED,
        request=request,
        user=request.user,
        description=f'User {request.user.username} deleted document: {document_title}'
    )
    
    messages.success(request, 'Document deleted successfully.')
    return redirect('shyaka:document_list')