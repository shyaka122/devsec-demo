from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.db import IntegrityError
from django.http import Http404
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from .forms import (
    RegistrationForm,
    LoginForm,
    UserProfileForm,
    PasswordChangeCustomForm,
    PasswordResetCustomForm,
    PasswordResetConfirmCustomForm,
)
from .models import UserProfile, LoginAttempt
from .auth_utils import (
    require_role,
    require_admin,
    get_user_role,
    is_admin,
    is_staff,
    is_safe_redirect_url,
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
                messages.success(
                    request,
                    'Registration successful! Please log in.'
                )
                # Safely redirect to login or next URL if provided
                if next_url and is_safe_redirect_url(next_url, request):
                    return redirect(f'shyaka:login?next={next_url}')
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




def get_client_ip(request):
    """
    Extract client IP address from request.
    Considers X-Forwarded-For header (for proxies) and falls back to REMOTE_ADDR.
    
    Security: Uses most recent IP from X-Forwarded-For to avoid spoofing via chain padding.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the last IP (most recent proxy)
        ip = x_forwarded_for.split(',')[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


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
    
    logout(request)
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
            messages.success(request, f'User {user.username} assigned to {role} group.')
        else:
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
