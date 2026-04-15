from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.db import IntegrityError

from .forms import (
    RegistrationForm,
    LoginForm,
    UserProfileForm,
    PasswordChangeCustomForm
)
from .models import UserProfile
from .auth_utils import (
    require_role,
    require_admin,
    get_user_role,
    is_admin,
    is_staff,
)


@require_http_methods(["GET", "POST"])
@csrf_protect
def register(request):
    """
    User registration view.
    Handles both GET (display form) and POST (process registration).
    """
    if request.user.is_authenticated:
        return redirect('shyaka:dashboard')
    
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
    
    return render(request, 'shyaka/register.html', {'form': form})


@require_http_methods(["GET", "POST"])
@csrf_protect
def login_view(request):
    """
    User login view.
    Authenticates user credentials and creates session.
    """
    if request.user.is_authenticated:
        return redirect('shyaka:dashboard')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect('shyaka:dashboard')
            else:
                messages.error(
                    request,
                    'Invalid username or password. Please try again.'
                )
    else:
        form = LoginForm()
    
    return render(request, 'shyaka/login.html', {'form': form})


@login_required(login_url='shyaka:login')
@require_http_methods(["GET", "POST"])
def logout_view(request):
    """
    User logout view.
    Destroys user session and redirects to homepage.
    """
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
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
def profile(request):
    """
    User profile view.
    Allows users to view and edit their profile information.
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
