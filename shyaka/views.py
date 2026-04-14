from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
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
    """
    profile = get_object_or_404(UserProfile, user=request.user)
    context = {
        'user': request.user,
        'profile': profile,
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
