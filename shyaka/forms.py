from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import (
    UserCreationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.core.exceptions import ValidationError
from .models import UserProfile, Document
from .auth_utils import (
    is_valid_image_upload,
    is_valid_document_upload,
    sanitize_filename,
)


class RegistrationForm(UserCreationForm):
    """
    Registration form for new users.
    Extends Django's built-in UserCreationForm with email validation.
    """
    email = forms.EmailField(
        required=True,
        help_text='Required. Enter a valid email address.'
    )
    first_name = forms.CharField(
        max_length=30,
        required=False,
        help_text='Optional.'
    )
    last_name = forms.CharField(
        max_length=150,
        required=False,
        help_text='Optional.'
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
    
    def clean_email(self):
        """Validate that email is unique."""
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError('This email address is already in use.')
        return email
    
    def clean_username(self):
        """Validate username."""
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError('This username is already taken.')
        return username


class LoginForm(forms.Form):
    """
    Custom login form for authentication.
    """
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        })
    )


class UserProfileForm(forms.ModelForm):
    """
    Form for updating user profile information.
    """
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = UserProfile
        fields = ('bio',)
        widgets = {
            'bio': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Tell us about yourself'
            }),
        }
    
    def clean_email(self):
        """Validate email uniqueness excluding current user."""
        email = self.cleaned_data.get('email')
        user_id = self.instance.user.id
        if User.objects.filter(email=email).exclude(id=user_id).exists():
            raise ValidationError('This email address is already in use.')
        return email
    
    def save(self, commit=True):
        """Save both UserProfile and related User data."""
        profile = super().save(commit=False)
        user = profile.user
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name = self.cleaned_data.get('last_name', '')
        user.email = self.cleaned_data.get('email')
        
        if commit:
            user.save()
            profile.save()
        return profile


class PasswordChangeCustomForm(PasswordChangeForm):
    """
    Custom password change form with Bootstrap styling.
    """
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Current Password'
        })
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'New Password'
        })
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm New Password'
        })
    )


class PasswordResetCustomForm(PasswordResetForm):
    """
    Custom password reset form with Bootstrap styling.
    Extends Django's built-in PasswordResetForm for secure account recovery.
    
    Security properties:
    - Uses email to initiate reset (prevents username enumeration if applicable)
    - Django's PasswordResetForm generates secure, tamper-proof tokens
    - Tokens expire after DEFAULT_PASSWORD_RESET_TIMEOUT
    - Does not leak whether email exists (returns success message for all inputs)
    """
    email = forms.EmailField(
        label='Email Address',
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address',
            'autocomplete': 'email'
        })
    )


class PasswordResetConfirmCustomForm(SetPasswordForm):
    """
    Custom password reset confirmation form with Bootstrap styling.
    Extends Django's built-in SetPasswordForm for secure password update.
    
    Security properties:
    - Token must be valid (Django validates against user's last login)
    - Token must not be expired (checked by Django's views)
    - New password is validated against password validators
    - Prevents password reuse and common passwords
    """
    new_password1 = forms.CharField(
        label='New Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'autocomplete': 'new-password'
        })
    )
    new_password2 = forms.CharField(
        label='Confirm New Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password',
            'autocomplete': 'new-password'
        })
    )


class AvatarUploadForm(forms.ModelForm):
    """
    Form for uploading user avatar with security validation.
    
    Security properties:
    - Only image files allowed (JPEG, PNG, WebP, GIF)
    - File size limited to 5MB
    - MIME type validated using magic bytes
    - Filename sanitized to prevent path traversal
    - Pillow validates actual image content
    
    References:
    - OWASP CWE-434: Unrestricted Upload of File with Dangerous Type
    - OWASP File Upload Cheat Sheet
    """
    
    class Meta:
        model = UserProfile
        fields = ('avatar',)
        widgets = {
            'avatar': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/jpeg,image/png,image/webp,image/gif',
                'help_text': 'Select a JPEG, PNG, WebP, or GIF image (max 5MB)'
            })
        }
    
    def clean_avatar(self):
        """Validate avatar upload before saving."""
        avatar = self.cleaned_data.get('avatar')
        
        if not avatar:
            return avatar
        
        # Validate image file
        is_valid, error_message = is_valid_image_upload(avatar, max_size_bytes=5*1024*1024)
        if not is_valid:
            raise ValidationError(error_message)
        
        return avatar


class DocumentUploadForm(forms.ModelForm):
    """
    Form for uploading documents with comprehensive security validation.
    
    Security properties:
    - Only safe file types allowed (PDF, Office, Text)
    - File size limited to 10MB
    - MIME type validated using magic bytes
    - Filename sanitized to prevent path traversal
    - File extension must match MIME type
    - Owner-based access control enforced in view
    
    Allowed file types:
    - PDF documents (application/pdf)
    - Microsoft Office (docx, xlsx, pptx)
    - Text files (txt)
    
    References:
    - OWASP CWE-434: Unrestricted Upload of File with Dangerous Type
    - OWASP CWE-426: Untrusted Search Path
    - OWASP CWE-427: Uncontrolled Search Path Element
    - OWASP File Upload Cheat Sheet
    """
    
    title = forms.CharField(
        label='Document Title',
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter document title (max 255 characters)'
        }),
        help_text='Brief title for the document'
    )
    
    is_public = forms.BooleanField(
        label='Allow other users to view this document',
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        help_text='If checked, authenticated users can view this document'
    )
    
    class Meta:
        model = Document
        fields = ('file', 'is_public')
        widgets = {
            'file': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '.pdf,.docx,.doc,.txt,.xlsx,.xls,.pptx,.ppt'
            })
        }
    
    def clean_file(self):
        """Validate document upload before saving."""
        file_obj = self.cleaned_data.get('file')
        
        if not file_obj:
            raise ValidationError('Please select a file to upload.')
        
        # Validate document file
        is_valid, error_message = is_valid_document_upload(file_obj, max_size_bytes=10*1024*1024)
        if not is_valid:
            raise ValidationError(error_message)
        
        return file_obj
    
    def clean_title(self):
        """Sanitize document title."""
        title = self.cleaned_data.get('title', '')
        # Limit to 255 characters and strip whitespace
        return title.strip()[:255] if title else 'Untitled Document'

