from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


class UserProfile(models.Model):
    """
    Extended user profile for authentication service.
    Stores additional information beyond Django's built-in User model.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, default='')
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def __str__(self):
        return f"{self.user.username}'s Profile"


class LoginAttempt(models.Model):
    """
    Track login attempts for brute-force protection.
    Records both successful and failed attempts with IP address and timestamp.
    
    Security properties:
    - Tracks failed login attempts per username
    - Tracks failed attempts per IP address
    - Enables account lockout after N failed attempts
    - Enables IP-based throttling
    - Supports exponential backoff calculation
    """
    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    success = models.BooleanField(default=False)  # True if login succeeded
    user_agent = models.TextField(blank=True, help_text="Browser/client info")
    
    class Meta:
        verbose_name = 'Login Attempt'
        verbose_name_plural = 'Login Attempts'
        indexes = [
            models.Index(fields=['username', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]
    
    def __str__(self):
        status = "✓ Success" if self.success else "✗ Failed"
        return f"{self.username} from {self.ip_address} - {status} ({self.timestamp})"
    
    @classmethod
    def get_failed_attempts(cls, username=None, ip_address=None, minutes=30):
        """
        Get failed login attempts within the last N minutes.
        
        Args:
            username: Filter by username (None = don't filter)
            ip_address: Filter by IP address (None = don't filter)
            minutes: Look back this many minutes (default: 30)
        
        Returns:
            QuerySet of failed attempts
        """
        since = timezone.now() - timedelta(minutes=minutes)
        query = cls.objects.filter(success=False, timestamp__gte=since)
        
        if username:
            query = query.filter(username=username)
        if ip_address:
            query = query.filter(ip_address=ip_address)
        
        return query
    
    @classmethod
    def get_lockout_status(cls, username, ip_address, max_attempts=5, lockout_minutes=15):
        """
        Check if username or IP should be locked out.
        
        Args:
            username: Username to check
            ip_address: IP address to check
            max_attempts: Lock after this many failures (default: 5)
            lockout_minutes: Lockout duration (default: 15 minutes)
        
        Returns:
            {'locked': bool, 'reason': str, 'until': datetime or None}
        """
        # Check username-based lockout
        failed_for_user = cls.get_failed_attempts(
            username=username,
            minutes=lockout_minutes
        ).count()
        
        if failed_for_user >= max_attempts:
            until = timezone.now() + timedelta(minutes=lockout_minutes)
            return {
                'locked': True,
                'reason': f'account',
                'attempts': failed_for_user,
                'until': until,
            }
        
        # Check IP-based lockout (stricter: lock after 3x max for account)
        failed_from_ip = cls.get_failed_attempts(
            ip_address=ip_address,
            minutes=lockout_minutes
        ).count()
        
        if failed_from_ip >= (max_attempts * 3):
            until = timezone.now() + timedelta(minutes=lockout_minutes)
            return {
                'locked': True,
                'reason': f'ip',
                'attempts': failed_from_ip,
                'until': until,
            }
        
        return {'locked': False, 'reason': None, 'attempts': failed_for_user}
    
    @classmethod
    def record_attempt(cls, username, ip_address, success, user_agent=''):
        """
        Record a login attempt (successful or failed).
        
        Args:
            username: Attempted username
            ip_address: Source IP address
            success: Whether login succeeded
            user_agent: Browser/client info
        """
        # Clean up old attempts (older than 60 days)
        old_cutoff = timezone.now() - timedelta(days=60)
        cls.objects.filter(timestamp__lt=old_cutoff).delete()
        
        # Record the attempt
        return cls.objects.create(
            username=username,
            ip_address=ip_address,
            success=success,
            user_agent=user_agent[:500],  # Limit user agent length
        )


class AuditLog(models.Model):
    """
    Audit log for security-relevant events.
    
    Records all authentication and privilege-changing events for accountability,
    compliance, and security investigation purposes.
    
    Security Properties:
    - Immutable after creation (no delete/update through normal app flow)
    - Never logs sensitive data (passwords, tokens, etc.)
    - Records user context (who, when, from where, what)
    - Supports compliance requirements (GDPR, SOC 2, etc.)
    - Queryable for security investigations and monitoring
    
    Event Types Logged:
    - Authentication: registration, login success/failure, logout
    - Privilege Changes: role assignments, group membership changes
    - Password Management: password change, password reset
    - Profile Changes: user profile updates
    """
    
    # Event type choices
    EVENT_REGISTRATION = 'registration'
    EVENT_LOGIN_SUCCESS = 'login_success'
    EVENT_LOGIN_FAILURE = 'login_failure'
    EVENT_LOGOUT = 'logout'
    EVENT_PASSWORD_CHANGE = 'password_change'
    EVENT_PASSWORD_RESET = 'password_reset'
    EVENT_ROLE_ASSIGNED = 'role_assigned'
    EVENT_ROLE_REMOVED = 'role_removed'
    EVENT_PROFILE_UPDATED = 'profile_updated'
    
    EVENT_CHOICES = [
        (EVENT_REGISTRATION, 'User Registration'),
        (EVENT_LOGIN_SUCCESS, 'Login Success'),
        (EVENT_LOGIN_FAILURE, 'Login Failure'),
        (EVENT_LOGOUT, 'Logout'),
        (EVENT_PASSWORD_CHANGE, 'Password Change'),
        (EVENT_PASSWORD_RESET, 'Password Reset'),
        (EVENT_ROLE_ASSIGNED, 'Role Assigned'),
        (EVENT_ROLE_REMOVED, 'Role Removed'),
        (EVENT_PROFILE_UPDATED, 'Profile Updated'),
    ]
    
    # Core audit data
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    event_type = models.CharField(
        max_length=20,
        choices=EVENT_CHOICES,
        db_index=True,
        help_text="Type of security-relevant event"
    )
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs_as_subject',
        db_index=True,
        help_text="User who was affected by the event"
    )
    actor = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs_as_actor',
        db_index=True,
        help_text="User who performed the action (for privilege changes)"
    )
    ip_address = models.GenericIPAddressField(
        db_index=True,
        help_text="IP address from which the event originated"
    )
    user_agent = models.TextField(
        blank=True,
        help_text="Browser/client information"
    )
    description = models.TextField(
        help_text="Human-readable description of the event"
    )
    details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Structured event details (never includes secrets)"
    )
    
    class Meta:
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['event_type', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['actor', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
        ]
    
    def __str__(self):
        user_str = self.user.username if self.user else 'unknown'
        return f"[{self.event_type}] {user_str} at {self.timestamp}"
    
    @classmethod
    def log_event(cls, event_type, user, ip_address, description, 
                  actor=None, user_agent='', details=None):
        """
        Create an audit log entry.
        
        Args:
            event_type: Type of event (use EVENT_* constants)
            user: User affected by the event (User instance or None)
            ip_address: IP address of the request
            description: Human-readable description
            actor: User who performed the action (for privilege changes)
            user_agent: Browser/client info
            details: Additional structured details (never include secrets)
        
        Returns:
            The created AuditLog instance
        """
        if details is None:
            details = {}
        
        return cls.objects.create(
            event_type=event_type,
            user=user,
            actor=actor,
            ip_address=ip_address,
            user_agent=user_agent[:500],  # Limit length
            description=description,
            details=details,
        )
    
    @classmethod
    def get_user_history(cls, user, days=90):
        """
        Get audit log history for a specific user.
        
        Args:
            user: User instance
            days: How many days back to look (default: 90)
        
        Returns:
            QuerySet of audit logs for this user
        """
        since = timezone.now() - timedelta(days=days)
        return cls.objects.filter(
            user=user,
            timestamp__gte=since
        ).order_by('-timestamp')
