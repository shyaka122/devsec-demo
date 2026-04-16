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
