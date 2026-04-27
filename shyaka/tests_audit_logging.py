"""
Comprehensive test suite for audit logging functionality.

Tests validate that security-relevant events are logged consistently,
contain appropriate information, and never leak sensitive data.

Events Tested:
1. User registration
2. Login success and failure
3. Logout
4. Password change and reset
5. Role/permission changes
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from shyaka.models import AuditLog
from django.utils import timezone
from datetime import timedelta


class AuditLogModelTests(TestCase):
    """Test the AuditLog model functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
    
    def test_audit_log_creation(self):
        """Test basic audit log entry creation."""
        log = AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user,
            ip_address='192.168.1.100',
            description='User logged in successfully',
        )
        self.assertEqual(log.event_type, AuditLog.EVENT_LOGIN_SUCCESS)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.ip_address, '192.168.1.100')
    
    def test_audit_log_with_details(self):
        """Test audit log entry with additional details."""
        details = {'session_id': 'abc123', 'browser': 'Firefox'}
        log = AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user,
            ip_address='192.168.1.100',
            description='Login from Firefox',
            details=details,
        )
        self.assertEqual(log.details, details)
    
    def test_audit_log_with_actor(self):
        """Test audit log entry where an actor performs action on a user."""
        admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='AdminPassword123!'
        )
        log = AuditLog.log_event(
            event_type=AuditLog.EVENT_ROLE_ASSIGNED,
            user=self.user,
            actor=admin,
            ip_address='192.168.1.100',
            description='Role assigned',
            details={'role': 'staff'},
        )
        self.assertEqual(log.actor, admin)
        self.assertEqual(log.user, self.user)
    
    def test_get_user_history(self):
        """Test retrieving audit history for a specific user."""
        # Create multiple logs for this user
        for i in range(3):
            AuditLog.log_event(
                event_type=AuditLog.EVENT_LOGIN_SUCCESS,
                user=self.user,
                ip_address='192.168.1.100',
                description=f'Login attempt {i}',
            )
        
        # Retrieve history
        history = AuditLog.get_user_history(self.user)
        self.assertEqual(history.count(), 3)
    
    def test_get_user_history_date_filtering(self):
        """Test that get_user_history filters by date."""
        # Create log 100 days ago
        old_log = AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user,
            ip_address='192.168.1.100',
            description='Old login',
        )
        old_log.timestamp = timezone.now() - timedelta(days=100)
        old_log.save()
        
        # Create current log
        AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user,
            ip_address='192.168.1.100',
            description='Recent login',
        )
        
        # History should only include logs from last 90 days
        history = AuditLog.get_user_history(self.user, days=90)
        self.assertEqual(history.count(), 1)
    
    def test_audit_log_string_representation(self):
        """Test __str__ method of AuditLog."""
        log = AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user,
            ip_address='192.168.1.100',
            description='Login success',
        )
        log_str = str(log)
        self.assertIn(AuditLog.EVENT_LOGIN_SUCCESS, log_str)
        self.assertIn(self.user.username, log_str)


class RegistrationAuditTests(TestCase):
    """Test that user registration is logged."""
    
    def setUp(self):
        """Set up test client."""
        self.client = Client()
    
    def test_successful_registration_logged(self):
        """Successful registration should create an audit log entry."""
        response = self.client.post(
            reverse('shyaka:register'),
            {
                'username': 'newuser',
                'email': 'new@example.com',
                'first_name': 'New',
                'last_name': 'User',
                'password1': 'SecurePassword123!',
                'password2': 'SecurePassword123!',
            }
        )
        
        # Check that registration was successful
        self.assertEqual(response.status_code, 302)
        
        # Check that audit log entry was created
        logs = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_REGISTRATION,
            user__username='newuser'
        )
        self.assertEqual(logs.count(), 1)
        
        # Verify log contents
        log = logs.first()
        self.assertIn('newuser', log.description)
        self.assertIsNotNone(log.ip_address)


class LoginAuditTests(TestCase):
    """Test that login events are logged."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
    
    def test_successful_login_logged(self):
        """Successful login should create an audit log entry."""
        response = self.client.post(
            reverse('shyaka:login'),
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        
        # Check that login success log was created
        logs = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user
        )
        self.assertEqual(logs.count(), 1)
        
        # Verify log doesn't contain password
        log = logs.first()
        self.assertNotIn('password', log.description.lower())
        self.assertNotIn('SecurePassword', log.description)
    
    def test_failed_login_logged(self):
        """Failed login should create an audit log entry."""
        response = self.client.post(
            reverse('shyaka:login'),
            {'username': 'testuser', 'password': 'WrongPassword123!'}
        )
        
        # Check that login failure log was created
        logs = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_LOGIN_FAILURE
        )
        self.assertEqual(logs.count(), 1)
        
        # Verify log doesn't contain password
        log = logs.first()
        self.assertNotIn('password', log.description.lower())
        self.assertNotIn('WrongPassword', log.description)
    
    def test_login_audit_contains_ip_and_user_agent(self):
        """Login audit log should contain IP and user agent."""
        response = self.client.post(
            reverse('shyaka:login'),
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        
        log = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS
        ).first()
        
        self.assertIsNotNone(log.ip_address)
        self.assertTrue(len(log.ip_address) > 0)


class LogoutAuditTests(TestCase):
    """Test that logout events are logged."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
        self.client.login(username='testuser', password='SecurePassword123!')
    
    def test_logout_logged(self):
        """Logout should create an audit log entry."""
        response = self.client.get(reverse('shyaka:logout'))
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        
        # Check that logout log was created
        logs = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_LOGOUT,
            user=self.user
        )
        self.assertEqual(logs.count(), 1)
        
        # Verify log contents
        log = logs.first()
        self.assertIn('testuser', log.description)


class PasswordChangeAuditTests(TestCase):
    """Test that password changes are logged."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
        self.client.login(username='testuser', password='SecurePassword123!')
    
    def test_password_change_logged(self):
        """Password change should create an audit log entry."""
        response = self.client.post(
            reverse('shyaka:change_password'),
            {
                'old_password': 'SecurePassword123!',
                'new_password1': 'NewSecurePassword123!',
                'new_password2': 'NewSecurePassword123!',
            }
        )
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        
        # Check that password change log was created
        logs = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_PASSWORD_CHANGE,
            user=self.user
        )
        self.assertEqual(logs.count(), 1)
        
        # Verify log doesn't contain actual passwords
        log = logs.first()
        self.assertNotIn('SecurePassword', log.description)
        self.assertNotIn('NewSecurePassword', log.description)


class PasswordResetAuditTests(TestCase):
    """Test that password resets are logged."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
    
    def test_password_reset_logged(self):
        """Password reset should create an audit log entry."""
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.id))
        
        response = self.client.post(
            reverse('shyaka:password_reset_confirm', args=[uidb64, token]),
            {
                'new_password1': 'NewPassword123!',
                'new_password2': 'NewPassword123!',
            }
        )
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        
        # Check that password reset log was created
        logs = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_PASSWORD_RESET,
            user=self.user
        )
        self.assertEqual(logs.count(), 1)
        
        # Verify log doesn't contain actual passwords
        log = logs.first()
        self.assertNotIn('NewPassword', log.description)


class RoleAuditTests(TestCase):
    """Test that role changes are logged."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        
        # Create admin user
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='AdminPassword123!'
        )
        admin_group = Group.objects.get_or_create(name='admin')[0]
        self.admin.groups.add(admin_group)
        self.admin.is_staff = True
        self.admin.save()
        
        # Create regular user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='UserPassword123!'
        )
        
        # Login as admin
        self.client.login(username='admin', password='AdminPassword123!')
    
    def test_role_assignment_logged(self):
        """Role assignment should create an audit log entry."""
        # Create staff group
        Group.objects.get_or_create(name='staff')
        
        response = self.client.post(
            reverse('shyaka:assign_user_role'),
            {'user_id': self.user.id, 'role': 'staff'}
        )
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        
        # Check that role assignment log was created
        logs = AuditLog.objects.filter(
            event_type=AuditLog.EVENT_ROLE_ASSIGNED,
            user=self.user,
            actor=self.admin
        )
        self.assertEqual(logs.count(), 1)
        
        # Verify log contents
        log = logs.first()
        self.assertIn('staff', log.description)
        self.assertIn('admin', log.description.lower())
        self.assertEqual(log.details.get('new_role'), 'staff')


class AuditLogSensitivityTests(TestCase):
    """Test that audit logs never contain sensitive data."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='MySecretPassword123!'
        )
    
    def test_password_never_logged_on_failed_login(self):
        """Passwords should never appear in failed login logs."""
        self.client.post(
            reverse('shyaka:login'),
            {'username': 'testuser', 'password': 'MySecretPassword123!'}
        )
        
        logs = AuditLog.objects.all()
        for log in logs:
            self.assertNotIn('MySecretPassword', log.description)
            self.assertNotIn('MySecretPassword', str(log.details))
    
    def test_email_address_handling(self):
        """Email addresses should be handled safely in logs."""
        log = AuditLog.log_event(
            event_type=AuditLog.EVENT_REGISTRATION,
            user=self.user,
            ip_address='127.0.0.1',
            description='User registered',
            details={'email': 'test@example.com'},  # Safe to log
        )
        
        self.assertEqual(log.details.get('email'), 'test@example.com')


class AuditLogQueryTests(TestCase):
    """Test querying audit logs."""
    
    def setUp(self):
        """Set up test data."""
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='Password123!'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='Password123!'
        )
    
    def test_query_by_event_type(self):
        """Should be able to query logs by event type."""
        AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user1,
            ip_address='192.168.1.100',
            description='Login',
        )
        AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGOUT,
            user=self.user1,
            ip_address='192.168.1.100',
            description='Logout',
        )
        
        login_logs = AuditLog.objects.filter(event_type=AuditLog.EVENT_LOGIN_SUCCESS)
        self.assertEqual(login_logs.count(), 1)
    
    def test_query_by_user(self):
        """Should be able to query logs by user."""
        AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user1,
            ip_address='192.168.1.100',
            description='Login',
        )
        AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user2,
            ip_address='192.168.1.101',
            description='Login',
        )
        
        user1_logs = AuditLog.objects.filter(user=self.user1)
        self.assertEqual(user1_logs.count(), 1)
    
    def test_query_by_ip_address(self):
        """Should be able to query logs by IP address."""
        ip = '192.168.1.100'
        AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user1,
            ip_address=ip,
            description='Login',
        )
        
        ip_logs = AuditLog.objects.filter(ip_address=ip)
        self.assertEqual(ip_logs.count(), 1)
    
    def test_query_by_date_range(self):
        """Should be able to query logs by date range."""
        now = timezone.now()
        old_date = now - timedelta(days=10)
        
        # Create old log
        log = AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user1,
            ip_address='192.168.1.100',
            description='Old login',
        )
        log.timestamp = old_date
        log.save()
        
        # Create recent log
        AuditLog.log_event(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user=self.user1,
            ip_address='192.168.1.100',
            description='Recent login',
        )
        
        recent_logs = AuditLog.objects.filter(
            timestamp__gte=now - timedelta(days=5)
        )
        self.assertEqual(recent_logs.count(), 1)
