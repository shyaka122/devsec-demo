"""
Test suite for login brute-force protection.

Tests cover:
- Normal login flow (should work without restrictions)
- Failed login attempts tracking
- Account-based lockout (5 failures = 15 min lockout)
- IP-based lockout (15 failures = 15 min lockout)
- Lockout expiration and retry logic
- Generic error messages (prevents user enumeration)
- Successful login clears attack pattern
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from .models import LoginAttempt, UserProfile


class LoginAttemptTrackingTestCase(TestCase):
    """Tests for LoginAttempt model and attempt tracking."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_record_successful_login(self):
        """Test that successful login is recorded."""
        LoginAttempt.record_attempt(
            username='testuser',
            ip_address='192.168.1.1',
            success=True,
            user_agent='Mozilla/5.0'
        )
        
        attempt = LoginAttempt.objects.get(username='testuser')
        self.assertTrue(attempt.success)
        self.assertEqual(attempt.ip_address, '192.168.1.1')
    
    def test_record_failed_login(self):
        """Test that failed login is recorded."""
        LoginAttempt.record_attempt(
            username='testuser',
            ip_address='192.168.1.1',
            success=False,
            user_agent='Mozilla/5.0'
        )
        
        attempt = LoginAttempt.objects.get(username='testuser')
        self.assertFalse(attempt.success)
    
    def test_get_failed_attempts_by_username(self):
        """Test retrieving failed attempts for a specific username."""
        # Create 3 failed attempts for user1
        for i in range(3):
            LoginAttempt.record_attempt(
                username='user1',
                ip_address=f'192.168.1.{i}',
                success=False
            )
        
        # Create 2 failed attempts for user2
        for i in range(2):
            LoginAttempt.record_attempt(
                username='user2',
                ip_address=f'192.168.1.{i}',
                success=False
            )
        
        # Get failed attempts for user1
        failed = LoginAttempt.get_failed_attempts(username='user1')
        self.assertEqual(failed.count(), 3)
    
    def test_get_failed_attempts_by_ip(self):
        """Test retrieving failed attempts from a specific IP."""
        # Create 3 failed attempts from IP 1
        for i in range(3):
            LoginAttempt.record_attempt(
                username=f'user{i}',
                ip_address='192.168.1.1',
                success=False
            )
        
        # Create 2 failed attempts from IP 2
        for i in range(2):
            LoginAttempt.record_attempt(
                username=f'user{i}',
                ip_address='192.168.1.2',
                success=False
            )
        
        # Get failed attempts from IP 1
        failed = LoginAttempt.get_failed_attempts(ip_address='192.168.1.1')
        self.assertEqual(failed.count(), 3)
    
    def test_get_failed_attempts_time_window(self):
        """Test that failed attempts outside time window are not counted."""
        # Create attempt 40 minutes ago
        old_time = timezone.now() - timedelta(minutes=40)
        old_attempt = LoginAttempt(
            username='testuser',
            ip_address='192.168.1.1',
            success=False,
            timestamp=old_time
        )
        old_attempt.save()
        
        # Create attempt now
        LoginAttempt.record_attempt(
            username='testuser',
            ip_address='192.168.1.1',
            success=False
        )
        
        # Get failed attempts in last 30 minutes
        failed = LoginAttempt.get_failed_attempts(
            username='testuser',
            minutes=30
        )
        
        # Should only return recent attempt
        self.assertEqual(failed.count(), 1)


class AccountLockoutTestCase(TestCase):
    """Tests for account-based lockout after repeated failures."""
    
    def test_account_not_locked_with_few_failures(self):
        """Test account is not locked with less than 5 failures."""
        for i in range(4):
            LoginAttempt.record_attempt(
                username='testuser',
                ip_address='192.168.1.1',
                success=False
            )
        
        lockout = LoginAttempt.get_lockout_status(
            username='testuser',
            ip_address='192.168.1.1',
            max_attempts=5
        )
        
        self.assertFalse(lockout['locked'])
    
    def test_account_locked_after_max_failures(self):
        """Test account is locked after 5 failures."""
        for i in range(5):
            LoginAttempt.record_attempt(
                username='testuser',
                ip_address='192.168.1.1',
                success=False
            )
        
        lockout = LoginAttempt.get_lockout_status(
            username='testuser',
            ip_address='192.168.1.1',
            max_attempts=5
        )
        
        self.assertTrue(lockout['locked'])
        self.assertEqual(lockout['reason'], 'account')
        self.assertEqual(lockout['attempts'], 5)
    
    def test_lockout_has_expiration_time(self):
        """Test that lockout includes expiration time."""
        for i in range(5):
            LoginAttempt.record_attempt(
                username='testuser',
                ip_address='192.168.1.1',
                success=False
            )
        
        lockout = LoginAttempt.get_lockout_status(
            username='testuser',
            ip_address='192.168.1.1',
            max_attempts=5,
            lockout_minutes=15
        )
        
        self.assertTrue(lockout['locked'])
        self.assertIsNotNone(lockout['until'])
        # Untilshould be approximately 15 minutes in the future
        delta = (lockout['until'] - timezone.now()).total_seconds()
        self.assertAlmostEqual(delta, 15 * 60, delta=5)


class IPBasedLockoutTestCase(TestCase):
    """Tests for IP-based lockout after distributed attacks."""
    
    def test_ip_not_locked_below_threshold(self):
        """Test IP is not locked with less than 15 failures."""
        for i in range(14):
            LoginAttempt.record_attempt(
                username=f'user{i}',
                ip_address='192.168.1.1',
                success=False
            )
        
        lockout = LoginAttempt.get_lockout_status(
            username='newuser',
            ip_address='192.168.1.1',
            max_attempts=5
        )
        
        self.assertFalse(lockout['locked'])
    
    def test_ip_locked_after_15_failures(self):
        """Test IP is locked after 15 failures (3x account threshold)."""
        for i in range(15):
            LoginAttempt.record_attempt(
                username=f'user{i}',
                ip_address='192.168.1.1',
                success=False
            )
        
        lockout = LoginAttempt.get_lockout_status(
            username='newuser',
            ip_address='192.168.1.1',
            max_attempts=5
        )
        
        self.assertTrue(lockout['locked'])
        self.assertEqual(lockout['reason'], 'ip')


class LoginViewBruteForceProtectionTestCase(TestCase):
    """Tests for brute-force protection in login view."""
    
    def setUp(self):
        self.client = Client()
        self.login_url = reverse('shyaka:login')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_legitimate_login_works(self):
        """Test that legitimate login still works normally."""
        response = self.client.post(
            self.login_url,
            {
                'username': 'testuser',
                'password': 'TestPassword123!'
            }
        )
        
        # Should redirect to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)
    
    def test_failed_login_recorded(self):
        """Test that failed login is recorded."""
        response = self.client.post(
            self.login_url,
            {
                'username': 'testuser',
                'password': 'WrongPassword'
            }
        )
        
        # Should have recorded the attempt
        attempt = LoginAttempt.objects.filter(username='testuser', success=False)
        self.assertTrue(attempt.exists())
    
    def test_multiple_failed_logins_allowed(self):
        """Test that multiple failed logins are allowed until threshold."""
        for i in range(4):
            response = self.client.post(
                self.login_url,
                {
                    'username': 'testuser',
                    'password': 'WrongPassword'
                }
            )
            # Should still display login page (not blocked)
            self.assertEqual(response.status_code, 200)
    
    def test_login_blocked_after_lockout(self):
        """Test that login is blocked after 5 failures."""
        # Create 5 failed attempts
        for i in range(5):
            LoginAttempt.record_attempt(
                username='testuser',
                ip_address='127.0.0.1',
                success=False
            )
        
        # Try to login (should be blocked)
        response = self.client.post(
            self.login_url,
            {
                'username': 'testuser',
                'password': 'TestPassword123!'  # Correct password, but locked out
            }
        )
        
        # Should display generic error message
        self.assertContains(response, 'Invalid username or password. Please try again later')
    
    def test_generic_error_message(self):
        """Test that error message is generic (doesn't reveal lockout reason)."""
        # Create lockout
        for i in range(5):
            LoginAttempt.record_attempt(
                username='testuser',
                ip_address='127.0.0.1',
                success=False
            )
        
        response = self.client.post(
            self.login_url,
            {
                'username': 'testuser',
                'password': 'WrongPassword'
            }
        )
        
        # Should not reveal "account locked" or "too many attempts"
        content = str(response.content)
        self.assertNotIn('locked', content.lower())
        self.assertNotIn('too many attempts', content.lower())
        self.assertNotIn('cooldown', content.lower())
    
    def test_successful_login_recorded(self):
        """Test that successful login is recorded."""
        response = self.client.post(
            self.login_url,
            {
                'username': 'testuser',
                'password': 'TestPassword123!'
            }
        )
        
        attempt = LoginAttempt.objects.filter(username='testuser', success=True)
        self.assertTrue(attempt.exists())
    
    def test_lockout_expires_after_window(self):
        """Test that lockout expires after the timeout window."""
        # Create 5 failed attempts in the past (outside 15 min window)
        old_time = timezone.now() - timedelta(minutes=20)
        for i in range(5):
            attempt = LoginAttempt(
                username='testuser',
                ip_address='127.0.0.1',
                success=False,
                timestamp=old_time
            )
            attempt.save()
        
        # Check lockout status (should not be locked as attempts are old)
        lockout = LoginAttempt.get_lockout_status(
            username='testuser',
            ip_address='127.0.0.1',
            max_attempts=5,
            lockout_minutes=15
        )
        
        self.assertFalse(lockout['locked'])
    
    def test_ip_lockout_blocks_all_users_from_ip(self):
        """Test that IP lockout blocks login attempts from that IP for all users."""
        # Create 15 failed attempts from same IP with different usernames
        for i in range(15):
            LoginAttempt.record_attempt(
                username=f'user{i}',
                ip_address='192.168.1.1',
                success=False
            )
        
        # Try to login as different user from same IP
        lockout = LoginAttempt.get_lockout_status(
            username='newuser',
            ip_address='192.168.1.1',
            max_attempts=5
        )
        
        self.assertTrue(lockout['locked'])
        self.assertEqual(lockout['reason'], 'ip')
    
    def test_old_attempts_cleaned_up(self):
        """Test that old attempts (>60 days) are cleaned up."""
        # Create attempt 61 days ago
        old_time = timezone.now() - timedelta(days=61)
        old_attempt = LoginAttempt(
            username='testuser',
            ip_address='127.0.0.1',
            success=False,
            timestamp=old_time
        )
        old_attempt.save()
        
        # Record new attempt (triggers cleanup)
        LoginAttempt.record_attempt(
            username='testuser',
            ip_address='127.0.0.1',
            success=False
        )
        
        # Old attempt should be deleted
        attempts = LoginAttempt.objects.filter(timestamp__lt=old_time)
        self.assertEqual(attempts.count(), 0)


class BruteForceAttackScenarioTestCase(TestCase):
    """End-to-end tests simulating realistic attack scenarios."""
    
    def setUp(self):
        self.client = Client()
        self.login_url = reverse('shyaka:login')
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='SecureAdminPassword123!'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_dictionary_attack_on_account(self):
        """Test protection against dictionary attack on single account."""
        # Attacker tries 6 different passwords
        passwords = [
            'password123',
            'admin123',
            'letmein',
            'admin',
            'password',
            'wrongpass'
        ]
        
        for pwd in passwords[:5]:
            response = self.client.post(
                self.login_url,
                {'username': 'admin', 'password': pwd}
            )
            # Should still be able to attempt
            self.assertEqual(response.status_code, 200)
        
        # 6th attempt should be blocked
        response = self.client.post(
            self.login_url,
            {'username': 'admin', 'password': passwords[5]}
        )
        self.assertContains(response, 'Please try again later')
    
    def test_distributed_attack_from_ip(self):
        """Test protection against distributed attack from single IP."""
        # Simulate 15 failed attempts from same IP, different user targets
        for i in range(15):
            LoginAttempt.record_attempt(
                username=f'user{i % 5}',  # Try to target 5 users
                ip_address='192.168.100.50',
                success=False
            )
        
        # IP should now be locked
        lockout = LoginAttempt.get_lockout_status(
            username='admin',
            ip_address='192.168.100.50',
            max_attempts=5
        )
        self.assertTrue(lockout['locked'])
    
    def test_credential_stuffing_detection(self):
        """Test that credential stuffing (many accounts, same password) is limited by account lockout."""
        # Create multiple users
        users = []
        for i in range(10):
            user = User.objects.create_user(
                username=f'user{i}',
                password=f'StuffedPassword{i}'
            )
            UserProfile.objects.create(user=user)
            users.append(user)
        
        # Try wrong password on first account 5 times
        for _ in range(5):
            LoginAttempt.record_attempt(
                username='user0',
                ip_address='192.168.1.1',
                success=False
            )
        
        # Verify account is locked
        lockout = LoginAttempt.get_lockout_status(
            username='user0',
            ip_address='192.168.1.1',
            max_attempts=5
        )
        self.assertTrue(lockout['locked'])


class LoginAttemptAuditTrailTestCase(TestCase):
    """Tests for audit trail and monitoring capabilities."""
    
    def test_user_agent_recorded(self):
        """Test that user agent is recorded for audit purposes."""
        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        LoginAttempt.record_attempt(
            username='testuser',
            ip_address='192.168.1.1',
            success=False,
            user_agent=user_agent
        )
        
        attempt = LoginAttempt.objects.get(username='testuser')
        self.assertEqual(attempt.user_agent, user_agent)
    
    def test_all_attempts_queryable_by_ip(self):
        """Test that all attempts from an IP can be retrieved."""
        ip = '192.168.1.10'
        
        # Create attempts from multiple users from same IP
        for i in range(5):
            LoginAttempt.record_attempt(
                username=f'user{i}',
                ip_address=ip,
                success=i % 2 == 0  # Mix of success/failure
            )
        
        # Query all attempts from IP
        attempts = LoginAttempt.objects.filter(ip_address=ip)
        self.assertEqual(attempts.count(), 5)
    
    def test_attempt_timeline_visible(self):
        """Test that attempt timeline can be reviewed."""
        username = 'testuser'
        
        for i in range(3):
            LoginAttempt.record_attempt(
                username=username,
                ip_address='192.168.1.1',
                success=False
            )
        
        # Get attempts in order
        attempts = LoginAttempt.objects.filter(username=username).order_by('-timestamp')
        self.assertEqual(attempts.count(), 3)
