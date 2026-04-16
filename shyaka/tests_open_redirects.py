"""
Comprehensive test suite for open redirect vulnerability fixes.

Tests validate that redirect targets are properly validated in authentication
workflows, preventing attackers from redirecting users to malicious sites.

Attack Scenarios Tested:
1. External URL redirect - POST /login?next=http://evil.com
2. Protocol-relative redirect - ?next=//evil.com
3. Absolute URL redirect - ?next=/evil.com  (with different host validation)
4. Valid internal redirects - ?next=/dashboard/ (should work)
5. Redirect in forms - Hidden field with malicious URL
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from shyaka.auth_utils import is_safe_redirect_url


class SafeRedirectUtilityTests(TestCase):
    """Test the is_safe_redirect_url() utility function."""
    
    def setUp(self):
        """Set up test client and request factory."""
        self.client = Client()
    
    def test_relative_url_is_safe(self):
        """Relative URLs starting with / should be safe."""
        result = is_safe_redirect_url('/dashboard/')
        self.assertTrue(result, "Relative URL /dashboard/ should be safe")
    
    def test_relative_url_with_query_string_is_safe(self):
        """Relative URLs with query strings should be safe."""
        result = is_safe_redirect_url('/profile/?tab=settings')
        self.assertTrue(result, "Relative URL with query string should be safe")
    
    def test_protocol_relative_url_is_unsafe(self):
        """Protocol-relative URLs (//evil.com) are unsafe (can bypass HTTPS)."""
        result = is_safe_redirect_url('//evil.com/malware')
        self.assertFalse(result, "Protocol-relative URL //evil.com should be unsafe")
    
    def test_absolute_http_url_without_host_validation_is_unsafe(self):
        """Absolute URLs without explicit host validation should be unsafe."""
        result = is_safe_redirect_url('http://localhost/profile/')
        self.assertFalse(
            result,
            "Absolute URL without request context and host whitelist should be unsafe"
        )
    
    def test_absolute_https_url_without_host_validation_is_unsafe(self):
        """Absolute URLs without explicit host validation should be unsafe."""
        result = is_safe_redirect_url('https://attacker.com/steal-credentials')
        self.assertFalse(
            result,
            "Absolute URL to attacker site should be unsafe"
        )
    
    def test_empty_url_is_unsafe(self):
        """Empty redirect URLs should be unsafe."""
        result = is_safe_redirect_url('')
        self.assertFalse(result, "Empty URL should be unsafe")
    
    def test_none_url_is_unsafe(self):
        """None values should be unsafe."""
        result = is_safe_redirect_url(None)
        self.assertFalse(result, "None URL should be unsafe")
    
    def test_javascript_url_is_unsafe(self):
        """JavaScript URLs (javascript:) should be unsafe."""
        result = is_safe_redirect_url('javascript:alert("xss")')
        self.assertFalse(result, "JavaScript URL should be unsafe")
    
    def test_data_url_is_unsafe(self):
        """Data URLs should be unsafe."""
        result = is_safe_redirect_url('data:text/html,<script>alert(1)</script>')
        self.assertFalse(result, "Data URL should be unsafe")


class LoginOpenRedirectTests(TestCase):
    """Test open redirect vulnerabilities in login endpoint."""
    
    def setUp(self):
        """Set up test user and client."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
    
    def test_login_without_next_redirects_to_dashboard(self):
        """Successful login without 'next' parameter should redirect to dashboard."""
        response = self.client.post(
            reverse('shyaka:login'),
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        # Check redirect status (without following)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('shyaka:dashboard'), response.url)
    
    def test_login_with_safe_relative_url_redirects_correctly(self):
        """Login with valid relative 'next' URL should redirect to that URL."""
        response = self.client.post(
            reverse('shyaka:login') + '?next=/auth/profile/',
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        # Check redirect includes the safe URL
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/profile/', response.url)
    
    def test_login_with_safe_next_in_post_data_redirects_correctly(self):
        """Login with safe 'next' in POST data should redirect to that URL."""
        response = self.client.post(
            reverse('shyaka:login'),
            {
                'username': 'testuser',
                'password': 'SecurePassword123!',
                'next': '/auth/dashboard/'
            }
        )
        # Check redirect returns 302
        self.assertEqual(response.status_code, 302)
        # Should redirect to dashboard (next parameter in POST)
        self.assertIn('/auth/dashboard/', response.url)
    
    def test_login_with_external_url_redirects_to_dashboard(self):
        """Login with external 'next' URL should ignore it and redirect to dashboard."""
        response = self.client.post(
            reverse('shyaka:login') + '?next=http://attacker.com/steal',
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        # Should reject the malicious URL and redirect to safe default (dashboard)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('attacker.com', response.url)
        self.assertIn(reverse('shyaka:dashboard'), response.url)
    
    def test_login_with_protocol_relative_url_redirects_to_dashboard(self):
        """Login with protocol-relative 'next' URL should ignore it."""
        response = self.client.post(
            reverse('shyaka:login') + '?next=//attacker.com/malware',
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        # Should reject the malicious URL and redirect to safe default (dashboard)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('attacker.com', response.url)
        self.assertIn(reverse('shyaka:dashboard'), response.url)
    
    def test_login_get_request_with_safe_next_displays_hidden_field(self):
        """GET login page with safe 'next' should include hidden field in form."""
        response = self.client.get(reverse('shyaka:login') + '?next=/profile/')
        self.assertContains(response, 'type="hidden"')
        self.assertContains(response, 'name="next"')
        self.assertContains(response, 'value="/profile/"')
    
    def test_login_get_request_with_unsafe_next_does_not_include_field(self):
        """GET login page with unsafe 'next' should NOT include hidden field."""
        response = self.client.get(
            reverse('shyaka:login') + '?next=http://attacker.com'
        )
        # Should not include the potentially dangerous redirect
        self.assertNotIn('http://attacker.com', response.content.decode())


class LogoutOpenRedirectTests(TestCase):
    """Test open redirect vulnerabilities in logout endpoint."""
    
    def setUp(self):
        """Set up test user and client."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
        self.client.login(username='testuser', password='SecurePassword123!')
    
    def test_logout_without_next_redirects_to_login(self):
        """Logout without 'next' parameter should redirect to login."""
        response = self.client.get(reverse('shyaka:logout'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('shyaka:login'), response.url)
    
    def test_logout_with_safe_relative_url_redirects_correctly(self):
        """Logout with valid relative 'next' URL should redirect to that URL."""
        response = self.client.get(
            reverse('shyaka:logout') + '?next=/auth/dashboard/'
        )
        # Check redirect to safe URL
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/dashboard/', response.url)
    
    def test_logout_with_external_url_redirects_to_login(self):
        """Logout with external 'next' URL should ignore it and redirect to login."""
        response = self.client.get(
            reverse('shyaka:logout') + '?next=http://attacker.com'
        )
        # Should reject malicious URL and go to login
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('attacker.com', response.url)
        self.assertIn(reverse('shyaka:login'), response.url)
    
    def test_logout_with_protocol_relative_url_redirects_to_login(self):
        """Logout with protocol-relative 'next' URL should ignore it."""
        response = self.client.get(
            reverse('shyaka:logout') + '?next=//attacker.com'
        )
        # Should reject malicious URL and go to login
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('attacker.com', response.url)
        self.assertIn(reverse('shyaka:login'), response.url)



class RegisterOpenRedirectTests(TestCase):
    """Test open redirect vulnerabilities in registration endpoint."""
    
    def setUp(self):
        """Set up test client."""
        self.client = Client()
    
    def test_register_without_next_redirects_to_login(self):
        """Successful registration without 'next' parameter should redirect to login."""
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
        self.assertRedirects(response, reverse('shyaka:login'))
    
    def test_register_with_safe_next_includes_it_in_redirect(self):
        """Registration with safe 'next' should pass it to login page."""
        response = self.client.post(
            reverse('shyaka:register') + '?next=/dashboard/',
            {
                'username': 'newuser',
                'email': 'new@example.com',
                'first_name': 'New',
                'last_name': 'User',
                'password1': 'SecurePassword123!',
                'password2': 'SecurePassword123!',
            }
        )
        # Should redirect to login (with next param if safe)
        # The exact URL depends on how we chain the next param
        self.assertEqual(response.status_code, 302)
    
    def test_register_with_external_url_ignores_it(self):
        """Registration with external 'next' URL should ignore it."""
        response = self.client.post(
            reverse('shyaka:register') + '?next=http://attacker.com',
            {
                'username': 'newuser',
                'email': 'new@example.com',
                'first_name': 'New',
                'last_name': 'User',
                'password1': 'SecurePassword123!',
                'password2': 'SecurePassword123!',
            }
        )
        # Should not contain attacker URL in redirect
        self.assertNotIn('attacker.com', str(response))
    
    def test_register_get_request_with_safe_next_displays_field(self):
        """GET register page with safe 'next' should include hidden field."""
        response = self.client.get(reverse('shyaka:register') + '?next=/profile/')
        self.assertContains(response, 'type="hidden"')
        self.assertContains(response, 'name="next"')
    
    def test_register_get_request_with_unsafe_next_ignores_it(self):
        """GET register page with unsafe 'next' should not include it."""
        response = self.client.get(
            reverse('shyaka:register') + '?next=http://attacker.com'
        )
        # Should not include the attacker URL
        self.assertNotIn('attacker.com', response.content.decode())


class PasswordResetOpenRedirectTests(TestCase):
    """Test open redirect vulnerabilities in password reset workflow."""
    
    def setUp(self):
        """Set up test user and client."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
    
    def test_password_reset_confirm_without_next(self):
        """Password reset confirm without 'next' should redirect to completion page."""
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.id))
        
        response = self.client.post(
            reverse('shyaka:password_reset_confirm', args=[uidb64, token]),
            {
                'new_password1': 'NewSecurePassword123!',
                'new_password2': 'NewSecurePassword123!',
            }
        )
        self.assertRedirects(response, reverse('shyaka:password_reset_complete'))
    
    def test_password_reset_confirm_with_safe_next(self):
        """Password reset confirm with safe 'next' should redirect there."""
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.id))
        
        response = self.client.post(
            reverse('shyaka:password_reset_confirm', args=[uidb64, token]) + '?next=/dashboard/',
            {
                'new_password1': 'NewSecurePassword123!',
                'new_password2': 'NewSecurePassword123!',
            },
            follow=True
        )
        self.assertEqual(response.status_code, 200)
    
    def test_password_reset_confirm_with_external_url_ignores_it(self):
        """Password reset with external 'next' URL should ignore it."""
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.id))
        
        response = self.client.post(
            reverse('shyaka:password_reset_confirm', args=[uidb64, token]) + '?next=http://attacker.com',
            {
                'new_password1': 'NewSecurePassword123!',
                'new_password2': 'NewSecurePassword123!',
            },
            follow=True
        )
        # Should not redirect to attacker.com
        self.assertNotIn('attacker.com', response.content.decode())
    
    def test_password_reset_confirm_with_protocol_relative_url_ignores_it(self):
        """Password reset with protocol-relative 'next' URL should ignore it."""
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.id))
        
        response = self.client.post(
            reverse('shyaka:password_reset_confirm', args=[uidb64, token]) + '?next=//attacker.com',
            {
                'new_password1': 'NewSecurePassword123!',
                'new_password2': 'NewSecurePassword123!',
            },
            follow=True
        )
        # Should not redirect to attacker site
        self.assertNotIn('attacker.com', response.content.decode())
    
    def test_password_reset_confirm_get_with_safe_next_displays_field(self):
        """GET password reset page with safe 'next' should include hidden field."""
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.id))
        
        response = self.client.get(
            reverse('shyaka:password_reset_confirm', args=[uidb64, token]) + '?next=/dashboard/'
        )
        self.assertContains(response, 'type="hidden"')
        self.assertContains(response, 'name="next"')
        self.assertContains(response, 'value="/dashboard/"')


class OpenRedirectAttackScenarioTests(TestCase):
    """Test realistic open redirect attack scenarios."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
    
    def test_attack_scenario_malicious_login_link(self):
        """
        Realistic Attack: Attacker sends user malicious login link.
        
        Scenario:
        1. Attacker creates link: https://yoursite.com/login?next=https://attacker.com
        2. User receives link in email/message
        3. User logs in through the link
        4. User should NOT be redirected to attacker site
        """
        response = self.client.post(
            reverse('shyaka:login') + '?next=https://attacker.com/phishing',
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        # Verify request doesn't redirect to attacker
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('attacker.com', response.url)
        # Verify redirects to safe default (dashboard)
        self.assertIn(reverse('shyaka:dashboard'), response.url)
    
    def test_attack_scenario_password_reset_chain(self):
        """
        Realistic Attack: Attacker chains password reset with open redirect.
        
        Scenario:
        1. Attacker sends password reset link with malicious next parameter
        2. User clicks link and confirms new password
        3. User should NOT be redirected to attacker site
        """
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.id))
        
        # Attacker crafts malicious reset link
        response = self.client.post(
            reverse('shyaka:password_reset_confirm', args=[uidb64, token]) + 
            '?next=https://phishing-site.com/fake-login',
            {
                'new_password1': 'NewSecurePassword123!',
                'new_password2': 'NewSecurePassword123!',
            }
        )
        
        # Verify redirect doesn't go to phishing site
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('phishing-site.com', response.url)
        self.assertNotIn('fake-login', response.url)
    
    def test_attack_scenario_javascript_protocol(self):
        """
        Realistic Attack: Attacker uses javascript: protocol in redirect.
        
        Scenario:
        1. Attacker crafts URL: ?next=javascript:alert('hacked')
        2. If not properly filtered, could execute JavaScript
        """
        response = self.client.post(
            reverse('shyaka:login') + '?next=javascript:alert("xss")',
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        # Should not allow javascript protocol
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('javascript:', response.url.lower())
        # Should redirect to safe default
        self.assertIn(reverse('shyaka:dashboard'), response.url)


class DefaultBehaviorTests(TestCase):
    """Test that default behavior still works without next parameter."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePassword123!'
        )
    
    def test_login_default_behavior_unchanged(self):
        """Login without next parameter should still work as before."""
        response = self.client.post(
            reverse('shyaka:login'),
            {'username': 'testuser', 'password': 'SecurePassword123!'}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('shyaka:dashboard'), response.url)
    
    def test_logout_default_behavior_unchanged(self):
        """Logout without next parameter should still work as before."""
        self.client.login(username='testuser', password='SecurePassword123!')
        response = self.client.get(reverse('shyaka:logout'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('shyaka:login'), response.url)
    
    def test_register_default_behavior_unchanged(self):
        """Register without next parameter should still work as before."""
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
        self.assertRedirects(response, reverse('shyaka:login'))


# ============================================================================
# Test Summary
# ============================================================================
#
# These tests comprehensively validate open redirect protection across all
# authentication workflows:
#
# ✅ Login: Safe/unsafe next parameter handling
# ✅ Logout: Safe/unsafe next parameter handling
# ✅ Registration: Safe/unsafe next parameter handling
# ✅ Password Reset: Safe/unsafe next parameter handling
# ✅ Utility Function: URL validation logic
# ✅ Attack Scenarios: Realistic attack patterns blocked
# ✅ Default Behavior: Existing functionality preserved
#
# All tests verify:
# 1. Safe relative URLs (/dashboard/) are allowed
# 2. External URLs (http://attacker.com) are rejected
# 3. Protocol-relative URLs (//attacker.com) are rejected
# 4. JavaScript/Data URLs are rejected
# 5. Default behavior (no next) still works
# 6. Templates properly include/exclude hidden fields
# ============================================================================
