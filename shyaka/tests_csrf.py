"""
Tests for CSRF protection on state-changing requests.

This test suite validates that CSRF tokens are properly required for all
state-changing POST operations to prevent cross-site request forgery attacks.
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.middleware.csrf import get_token
from django.test import RequestFactory


class ProfileCSRFProtectionTests(TestCase):
    """Tests for CSRF protection on the profile endpoint."""
    
    def setUp(self):
        """Set up test user and client with CSRF checks enabled."""
        self.client = Client(enforce_csrf_checks=True)
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123'
        )
    
    def test_profile_post_without_csrf_token_fails(self):
        """
        CRITICAL: POST to profile without CSRF token must be rejected with 403.
        
        This is the core CSRF protection test. If CSRF protection is not active,
        an attacker can forge profile update requests from another website.
        """
        # Login first
        self.client.login(username='testuser', password='testpassword123')
        
        # Attempt POST without CSRF token - should fail
        response = self.client.post(
            reverse('shyaka:profile'),
            {'first_name': 'Hacked', 'email': 'hacked@example.com'},
            follow=False
        )
        
        # CSRF middleware should reject this with 403 Forbidden
        self.assertEqual(
            response.status_code, 403,
            "CSRF protection failed! POST without token was not rejected with 403."
        )
    
    def test_profile_get_still_works(self):
        """
        GET requests should still work (no CSRF token needed for GET).
        
        Ensures CSRF protection doesn't break legitimate read operations.
        """
        self.client.login(username='testuser', password='testpassword123')
        
        response = self.client.get(reverse('shyaka:profile'))
        
        # GET should work fine
        self.assertEqual(response.status_code, 200)
    
    def test_profile_form_includes_csrf_token(self):
        """
        Verify profile form includes csrfmiddlewaretoken in HTML.
        
        Users' browsers need CSRF token in form to make requests.
        """
        self.client.login(username='testuser', password='testpassword123')
        
        response = self.client.get(reverse('shyaka:profile'))
        
        # HTML should contain CSRF token
        self.assertContains(response, 'csrfmiddlewaretoken')


class CSRFProtectionOnAllEndpointsTests(TestCase):
    """Validate CSRF protection is applied to all state-changing endpoints."""
    
    def setUp(self):
        """Set up test users and client."""
        self.client = Client(enforce_csrf_checks=False)
        self.csrf_client = Client(enforce_csrf_checks=True)
        
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        
        # Create UserProfile for users
        from .models import UserProfile
        UserProfile.objects.create(user=self.user)
        UserProfile.objects.create(user=self.admin_user)
    
    def test_register_endpoint_has_csrf_token(self):
        """Register form must include CSRF token."""
        response = self.client.get(reverse('shyaka:register'))
        self.assertContains(response, 'csrfmiddlewaretoken')
    
    def test_login_endpoint_has_csrf_token(self):
        """Login form must include CSRF token."""
        response = self.client.get(reverse('shyaka:login'))
        self.assertContains(response, 'csrfmiddlewaretoken')
    
    def test_change_password_endpoint_has_csrf_token(self):
        """Change password form must include CSRF token."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('shyaka:change_password'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'csrfmiddlewaretoken')
    
    def test_password_reset_endpoint_has_csrf_token(self):
        """Password reset form must include CSRF token."""
        response = self.client.get(reverse('shyaka:password_reset_request'))
        self.assertContains(response, 'csrfmiddlewaretoken')
    
    def test_edit_profile_endpoint_has_csrf_token(self):
        """Edit profile form must include CSRF token."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(
            reverse('shyaka:edit_user_profile', args=[self.user.id])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'csrfmiddlewaretoken')


class CSRFAttackPreventionTests(TestCase):
    """Test that CSRF attacks are actually prevented."""
    
    def setUp(self):
        """Set up test environment."""
        self.csrf_client = Client(enforce_csrf_checks=True)
        self.user = User.objects.create_user(
            username='victimuser',
            email='victim@example.com',
            password='victimpass123'
        )
        from .models import UserProfile
        UserProfile.objects.create(user=self.user)
    
    def test_attacker_cannot_submit_form_from_external_site(self):
        """
        Prevent attacker from forging profile update from external JavaScript.
        
        Simulates CSRF attack scenario:
        1. Victim logs into our site (authenticated)
        2. Victim visits attacker's website (still has valid session cookie)
        3. Attacker's site tries to POST form to our site
        4. POST is rejected because attacker doesn't have valid CSRF token
        """
        # Victim logs in
        self.csrf_client.login(username='victimuser', password='victimpass123')
        
        # Attacker tries to forge POST (without CSRF token)
        # Attacker's malicious script would try to do this:
        response = self.csrf_client.post(
            reverse('shyaka:profile'),
            {
                'first_name': 'Hacker',
                'last_name': 'Attack',
                'email': 'hacker@attacker.com',
                'bio': 'Account taken over'
            }
        )
        
        # Attack should be blocked
        self.assertEqual(response.status_code, 403)
        
        # Verify original data is unchanged
        victim = User.objects.get(username='victimuser')
        self.assertEqual(victim.email, 'victim@example.com')
