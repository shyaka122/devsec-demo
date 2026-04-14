"""
Tests for Role-Based Access Control (RBAC) in the User Authentication Service.
Tests cover authentication, authorization, and access control enforcement.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from .models import UserProfile
from .auth_utils import get_user_role, is_admin, is_staff


class UserRoleTests(TestCase):
    """Tests for role determination and role checking functions."""

    def setUp(self):
        """Set up test data with different user roles."""
        # Create groups
        self.admin_group = Group.objects.create(name='admin')
        self.staff_group = Group.objects.create(name='staff')
        
        # Create users
        self.admin_user = User.objects.create_user(
            username='admin',
            password='admin123'
        )
        self.admin_user.groups.add(self.admin_group)
        UserProfile.objects.create(user=self.admin_user)
        
        self.staff_user = User.objects.create_user(
            username='staff',
            password='staff123'
        )
        self.staff_user.groups.add(self.staff_group)
        UserProfile.objects.create(user=self.staff_user)
        
        self.regular_user = User.objects.create_user(
            username='user',
            password='user123'
        )
        UserProfile.objects.create(user=self.regular_user)
        
        self.anonymous_user = User()  # Not authenticated
    
    def test_get_user_role_admin(self):
        """Test that admin users are correctly identified."""
        self.assertEqual(get_user_role(self.admin_user), 'admin')
    
    def test_get_user_role_staff(self):
        """Test that staff users are correctly identified."""
        self.assertEqual(get_user_role(self.staff_user), 'staff')
    
    def test_get_user_role_user(self):
        """Test that regular users are correctly identified."""
        self.assertEqual(get_user_role(self.regular_user), 'user')
    
    def test_get_user_role_anonymous(self):
        """Test that anonymous users are correctly identified."""
        self.assertEqual(get_user_role(self.anonymous_user), 'anonymous')
    
    def test_is_admin_true(self):
        """Test is_admin returns True for admin users."""
        self.assertTrue(is_admin(self.admin_user))
    
    def test_is_admin_false_for_staff(self):
        """Test is_admin returns False for staff users."""
        self.assertFalse(is_admin(self.staff_user))
    
    def test_is_admin_false_for_user(self):
        """Test is_admin returns False for regular users."""
        self.assertFalse(is_admin(self.regular_user))
    
    def test_is_staff_for_admin(self):
        """Test is_staff returns True for admin users."""
        self.assertTrue(is_staff(self.admin_user))
    
    def test_is_staff_for_staff(self):
        """Test is_staff returns True for staff users."""
        self.assertTrue(is_staff(self.staff_user))
    
    def test_is_staff_false_for_user(self):
        """Test is_staff returns False for regular users."""
        self.assertFalse(is_staff(self.regular_user))


class AuthenticationTests(TestCase):
    """Tests for authentication views and behavior."""

    def setUp(self):
        """Set up test client and test user."""
        self.client = Client()
        self.username = 'testuser'
        self.password = 'testpass123'
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
            email='test@example.com'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_register_page_accessible_to_anonymous(self):
        """Test registration page is accessible to unauthenticated users."""
        response = self.client.get(reverse('shyaka:register'))
        self.assertEqual(response.status_code, 200)
    
    def test_register_redirects_authenticated_user(self):
        """Test authenticated users are redirected from register page."""
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('shyaka:register'))
        self.assertEqual(response.status_code, 302)
    
    def test_login_page_accessible_to_anonymous(self):
        """Test login page is accessible to unauthenticated users."""
        response = self.client.get(reverse('shyaka:login'))
        self.assertEqual(response.status_code, 200)
    
    def test_login_redirects_authenticated_user(self):
        """Test authenticated users are redirected from login page."""
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('shyaka:login'))
        self.assertEqual(response.status_code, 302)
    
    def test_successful_login(self):
        """Test successful user login."""
        response = self.client.post(
            reverse('shyaka:login'),
            {
                'username': self.username,
                'password': self.password,
            }
        )
        self.assertEqual(response.status_code, 302)
    
    def test_failed_login(self):
        """Test login fails with wrong password."""
        response = self.client.post(
            reverse('shyaka:login'),
            {
                'username': self.username,
                'password': 'wrongpassword',
            }
        )
        self.assertEqual(response.status_code, 200)


class AuthorizationTests(TestCase):
    """Tests for role-based access control enforcement."""

    def setUp(self):
        """Set up test data with different user roles."""
        self.client = Client()
        
        # Create groups
        self.admin_group = Group.objects.create(name='admin')
        self.staff_group = Group.objects.create(name='staff')
        
        # Create admin user
        self.admin_user = User.objects.create_user(
            username='admin',
            password='admin123'
        )
        self.admin_user.groups.add(self.admin_group)
        UserProfile.objects.create(user=self.admin_user)
        
        # Create staff user
        self.staff_user = User.objects.create_user(
            username='staff',
            password='staff123'
        )
        self.staff_user.groups.add(self.staff_group)
        UserProfile.objects.create(user=self.staff_user)
        
        # Create regular user
        self.regular_user = User.objects.create_user(
            username='user',
            password='user123'
        )
        UserProfile.objects.create(user=self.regular_user)
    
    def test_dashboard_requires_authentication(self):
        """Test dashboard is only accessible to authenticated users."""
        response = self.client.get(reverse('shyaka:dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_dashboard_accessible_to_authenticated(self):
        """Test authenticated users can access dashboard."""
        self.client.login(username='user', password='user123')
        response = self.client.get(reverse('shyaka:dashboard'))
        self.assertEqual(response.status_code, 200)
    
    def test_admin_dashboard_requires_admin_role(self):
        """Test admin dashboard is only accessible to admins."""
        # Try as regular user
        self.client.login(username='user', password='user123')
        response = self.client.get(reverse('shyaka:admin_dashboard'))
        self.assertEqual(response.status_code, 403)
    
    def test_admin_dashboard_accessible_to_admin(self):
        """Test admin can access admin dashboard."""
        self.client.login(username='admin', password='admin123')
        response = self.client.get(reverse('shyaka:admin_dashboard'))
        self.assertEqual(response.status_code, 200)
    
    def test_admin_dashboard_inaccessible_to_staff(self):
        """Test staff users cannot access admin dashboard."""
        self.client.login(username='staff', password='staff123')
        response = self.client.get(reverse('shyaka:admin_dashboard'))
        self.assertEqual(response.status_code, 403)
    
    def test_manage_users_requires_admin(self):
        """Test user management is only accessible to admins."""
        # Try as regular user
        self.client.login(username='user', password='user123')
        response = self.client.get(reverse('shyaka:manage_users'))
        self.assertEqual(response.status_code, 403)
    
    def test_manage_users_accessible_to_admin(self):
        """Test admin can access user management."""
        self.client.login(username='admin', password='admin123')
        response = self.client.get(reverse('shyaka:manage_users'))
        self.assertEqual(response.status_code, 200)
    
    def test_assign_role_requires_admin(self):
        """Test role assignment requires admin role."""
        self.client.login(username='user', password='user123')
        response = self.client.post(
            reverse('shyaka:assign_user_role'),
            {
                'user_id': self.staff_user.id,
                'role': 'admin',
            }
        )
        self.assertEqual(response.status_code, 403)
    
    def test_assign_role_by_admin(self):
        """Test admin can assign roles."""
        self.client.login(username='admin', password='admin123')
        response = self.client.post(
            reverse('shyaka:assign_user_role'),
            {
                'user_id': self.regular_user.id,
                'role': 'staff',
            }
        )
        self.assertEqual(response.status_code, 302)
        
        # Verify role was assigned
        self.regular_user.refresh_from_db()
        self.assertTrue(self.regular_user.groups.filter(name='staff').exists())


class AccessControlTests(TestCase):
    """Tests for access control policy enforcement."""

    def setUp(self):
        """Set up test data."""
        self.client = Client()
        
        # Create groups
        self.admin_group = Group.objects.create(name='admin')
        self.staff_group = Group.objects.create(name='staff')
        
        # Create users
        self.admin_user = User.objects.create_user(
            username='admin', password='admin123'
        )
        self.admin_user.groups.add(self.admin_group)
        UserProfile.objects.create(user=self.admin_user)
        
        self.staff_user = User.objects.create_user(
            username='staff', password='staff123'
        )
        self.staff_user.groups.add(self.staff_group)
        UserProfile.objects.create(user=self.staff_user)
        
        self.regular_user = User.objects.create_user(
            username='user', password='user123'
        )
        UserProfile.objects.create(user=self.regular_user)
    
    def test_anonymous_cannot_access_protected_views(self):
        """Test anonymous users cannot access protected views."""
        protected_urls = [
            reverse('shyaka:dashboard'),
            reverse('shyaka:profile'),
            reverse('shyaka:change_password'),
        ]
        
        for url in protected_urls:
            response = self.client.get(url)
            self.assertIn(response.status_code, [302, 403])  # Redirect or forbidden
    
    def test_privileged_actions_denied_to_standard_users(self):
        """Test standard users cannot perform privileged actions."""
        self.client.login(username='user', password='user123')
        
        # Try to access admin dashboard
        response = self.client.get(reverse('shyaka:admin_dashboard'))
        self.assertEqual(response.status_code, 403)
        
        # Try to manage users
        response = self.client.get(reverse('shyaka:manage_users'))
        self.assertEqual(response.status_code, 403)
    
    def test_unauthorized_access_returns_403(self):
        """Test unauthorized access returns 403 Forbidden."""
        self.client.login(username='user', password='user123')
        response = self.client.get(reverse('shyaka:admin_dashboard'))
        self.assertEqual(response.status_code, 403)


class ContextTests(TestCase):
    """Tests for context variables passed to templates."""

    def setUp(self):
        """Set up test data."""
        self.client = Client()
        
        # Create groups
        self.admin_group = Group.objects.create(name='admin')
        
        # Create admin user
        self.admin_user = User.objects.create_user(
            username='admin',
            password='admin123'
        )
        self.admin_user.groups.add(self.admin_group)
        UserProfile.objects.create(user=self.admin_user)
        
        # Create regular user
        self.regular_user = User.objects.create_user(
            username='user',
            password='user123'
        )
        UserProfile.objects.create(user=self.regular_user)
    
    def test_dashboard_context_includes_role_info(self):
        """Test dashboard context includes role information."""
        self.client.login(username='user', password='user123')
        response = self.client.get(reverse('shyaka:dashboard'))
        
        self.assertIn('user_role', response.context)
        self.assertIn('is_admin', response.context)
        self.assertIn('is_staff', response.context)
    
    def test_admin_context_for_admin_user(self):
        """Test admin context variables for admin users."""
        self.client.login(username='admin', password='admin123')
        response = self.client.get(reverse('shyaka:dashboard'))
        
        self.assertEqual(response.context['user_role'], 'admin')
        self.assertTrue(response.context['is_admin'])
