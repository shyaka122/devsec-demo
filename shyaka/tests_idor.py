"""
IDOR (Insecure Direct Object Reference) Tests

This test suite verifies that object-level access control is properly enforced
for user profiles. Tests ensure that:

1. Users can only access their own profile without proper authorization
2. Admins can access any user's profile
3. Unauthorized access attempts are denied with safe behavior (403/redirect)
4. The IDOR vulnerability is prevented across both view and edit operations
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from .models import UserProfile


class IDORProfileAccessTestCase(TestCase):
    """Test cases for IDOR protection on profile views."""
    
    def setUp(self):
        """Set up test users and profiles."""
        self.client = Client()
        
        # Create standard users
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='Password123!'
        )
        self.profile1 = UserProfile.objects.create(
            user=self.user1,
            bio='User 1 bio'
        )
        
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='Password123!'
        )
        self.profile2 = UserProfile.objects.create(
            user=self.user2,
            bio='User 2 bio'
        )
        
        # Create admin user
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='AdminPassword123!'
        )
        admin_group = Group.objects.get_or_create(name='admin')[0]
        self.admin_user.groups.add(admin_group)
        self.admin_profile = UserProfile.objects.create(
            user=self.admin_user,
            bio='Admin bio'
        )
    
    # ========================================================================
    # View User Profile Tests
    # ========================================================================
    
    def test_user_can_view_own_profile(self):
        """Test that user can view their own profile."""
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:view_user_profile', args=[self.user1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'User 1 bio')
    
    def test_user_cannot_view_other_user_profile_idor(self):
        """
        Test IDOR prevention: User1 attempts to access User2's profile.
        Should be denied with redirect.
        """
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:view_user_profile', args=[self.user2.id])
        response = self.client.get(url)
        
        # Should redirect (deny access)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)
    
    def test_unauthenticated_user_cannot_view_profile(self):
        """Test that unauthenticated users are redirected to login."""
        url = reverse('shyaka:view_user_profile', args=[self.user1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_admin_can_view_any_user_profile(self):
        """Test that admin users can view any user's profile."""
        self.client.login(username='admin', password='AdminPassword123!')
        
        # Admin views user1's profile
        url = reverse('shyaka:view_user_profile', args=[self.user1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'User 1 bio')
        
        # Admin views user2's profile
        url = reverse('shyaka:view_user_profile', args=[self.user2.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'User 2 bio')
    
    def test_nonexistent_user_profile_returns_404(self):
        """Test that accessing nonexistent user returns 404."""
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:view_user_profile', args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
    
    # ========================================================================
    # Edit User Profile Tests (POST)
    # ========================================================================
    
    def test_user_can_edit_own_profile(self):
        """Test that user can edit their own profile."""
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:edit_user_profile', args=[self.user1.id])
        
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'user1@example.com',
            'bio': 'Updated bio',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)
        
        # Verify profile was updated
        self.profile1.refresh_from_db()
        self.assertEqual(self.profile1.bio, 'Updated bio')
    
    def test_user_cannot_edit_other_user_profile_idor(self):
        """
        Test IDOR prevention: User1 attempts to edit User2's profile.
        Should be denied with redirect.
        """
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:edit_user_profile', args=[self.user2.id])
        
        data = {
            'first_name': 'Hacked',
            'last_name': 'User',
            'email': 'user2@example.com',
            'bio': 'HACKED PROFILE',
        }
        response = self.client.post(url, data)
        
        # Should redirect (deny access)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)
        
        # Verify profile was NOT modified
        self.profile2.refresh_from_db()
        self.assertEqual(self.profile2.bio, 'User 2 bio')
    
    def test_unauthenticated_user_cannot_edit_profile(self):
        """Test that unauthenticated users are redirected to login."""
        url = reverse('shyaka:edit_user_profile', args=[self.user1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_admin_can_edit_any_user_profile(self):
        """Test that admin users can edit any user's profile."""
        self.client.login(username='admin', password='AdminPassword123!')
        url = reverse('shyaka:edit_user_profile', args=[self.user1.id])
        
        data = {
            'first_name': 'AdminEdited',
            'last_name': 'User',
            'email': 'user1@example.com',
            'bio': 'Admin edited this profile',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)
        
        # Verify profile was updated
        self.profile1.refresh_from_db()
        self.assertEqual(self.profile1.bio, 'Admin edited this profile')
    
    def test_edit_profile_get_request_loads_form(self):
        """Test that GET request to edit profile loads the form."""
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:edit_user_profile', args=[self.user1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'form')
    
    def test_nonexistent_profile_edit_returns_404(self):
        """Test that editing nonexistent user returns 404."""
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:edit_user_profile', args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
    
    # ========================================================================
    # Access Control Matrix Tests
    # ========================================================================
    
    def test_access_control_matrix_view_user_profile(self):
        """
        Access control matrix for view_user_profile endpoint:
        
        | User Type | Own Profile | Other Profile | Admin Profile |
        |-----------|-------------|---------------|---------------|
        | Anonymous | 302/Login   | 302/Login     | 302/Login     |
        | User      | 200 OK      | 302/Redirect  | 302/Redirect  |
        | Admin     | 200 OK      | 200 OK        | 200 OK        |
        """
        # Anonymous access
        url = reverse('shyaka:view_user_profile', args=[self.user1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        
        # User accessing own profile
        self.client.login(username='user1', password='Password123!')
        response = self.client.get(reverse('shyaka:view_user_profile', args=[self.user1.id]))
        self.assertEqual(response.status_code, 200)
        self.client.logout()
        
        # User accessing other profile
        self.client.login(username='user1', password='Password123!')
        response = self.client.get(reverse('shyaka:view_user_profile', args=[self.user2.id]))
        self.assertEqual(response.status_code, 302)
        self.client.logout()
        
        # Admin accessing any profile
        self.client.login(username='admin', password='AdminPassword123!')
        response = self.client.get(reverse('shyaka:view_user_profile', args=[self.user1.id]))
        self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse('shyaka:view_user_profile', args=[self.user2.id]))
        self.assertEqual(response.status_code, 200)


class IDORExistenceLeakTestCase(TestCase):
    """Test cases for preventing existence information leakage."""
    
    def setUp(self):
        """Set up test users."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='Password123!'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_nonexistent_user_id_returns_404_not_403(self):
        """
        Test that accessing a nonexistent user returns 404 (not found),
        not 403 (forbidden). This prevents leaking information about
        which user IDs exist in the system.
        """
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:view_user_profile', args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
    
    def test_unauthorized_access_returns_redirect_safe_behavior(self):
        """
        Test that unauthorized access returns a safe response (redirect),
        not a 403, to avoid information leakage about user ID validity.
        """
        user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='Password123!'
        )
        UserProfile.objects.create(user=user2)
        
        self.client.login(username='user1', password='Password123!')
        url = reverse('shyaka:view_user_profile', args=[user2.id])
        response = self.client.get(url)
        # Should be 302 (redirect), not 403 (forbidden)
        self.assertEqual(response.status_code, 302)


class IDORMultipleAttemptTestCase(TestCase):
    """Test cases for multiple IDOR attack attempts."""
    
    def setUp(self):
        """Set up test users."""
        self.client = Client()
        
        # Create multiple users
        self.users = []
        for i in range(5):
            user = User.objects.create_user(
                username=f'user{i}',
                email=f'user{i}@example.com',
                password='Password123!'
            )
            UserProfile.objects.create(user=user, bio=f'User {i} bio')
            self.users.append(user)
    
    def test_user_cannot_access_multiple_other_profiles(self):
        """
        Test that a user attempting to access multiple other profiles
        through IDOR are all denied.
        """
        attacker = self.users[0]
        self.client.login(username=attacker.username, password='Password123!')
        
        # Try to access all other users' profiles
        for target_user in self.users[1:]:
            url = reverse('shyaka:view_user_profile', args=[target_user.id])
            response = self.client.get(url)
            self.assertEqual(
                response.status_code,
                302,
                f"User {attacker.username} should not access {target_user.username}"
            )
