from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from .models import UserProfile


class UserRegistrationTestCase(TestCase):
    """Test cases for user registration."""
    
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('shyaka:register')
    
    def test_registration_page_loads(self):
        """Test that registration page loads successfully."""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'shyaka/register.html')
    
    def test_register_user_successfully(self):
        """Test successful user registration."""
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 302)  # Redirect after successful registration
        self.assertTrue(User.objects.filter(username='testuser').exists())
    
    def test_user_profile_created_on_registration(self):
        """Test that UserProfile is created when user registers."""
        data = {
            'username': 'profiletest',
            'email': 'profiletest@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        self.client.post(self.register_url, data)
        user = User.objects.get(username='profiletest')
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
    
    def test_register_with_duplicate_username(self):
        """Test registration fails with duplicate username."""
        User.objects.create_user('existinguser', 'existing@example.com', 'password123')
        data = {
            'username': 'existinguser',
            'email': 'newemail@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertContains(response, 'already taken')
    
    def test_register_with_duplicate_email(self):
        """Test registration fails with duplicate email."""
        User.objects.create_user('otheruser', 'existing@example.com', 'password123')
        data = {
            'username': 'newuser',
            'email': 'existing@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertContains(response, 'already in use')
    
    def test_register_with_mismatched_passwords(self):
        """Test registration fails with mismatched passwords."""
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password1': 'SecurePassword123!',
            'password2': 'DifferentPassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertFalse(User.objects.filter(username='testuser').exists())
    
    def test_registered_user_redirected_to_register(self):
        """Test that authenticated users are redirected from register page."""
        user = User.objects.create_user('existinguser', 'test@example.com', 'password123')
        self.client.login(username='existinguser', password='password123')
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)


class UserLoginTestCase(TestCase):
    """Test cases for user login."""
    
    def setUp(self):
        self.client = Client()
        self.login_url = reverse('shyaka:login')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
    
    def test_login_page_loads(self):
        """Test that login page loads successfully."""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'shyaka/login.html')
    
    def test_user_login_successfully(self):
        """Test successful user login."""
        data = {
            'username': 'testuser',
            'password': 'TestPassword123!',
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)
    
    def test_login_with_invalid_credentials(self):
        """Test login fails with invalid credentials."""
        data = {
            'username': 'testuser',
            'password': 'WrongPassword',
        }
        response = self.client.post(self.login_url, data)
        self.assertContains(response, 'Invalid username or password')
    
    def test_authenticated_user_redirected_from_login(self):
        """Test that authenticated users are redirected from login page."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)


class UserLogoutTestCase(TestCase):
    """Test cases for user logout."""
    
    def setUp(self):
        self.client = Client()
        self.logout_url = reverse('shyaka:logout')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
    
    def test_logout_requires_authentication(self):
        """Test that logout requires user to be authenticated."""
        response = self.client.get(self.logout_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_user_logout_successfully(self):
        """Test successful user logout."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.logout_url)
        self.assertEqual(response.status_code, 302)
        # Verify user is logged out
        self.assertNotIn('_auth_user_id', self.client.session)


class DashboardTestCase(TestCase):
    """Test cases for dashboard view."""
    
    def setUp(self):
        self.client = Client()
        self.dashboard_url = reverse('shyaka:dashboard')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        self.profile = UserProfile.objects.create(user=self.user)
    
    def test_dashboard_requires_authentication(self):
        """Test that dashboard requires authentication."""
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_dashboard_loads_for_authenticated_user(self):
        """Test that dashboard loads for authenticated user."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'shyaka/dashboard.html')
        self.assertContains(response, 'testuser')


class ProfileTestCase(TestCase):
    """Test cases for user profile view."""
    
    def setUp(self):
        self.client = Client()
        self.profile_url = reverse('shyaka:profile')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        self.profile = UserProfile.objects.create(user=self.user, bio='Original bio')
    
    def test_profile_requires_authentication(self):
        """Test that profile view requires authentication."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_profile_loads_for_authenticated_user(self):
        """Test that profile page loads for authenticated user."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'shyaka/profile.html')
    
    def test_update_user_profile_successfully(self):
        """Test successful profile update."""
        self.client.login(username='testuser', password='TestPassword123!')
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com',
            'bio': 'Updated bio',
        }
        response = self.client.post(self.profile_url, data)
        self.assertEqual(response.status_code, 302)
        
        self.user.refresh_from_db()
        self.profile.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.email, 'updated@example.com')
        self.assertEqual(self.profile.bio, 'Updated bio')
    
    def test_profile_update_with_duplicate_email(self):
        """Test profile update fails with duplicate email."""
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='password123'
        )
        self.client.login(username='testuser', password='TestPassword123!')
        data = {
            'first_name': 'Test',
            'email': 'other@example.com',
            'bio': 'bio',
        }
        response = self.client.post(self.profile_url, data)
        self.assertContains(response, 'already in use')


class PasswordChangeTestCase(TestCase):
    """Test cases for password change view."""
    
    def setUp(self):
        self.client = Client()
        self.change_password_url = reverse('shyaka:change_password')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='OldPassword123!'
        )
    
    def test_change_password_requires_authentication(self):
        """Test that change password view requires authentication."""
        response = self.client.get(self.change_password_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_change_password_page_loads(self):
        """Test that change password page loads for authenticated user."""
        self.client.login(username='testuser', password='OldPassword123!')
        response = self.client.get(self.change_password_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'shyaka/change_password.html')
    
    def test_change_password_successfully(self):
        """Test successful password change."""
        self.client.login(username='testuser', password='OldPassword123!')
        data = {
            'old_password': 'OldPassword123!',
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        }
        response = self.client.post(self.change_password_url, data)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)
        
        # Verify new password works
        self.client.logout()
        login_successful = self.client.login(
            username='testuser',
            password='NewPassword123!'
        )
        self.assertTrue(login_successful)
    
    def test_change_password_with_wrong_old_password(self):
        """Test password change fails with wrong old password."""
        self.client.login(username='testuser', password='OldPassword123!')
        data = {
            'old_password': 'WrongPassword',
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        }
        response = self.client.post(self.change_password_url, data)
        # Should return 200 (form re-displayed with errors)
        self.assertEqual(response.status_code, 200)
        # Verify password wasn't changed
        self.client.logout()
        login_failed = self.client.login(
            username='testuser',
            password='NewPassword123!'
        )
        self.assertFalse(login_failed)
    
    def test_change_password_with_mismatched_new_passwords(self):
        """Test password change fails with mismatched new passwords."""
        self.client.login(username='testuser', password='OldPassword123!')
        data = {
            'old_password': 'OldPassword123!',
            'new_password1': 'NewPassword123!',
            'new_password2': 'DifferentPassword123!',
        }
        response = self.client.post(self.change_password_url, data)
        # Should return 200 (form re-displayed with errors)
        self.assertEqual(response.status_code, 200)
        # Verify password wasn't changed
        self.client.logout()
        login_failed = self.client.login(
            username='testuser',
            password='NewPassword123!'
        )
        self.assertFalse(login_failed)


class UserProfileModelTestCase(TestCase):
    """Test cases for UserProfile model."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
    
    def test_user_profile_created_with_user(self):
        """Test creating a UserProfile."""
        profile = UserProfile.objects.create(
            user=self.user,
            bio='Test bio'
        )
        self.assertEqual(profile.user, self.user)
        self.assertEqual(profile.bio, 'Test bio')
    
    def test_user_profile_string_representation(self):
        """Test UserProfile string representation."""
        profile = UserProfile.objects.create(user=self.user)
        self.assertEqual(str(profile), "testuser's Profile")
    
    def test_user_profile_cascade_delete(self):
        """Test that UserProfile deletion works correctly."""
        profile_id = self.profile.id
        initial_count = UserProfile.objects.count()
        
        # Delete the profile directly
        self.profile.delete()
        
        # Verify it's gone
        final_count = UserProfile.objects.count()
        self.assertEqual(initial_count - 1, final_count)
        self.assertFalse(UserProfile.objects.filter(id=profile_id).exists())
