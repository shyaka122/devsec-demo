"""
Comprehensive tests for stored XSS vulnerability prevention in user-controlled content.

Tests verify that:
- Malicious scripts in user bio are properly escaped and not executed
- HTML markup in user content is displayed as text, not rendered
- Event handlers are disabled and cannot execute
- User-controlled content cannot break out of DOM context
- Legitimate text content renders normally
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils.html import escape
from .models import UserProfile


class StoredXSSUserBioTests(TestCase):
    """Test stored XSS prevention in user profile bio field."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()
        
        # Create normal user
        self.user = User.objects.create_user(
            username='normaluser',
            email='normal@example.com',
            password='Password123!'
        )
        self.user_profile = UserProfile.objects.create(
            user=self.user,
            bio='This is a normal bio'
        )
        
        # Create another user for viewing profile
        self.viewer = User.objects.create_user(
            username='viewer',
            email='viewer@example.com',
            password='Password123!'
        )
        
        # Create admin user for broader access
        self.admin = User.objects.create_user(
            username='adminuser',
            email='admin@example.com',
            password='Password123!',
            is_staff=True,
            is_superuser=True
        )
        
        self.view_profile_url = reverse('shyaka:view_user_profile', args=[self.user.id])
        self.dashboard_url = reverse('shyaka:dashboard')
    
    def test_script_tag_in_bio_is_escaped_in_view_profile(self):
        """Test that <script> tags in bio are escaped when viewing profile."""
        # Inject malicious script tag
        malicious_bio = '<script>alert("XSS")</script>Normal text'
        self.user_profile.bio = malicious_bio
        self.user_profile.save()
        
        # Admin can view any profile
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        
        # Verify script tag is escaped and displayed as text
        content = response.content.decode('utf-8')
        self.assertIn(escape(malicious_bio), content)
        # The raw script tag opening should NOT be in the HTML
        self.assertNotIn('<script>alert', content)
    
    def test_script_tag_in_bio_is_escaped_in_dashboard(self):
        """Test that <script> tags in bio are escaped in dashboard display."""
        malicious_bio = '<script>alert("HACKED")</script>'
        self.user_profile.bio = malicious_bio
        self.user_profile.save()
        
        # User sees their own bio in dashboard
        self.client.login(username='normaluser', password='Password123!')
        response = self.client.get(self.dashboard_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify script tag is escaped
        self.assertIn(escape(malicious_bio), content)
        # Raw script tag should not be in HTML
        self.assertNotIn('<script>alert', content)
    
    def test_html_markup_in_bio_is_escaped(self):
        """Test that HTML markup in bio is displayed as text, not rendered."""
        html_bio = '<img src=x onerror=alert("XSS")> <h1>Hacker</h1>'
        self.user_profile.bio = html_bio
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify dangerous HTML is escaped in the content
        self.assertIn(escape(html_bio), content)
        # Raw img and h1 tags should not be executable (verify escaped form exists)
        self.assertNotIn('<img src=x onerror', content)
        self.assertIn('&lt;h1&gt;', content)  # Should be escaped h1 tag
    
    def test_event_handler_in_bio_is_escaped(self):
        """Test that event handlers in bio are escaped and cannot execute."""
        event_bio = '<div onclick=alert("XSS")>Click me</div>'
        self.user_profile.bio = event_bio
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify onclick handler is escaped
        self.assertIn(escape(event_bio), content)
        # Raw tag opening should not be in HTML
        self.assertNotIn('<div onclick', content)
    
    def test_svg_xss_vector_in_bio_is_escaped(self):
        """Test that SVG-based XSS vectors are escaped."""
        svg_xss = '<svg onload=alert("XSS")></svg>'
        self.user_profile.bio = svg_xss
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify SVG with event handler is escaped
        self.assertIn(escape(svg_xss), content)
        # Raw SVG tag should not be in HTML
        self.assertNotIn('<svg onload', content)
    
    def test_javascript_protocol_in_bio_is_escaped(self):
        """Test that javascript: protocol URLs are escaped."""
        js_proto = '<a href="javascript:alert(\'XSS\')">Click</a>'
        self.user_profile.bio = js_proto
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify javascript: protocol is escaped
        self.assertIn(escape(js_proto), content)
        # Raw anchor tag should not be in HTML
        self.assertNotIn('<a href="javascript', content)
    
    def test_data_uri_xss_in_bio_is_escaped(self):
        """Test that data: URI XSS vectors are escaped."""
        data_uri = '<img src="data:text/html,<script>alert(\'XSS\')</script>">'
        self.user_profile.bio = data_uri
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify data: URI is escaped
        self.assertIn(escape(data_uri), content)
        # Raw img tag should not be in HTML
        self.assertNotIn('<img src="data', content)
    
    def test_legitimate_text_renders_normally(self):
        """Test that legitimate text content renders without modification."""
        legitimate_bio = 'Hello! I am a software engineer interested in security.'
        self.user_profile.bio = legitimate_bio
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify legitimate content appears in the response
        self.assertIn(legitimate_bio, content)
    
    def test_special_characters_in_bio_are_escaped(self):
        """Test that special characters are properly escaped."""
        special_bio = 'Price < $100 & > FREE! Use "quotes" and \'apostrophes\''
        self.user_profile.bio = special_bio
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify special characters are properly escaped
        self.assertIn(escape(special_bio), content)
        # Verify that < and > are converted to HTML entities
        self.assertIn('&lt;', content)
        self.assertIn('&gt;', content)
    
    def test_multiple_xss_vectors_all_escaped(self):
        """Test that multiple XSS vectors in one bio are all escaped."""
        multi_xss = '<script>alert(1)</script><img src=x onerror=alert(2)><svg onload=alert(3)>'
        self.user_profile.bio = multi_xss
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify all vectors are escaped
        self.assertIn(escape(multi_xss), content)
        # Raw tags should not be executable
        self.assertNotIn('<script>alert', content)
        self.assertNotIn('<img src=x onerror', content)
        self.assertNotIn('<svg onload', content)
    
    def test_encoded_xss_attacks_are_escaped(self):
        """Test that HTML-encoded XSS attacks are displayed safely."""
        encoded_xss = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
        self.user_profile.bio = encoded_xss
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # The escape filter will double-escape, so we check for the double-escaped version
        # or just verify the raw script tag is not present
        self.assertNotIn('<script>alert', content)
    
    def test_null_bytes_in_bio_handled_safely(self):
        """Test that null bytes and control characters are handled safely."""
        null_byte_bio = 'Normal\x00text with null'
        self.user_profile.bio = null_byte_bio
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        # Should not crash when rendering
        self.assertIn('Normal', response.content.decode('utf-8'))
    
    def test_very_long_bio_with_xss_is_escaped(self):
        """Test that very long bios with XSS payloads are properly escaped."""
        long_xss = '<script>alert("XSS")</script>' * 100
        self.user_profile.bio = long_xss
        self.user_profile.save()
        
        self.client.login(username='adminuser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify script tags are escaped even in very long content
        # Raw script tag should not appear
        self.assertNotIn('<script>alert', content)
    
    def test_user_can_view_own_profile_with_xss_content_safely(self):
        """Test that users can safely view their own profile even with malicious bio."""
        xss_bio = '<img src=x onerror=alert("HACKED")>'
        self.user_profile.bio = xss_bio
        self.user_profile.save()
        
        # User views their own profile
        self.client.login(username='normaluser', password='Password123!')
        response = self.client.get(self.view_profile_url)
        
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify content is escaped (xss_bio is rendered as text, not as HTML)
        self.assertIn(escape(xss_bio), content)
        # Verify raw img tag is NOT in content (would indicate unescaped HTML)
        self.assertNotIn('<img src=x', content)


class DOMContextEscapingTests(TestCase):
    """Test that user content cannot break out of its DOM context."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='Password123!',
            is_staff=True,
            is_superuser=True
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='Password123!'
        )
        self.profile = UserProfile.objects.create(user=self.user)
        self.view_url = reverse('shyaka:view_user_profile', args=[self.user.id])
    
    def test_bio_cannot_close_paragraph_tag(self):
        """Test that user bio cannot close enclosing paragraph tags."""
        closing_bio = '</p><script>alert("XSS")</script><p>'
        self.profile.bio = closing_bio
        self.profile.save()
        
        self.client.login(username='admin', password='Password123!')
        response = self.client.get(self.view_url)
        
        content = response.content.decode('utf-8')
        # Script tag should be escaped, not executed
        # Raw script tag should not appear
        self.assertNotIn('<script>alert', content)
    
    def test_bio_cannot_inject_script_after_escaping(self):
        """Test that even with complex escaping attempts, script injection is prevented."""
        injection = '"><script>alert("XSS")</script><span class="'
        self.profile.bio = injection
        self.profile.save()
        
        self.client.login(username='admin', password='Password123!')
        response = self.client.get(self.view_url)
        
        content = response.content.decode('utf-8')
        self.assertNotIn('<script>', content)
    
    def test_bio_with_html_comment_escape_attempt(self):
        """Test that HTML comment-based escape attempts are handled."""
        comment_escape = '--><script>alert("XSS")</script><!--'
        self.profile.bio = comment_escape
        self.profile.save()
        
        self.client.login(username='admin', password='Password123!')
        response = self.client.get(self.view_url)
        
        content = response.content.decode('utf-8')
        # Raw closing tag attempt should not create executable script
        self.assertNotIn('--><script', content)


class AttributeEscapingTests(TestCase):
    """Test that user content cannot inject malicious attributes."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='Password123!',
            is_staff=True,
            is_superuser=True
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='Password123!'
        )
        self.profile = UserProfile.objects.create(user=self.user)
        self.view_url = reverse('shyaka:view_user_profile', args=[self.user.id])
    
    def test_bio_cannot_inject_onclick_attribute(self):
        """Test that user bio cannot inject onclick handlers."""
        onclick_attempt = '" onclick="alert(\'XSS\')" class="'
        self.profile.bio = onclick_attempt
        self.profile.save()
        
        self.client.login(username='admin', password='Password123!')
        response = self.client.get(self.view_url)
        
        content = response.content.decode('utf-8')
        # Raw onclick handler should not appear
        self.assertNotIn(" onclick=\"", content)
    
    def test_bio_cannot_inject_data_attributes(self):
        """Test that user bio cannot inject data attributes."""
        data_attr = '" data-xss="<script>alert(\'XSS\')</script>" class="'
        self.profile.bio = data_attr
        self.profile.save()
        
        self.client.login(username='admin', password='Password123!')
        response = self.client.get(self.view_url)
        
        content = response.content.decode('utf-8')
        # The injection should be escaped
        self.assertIn(escape(data_attr), content)
        # Raw data attribute should not appear in unescaped form
        self.assertNotIn(" data-xss=\"", content)


class RegressionTests(TestCase):
    """Test that XSS fixes don't break normal functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='Password123!'
        )
        self.profile = UserProfile.objects.create(user=self.user)
        self.dashboard_url = reverse('shyaka:dashboard')
        self.profile_url = reverse('shyaka:profile')
        self.edit_url = reverse('shyaka:edit_user_profile', args=[self.user.id])
    
    def test_normal_profile_text_still_displays(self):
        """Test that normal profile text displays correctly."""
        normal_bio = 'I am a software engineer'
        self.profile.bio = normal_bio
        self.profile.save()
        
        self.client.login(username='testuser', password='Password123!')
        response = self.client.get(self.dashboard_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(normal_bio, response.content.decode('utf-8'))
    
    def test_profile_edit_still_works_with_special_chars(self):
        """Test that profile editing works with special characters."""
        self.client.login(username='testuser', password='Password123!')
        
        new_bio = 'I love C++ and Python! Price: $100 > 50 & free'
        data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'bio': new_bio
        }
        
        response = self.client.post(self.edit_url, data)
        self.assertEqual(response.status_code, 302)
        
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.bio, new_bio)
    
    def test_multiline_bio_displays_correctly(self):
        """Test that multiline bios display correctly."""
        multiline_bio = '''Line 1
Line 2
Line 3'''
        self.profile.bio = multiline_bio
        self.profile.save()
        
        self.client.login(username='testuser', password='Password123!')
        response = self.client.get(self.dashboard_url)
        
        self.assertEqual(response.status_code, 200)
        # Content should be in response (though newlines might be preserved or converted)
        self.assertIn('Line 1', response.content.decode('utf-8'))
    
    def test_bio_with_urls_displays_correctly(self):
        """Test that bios with URLs display correctly (as text)."""
        url_bio = 'Check out https://example.com for more info'
        self.profile.bio = url_bio
        self.profile.save()
        
        self.client.login(username='testuser', password='Password123!')
        response = self.client.get(self.dashboard_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(url_bio, response.content.decode('utf-8'))
    
    def test_bio_with_email_addresses_displays_correctly(self):
        """Test that bios with email addresses display correctly."""
        email_bio = 'Contact me at user@example.com'
        self.profile.bio = email_bio
        self.profile.save()
        
        self.client.login(username='testuser', password='Password123!')
        response = self.client.get(self.dashboard_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(email_bio, response.content.decode('utf-8'))
    
    def test_empty_bio_displays_default_text(self):
        """Test that empty bio shows default text."""
        self.profile.bio = ''
        self.profile.save()
        
        self.client.login(username='testuser', password='Password123!')
        response = self.client.get(reverse('shyaka:view_user_profile', args=[self.user.id]))
        
        self.assertEqual(response.status_code, 200)
        # Should show default text for missing bio (could be in various cases)
        content = response.content.decode('utf-8')
        # Check for the default value
        self.assertTrue(
            'no bio provided' in content.lower() or 
            'no bio' in content.lower(),
            'Default bio text not found in response'
        )
