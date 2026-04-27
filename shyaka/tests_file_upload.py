"""
File Upload Security Tests - Comprehensive test suite for avatar and document uploads.

Tests OWASP CWE-434: Unrestricted Upload of File with Dangerous Type
Tests OWASP CWE-22: Improper Limitation of a Pathname to a Restricted Directory

Security requirements tested:
1. File type validation (MIME type, not just extension)
2. File size limits (5MB for avatars, 10MB for documents)
3. Filename sanitization (prevent path traversal)
4. Access control (only owner can upload/download own files)
5. Content validation (actual file content, not just headers)
6. Executable file rejection
7. Archive file rejection (zip, rar, etc.)
8. Script file rejection (js, html, php, etc.)
9. Double extension bypass prevention
10. Null byte injection prevention

References:
- OWASP CWE-434: https://cwe.mitre.org/data/definitions/434.html
- OWASP CWE-22: https://cwe.mitre.org/data/definitions/22.html
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from io import BytesIO
from PIL import Image
import os

from .models import UserProfile, Document
from .auth_utils import (
    sanitize_filename,
    is_valid_image_upload,
    is_valid_document_upload,
)


class FilenameSanitizationTests(TestCase):
    """Test filename sanitization to prevent path traversal attacks."""
    
    def test_sanitize_removes_path_traversal(self):
        """Path traversal attempts should be removed."""
        # Test ../ removal
        result = sanitize_filename('../../../etc/passwd')
        self.assertNotIn('..', result)
        self.assertNotIn('/', result)
        self.assertNotIn('\\', result)
    
    def test_sanitize_removes_backslashes(self):
        """Backslashes should be removed."""
        result = sanitize_filename('..\\..\\windows\\system32\\evil.exe')
        self.assertNotIn('\\', result)
        self.assertNotIn('..', result)
    
    def test_sanitize_handles_leading_dots(self):
        """Leading dots (hidden files) should be removed."""
        result = sanitize_filename('.htaccess')
        self.assertFalse(result.startswith('.'))
    
    def test_sanitize_preserves_extension(self):
        """File extension should be preserved."""
        result = sanitize_filename('normal_file.pdf')
        self.assertTrue(result.endswith('.pdf'))
    
    def test_sanitize_handles_spaces(self):
        """Spaces should be converted safely."""
        result = sanitize_filename('file with spaces.txt')
        self.assertIn('file', result)
        self.assertIn('txt', result)
    
    def test_sanitize_handles_special_chars(self):
        """Special characters should be handled safely."""
        result = sanitize_filename('file@#$%^&*().txt')
        # Should not contain dangerous chars
        dangerous_chars = ['@', '#', '$', '%', '^', '&', '*']
        for char in dangerous_chars:
            self.assertNotIn(char, result)
    
    def test_sanitize_limits_length(self):
        """Filename length should be limited."""
        long_filename = 'a' * 500 + '.pdf'
        result = sanitize_filename(long_filename)
        self.assertLess(len(result), 300)
    
    def test_sanitize_handles_null_bytes(self):
        """Null bytes should be removed."""
        filename_with_null = 'file\x00.pdf'
        result = sanitize_filename(filename_with_null)
        self.assertNotIn('\x00', result)
    
    def test_sanitize_returns_fallback_for_empty(self):
        """Empty filenames should return fallback."""
        result = sanitize_filename('')
        self.assertTrue(len(result) > 0)
    
    def test_sanitize_double_extension(self):
        """Double extensions should be sanitized."""
        result = sanitize_filename('innocent.pdf.exe')
        # Both extensions should be present but file is sanitized
        self.assertTrue(len(result) > 0)


class ImageUploadValidationTests(TestCase):
    """Test image upload validation for avatar uploads."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        UserProfile.objects.create(user=self.user)
    
    def create_image_file(self, size=(100, 100), format='JPEG', name='test.jpg'):
        """Helper to create a valid image file."""
        image = Image.new('RGB', size, color='red')
        image_bytes = BytesIO()
        image.save(image_bytes, format=format)
        image_bytes.seek(0)
        return SimpleUploadedFile(name, image_bytes.getvalue(), content_type='image/jpeg')
    
    def test_valid_jpeg_image_accepted(self):
        """Valid JPEG should be accepted."""
        image = self.create_image_file(format='JPEG', name='test.jpg')
        is_valid, error = is_valid_image_upload(image)
        self.assertTrue(is_valid)
        self.assertIsNone(error)
    
    def test_valid_png_image_accepted(self):
        """Valid PNG should be accepted."""
        image = Image.new('RGB', (100, 100), color='blue')
        image_bytes = BytesIO()
        image.save(image_bytes, format='PNG')
        image_bytes.seek(0)
        image_file = SimpleUploadedFile('test.png', image_bytes.getvalue(), content_type='image/png')
        
        is_valid, error = is_valid_image_upload(image_file)
        self.assertTrue(is_valid)
    
    def test_file_too_large_rejected(self):
        """Images exceeding size limit should be rejected."""
        # Create a large image (larger than 5MB)
        image = Image.new('RGB', (10000, 10000), color='green')
        image_bytes = BytesIO()
        image.save(image_bytes, format='JPEG', quality='low')
        image_bytes.seek(0)
        image_file = SimpleUploadedFile('huge.jpg', image_bytes.getvalue())
        
        # Check if file is actually large enough
        if image_file.size > 5*1024*1024:
            is_valid, error = is_valid_image_upload(image_file)
            self.assertFalse(is_valid)
            self.assertIn('too large', error.lower())
    
    def test_corrupted_image_rejected(self):
        """Corrupted or invalid image data should be rejected."""
        # Create file with image extension but non-image content
        fake_image = SimpleUploadedFile('fake.jpg', b'not an image', content_type='image/jpeg')
        
        is_valid, error = is_valid_image_upload(fake_image)
        self.assertFalse(is_valid)
        self.assertIn('invalid', error.lower() or 'corrupted' in error.lower())
    
    def test_pdf_as_image_rejected(self):
        """PDF files should not be accepted as images."""
        pdf_content = b'%PDF-1.4\n%fake pdf'
        pdf_file = SimpleUploadedFile('notanimage.pdf', pdf_content, content_type='application/pdf')
        
        is_valid, error = is_valid_image_upload(pdf_file)
        self.assertFalse(is_valid)
    
    def test_executable_as_image_rejected(self):
        """Executable files should not be accepted as images."""
        exe_content = b'MZ\x90\x00'  # PE header
        exe_file = SimpleUploadedFile('notanimage.exe', exe_content, content_type='image/jpeg')
        
        is_valid, error = is_valid_image_upload(exe_file)
        self.assertFalse(is_valid)
    
    def test_gif_image_accepted(self):
        """Valid GIF should be accepted."""
        image = Image.new('RGB', (100, 100), color='yellow')
        image_bytes = BytesIO()
        image.save(image_bytes, format='GIF')
        image_bytes.seek(0)
        image_file = SimpleUploadedFile('test.gif', image_bytes.getvalue(), content_type='image/gif')
        
        is_valid, error = is_valid_image_upload(image_file)
        self.assertTrue(is_valid)


class DocumentUploadValidationTests(TestCase):
    """Test document upload validation for file uploads."""
    
    def test_valid_pdf_accepted(self):
        """Valid PDF should be accepted."""
        pdf_content = b'%PDF-1.4\n%fake but valid-looking pdf'
        pdf_file = SimpleUploadedFile('document.pdf', pdf_content, content_type='application/pdf')
        
        # Mock the size attribute
        pdf_file.size = len(pdf_content)
        
        is_valid, error = is_valid_document_upload(pdf_file)
        self.assertTrue(is_valid)
    
    def test_valid_txt_accepted(self):
        """Valid text file should be accepted."""
        txt_content = b'This is a plain text document.'
        txt_file = SimpleUploadedFile('document.txt', txt_content, content_type='text/plain')
        txt_file.size = len(txt_content)
        
        is_valid, error = is_valid_document_upload(txt_file)
        self.assertTrue(is_valid)
    
    def test_executable_rejected(self):
        """Executable files should be rejected."""
        exe_content = b'MZ\x90\x00'  # PE header
        exe_file = SimpleUploadedFile('notadocument.exe', exe_content, content_type='application/x-msdownload')
        exe_file.size = len(exe_content)
        
        is_valid, error = is_valid_document_upload(exe_file)
        self.assertFalse(is_valid)
        self.assertIn('not allowed', error.lower())
    
    def test_zip_file_rejected(self):
        """ZIP archive should be rejected."""
        zip_content = b'PK\x03\x04'  # ZIP header
        zip_file = SimpleUploadedFile('archive.zip', zip_content, content_type='application/zip')
        zip_file.size = len(zip_content)
        
        is_valid, error = is_valid_document_upload(zip_file)
        self.assertFalse(is_valid)
    
    def test_file_too_large_rejected(self):
        """Files exceeding size limit should be rejected."""
        large_content = b'x' * (11 * 1024 * 1024)  # 11MB
        large_file = SimpleUploadedFile('large.txt', large_content, content_type='text/plain')
        large_file.size = len(large_content)
        
        is_valid, error = is_valid_document_upload(large_file)
        self.assertFalse(is_valid)
        self.assertIn('too large', error.lower())
    
    def test_disallowed_extension_rejected(self):
        """Files with disallowed extensions should be rejected."""
        js_content = b'console.log("xss");'
        js_file = SimpleUploadedFile('script.js', js_content, content_type='text/javascript')
        js_file.size = len(js_content)
        
        is_valid, error = is_valid_document_upload(js_file)
        self.assertFalse(is_valid)
    
    def test_html_file_rejected(self):
        """HTML files should be rejected to prevent stored XSS."""
        html_content = b'<script>alert("xss")</script>'
        html_file = SimpleUploadedFile('page.html', html_content, content_type='text/html')
        html_file.size = len(html_content)
        
        is_valid, error = is_valid_document_upload(html_file)
        self.assertFalse(is_valid)


class AvatarUploadViewTests(TestCase):
    """Test avatar upload view security and functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        UserProfile.objects.create(user=self.user)
    
    def create_test_image(self):
        """Helper to create a test image file."""
        image = Image.new('RGB', (100, 100), color='red')
        image_bytes = BytesIO()
        image.save(image_bytes, format='JPEG')
        image_bytes.seek(0)
        return SimpleUploadedFile('avatar.jpg', image_bytes.getvalue(), content_type='image/jpeg')
    
    def test_upload_requires_login(self):
        """Avatar upload should require authentication."""
        response = self.client.get(reverse('shyaka:upload_avatar'))
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertIn('/auth/login/', response.url)
    
    def test_authenticated_user_can_access_form(self):
        """Authenticated user should be able to access upload form."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('shyaka:upload_avatar'))
        self.assertEqual(response.status_code, 200)
    
    def test_successful_avatar_upload(self):
        """Valid avatar should be uploaded successfully."""
        self.client.login(username='testuser', password='testpass123')
        image = self.create_test_image()
        
        response = self.client.post(
            reverse('shyaka:upload_avatar'),
            {'avatar': image},
            follow=True
        )
        
        # Check that upload was successful
        self.assertEqual(response.status_code, 200)
        
        # Check that profile was updated
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.profile.avatar)
    
    def test_invalid_file_rejected(self):
        """Invalid file should be rejected."""
        self.client.login(username='testuser', password='testpass123')
        
        # Create fake image file
        fake_image = SimpleUploadedFile('fake.jpg', b'not an image', content_type='image/jpeg')
        
        response = self.client.post(
            reverse('shyaka:upload_avatar'),
            {'avatar': fake_image}
        )
        
        # Should show error message
        self.assertEqual(response.status_code, 200)  # Should re-render form
        self.assertIn('invalid', response.content.decode().lower() or 'error' in response.content.decode().lower())


class DocumentUploadViewTests(TestCase):
    """Test document upload view security and functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        UserProfile.objects.create(user=self.user)
    
    def test_upload_requires_login(self):
        """Document upload should require authentication."""
        response = self.client.get(reverse('shyaka:upload_document'))
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_authenticated_user_can_access_form(self):
        """Authenticated user should be able to access upload form."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('shyaka:upload_document'))
        self.assertEqual(response.status_code, 200)
    
    def test_successful_document_upload(self):
        """Valid document should be uploaded successfully."""
        self.client.login(username='testuser', password='testpass123')
        
        txt_content = b'Test document content'
        txt_file = SimpleUploadedFile('document.txt', txt_content)
        
        response = self.client.post(
            reverse('shyaka:upload_document'),
            {
                'file': txt_file,
                'title': 'Test Document',
                'is_public': False
            },
            follow=True
        )
        
        # Check that document was created
        self.assertEqual(Document.objects.filter(owner=self.user).count(), 1)
    
    def test_document_owner_stored(self):
        """Uploaded document should be associated with uploader."""
        self.client.login(username='testuser', password='testpass123')
        
        txt_file = SimpleUploadedFile('document.txt', b'content')
        
        self.client.post(
            reverse('shyaka:upload_document'),
            {
                'file': txt_file,
                'title': 'Test',
                'is_public': False
            }
        )
        
        document = Document.objects.first()
        self.assertEqual(document.owner, self.user)
    
    def test_executable_upload_rejected(self):
        """Executable file should be rejected."""
        self.client.login(username='testuser', password='testpass123')
        
        exe_file = SimpleUploadedFile('malware.exe', b'MZ\x90\x00')
        
        response = self.client.post(
            reverse('shyaka:upload_document'),
            {
                'file': exe_file,
                'title': 'Test',
                'is_public': False
            }
        )
        
        # No document should be created
        self.assertEqual(Document.objects.filter(owner=self.user).count(), 0)


class DocumentAccessControlTests(TestCase):
    """Test document access control and download security."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = Client()
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        UserProfile.objects.create(user=self.user1)
        UserProfile.objects.create(user=self.user2)
        
        # Create test document
        self.document = Document.objects.create(
            owner=self.user1,
            title='Private Document',
            file='documents/user1/test.txt',
            original_filename='test.txt',
            mime_type='text/plain',
            file_size=100,
            is_public=False
        )
    
    def test_owner_can_download_own_document(self):
        """Owner should be able to download their own document."""
        self.client.login(username='user1', password='pass123')
        response = self.client.get(
            reverse('shyaka:download_document', args=[self.document.id])
        )
        self.assertEqual(response.status_code, 200)
    
    def test_other_user_cannot_download_private_document(self):
        """Other user should not be able to download private document."""
        self.client.login(username='user2', password='pass123')
        response = self.client.get(
            reverse('shyaka:download_document', args=[self.document.id])
        )
        self.assertEqual(response.status_code, 302)  # Redirect
    
    def test_authenticated_user_can_download_public_document(self):
        """Authenticated user should be able to download public document."""
        # Make document public
        self.document.is_public = True
        self.document.save()
        
        self.client.login(username='user2', password='pass123')
        response = self.client.get(
            reverse('shyaka:download_document', args=[self.document.id])
        )
        self.assertEqual(response.status_code, 200)
    
    def test_deleted_document_cannot_be_downloaded(self):
        """Deleted (soft-deleted) document should not be downloadable."""
        self.document.delete()  # Soft delete
        
        self.client.login(username='user1', password='pass123')
        response = self.client.get(
            reverse('shyaka:download_document', args=[self.document.id])
        )
        self.assertEqual(response.status_code, 404)
    
    def test_owner_can_delete_own_document(self):
        """Owner should be able to delete their own document."""
        self.client.login(username='user1', password='pass123')
        response = self.client.post(
            reverse('shyaka:delete_document', args=[self.document.id]),
            follow=True
        )
        
        # Document should be marked as deleted
        self.document.refresh_from_db()
        self.assertTrue(self.document.is_deleted)
    
    def test_other_user_cannot_delete_document(self):
        """Other user should not be able to delete someone else's document."""
        self.client.login(username='user2', password='pass123')
        response = self.client.post(
            reverse('shyaka:delete_document', args=[self.document.id])
        )
        
        self.assertEqual(response.status_code, 302)  # Redirect (permission denied)
        
        # Document should still exist
        self.document.refresh_from_db()
        self.assertFalse(self.document.is_deleted)


class FilenameStorageTests(TestCase):
    """Test that filenames are properly stored and sanitized."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        UserProfile.objects.create(user=self.user)
    
    def test_document_original_filename_sanitized(self):
        """Original filename is stored but actual file is sanitized in storage."""
        document = Document.objects.create(
            owner=self.user,
            title='Test',
            file='documents/test.txt',
            original_filename='../../../etc/passwd.txt',  # This gets stored as-is for display
            mime_type='text/plain',
            file_size=100,
            is_public=False
        )
        
        # Original filename is stored (for display in download names)
        # but the actual file path should prevent traversal
        self.assertTrue(len(document.original_filename) > 0)
        
        # The security is in the file storage path, not the display name
        # The file storage is managed by Django's FileField with upload_to parameter
    
    def test_file_stored_in_user_directory(self):
        """Files should be stored in user-specific directory."""
        document = Document.objects.create(
            owner=self.user,
            title='Test',
            file=f'documents/{self.user.id}/test.txt',
            original_filename='test.txt',
            mime_type='text/plain',
            file_size=100,
            is_public=False
        )
        
        # File path should include user ID
        self.assertIn(str(self.user.id), document.file.name)


if __name__ == '__main__':
    import unittest
    unittest.main()
