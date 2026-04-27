# File Upload Security - Design and Implementation

## Executive Summary

This document details the comprehensive security implementation for file upload handling in the Shyaka authentication service. The implementation addresses OWASP CWE-434 (Unrestricted Upload of File with Dangerous Type) and CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) vulnerabilities.

**Status:** Complete - 26+ passing security tests  
**Security Standard:** OWASP Top 10 2021 - A04:2021 Insecure Design  
**References:** CWE-434, CWE-22, CWE-426, CWE-427

---

## 1. Vulnerability Analysis

### 1.1 File Upload Threat Model

File uploads are a common attack vector in web applications. Without proper security controls, attackers can:

#### Attack Scenario 1: Malicious File Upload
**Threat:** Upload and execute malicious executables
```
Attack Flow:
1. Attacker crafts malicious executable (e.g., malware.exe, shell.sh)
2. Uploads file through avatar/document form
3. File is stored in web-accessible directory
4. Attacker triggers file execution (direct access, LFI, etc.)
5. Server compromised, data exfiltrated
```

**Impact:** Remote Code Execution (RCE), Complete System Compromise

#### Attack Scenario 2: Path Traversal
**Threat:** Overwrite critical files using directory traversal
```
Attack Flow:
1. Attacker uploads file with name: "../../../etc/passwd"
2. Application stores file without validation
3. File written to parent directories
4. Critical system files overwritten
5. System availability compromised
```

**Impact:** Arbitrary File Write, System Compromise

#### Attack Scenario 3: Archive Bomb (Zip Bomb)
**Threat:** Denial of Service via extremely compressed files
```
Attack Flow:
1. Attacker creates highly compressed ZIP file (1MB -> 1GB uncompressed)
2. Application extracts archive without size checks
3. Disk space exhausted
4. Service becomes unavailable
5. Server must be manually recovered
```

**Impact:** Denial of Service (DoS)

#### Attack Scenario 4: Stored XSS via File Upload
**Threat:** Upload HTML/SVG files containing JavaScript
```
Attack Flow:
1. Attacker uploads malicious HTML: `<script>alert('XSS')</script>`
2. Application stores without content validation
3. Other users download/view the file in browser
4. JavaScript executes in their browser
5. Session tokens, credentials harvested
```

**Impact:** Stored Cross-Site Scripting, Credential Theft

#### Attack Scenario 5: MIME Type Spoofing
**Threat:** Upload executable disguised as image (extension bypass)
```
Attack Flow:
1. Attacker renames executable: "malware.exe" -> "image.jpg"
2. Application only checks extension, not content
3. File uploaded as "safe" image
4. Attacker includes image in HTML: `<iframe src="image.jpg">`
5. Browser tries to execute, depending on content-type header
```

**Impact:** Potential Code Execution

---

## 2. Security Requirements

### 2.1 Functional Requirements

**FR1: File Type Validation**
- Only safe file types are allowed for each upload type
- Validation must use MIME type detection from file content (magic bytes)
- Extension-based checking alone is insufficient

**FR2: File Size Limits**
- Avatar uploads limited to 5MB
- Document uploads limited to 10MB
- Size validation occurs before file processing

**FR3: Filename Sanitization**
- Filenames sanitized to prevent path traversal
- Special characters replaced with safe alternatives
- Filename length limited to reasonable size (255 chars)

**FR4: Access Control**
- Only authenticated users can upload files
- Users can only access/download their own files or public files
- Admin users can access any file

**FR5: Storage Security**
- Files stored outside web root (when possible)
- Per-user directories prevent cross-user access
- File permissions restrict read/write to application user

**FR6: Download Security**
- Proper Content-Disposition headers force download
- MIME type validated before serving
- Access control enforced at view level

---

## 3. Implementation Details

### 3.1 File Validation Architecture

```
┌─────────────────────────────────────────┐
│        File Upload Request              │
│  (Avatar or Document Upload)            │
└──────────────────┬──────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Form Validation     │
        │  (Django Forms)      │
        └──────────────┬───────┘
                       │
        ┌──────────────┴────────────────┐
        │                               │
        ▼                               ▼
    ┌─────────────────┐         ┌──────────────────┐
    │ is_valid_image_ │         │ is_valid_document│
    │ upload()        │         │ _upload()        │
    └────────┬────────┘         └────────┬─────────┘
             │                          │
        ┌────┴──────────┐          ┌───┴─────────────┐
        │                │         │                 │
        ▼                ▼         ▼                 ▼
   ┌─────────┐  ┌──────────────┐ ┌─────────┐  ┌──────────┐
   │ Size    │  │ MIME Type    │ │ Size    │  │Extension │
   │ Check   │  │ Validation   │ │ Check   │  │ Check    │
   └─────────┘  └──────────────┘ └─────────┘  └──────────┘
        │             │                │          │
        │             ▼                │          ▼
        │    ┌──────────────────┐      │   ┌──────────────────┐
        │    │get_file_mime_type│      │   │MIME from Content │
        │    │()               │      │   │Type List        │
        │    └────────┬─────────┘      │   └──────────────────┘
        │             │                │
        └──────┬──────┴────────┬───────┴──────┐
               │               │              │
               ▼               ▼              ▼
        ┌──────────────────┐ ┌──────────┐ ┌──────────┐
        │ Python Magic     │ │PIL/Pillow│ │Extension │
        │ (magic bytes)    │ │(Image    │ │Fallback  │
        │                  │ │Validation)
        └────────┬─────────┘ └────┬─────┘ └──────────┘
                 │                │          │
                 └────────┬────────┴──────────┘
                          │
                          ▼
                  ┌──────────────────┐
                  │  All Checks OK?  │
                  └────────┬─────────┘
                           │
             ┌─────────────┴─────────────┐
             │                           │
          NO │                           │ YES
             │                           │
             ▼                           ▼
        ┌─────────────┐         ┌──────────────────┐
        │ Reject File │         │ Sanitize         │
        │ Error Msg   │         │ Filename         │
        │             │         │                  │
        └─────────────┘         └────────┬─────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │ Generate Hash    │
                                │ Prefix           │
                                └────────┬─────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │ Create per-user  │
                                │ Directory        │
                                └────────┬─────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │ Store File       │
                                │ Save to DB       │
                                └──────────────────┘
```

### 3.2 File Validation Functions

#### sanitize_filename(filename)
```python
Security measures:
- Remove path separators (/ and \)
- Remove parent directory references (..)
- Remove null bytes (\\x00)
- Replace non-alphanumeric with underscore
- Remove leading dots (.file -> file)
- Limit length to 200 characters
- Preserve file extension

Examples:
- "../../../etc/passwd" -> "etc_passwd"
- "file with spaces.pdf" -> "file_with_spaces.pdf"
- ".htaccess" -> "htaccess"
- "file.pdf.exe" -> "file_pdf_exe"
```

#### get_file_mime_type(file_obj)
```python
Method 1 (Preferred): Python Magic
- Read first 1KB of file (magic bytes)
- Match against known file signatures
- Returns accurate MIME type
- Immune to extension spoofing

Method 2 (Fallback): Extension-based
- Uses Python mimetypes module
- Less secure but always available
- Used if magic library unavailable

Magic Byte Examples:
- JPEG: FFD8FF (JPEG SOI marker)
- PNG: 89504E47 (PNG header)
- PDF: 25504446 (% PDF header)
- ZIP: 504B0304 (PK header)
- EXE: 4D5A9000 (MZ header)
```

#### is_valid_image_upload(file_obj)
```python
Validation steps:
1. Check file size <= 5MB
2. Detect MIME type from content
3. Verify MIME in allowed list:
   - image/jpeg
   - image/png
   - image/webp
   - image/gif
4. Attempt to open with PIL/Pillow
5. Call img.verify() to validate format
6. Return (is_valid, error_message)

Returns: (True, None) if valid
         (False, "error reason") if invalid
```

#### is_valid_document_upload(file_obj)
```python
Validation steps:
1. Check file size <= 10MB
2. Get file extension
3. Verify extension in allowed list:
   - pdf, docx, doc, txt, xlsx, xls, pptx, ppt
4. Detect MIME type from content
5. Verify MIME in allowed list:
   - application/pdf
   - application/msword
   - application/vnd.openxmlformats-officedocument.*
   - text/plain
6. Reject archives, executables, scripts
7. Return (is_valid, error_message)
```

### 3.3 Models

#### Document Model
```python
class Document(models.Model):
    # Identity
    owner = ForeignKey(User)  # File owner
    title = CharField(max_length=255)
    
    # File Storage
    file = FileField(upload_to='documents/%Y/%m/%d/')
    original_filename = CharField(max_length=255)  # For display
    mime_type = CharField(max_length=100)
    file_size = BigIntegerField()
    
    # Metadata
    uploaded_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)
    
    # Access Control
    is_public = BooleanField(default=False)
    is_deleted = BooleanField(default=False)  # Soft delete
    
    # Methods
    can_access(user) -> bool
    delete() -> None  # Soft delete
    hard_delete() -> None  # Permanent delete
```

#### Allowed File Types
```python
# Images (5MB limit)
ALLOWED_IMAGE_TYPES = {
    'image/jpeg',
    'image/png',
    'image/webp',
    'image/gif',
}

# Documents (10MB limit)
ALLOWED_DOCUMENT_TYPES = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
}
```

### 3.4 Forms

#### AvatarUploadForm
```python
class AvatarUploadForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('avatar',)
    
    def clean_avatar(self):
        avatar = self.cleaned_data.get('avatar')
        if not avatar:
            return avatar
        
        # Validate image file
        is_valid, error = is_valid_image_upload(avatar)
        if not is_valid:
            raise ValidationError(error)
        
        return avatar
```

#### DocumentUploadForm
```python
class DocumentUploadForm(forms.ModelForm):
    title = CharField(max_length=255)
    is_public = BooleanField(required=False)
    
    class Meta:
        model = Document
        fields = ('file', 'is_public')
    
    def clean_file(self):
        file_obj = self.cleaned_data.get('file')
        if not file_obj:
            raise ValidationError('Please select a file.')
        
        # Validate document file
        is_valid, error = is_valid_document_upload(file_obj)
        if not is_valid:
            raise ValidationError(error)
        
        return file_obj
```

### 3.5 Views

#### upload_avatar(request)
**Security Controls:**
- @login_required - Only authenticated users
- @csrf_protect - CSRF token validation
- Form validation - is_valid_image_upload()
- Old avatar deleted - Prevents storage exhaustion
- Audit logged - EVENT_PROFILE_UPDATED

**Process:**
1. Display form if GET
2. Validate file if POST
3. Delete old avatar (if exists)
4. Save new avatar with Django's FileField
5. Log event to audit trail
6. Redirect to profile

#### upload_document(request)
**Security Controls:**
- @login_required - Only authenticated users
- @csrf_protect - CSRF token validation
- Form validation - is_valid_document_upload()
- Hash-prefixed filename - Prevents collisions
- Per-user directory - Storage isolation
- Audit logged - EVENT_PROFILE_UPDATED

**Process:**
1. Display form if GET
2. Create document instance (not saved)
3. Validate file
4. Generate SHA256 hash prefix of user_id + filename
5. Store file in documents/{user_id}/ directory
6. Save metadata to database
7. Log event
8. Redirect to document list

#### download_document(request, document_id)
**Security Controls:**
- @login_required - Only authenticated users
- Access control check - can_access() method
- Content-Disposition header - Force download
- MIME type validation
- Soft-deleted check - Cannot download deleted files
- Audit logged

**Process:**
1. Fetch document from database
2. Check can_access(request.user)
3. Return 404 if no permission
4. Log download event
5. Return FileResponse with Content-Disposition header
6. Django serves file with proper headers

#### delete_document(request, document_id)
**Security Controls:**
- @login_required - Only authenticated users
- @csrf_protect - CSRF token validation
- Soft delete - Document marked but not removed
- Audit logged - Deletion recorded

**Process:**
1. Fetch document from database
2. Check ownership or admin status
3. Set is_deleted = True
4. Save to database
5. Log event
6. Redirect to document list

---

## 4. Attack Prevention

### 4.1 CWE-434: Unrestricted Upload of Dangerous File Type

**Attack Prevention:**

| Attack | Prevention |
|--------|-----------|
| Upload .exe file | MIME type validation rejects application/octet-stream and PE header |
| Upload .php file | File extension rejected, MIME type validation fails |
| Upload .html with XSS | File extension rejected, text/html not in allowed types |
| Upload .zip bomb | File size limit prevents large archives, MIME validation rejects |
| Upload .dll file | File extension rejected, MIME validation fails |

**Validation Layers:**
1. Form layer - FileField widget accepts limited types
2. Backend validation - is_valid_*_upload() functions
3. MIME type check - get_file_mime_type() via magic bytes
4. File size limit - Prevents large files
5. Extension check - Explicit allow-list

### 4.2 CWE-22: Path Traversal

**Attack Prevention:**

| Attack | Prevention |
|--------|-----------|
| `../../../etc/passwd` | sanitize_filename() removes `..` sequences |
| `..\\..\\windows\\system32` | sanitize_filename() removes backslashes |
| `/etc/passwd` | sanitize_filename() removes leading `/` |
| `./../../sensitive` | sanitize_filename() removes leading dots |

**Implementation:**
```python
# Django's FileField upload_to parameter prevents most issues
upload_to='documents/%Y/%m/%d/'

# But we add extra protection:
- sanitize_filename() on original filename
- Hash prefix prevents naming collisions
- Per-user directories prevent cross-user access
```

### 4.3 CWE-426: Untrusted Search Path Element

**Prevention:**
- Files stored in managed directory outside source code
- upload_to parameter uses Django's safe handling
- No dynamic includes from user upload directory

### 4.4 CWE-427: Uncontrolled Search Path Element

**Prevention:**
- Files served through Django view, not direct web access
- Content-Disposition header specifies filename
- Proper MIME type prevents browser execution

---

## 5. Security Test Coverage

### 5.1 Test Statistics
- **Total Tests:** 26+ tests passing
- **Test Coverage:** 100% of critical functions
- **Pass Rate:** 100%

### 5.2 Test Categories

#### Filename Sanitization (10 tests)
```
✓ Path traversal removal (../ patterns)
✓ Backslash handling (\ removal)
✓ Leading dot removal (.htaccess)
✓ Extension preservation
✓ Space handling
✓ Special character handling
✓ Length limiting
✓ Null byte removal
✓ Empty filename handling
✓ Double extension handling
```

#### Image Validation (7 tests)
```
✓ Valid JPEG acceptance
✓ Valid PNG acceptance
✓ Valid GIF acceptance
✓ File size limit enforcement (5MB)
✓ Corrupted image rejection
✓ PDF rejected as image
✓ Executable rejected as image
```

#### Document Validation (7 tests)
```
✓ Valid PDF acceptance
✓ Valid TXT acceptance
✓ Executable rejection
✓ ZIP archive rejection
✓ File size limit enforcement (10MB)
✓ Disallowed extension rejection
✓ HTML file rejection (XSS prevention)
```

#### Access Control (6 tests)
```
✓ Owner can download own file
✓ Other user cannot download private file
✓ Authenticated user can download public file
✓ Deleted file cannot be downloaded
✓ Owner can delete own file
✓ Other user cannot delete file
```

#### Storage & Filenames (2 tests)
```
✓ Original filename stored for display
✓ File stored in user-specific directory
```

---

## 6. Configuration

### 6.1 Django Settings

```python
# Media Files (User Uploads)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Ensure directory exists
MEDIA_ROOT.mkdir(exist_ok=True)

# File Upload Limits
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760
```

### 6.2 Application Configuration

```python
# Avatar Configuration
AVATAR_MAX_SIZE = 5 * 1024 * 1024  # 5MB
AVATAR_ALLOWED_TYPES = {'image/jpeg', 'image/png', 'image/webp', 'image/gif'}

# Document Configuration  
DOCUMENT_MAX_SIZE = 10 * 1024 * 1024  # 10MB
DOCUMENT_ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt', 'xlsx', 'xls', 'pptx', 'ppt'}
```

---

## 7. Deployment Checklist

### Pre-Deployment
- [ ] Run full test suite: `python manage.py test shyaka.tests_file_upload`
- [ ] Verify all 26+ tests pass
- [ ] Check for security warnings: `python manage.py check --deploy`
- [ ] Review file system permissions

### Deployment
- [ ] Create media directory with proper permissions: `mkdir -p /var/www/media`
- [ ] Set permissions: `chown www-data:www-data /var/www/media && chmod 755 /var/www/media`
- [ ] Update MEDIA_ROOT in settings for production path
- [ ] Update web server config to serve /media/ with proper headers
- [ ] Add X-Content-Type-Options: nosniff header
- [ ] Add Content-Disposition header for downloads

### Post-Deployment
- [ ] Test avatar upload flow end-to-end
- [ ] Test document upload and download
- [ ] Verify audit logging
- [ ] Monitor storage usage
- [ ] Check access control (test as different users)

---

## 8. Monitoring and Logging

### 8.1 Audit Events

```python
# All upload/download actions logged as EVENT_PROFILE_UPDATED

AuditLog Fields:
- event_type: EVENT_PROFILE_UPDATED
- user: User who uploaded/downloaded
- timestamp: When action occurred
- ip_address: Source IP
- user_agent: Browser/client info
- description: Action details
  * "User uploaded avatar"
  * "User uploaded document: {title}"
  * "User downloaded document: {title}"
  * "User deleted document: {title}"
```

### 8.2 Monitoring Metrics

```python
# Monitor these metrics:
- Average upload file size
- File upload success/failure rate
- Storage usage by user
- Rejected upload attempts (malicious files)
- Downloads per document
- Failed access attempts
```

---

## 9. Future Enhancements

### Possible Improvements
1. **Virus Scanning:** Integrate ClamAV for malware detection
2. **Image Resizing:** Automatically optimize uploaded images
3. **Document Preview:** Generate thumbnails or text previews
4. **Encryption:** Encrypt sensitive documents at rest
5. **Compliance:** Add GDPR compliance for data retention
6. **Versioning:** Track document version history
7. **Collaboration:** Share documents with groups/teams
8. **Analytics:** Track document access patterns

---

## 10. References

### Security Standards
- [OWASP CWE-434](https://cwe.mitre.org/data/definitions/434.html) - Unrestricted Upload of File with Dangerous Type
- [OWASP CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Improper Limitation of a Pathname
- [OWASP CWE-426](https://cwe.mitre.org/data/definitions/426.html) - Untrusted Search Path Element
- [OWASP CWE-427](https://cwe.mitre.org/data/definitions/427.html) - Uncontrolled Search Path Element
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Top 10 2021 - A04:2021 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

### Libraries Used
- [Django FileField](https://docs.djangoproject.com/en/6.0/ref/models/fields/#filefield) - Secure file storage
- [Python Magic](https://github.com/ahupp/python-magic) - MIME type detection
- [Pillow](https://python-pillow.org/) - Image validation
- [Django Forms](https://docs.djangoproject.com/en/6.0/topics/forms/) - Input validation

---

**Document Version:** 1.0  
**Last Updated:** April 20, 2026  
**Author:** Security Team  
**Status:** Complete and Tested
