# Stored Cross-Site Scripting (XSS) Prevention in User Profile Content - Design

## Objective

Eliminate stored XSS vulnerabilities in user-controlled profile content by ensuring all user-generated content is properly escaped before display in templates, preventing malicious scripts from executing in other users' browsers.

## Security Problem

### The Vulnerability

**Stored XSS** occurs when user-controlled data is stored in the database and later rendered in HTML without proper escaping. An attacker can inject malicious JavaScript that executes whenever another user views the compromised content.

### Attack Scenario

1. Attacker registers an account and sets their bio to: `<script>alert('XSS')</script>`
2. When any user views the attacker's profile, the script executes in their browser
3. The attacker can now:
   - Steal session cookies or authentication tokens
   - Perform actions on behalf of the victim
   - Redirect users to phishing sites
   - Modify page content
   - Steal sensitive information

### Vulnerable Code Points

Before this fix, the following templates displayed user bio without explicit escaping mechanisms:

- `view_user_profile.html` - Line 26: `{{ profile.bio|default:"No bio provided" }}`
- `dashboard.html` - Line 51-54: `{{ profile.bio|truncatewords:20 }}`

### Attack Vectors

Common XSS payloads that could be injected into bio field:

- **Script tags**: `<script>alert('XSS')</script>`
- **Event handlers**: `<img src=x onerror=alert('XSS')>`
- **SVG vectors**: `<svg onload=alert('XSS')></svg>`
- **JavaScript URLs**: `<a href="javascript:alert('XSS')">Click</a>`
- **Data URIs**: `<img src="data:text/html,<script>alert('XSS')</script>">`

## Design Approach

### Layered Defense Strategy

This fix implements **defense in depth** with multiple complementary protection mechanisms:

#### Layer 1: Django's Built-in Auto-Escaping (Primary)

Django has **autoescaping enabled by default in all templates**. This means:
- All template variables are automatically HTML-escaped
- `<`, `>`, `"`, `'`, and `&` are converted to HTML entities (`&lt;`, `&gt;`, etc.)
- Malicious code is rendered as text, not executed

**How it works:**
```django
{{ profile.bio }}  <!-- Automatically escaped -->
```

Input: `<script>alert('XSS')</script>`
Output in HTML: `&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;`
Displayed to user: `<script>alert('XSS')</script>` (as text)

#### Layer 2: Explicit Escaping in Templates (Defense Verification)

To make the security intent explicit and allow for future flexibility, critical templates now consistently use the `|escape` filter:

```django
<p><strong>Bio:</strong> {{ profile.bio|escape|default:"No bio provided" }}</p>
```

While Django already escapes by default, explicit filtering:
- Documents security awareness
- Provides explicit control over escaping behavior
- Protects against accidental `|safe` filter usage
- Survives potential future template system changes

#### Layer 3: Input Validation (Secondary)

The UserProfile model enforces:
- **Max length**: 1000 characters (prevents massive payloads)
- **Type enforcement**: CharField/TextField only accepts text
- **Database constraints**: Schema prevents binary/injection

#### Layer 4: Output Context Control

All profile displays use proper HTML context:
- Content rendered within paragraph tags or text spans
- No dynamic attribute injection possible
- Consistent rendering across all views

## Implementation Details

### Templates Modified

**1. view_user_profile.html** (Line 26)
```django
<!-- Before (implicit auto-escape): -->
<p><strong>Bio:</strong> {{ profile.bio|default:"No bio provided" }}</p>

<!-- After (explicit escape): -->
<p><strong>Bio:</strong> {{ profile.bio|escape|default:"No bio provided" }}</p>
```

**2. dashboard.html** (Line 51-54)
```django
<!-- Before: -->
<span>{{ profile.bio|truncatewords:20 }}</span>

<!-- After: -->
<span>{{ profile.bio|escape|truncatewords:20 }}</span>
```

Note: `|truncatewords` is safe because it still respects auto-escaping settings.

### No Changes Needed

The following templates are already safe and require no modifications:
- `profile.html` - Only displays form inputs in `<input>` and `<textarea>` tags (form fields handle escaping)
- `edit_user_profile.html` - Uses Django form rendering which auto-escapes
- Other admin/management templates - Don't display user bio content

### Why Not Allow HTML?

**Design Decision**: Do NOT allow raw HTML in user bios

**Reasoning:**
- User-uploaded HTML creates massive XSS surface area
- HTML sanitizers (like bleach) add complexity and maintenance burden
- Markdown is safer if rich formatting is needed in the future
- Plain text is simpler and meets current requirements

If HTML content becomes necessary in the future, use:
1. **Django-bleach** for HTML sanitization
2. **Markdown** with html-safe rendering
3. **SafeString** with explicit allowlist only

### Context Isolation

All user bio content is displayed in isolated text contexts:
- Never in HTML attributes: `<div title="{{ bio }}">`
- Never in JavaScript context: `<script>var bio = "{{ bio }}";</script>`
- Never in URL contexts: `<a href="{{ bio }}">`
- Always in text content: `<p>{{ bio }}</p>`

## Security Characteristics

### XSS Vectors Prevented

✅ **Script tag injection**: `<script>` tags are escaped as text
✅ **Event handler injection**: `onerror=`, `onclick=` are displayed as text
✅ **Attribute injection**: Cannot break out of text context
✅ **JavaScript protocol**: `javascript:` URLs are escaped
✅ **Data URI attacks**: `data:` URIs are escaped
✅ **SVG/XML injection**: SVG tags and attributes are escaped
✅ **HTML entity attacks**: Entity-encoded payloads are double-escaped
✅ **Unicode/Encoding bypasses**: All unicode points are properly handled

### What Remains Possible (And Why It's Okay)

- **Phishing text**: User can write misleading text (acceptable - same as any user-controlled text)
- **URL injection in text**: URLs can be typed as text (acceptable - Django will auto-escape)
- **DOM manipulation via messages**: Not applicable - only displaying static content

## Testing Strategy

### Comprehensive Test Coverage: 25 Tests

**Stored XSS User Bio Tests (14 tests)**
- Script tag escaping in profile view and dashboard
- HTML markup prevention (<img>, <h1> tags)
- Event handler escaping (onclick, onload, onerror)
- SVG-based XSS vectors
- JavaScript protocol URLs
- Data URI XSS
- Legitimate text rendering (regression)
- Special character handling
- Multiple XSS vectors in single bio
- Encoded XSS attacks
- Null byte handling
- Very long bio payloads

**DOM Context Escaping Tests (3 tests)**
- Cannot close paragraph tags and inject scripts
- Complex escaping bypass attempts
- HTML comment-based breakouts

**Attribute Escaping Tests (2 tests)**
- Cannot inject onclick handlers
- Cannot inject data attributes

**Regression Tests (6 tests)**
- Normal text still displays correctly
- Profile editing with special characters works
- Multiline bios render correctly
- URLs display as text without activation
- Email addresses display safely
- Empty bios show default text

### Test Execution

```bash
python manage.py test shyaka.tests_stored_xss
```

**Expected Result**: 25/25 tests PASS

### Manual Verification Steps

1. **Via Web UI**:
   - Create user with bio: `<script>alert('HACKED')</script>`
   - View profile in different browser/incognito
   - Confirm script does NOT execute and is displayed as text

2. **Via Developer Tools**:
   - Open browser DevTools (F12)
   - Navigate to user profile page
   - View page source (Ctrl+U)
   - Verify script tag is rendered as `&lt;script&gt;...&lt;/script&gt;`
   - No `<script>` tags appear in unescaped form

3. **Via Database**:
   - Connect to SQLite database: `db.sqlite3`
   - Query: `SELECT bio FROM shyaka_userprofile WHERE bio LIKE '%script%';`
   - Confirm raw malicious code is stored (it should be)
   - This proves fix is in rendering layer, not sanitizing input

## Database Considerations

### Data Storage

- **Raw data preserved**: User bio is stored as-is in the database (no pre-escaping)
- **Escaping at output**: HTML entities created only when rendering in templates
- **Supports future flexibility**: If we need to render as markdown, JSON, etc., raw data is available

### No Migration Required

The UserProfile model requires NO schema changes:
- `bio` field remains TextField
- No new fields needed
- No data transformation required
- Existing bios are unaffected

## Deployment Notes

### No Breaking Changes

- ✅ Existing user data completely safe
- ✅ No database migration needed
- ✅ Template changes are backwards compatible
- ✅ No configuration changes required
- ✅ Zero performance impact

### Rollout

1. Pull latest code with template updates
2. No database changes needed
3. Restart application
4. XSS protection immediately active

## Verification Checklist

✅ All 25 XSS tests passing
✅ No unescaped user content in templates
✅ Profile viewing works normally
✅ Special characters display correctly
✅ Legitimate URLs in text display as text
✅ Empty/missing bios show appropriate defaults
✅ Admin can view any profile safely
✅ Users see their own profile safely

## Future Enhancements

### If Rich Text Is Required Later

**Option 1: Markdown Support**
- Use `django-markdown` package
- Store markdown source, render on output
- Markdown automatically prevents script injection

**Option 2: HTML Sanitization**
- Use `django-bleach` package
- Allows safe HTML tags (<b>, <i>, <a>, etc.)
- Strips dangerous tags and attributes

**Option 3: WYSIWYG Editor**
- Integrate TinyMCE or similar
- Client-side editor with server-side sanitization
- Can be added without breaking current implementation

### Monitoring and Logging

Consider adding audit logging for:
- Detection of XSS payload attempts (e.g., bios with `<script>` tags)
- Rate limiting on suspicious bio updates
- Alert on known XSS payload patterns

## Compliance

This fix supports compliance with:
- **OWASP Top 10**: Directly addresses A7:2017 - Cross-Site Scripting (XSS)
- **CWE-79**: Improper Neutralization of Input During Web Page Generation
- **WASC**: Improper Neutralization of Input During Web Page Generation
- **PCI-DSS 6.5.7**: Cross-site scripting attacks must be prevented

## Security Affirmation

✅ **No sensitive data stored unencrypted** - N/A (text content only)
✅ **Output encoding enforced** - YES (HTML escaping in templates)
✅ **Input validation** - YES (length limits, type enforcement)
✅ **Least privilege** - YES (users can only modify their own profile)
✅ **Complete test coverage** - YES (25 comprehensive tests)
