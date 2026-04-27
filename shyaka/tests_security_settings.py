"""
Tests for Django Security Settings Hardening (Assignment 6).

Validates that all security-relevant Django configuration settings
are properly hardened for production deployment.

Security Focus Areas:
- CWE-16: Configuration/Default Settings
- OWASP A05:2021 - Security Misconfiguration
- OWASP A06:2021 - Vulnerable and Outdated Components
"""

import os
from django.test import TestCase, override_settings
from django.conf import settings


class DebugModeSecurityTests(TestCase):
    """
    Tests that DEBUG mode is properly controlled and set to False in production.
    
    DEBUG=True exposes sensitive information including:
    - Full stack traces with source code paths
    - Database queries and connection details
    - Environment variables and SECRET_KEY
    - Installed apps and middleware configuration
    
    CWE-209: Information Exposure Through an Error Message
    """

    def test_debug_is_boolean(self):
        """DEBUG setting must be a boolean, not a string."""
        self.assertIsInstance(settings.DEBUG, bool)

    def test_debug_disabled_in_production(self):
        """In production, DEBUG must be False."""
        # This test uses the actual environment setting
        if os.environ.get('ENVIRONMENT') == 'production':
            self.assertFalse(
                settings.DEBUG,
                "DEBUG must be False in production to prevent information disclosure"
            )

    def test_debug_development_mode_allowed(self):
        """DEBUG may be True in development for convenience."""
        # This just validates the boolean type check works
        if settings.DEBUG:
            self.assertTrue(settings.DEBUG)


class SecretKeySecurityTests(TestCase):
    """
    Tests that SECRET_KEY is properly managed and protected.
    
    The SECRET_KEY is used for:
    - Signing session cookies
    - Generating password reset tokens
    - CSRF token generation
    - Other cryptographic operations
    
    Exposure of SECRET_KEY allows attackers to:
    - Forge session cookies and impersonate users
    - Generate valid password reset tokens
    - Bypass CSRF protection
    
    CWE-798: Use of Hard-Coded Credentials
    CWE-321: Use of Hard-Coded Cryptographic Key
    """

    def test_secret_key_exists(self):
        """SECRET_KEY must be set."""
        self.assertIsNotNone(settings.SECRET_KEY)
        self.assertTrue(len(settings.SECRET_KEY) > 0)

    def test_secret_key_length_sufficient(self):
        """SECRET_KEY must be long enough for security."""
        # Django recommends at least 50 characters
        self.assertGreaterEqual(
            len(settings.SECRET_KEY),
            50,
            "SECRET_KEY should be at least 50 characters for security"
        )

    def test_secret_key_not_dev_default(self):
        """SECRET_KEY must not use development default value."""
        if os.environ.get('ENVIRONMENT') == 'production':
            self.assertNotEqual(
                settings.SECRET_KEY,
                'dev-key-only-for-development-not-for-production',
                "Production must not use development default SECRET_KEY"
            )

    def test_secret_key_is_string(self):
        """SECRET_KEY must be a string."""
        self.assertIsInstance(settings.SECRET_KEY, str)


class AllowedHostsSecurityTests(TestCase):
    """
    Tests that ALLOWED_HOSTS is properly configured to prevent Host header attacks.
    
    Host header attacks occur when:
    - Attacker sends request with spoofed Host header
    - Application uses this to construct URLs in responses
    - Leads to password reset link to attacker's server
    - Or HTML injection/cache poisoning
    
    CWE-74: Improper Neutralization of Special Elements in Output ('Injection')
    CWE-943: Improper Neutralization of Special Elements in Data Query Logic
    """

    def test_allowed_hosts_is_list(self):
        """ALLOWED_HOSTS must be a list."""
        self.assertIsInstance(settings.ALLOWED_HOSTS, list)

    def test_allowed_hosts_not_empty_in_production(self):
        """In production, ALLOWED_HOSTS must contain actual domain(s)."""
        if os.environ.get('ENVIRONMENT') == 'production':
            self.assertGreater(
                len(settings.ALLOWED_HOSTS),
                0,
                "ALLOWED_HOSTS must be configured with actual domain(s) in production"
            )

    def test_allowed_hosts_no_wildcards_in_production(self):
        """In production, ALLOWED_HOSTS should not use wildcards."""
        if os.environ.get('ENVIRONMENT') == 'production':
            for host in settings.ALLOWED_HOSTS:
                self.assertNotIn(
                    '*',
                    host,
                    "ALLOWED_HOSTS should not use wildcards in production"
                )


class HTTPSSecurityTests(TestCase):
    """
    Tests that HTTPS/SSL security settings are properly configured.
    
    HTTPS protects against:
    - Man-in-the-middle attacks
    - Session hijacking
    - Eavesdropping on credentials and data
    
    HSTS (HTTP Strict-Transport-Security) prevents:
    - SSL stripping attacks
    - Downgrade attacks
    
    CWE-295: Improper Certificate Validation
    CWE-296: Improper Certificate Validation
    """

    def test_ssl_redirect_enabled_in_production(self):
        """In production, SECURE_SSL_REDIRECT must be True."""
        if os.environ.get('ENVIRONMENT') == 'production':
            self.assertTrue(
                settings.SECURE_SSL_REDIRECT,
                "SECURE_SSL_REDIRECT must be True to redirect HTTP to HTTPS"
            )

    def test_session_cookie_secure_flag_set(self):
        """Session cookies must have Secure flag set."""
        self.assertTrue(
            settings.SESSION_COOKIE_SECURE or not os.environ.get('ENVIRONMENT') == 'production',
            "SESSION_COOKIE_SECURE should be True in production"
        )

    def test_csrf_cookie_secure_flag_set(self):
        """CSRF cookies must have Secure flag set."""
        self.assertTrue(
            settings.CSRF_COOKIE_SECURE or not os.environ.get('ENVIRONMENT') == 'production',
            "CSRF_COOKIE_SECURE should be True in production"
        )

    def test_hsts_enabled_in_production(self):
        """HSTS headers must be enabled in production."""
        if os.environ.get('ENVIRONMENT') == 'production':
            self.assertGreater(
                settings.SECURE_HSTS_SECONDS,
                0,
                "SECURE_HSTS_SECONDS must be > 0 in production"
            )

    def test_hsts_includes_subdomains(self):
        """HSTS should include subdomains in production."""
        if os.environ.get('ENVIRONMENT') == 'production':
            self.assertTrue(
                settings.SECURE_HSTS_INCLUDE_SUBDOMAINS,
                "SECURE_HSTS_INCLUDE_SUBDOMAINS should be True"
            )

    def test_hsts_preload_enabled(self):
        """HSTS preload should be enabled in production."""
        if os.environ.get('ENVIRONMENT') == 'production':
            self.assertTrue(
                settings.SECURE_HSTS_PRELOAD,
                "SECURE_HSTS_PRELOAD should be True"
            )


class CookieSecurityTests(TestCase):
    """
    Tests that cookie security settings prevent theft and tampering.
    
    HttpOnly flag prevents:
    - JavaScript access to cookies
    - XSS attacks stealing cookies
    
    SameSite flag prevents:
    - Cross-site request forgery (CSRF)
    - Cookie leakage to third-party sites
    
    CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    CWE-1275: Sensitive Cookie with Improper SameSite Attribute
    """

    def test_session_cookie_httponly_set(self):
        """Session cookies must have HttpOnly flag."""
        self.assertTrue(
            settings.SESSION_COOKIE_HTTPONLY,
            "SESSION_COOKIE_HTTPONLY must be True to prevent XSS attacks"
        )

    def test_csrf_cookie_httponly_set(self):
        """CSRF cookies must have HttpOnly flag."""
        self.assertTrue(
            settings.CSRF_COOKIE_HTTPONLY,
            "CSRF_COOKIE_HTTPONLY must be True to prevent XSS attacks"
        )

    def test_session_cookie_samesite_set(self):
        """Session cookies must have SameSite attribute."""
        self.assertIn(
            settings.SESSION_COOKIE_SAMESITE,
            ['Strict', 'Lax', 'None'],
            "SESSION_COOKIE_SAMESITE must be Strict, Lax, or None"
        )

    def test_csrf_cookie_samesite_set(self):
        """CSRF cookies must have SameSite attribute."""
        self.assertIn(
            settings.CSRF_COOKIE_SAMESITE,
            ['Strict', 'Lax', 'None'],
            "CSRF_COOKIE_SAMESITE must be Strict, Lax, or None"
        )

    def test_session_cookie_age_reasonable(self):
        """Session cookie expiration should be reasonable."""
        # Default is 2 weeks = 1209600 seconds
        self.assertLessEqual(
            settings.SESSION_COOKIE_AGE,
            2592000,  # 30 days
            "SESSION_COOKIE_AGE should not exceed 30 days"
        )
        self.assertGreater(
            settings.SESSION_COOKIE_AGE,
            0,
            "SESSION_COOKIE_AGE must be positive"
        )


class FrameOptionsSecurityTests(TestCase):
    """
    Tests that X-Frame-Options header is properly configured.
    
    X-Frame-Options header prevents:
    - Clickjacking attacks
    - UI redressing attacks
    - Malicious sites embedding application in iframes
    
    CWE-693: Protection Mechanism Failure
    CWE-1021: Improper Restriction of Rendered UI Layers or Frames
    """

    def test_x_frame_options_set(self):
        """X-Frame-Options header must be set."""
        self.assertIn(
            settings.X_FRAME_OPTIONS,
            ['DENY', 'SAMEORIGIN'],
            "X_FRAME_OPTIONS should be DENY or SAMEORIGIN"
        )

    def test_x_frame_options_deny_for_strict_security(self):
        """X-Frame-Options should be DENY for maximum security."""
        self.assertEqual(
            settings.X_FRAME_OPTIONS,
            'DENY',
            "X_FRAME_OPTIONS should be DENY to prevent clickjacking"
        )


class PasswordValidationSecurityTests(TestCase):
    """
    Tests that password validation enforces strong password requirements.
    
    Strong passwords prevent:
    - Brute force attacks
    - Dictionary attacks
    - Credential stuffing
    
    CWE-521: Weak Password Requirements
    OWASP: Authentication Cheat Sheet
    """

    def test_password_validators_configured(self):
        """Password validators must be configured."""
        self.assertIsNotNone(settings.AUTH_PASSWORD_VALIDATORS)
        self.assertGreater(
            len(settings.AUTH_PASSWORD_VALIDATORS),
            0,
            "AUTH_PASSWORD_VALIDATORS must have at least one validator"
        )

    def test_minimum_password_length_enforced(self):
        """Minimum password length must be at least 12 characters."""
        min_length_found = False
        for validator in settings.AUTH_PASSWORD_VALIDATORS:
            if 'MinimumLengthValidator' in validator.get('NAME', ''):
                options = validator.get('OPTIONS', {})
                min_len = options.get('min_length', 8)
                self.assertGreaterEqual(
                    min_len,
                    12,
                    "Minimum password length should be at least 12 characters"
                )
                min_length_found = True

        self.assertTrue(
            min_length_found,
            "MinimumLengthValidator must be configured"
        )

    def test_common_password_validator_present(self):
        """CommonPasswordValidator must be present."""
        validators = [v.get('NAME', '') for v in settings.AUTH_PASSWORD_VALIDATORS]
        self.assertTrue(
            any('CommonPasswordValidator' in v for v in validators),
            "CommonPasswordValidator should be configured"
        )


class ContentSecurityTests(TestCase):
    """
    Tests that content security policies prevent injection attacks.
    
    CSP prevents:
    - Cross-site scripting (XSS)
    - Injection attacks
    - Data exfiltration
    
    CWE-79: Improper Neutralization of Input During Web Page Generation
    CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
    """

    def test_content_security_policy_configured(self):
        """Content Security Policy should be configured."""
        self.assertIsNotNone(settings.SECURE_CONTENT_SECURITY_POLICY)
        self.assertIsInstance(settings.SECURE_CONTENT_SECURITY_POLICY, dict)

    def test_csp_has_default_src(self):
        """CSP must have default-src directive."""
        self.assertIn(
            'default-src',
            settings.SECURE_CONTENT_SECURITY_POLICY,
            "CSP should have default-src directive"
        )

    def test_csp_default_src_self_only(self):
        """CSP default-src should be 'self' for security."""
        csp = settings.SECURE_CONTENT_SECURITY_POLICY
        self.assertIn(
            "'self'",
            csp.get('default-src', []),
            "CSP default-src should include 'self'"
        )


class ReferrerPolicySecurityTests(TestCase):
    """
    Tests that Referrer-Policy header prevents information leakage.
    
    Referrer-Policy prevents:
    - Leaking sensitive query parameters in referrer header
    - Information disclosure about user activity
    
    CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    """

    def test_referrer_policy_set(self):
        """Referrer-Policy header must be set."""
        self.assertIsNotNone(settings.SECURE_REFERRER_POLICY)
        self.assertIn(
            settings.SECURE_REFERRER_POLICY,
            [
                'no-referrer',
                'no-referrer-when-downgrade',
                'same-origin',
                'origin',
                'strict-origin',
                'origin-when-cross-origin',
                'strict-origin-when-cross-origin',
                'unsafe-url',
            ],
            "SECURE_REFERRER_POLICY should be a valid value"
        )


class MiddlewareSecurityTests(TestCase):
    """
    Tests that security-relevant middleware is enabled.
    
    SecurityMiddleware provides:
    - Content-Type header protection
    - X-Content-Type-Options header
    - X-XSS-Protection header (legacy)
    - Secure cookie handling
    
    CWE-693: Protection Mechanism Failure
    """

    def test_security_middleware_enabled(self):
        """SecurityMiddleware must be enabled."""
        self.assertIn(
            'django.middleware.security.SecurityMiddleware',
            settings.MIDDLEWARE,
            "SecurityMiddleware must be first in MIDDLEWARE list"
        )

    def test_csrf_middleware_enabled(self):
        """CSRF middleware must be enabled."""
        self.assertIn(
            'django.middleware.csrf.CsrfViewMiddleware',
            settings.MIDDLEWARE,
            "CsrfViewMiddleware must be in MIDDLEWARE list"
        )


class StaticFilesSecurityTests(TestCase):
    """
    Tests that static files configuration is properly set up for deployment.
    
    STATIC_ROOT is used by collectstatic to gather static files
    for production deployment.
    """

    def test_static_root_configured(self):
        """STATIC_ROOT must be configured for production."""
        self.assertIsNotNone(settings.STATIC_ROOT)
        self.assertTrue(len(str(settings.STATIC_ROOT)) > 0)

    def test_static_url_set(self):
        """STATIC_URL must be set."""
        self.assertIsNotNone(settings.STATIC_URL)
        self.assertTrue(
            settings.STATIC_URL.startswith('/') or settings.STATIC_URL.startswith('static'),
            "STATIC_URL should start with / or 'static'"
        )


class MediaFilesSecurityTests(TestCase):
    """
    Tests that media files configuration prevents directory traversal attacks.
    
    Media files are user-uploaded content (avatars, documents, etc.)
    Directory traversal attacks attempt to write files outside MEDIA_ROOT.
    """

    def test_media_url_set(self):
        """MEDIA_URL must be set."""
        self.assertIsNotNone(settings.MEDIA_URL)
        self.assertEqual(settings.MEDIA_URL, '/media/')

    def test_media_root_configured(self):
        """MEDIA_ROOT must be configured."""
        self.assertIsNotNone(settings.MEDIA_ROOT)


class EmailSecurityTests(TestCase):
    """
    Tests that email configuration is properly set.
    
    Email is used for password resets, notifications, etc.
    """

    def test_email_backend_configured(self):
        """EMAIL_BACKEND must be configured."""
        self.assertIsNotNone(settings.EMAIL_BACKEND)

    def test_default_from_email_set(self):
        """DEFAULT_FROM_EMAIL must be set."""
        self.assertIsNotNone(settings.DEFAULT_FROM_EMAIL)
        self.assertTrue(len(settings.DEFAULT_FROM_EMAIL) > 0)


class EnvironmentSecurityTests(TestCase):
    """
    Tests that environment awareness prevents misconfigurations.
    
    The ENVIRONMENT variable controls:
    - Production vs development settings
    - Security level of configuration
    - Whether debug information is exposed
    """

    def test_environment_set(self):
        """ENVIRONMENT must be explicitly set."""
        self.assertIsNotNone(settings.ENVIRONMENT)
        self.assertIn(
            settings.ENVIRONMENT,
            ['development', 'production', 'staging'],
            "ENVIRONMENT must be development, production, or staging"
        )

    def test_environment_in_dev_or_prod(self):
        """ENVIRONMENT should be either development or production."""
        self.assertIn(
            settings.ENVIRONMENT,
            ['development', 'production'],
            "ENVIRONMENT should typically be development or production"
        )


class SecurityHeadersIntegrationTests(TestCase):
    """
    Integration tests for security headers and settings.
    
    Validates that all security settings work together coherently.
    """

    def test_production_mode_consistency(self):
        """In production, all security settings should be enabled."""
        if os.environ.get('ENVIRONMENT') == 'production':
            # Verify SSL settings
            self.assertTrue(settings.SECURE_SSL_REDIRECT)
            self.assertTrue(settings.SESSION_COOKIE_SECURE)
            self.assertTrue(settings.CSRF_COOKIE_SECURE)

            # Verify HSTS
            self.assertGreater(settings.SECURE_HSTS_SECONDS, 0)
            self.assertTrue(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)

            # Verify cookies
            self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
            self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)

            # Verify debug is disabled
            self.assertFalse(settings.DEBUG)

    def test_development_mode_allows_flexibility(self):
        """In development, some security settings may be relaxed."""
        if os.environ.get('ENVIRONMENT') == 'development':
            # Development can allow HTTP
            # DEBUG can be True
            # But should still have some basic protections
            self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
            self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
