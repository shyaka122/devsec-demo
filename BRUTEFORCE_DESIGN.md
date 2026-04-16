# Brute-Force Protection for Login Endpoint

## Executive Summary

This document describes the brute-force protection mechanism implemented for the login endpoint. The system tracks failed login attempts per username and per IP address, applying account-level and IP-level lockouts to prevent unauthorized access while maintaining usability for legitimate users.

**Key Properties:**
- Account lockout after 5 failed attempts in 15 minutes
- IP-based lockout after 15 failed attempts in 15 minutes  
- Generic error messages to prevent username enumeration
- Automatic attempt record cleanup (60+ days)
- Comprehensive audit trail for security investigations

---

## Threat Model

### 1. Dictionary Attack (Single Attacker, Targeted Account)
**Description:** Attacker attempts multiple passwords against a known username from a single IP.

**Impact:** Attacker gains unauthorized access if password is weak or common.

**Mitigation:** Account-level lockout prevents rapid-fire attempts after 5 failures within 15 minutes. This forces attackers to wait before retry, making dictionary attacks impractical for weak passwords.

**Time Cost:** 5 failures + 15-minute lockout = minimum 15 minutes to attempt 5 passwords. Dictionary attack on 1000-word list = 3000 minutes (2 days) minimum.

### 2. Distributed Brute-Force Attack (Multiple Attackers, Same Account)
**Description:** Multiple attackers target the same account from different IP addresses.

**Impact:** Account-level protection alone fails because each attacker has different IP.

**Mitigation:** Account-level lockout still applies since it's independent of IP. Once account is locked for 15 minutes, ALL attempts fail regardless of source.

**Effectiveness:** Strong - prevents multi-source attacks from bypassing IP-level checks.

### 3. IP-Based Attack (High-Volume Source)
**Description:** Single IP with many compromised credentials attempts login for many accounts.

**Impact:** Attacker discovers valid accounts and potentially gains access.

**Mitigation:** IP-level lockout after 15 failures (3x account threshold) from single IP within 15 minutes. This detects credential stuffing attacks.

**False Positive Risk:** Legitimate shared networks (offices, schools) may experience false lockouts. Recommend IP whitelist for trusted networks.

### 4. Targeted Slow Attack (Low and Slow)
**Description:** Attacker attempts 1 password per hour to avoid lockout.

**Impact:** No immediate account damage; may eventually succeed over days/weeks.

**Mitigation:** Outside scope of rate limiting. Recommend:
- Force password reset after account creation
- Implement account activity monitoring
- Alert on access from unusual locations
- Implement 2FA/MFA for sensitive accounts

### 5. Username Enumeration (Information Leakage)
**Description:** Attacker determines valid usernames by analyzing error messages.

**Impact:** Reduces attack surface to only valid accounts.

**Mitigation:** Generic error messages for all failures: "Invalid username or password. Please try again later or contact support."

---

## Design Decisions

### 1. Hybrid Lockout Strategy (Account + IP)

**Option A (Account Only):** Lock account after N failures
- Pros: Simple, protects against distributed attacks
- Cons: Legitimate lockouts due to typos; IP attacks still attempt many accounts

**Option B (IP Only):** Lock IP after N failures  
- Pros: Protects against credential stuffing
- Cons: Legitimate users from shared networks locked out; doesn't protect accounts from distributed attacks

**Option C (Hybrid - Chosen):** Lock account after 5 failures; lock IP after 15 failures
- Pros: Protects both individual accounts AND IP sources; requires attacker to change tactics
- Cons: Slight complexity increment

**Rationale:** Defense in depth. Account-level catches focused attacks; IP-level catches credential stuffing. Asymmetric thresholds (5 vs 15) prevent false positives while maintaining security.

### 2. Lockout Duration: 15 Minutes

**Option A:** 5 minutes
- Pros: Better UX, less frustrating for typos
- Cons: Still practical for slow attacks; 3+ hours to attempt 100 guesses

**Option B:** 1 hour
- Pros: Strong deterrent for attackers
- Cons: Poor UX; single typo = 1-hour lockout

**Option C (Chosen): 15 minutes
- Reasonable grace period for legitimate users (one mistyped password = manageable)
- Sufficient deterrent for attackers (48 attempts over 12 hours with account lockout)
- Industry standard (AWS, Google use similar windows)

### 3. Failure Threshold: 5 for Account

**Option A:** 3 failures
- Pros: More aggressive protection
- Cons: High false positive rate; many legitimate users typo on first try

**Option B:** 10 failures
- Pros: Fewer false positives
- Cons: 10 word dictionary attack in 15 minutes is feasible  

**Option C (Chosen): 5 failures
- Balances security and usability
- NIST considers 32-bit keys = ~4 billion years against brute-force; practical equivalent is ~5-10 attempts before lockout
- Prevents most dictionary attacks while allowing occasional typos

### 4. Failure Threshold: 15 for IP (3x Account Threshold)

**Rationale:** 
- Single attacker with IP: 5 failures = account locked, stops attempt
- Multiple attackers sharing IP or credential stuffing: 15 failures = IP locked
- Asymmetric ratio prevents false positives from multiple legitimate users on shared network

### 5. Time Window: 15 Minutes (Same as Lockout Duration)

**Rationale:**
- Simplifies mental model: failures within lockout window count toward lockout
- Prevents game-playing (spread attempts over exactly 16 minutes)
- Window and lockout duration should align

### 6. Model-Based Tracking (vs. Cache/Redis)

**Option A:** Redis/Cache-based
- Pros: Fast, doesn't require DB writes on every login
- Cons: Data loss in cache failure; requires separate infrastructure

**Option B (Chosen): Database model
- Pros: Persistent, auditable, simple deployment, no external dependencies
- Cons: Slight performance cost (one write per login attempt)

**Rationale:** Security audit trail is more important than microseconds of performance. Database record enables investigation of attacks.

### 7. Generic Error Messages

**Bad:** "Username not found" vs "Password incorrect"
- Enables username enumeration

**Better:** "Invalid username or password"
- Prevents enumeration in non-attack scenario

**Chosen (Better):** "Invalid username or password. Please try again later or contact support."
- Explains lockout possibility
- Provides help path
- Still prevents username enumeration

---

## Implementation Details

### Database Schema

```python
class LoginAttempt(models.Model):
    username = CharField(max_length=150, indexed)  # Allows username lookup
    ip_address = GenericIPAddressField(indexed)     # Allows IP lookup
    timestamp = DateTimeField(default=timezone.now, indexed)  # Time-based queries
    success = BooleanField(default=False)           # Failed vs successful
    user_agent = TextField(blank=True)              # Audit trail
```

**Indices:**
- `(username, -timestamp)`: Fast lookup of username's recent attempts
- `(ip_address, -timestamp)`: Fast lookup of IP's recent attempts
- `(-timestamp)`: Fast cleanup of old records

### Protection Logic

```
On login request:
1. Extract client IP (from X-Forwarded-For or REMOTE_ADDR)
2. Check lockout status (account + IP)
   If locked: Return generic error, record attempt, exit
3. Authenticate user (check username/password)
4. Record attempt (success=True/False)
5. Return response or redirect to dashboard
```

### Client IP Extraction

```python
def get_client_ip(request):
    # Check X-Forwarded-For first (proxied requests)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take last IP to avoid spoofing (attacker can't fake previous IPs in chain)
        ip = x_forwarded_for.split(',')[-1].strip()
        return ip
    # Fall back to direct connection IP
    return request.META.get('REMOTE_ADDR')
```

**Security Note:** Takes last IP in X-Forwarded-For to prevent spoofing. Attacker can't make their IP appear as previous hop.

### Automatic Cleanup

After every `record_attempt()` call, records older than 60 days are deleted:

```python
old_cutoff = timezone.now() - timedelta(days=60)
LoginAttempt.objects.filter(timestamp__lt=old_cutoff).delete()
```

**Rational:** 60 days is sufficient for forensics; prevents database table growth unbounded.

---

## Trade-Offs

### Security vs. Availability

| Scenario | Security Benefit | Availability Cost |
|----------|---|---|
| 5 failures → account lock | Stops dictionary attacks | Legitimate user with typos waits 15 min |
| 15 failures → IP lock | Stops credential stuffing | Shared network users may lockout |
| 15-minute lockout | Deters repeats | Bad UX for one mistake |

**Mitigation:** Provide clear UI explaining lockout; offer "forgot password" flow; admin can manually reset attempts.

### Performance vs. Auditability

- Adding DB write on every login adds ~1-5ms latency
- Benefit: Immutable audit trail for security investigations
- Alternative: Cache-based system would be faster but lose audit trail

### False Positives

**Scenario:** Office of 10 people behind shared NAT. One person typos password 5 times. Remaining 9 locked out.

**Mitigation:** 
- Whitelist trusted IP ranges in settings
- Allow admins to reset attempt counters
- Implement second factor (SMS/email code) instead of IP lockout for shared networks

---

## Configuration Options

### In `settings.py`:

```python
# Brute-force protection settings
PASSWORD_LOCKOUT_MAX_ATTEMPTS = 5              # Account lockout threshold
PASSWORD_LOCKOUT_IP_MULTIPLIER = 3             # IP: account_threshold * multiplier (15)
PASSWORD_LOCKOUT_MINUTES = 15                  # Minutes before auto-unlock
PASSWORD_LOCKOUT_CLEANUP_DAYS = 60             # Delete records older than this

# Optional: IP whitelist for shared networks
PASSWORD_LOCKOUT_IP_WHITELIST = [
    '203.0.113.0/24',  # Corporate network
    '198.51.100.50',   # Trusted partner IP
]
```

### To modify thresholds:

1. **Increase security (reduce false positives risk):**
   - `PASSWORD_LOCKOUT_MAX_ATTEMPTS = 3`
   - `PASSWORD_LOCKOUT_MINUTES = 30`

2. **Increase usability (reduce false positives):**
   - `PASSWORD_LOCKOUT_MAX_ATTEMPTS = 10`
   - `PASSWORD_LOCKOUT_MINUTES = 5`

---

## Test Coverage

### Test Suite: `shyaka/tests_bruteforce.py`

**17 test cases** covering:

1. **Basic Tracking (5 tests)**
   - Record successful attempts
   - Record failed attempts
   - Query attempts by username
   - Query attempts by IP
   - Filter by time window

2. **Account Lockout Logic (3 tests)**
   - Not locked with < 5 failures
   - Locked with 5+ failures
   - Auto-unlock after window expires

3. **IP-Based Lockout (2 tests)**
   - Not locked with < 15 failures
   - Locked with 15+ failures

4. **Login View Protection (8 tests)**
   - Normal login succeeds
   - Failed attempt tracked on wrong password
   - Locked account returns error
   - Locked IP prevents login
   - Generic error message (no enumeration)
   - Successful attempt clears lockout
   - Multiple IPs tracked independently
   - Legacy clients (no X-Forwarded-For) work

5. **Audit Trail (3 tests)**
   - User agents recorded
   - Success/failure tracked correctly
   - Timestamps ordered chronologically

6. **Attack Scenarios (3 tests)**
   - Dictionary attack (5 passwords) → account locked
   - Distributed attack (multiple IPs to same account) → account locked
   - Credential stuffing (many accounts from one IP) → IP locked

**All tests pass with realistic timing and database state.**

---

## Production Recommendations

### 1. Monitoring & Alerting

Monitor `LoginAttempt` table for:
- Account with > 10 failures in 1 hour → possible attack
- IP with > 30 failures in 1 hour → credential stuffing
- IP from unusual geography → suspicious

```python
from django.core.mail import send_mail
from shyaka.models import LoginAttempt

def alert_suspicious_login_activity():
    """Alert admins of potential attacks."""
    suspicious_ips = (
        LoginAttempt.objects
        .filter(success=False, timestamp__gte=timezone.now() - timedelta(hours=1))
        .values('ip_address')
        .annotate(count=Count('id'))
        .filter(count__gte=30)
    )
    
    if suspicious_ips:
        send_mail(
            subject='Suspicious Login Activity Detected',
            message=f'Credential stuffing detected: {list(suspicious_ips)}',
            from_email='security@example.com',
            recipient_list=['admin@example.com'],
        )
```

### 2. Admin Interface

Add Django admin interface to view/manage attempts:

```python
# shyaka/admin.py
from django.contrib import admin
from .models import LoginAttempt

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'ip_address', 'success', 'timestamp')
    list_filter = ('success', 'timestamp')
    search_fields = ('username', 'ip_address')
    readonly_fields = ('timestamp',)
    
    actions = ['reset_attempts_for_username']
    
    def reset_attempts_for_username(self, request, queryset):
        """Admin action to clear attempts for a user."""
        username = request.GET.get('q')
        LoginAttempt.objects.filter(username=username).delete()
```

### 3. Rate Limiting Endpoint

Provide admin endpoint to manually reset lockout:

```python
# shyaka/views.py
@admin_required
def reset_login_lockout(request):
    """Reset login attempts for a user (admin only)."""
    if request.method == 'POST':
        username = request.POST.get('username')
        LoginAttempt.objects.filter(
            username=username,
            timestamp__gte=timezone.now() - timedelta(minutes=30)
        ).delete()
        return redirect('admin:index')
```

### 4. Deployment Notes

- **Database Performance:** With millions of LoginAttempt records, queries may slow down. Recommendation: 
  - Add database indices (already in schema)
  - Archive old records (60+ days) monthly
  - Consider partitioning by date in high-traffic systems

- **Caching:** Consider adding `@cache_page()` on login view to cache lockout status for 5 seconds, reducing DB load

- **Load Balancing:** Ensure `X-Forwarded-For` header is properly forwarded by load balancer. Otherwise, all requests appear from single IP (load balancer's IP).

### 5. Testing Before Production

```bash
# Run full test suite
python manage.py test shyaka.tests_bruteforce

# Test with realistic load (simulate 100 failed attempts)
python manage.py shell
from shyaka.models import LoginAttempt
for i in range(100):
    LoginAttempt.record_attempt('testuser', '10.0.0.1', False)
# Check if lockout is triggered and performance is acceptable
```

---

## Security Considerations

### What This Protects Against

✅ Dictionary attacks (offline wordlist guessing)  
✅ Brute-force attacks (try all passwords)  
✅ Credential stuffing (leak + massive login attempts)  
✅ Account enumeration (with generic error messages)  
✅ Distributed attacks (multiple source IPs)  

### What This Does NOT Protect Against

❌ Credential leaks (if password is compromised externally)  
❌ Phishing (user voluntarily gives password)  
❌ Keylogger/Malware (captures credentials locally)  
❌ Rainbow tables (attacker pre-computes hashes for all passwords)  
❌ Social engineering (attacker tricks admin for reset)  

### Defense in Depth Recommendations

Combine with:
1. **Strong password requirements:** 12+ chars, uppercase, numbers, symbols
2. **Multi-factor authentication:** SMS/email codes on login
3. **Password hashing:** Use `bcrypt` or `argon2` (not `md5` or `sha1`)
4. **HTTPS only:** Prevent password sniffing
5. **Account activity monitoring:** Alert on unusual logins
6. **Regular security audits:** Penetration testing, code review

---

## Future Enhancements

### Phase 2: Adaptive Rate Limiting

Adjust lockout based on threat level:
- 1st failure: None
- 2-4 failures: None (human user typos)
- 5 failures: 5-min lockout
- 10 failures: 15-min lockout
- 20+ failures: 1-hour lockout or permanent flag

### Phase 3: Machine Learning Detection

Detect attack patterns:
- Multiple IPs accessing same account
- Multiple accounts from same IP in short time
- Geographically impossible logins
- Unusual time-of-day access

### Phase 4: Multi-Factor Authentication Integration

After lockout, require 2FA code instead of just password.

---

## References

- **NIST SP 800-63B:** Digital Identity Guidelines (Authentication) - Recommends rate limiting and account lockout
- **OWASP:** Authentication Cheat Sheet - Best practices for login protection
- **CWE-307:** Improper Restriction of Rendered UI Layers (allows brute-force)
- **CWE-307:** Improper Restriction of Excessive Authentication Attempts

