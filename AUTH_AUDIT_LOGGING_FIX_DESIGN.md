# Authentication and Privilege Change Audit Logging Design

## Objective

Implement a comprehensive audit logging system that records all security-relevant events in the authentication and privilege management flows, enabling security audits, compliance reporting, and incident investigation.

## Security Problem

The application previously lacked detailed audit trails for critical security events. Without audit logging:
- Security breaches go undetected due to lack of event history
- Unauthorized access and privilege escalation attempts cannot be investigated
- Compliance requirements for activity tracking cannot be met
- Incident response teams cannot reconstruct attack timelines
- Privileged access changes are not monitored

## Design Approach

### Event-Based Architecture

The audit logging system captures nine distinct security events:

1. **EVENT_REGISTRATION** - User account creation
2. **EVENT_LOGIN_SUCCESS** - Successful authentication
3. **EVENT_LOGIN_FAILURE** - Failed authentication attempts
4. **EVENT_LOGOUT** - Session termination
5. **EVENT_PASSWORD_CHANGE** - Password modification by user
6. **EVENT_PASSWORD_RESET** - Password reset via email token
7. **EVENT_ROLE_ASSIGNED** - Privilege grant (admin/staff/user group assignment)
8. **EVENT_ROLE_REMOVED** - Privilege revocation
9. **EVENT_PROFILE_UPDATED** - User profile modifications

### Data Model

The `AuditLog` model stores immutable audit records with the following fields:

- **timestamp** - Event occurrence time (timezone-aware UTC)
- **event_type** - Type of security event (one of 9 EVENT_* constants)
- **user** - The user being audited (ForeignKey, nullable for registration/reset events)
- **actor** - The user performing the action (ForeignKey, nullable, indicates admin actions)
- **ip_address** - Source IP address (extracted from X-Forwarded-For or REMOTE_ADDR)
- **user_agent** - Client browser/device identifier (truncated to 500 chars)
- **description** - Human-readable event summary
- **details** - JSONField for event-specific data

### Indexes for Performance

- `(timestamp, event_type)` - Fast filtering by event time and type
- `(user, timestamp)` - Fast user activity queries
- `(actor, timestamp)` - Fast admin action queries
- `(ip_address, timestamp)` - Fast IP-based forensics queries

## Implementation Details

### Integration Points

**User Registration** (`register` view)
- Logs EVENT_REGISTRATION after account creation
- Records new user's IP, user-agent, and email
- Enables detection of mass account creation attacks

**Authentication** (`login_view`)
- Logs EVENT_LOGIN_SUCCESS for valid credentials
- Logs EVENT_LOGIN_FAILURE for invalid attempts
- Records IP, user-agent, and failed username
- Enables brute-force attack detection

**Session Management** (`logout_view`)
- Logs EVENT_LOGOUT before session destruction
- Preserves user reference before session cleanup
- Tracks session duration and termination

**Password Management** (`change_password` view)
- Logs EVENT_PASSWORD_CHANGE for user-initiated password changes
- Records change timestamp and successful completion
- Ensures password values are never logged

**Password Reset** (`password_reset_confirm` view)
- Logs EVENT_PASSWORD_RESET after token validation
- Records reset timestamp and method
- Prevents logging of temporary passwords

**Privilege Management** (`assign_user_role` view)
- Logs EVENT_ROLE_ASSIGNED with `actor` field when admin grants privileges
- Logs EVENT_ROLE_REMOVED with `actor` field when admin revokes privileges
- Enables accountability for privilege changes

### Utility Functions

**`get_client_ip(request)`** in `auth_utils.py`
- Safely extracts client IP from X-Forwarded-For header (for proxies)
- Falls back to REMOTE_ADDR
- Returns '0.0.0.0' if unavailable

**`get_user_agent(request)`** in `auth_utils.py`
- Extracts HTTP_USER_AGENT header
- Truncates to 500 characters to prevent storage issues
- Returns empty string if unavailable

**`log_audit_event(event_type, request, user=None, actor=None, description='', details=None)`** in `auth_utils.py`
- Creates AuditLog entries safely
- Catches and logs exceptions gracefully
- Prevents audit logging failures from breaking application
- Validates event_type against supported constants

## Security Characteristics

### Attack Prevention Capabilities

1. **Brute-Force Attack Detection**
   - Multiple EVENT_LOGIN_FAILURE events from same IP
   - Historical analysis of failed attempts

2. **Account Takeover Detection**
   - EVENT_PASSWORD_CHANGE from unusual IP/device
   - Compare against historical user patterns

3. **Privilege Escalation Detection**
   - EVENT_ROLE_ASSIGNED without corresponding authorization request
   - Identify unauthorized admin actions via `actor` field

4. **Unauthorized Access Detection**
   - EVENT_LOGIN_SUCCESS from suspicious locations
   - Cross-reference with geographic data

5. **Compliance Violation Detection**
   - All privilege changes tracked with actor identification
   - Complete audit trail for regulatory investigations

### Data Sensitivity

**Never Logged**
- Password values or hashes
- Authentication tokens
- Session IDs
- Sensitive personal information

**Safe to Log**
- IP addresses (for forensics)
- User agents (for device tracking)
- Event types and timestamps
- User and actor identities
- Event descriptions (generic text, no values)

## Testing Strategy

Comprehensive test suite with 20 tests covering:

### Model Tests (5 tests)
- AuditLog creation with required fields
- JSONField details storage and retrieval
- Actor tracking for admin actions
- User history queries
- Event type validation

### View Integration Tests (12 tests)
- Registration event logging
- Login success/failure logging with IP/user-agent
- Logout event logging
- Password change logging
- Password reset logging
- Role assignment/removal with actor tracking

### Security Tests (3 tests)
- Sensitive data never appears in descriptions
- No password values stored
- No plaintext sensitive data in details field

All 20 tests validate that:
- Events are created with correct types
- IP addresses and user-agents are captured
- Actor field tracks privileged operations
- No sensitive data is exposed
- Query methods return correct results

## Future Considerations

### Advanced Features
- Log retention policies and archival strategy
- Real-time alerting on suspicious patterns
- Integration with SIEM (Security Information and Event Management)
- Automated analysis for threat detection
- Geographic anomaly detection for login events
- Device fingerprinting for user activity baseline

### Compliance Integration
- SOC 2 Type II audit trail requirements
- PCI-DSS privilege change accountability
- HIPAA user activity tracking
- GDPR right to be forgotten considerations

### Performance Optimization
- Consider partitioning by date for large deployments
- Implement log rotation and archival
- Add database maintenance procedures
- Monitor query performance on history queries

## Validation

✅ 20 comprehensive tests pass (100% success rate)
✅ Database migration applies without errors
✅ No sensitive data in audit logs
✅ All security events properly instrumented
✅ Historical query methods functional
✅ Actor tracking for admin operations working
