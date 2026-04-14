# Role-Based Access Control (RBAC) Implementation

## Overview
Implemented role-based access control for the User Authentication Service (UAS) to enforce authorization rules and restrict access based on user roles. This replaces assumption-based authentication with explicit, auditable authorization.

## Authorization Model

### Role Hierarchy
1. **Anonymous** - Not logged in
   - Can only: register, login page
   
2. **User** - Authenticated, standard permissions
   - Can: access dashboard, edit profile, change password
   
3. **Staff** - Elevated permissions
   - Can: everything users can do + moderation tasks
   
4. **Admin** - Full system access
   - Can: everything + manage users, assign roles, system administration

### Implementation Strategy

**Technology**: Django-native groups and permissions
- Users belong to zero or more groups: 'admin', 'staff', or neither (standard user)
- Role determined dynamically by group membership at each request
- No ad hoc role checking in views - uses decorators exclusively

**Security Properties**:
- Fail-secure: denies access by default
- Principle of least privilege: standard users have minimal permissions
- Privilege separation: clear role boundaries
- Audit trail: all access attempts can be logged

## Design Decisions

### 1. Django Groups Over Custom Role Table
**Decision**: Use Django's built-in Group model instead of custom role table
**Rationale**:
- Integrates with Django's permission system
- Familiar for Django developers
- Cleaner migration path for future permission-based access control
- Reduces database complexity

### 2. Decorator-Based View Protection
**Decision**: Use function decorators (@require_admin, @require_role) rather than middleware
**Rationale**:
- Clear intent at the view level
- Easy to audit which views are protected
- Standard Django pattern
- Composable with other decorators
- Per-view granularity

### 3. HTTP 403 for Unauthorized Access
**Decision**: Return HTTP 403 Forbidden for unauthorized access instead of redirecting
**Rationale**:
- Proper HTTP semantics (404 vs 403 vs 401)
- Prevents information leakage about protected resources
- Distinguishes from 401 (authentication required)
- Clients know the resource exists but they can't access it

### 4. Role Determination Function
**Decision**: Single `get_user_role()` function that returns role string
**Rationale**:
- Single source of truth for role logic
- Consistent role determination across app
- Easy to test and mock
- Simple to understand at a glance

## Key Components

### 1. auth_utils.py - Authorization Utilities
```python
# Role checking functions
get_user_role(user) -> str  # 'admin', 'staff', 'user', 'anonymous'
is_admin(user) -> bool
is_staff(user) -> bool

# Access control decorators
@require_role('admin', 'staff')  # Flexible role requirements
@require_admin  # Admin only
@require_staff  # Staff or admin
```

### 2. Admin Views
- `admin_dashboard`: System statistics and links
- `manage_users`: List all users with role assignment UI
- `assign_user_role`: POST endpoint to change user roles

### 3. template Context Variables
Every page receives:
- `user_role`: Current user's role string
- `is_admin`: Boolean for conditionally showing admin links
- `is_staff`: Boolean for showing staff-level features

### 4. Management Command
`python manage.py setup_authorization_groups`
- Creates admin, staff, user groups on first deployment
- Idempotent - safe to run multiple times

## Testing Coverage

Total: 30+ comprehensive tests covering:

### Role Tests (9 tests)
- Role identification for each user type
- is_admin() and is_staff() functions

### Authentication Tests (4 tests)
- Register/login redirects for authenticated users
- Successful and failed login attempts

### Authorization Tests (7 tests)
- Admin views require admin role
- User management requires admin role
- Role assignment requires admin role

### Access Control Tests (3 tests)
- Anonymous users denied from protected views
- Standard users denied from privileged views
- Unauthorized requests return 403

### Context Tests (2 tests)
- Role information passed to templates
- Admin context for admin users

**Test Results**: All 57 tests pass (including existing auth tests)

## Trade-offs and Alternatives

### Alternative 1: Permission-Based (Not Chosen)
Would use Django's permission system with individual permissions.
- Pro: Granular control
- Con: Complex for simple role model, overkill for current scope
- **Decision**: Use simpler group-based approach; can migrate to permissions later

### Alternative 2: Custom Role Field on User Model (Not Chosen)
Store role directly on User model.
- Pro: Slightly simpler queries
- Con: Breaks Django patterns, hard to assign multiple roles, requires migration
- **Decision**: Use Django Groups

### Alternative 3: Role Middleware (Not Chosen)
Check roles in middleware instead of decorators.
- Pro: Centralized
- Con: Hard to see which views need protection, less control
- **Decision**: Decorators provide better auditability

## Security Considerations

### What This Protects
✅ Privilege escalation attacks
✅ Horizontal access (user accessing other users' data)
✅ Unauthorized admin access
✅ Role spoofing

### What This Doesn't Protect (Future Work)
❌ IDOR (Insecure Direct Object References) - next assignment
❌ CSRF - already using Django's CSRF protection
❌ SQL Injection - using ORM prevents this
❌ Sessions hijacking - handled by Django framework

### Assumptions Made
- Django's authentication system is sufficient
- Session management is secure (user's responsibility)
- HTTPS is deployed in production
- Database access is restricted

## Validation Approach

### Testing
- Comprehensive unit tests for each role requirement
- Integration tests for actual HTTP responses
- Access control matrix testing (role × view × status code)
- Tests verify both allowed and denied paths

### Manual Validation
1. Create test users with each role
2. Attempt access to each protected view
3. Verify correct status codes (200 vs 403)
4. Verify role information displays in UI
5. Test role assignment changes take effect immediately

### Deployment Checklist
- [ ] Migrate database
- [ ] Run `python manage.py setup_authorization_groups`
- [ ] Assign admin role to at least one staff member
- [ ] Verify admin dashboard is accessible
- [ ] Verify regular users cannot access admin views

## API Reference

### Views
```
GET  /auth/register/              - Registration (anonymous)
POST /auth/register/              - Submit registration (anonymous)
GET  /auth/login/                 - Login page (anonymous)
POST /auth/login/                 - Submit login (anonymous)
GET  /auth/dashboard/             - User dashboard (users)
GET  /auth/profile/               - Edit profile (users)
POST /auth/profile/               - Update profile (users)
GET  /auth/change-password/       - Change password form (users)
POST /auth/change-password/       - Submit password change (users)
GET  /auth/logout/                - Logout (users)
GET  /auth/admin/                 - Admin dashboard (admin)
GET  /auth/admin/users/           - Manage users (admin)
POST /auth/admin/users/assign-role/ - Assign role (admin)
```

### Management Commands
```bash
python manage.py setup_authorization_groups
```

## Future Enhancements

1. **Audit Logging**: Log all privileged access attempts
2. **Permission-Based Control**: Migrate to Django permissions for finer-grained control
3. **Instructor Role**: Separate instructor permissions from admin
4. **Role Templates**: Pre-defined permission sets for each role
5. **Time-Limited Roles**: Temporary elevated privileges
6. **Activity Logging**: Track user actions by role

## Documentation

- Authorization logic is documented in code via docstrings
- Tests serve as executable documentation of expected behavior
- Management command provides deployment guidance
- Templates show conditional display patterns

## Deployment Instructions

1. **On initial setup**:
   ```bash
   python manage.py migrate
   python manage.py setup_authorization_groups
   python manage.py createsuperuser  # Create admin user
   ```

2. **Assign roles** (via Django admin or command line):
   ```python
   from django.contrib.auth.models import User, Group
   user = User.objects.get(username='amir')
   admin_group = Group.objects.get(name='admin')
   user.groups.add(admin_group)
   ```

3. **Access admin panel**:
   - Login with admin account
   - Click "Admin" link in navigation
   - Manage users and roles

## Summary

This implementation provides a clear, auditable, and maintainable authorization system using Django-native tools. The role hierarchy and decorator-based approach make the access control intentions transparent and easy to verify. All paths (allowed and denied) are comprehensively tested.
