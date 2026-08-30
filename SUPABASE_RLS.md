# Row-Level Security (RLS) Policies

This document describes all RLS policies implemented in the Supabase database for the Phishing Detection System.

## Overview

Row-Level Security ensures that:
- Regular users can only access their own data
- Admins have full access to system data
- Data access is enforced at the database level (not just application level)
- Unauthorized access attempts are rejected by the database itself

---

## Policies by Table

### 1. Profiles Table

**Table**: `profiles`  
**Purpose**: Store user profile information

#### Policy: "Users can view their own profile"
- **Type**: SELECT
- **Condition**: `auth.uid() = id`
- **Effect**: Users can only see their own profile

#### Policy: "Users can update their own profile"
- **Type**: UPDATE
- **Condition**: `auth.uid() = id`
- **Effect**: Users can only update their own profile

#### Policy: "Admins can view all profiles"
- **Type**: SELECT
- **Condition**: User has `role = 'admin'`
- **Effect**: Admins can view all user profiles

---

### 2. URL Scans Table

**Table**: `url_scans`  
**Purpose**: Store all URL scan results

#### Policy: "Users can view their own scans"
- **Type**: SELECT
- **Condition**: `auth.uid() = user_id`
- **Effect**: Users see only their own scans

#### Policy: "Users can create their own scans"
- **Type**: INSERT
- **Condition**: `auth.uid() = user_id`
- **Effect**: Users can only create scans under their own user_id

#### Policy: "Users can update their own scans"
- **Type**: UPDATE
- **Condition**: `auth.uid() = user_id`
- **Effect**: Users can only modify their own scans

#### Policy: "Admins can view all scans"
- **Type**: SELECT
- **Condition**: User has `role = 'admin'`
- **Effect**: Admins see all scans in the system

---

### 3. Threat Intelligence Table

**Table**: `threat_intelligence`  
**Purpose**: Store threat data associated with scans

#### Policy: "Users can view threats from their scans"
- **Type**: SELECT
- **Condition**: Scan is owned by `auth.uid()`
- **Effect**: Users see threat data only for their own scans

#### Policy: "Admins can view all threats"
- **Type**: SELECT
- **Condition**: User has `role = 'admin'`
- **Effect**: Admins see all threat intelligence

---

### 4. Alerts Table

**Table**: `alerts`  
**Purpose**: Store alerts for high-risk scans

#### Policy: "Users can view their own alerts"
- **Type**: SELECT
- **Condition**: `auth.uid() = user_id`
- **Effect**: Users only see alerts for their account

#### Policy: "Users can update their own alerts"
- **Type**: UPDATE
- **Condition**: `auth.uid() = user_id`
- **Effect**: Users can mark their own alerts as read

#### Policy: "Admins can view all alerts"
- **Type**: SELECT
- **Condition**: User has `role = 'admin'`
- **Effect**: Admins see all system alerts

---

### 5. API Logs Table

**Table**: `api_logs`  
**Purpose**: Audit trail of API calls

#### Policy: "Admins can view all API logs"
- **Type**: SELECT
- **Condition**: User has `role = 'admin'`
- **Effect**: Only admins can view API logs

#### Policy: "Backend can insert API logs"
- **Type**: INSERT
- **Condition**: Always true (called with service role key)
- **Effect**: Backend logs all API calls (no user restriction needed)

---

### 6. Model Versions Table

**Table**: `model_versions`  
**Purpose**: Store ML model versions and metrics

#### Policy: "Everyone can view model versions"
- **Type**: SELECT
- **Condition**: No condition (always true)
- **Effect**: All authenticated users can see model versions

#### Policy: "Admins can insert model versions"
- **Type**: INSERT
- **Condition**: User has `role = 'admin'`
- **Effect**: Only admins can create new model versions

---

## Security Implementation Details

### User Authentication

- Supabase Auth provides the `auth.uid()` function
- This returns the authenticated user's UUID from `auth.users` table
- Each user has a corresponding entry in the `profiles` table
- The profile's `id` matches `auth.uid()`

### Admin Detection

All admin policies check:
```sql
auth.uid() IN (
  SELECT id FROM profiles WHERE role = 'admin' AND auth.uid() = id
)
```

This verifies:
1. The user is authenticated
2. They have `role = 'admin'` in their profile
3. It's actually their profile (extra security)

### Foreign Key Relationships

```
profiles.id ──────┐
                  ├── url_scans.user_id
                  ├── alerts.user_id
                  └── api_logs.user_id

url_scans.id ──────┬── threat_intelligence.scan_id
                   └── alerts.scan_id
```

This ensures data consistency and enables efficient RLS checks.

---

## Best Practices

1. **Always use authenticated requests**: Send valid JWT token in Authorization header
2. **Never bypass RLS from backend**: Always use the appropriate Supabase client
   - Use ANON key for frontend (RLS enforced)
   - Use SERVICE ROLE key for backend admin operations only
3. **Verify role in application**: Even though RLS enforces security, also check in application logic
4. **Log access attempts**: API logs table captures all API calls for audit
5. **Test RLS policies**: Verify users can't access other users' data
6. **Keep service role key secret**: Never expose it in frontend or version control

---

## Testing RLS Policies

### Test: User Cannot Access Other User's Data

```javascript
// Login as User A
const userAToken = /* ... */;

// Try to fetch User B's scans
const response = await fetch('/api/scan/user-b-scan-id', {
  headers: { 'Authorization': `Bearer ${userAToken}` }
});

// Should get 403 Forbidden error
```

### Test: Admin Can Access All Data

```javascript
// Login as Admin
const adminToken = /* ... */;

// Fetch all scans
const response = await fetch('/api/admin/scans', {
  headers: { 'Authorization': `Bearer ${adminToken}` }
});

// Should get 200 OK with all scans
```

### Test: Unauthenticated Request is Blocked

```javascript
// No token provided
const response = await fetch('/api/scans');

// Should get 401 Unauthorized
```

---

## Monitoring RLS

To check if RLS is working:

1. **Supabase Dashboard → Table Editor**
   - Try viewing each table as different users
   - Users should only see their own rows

2. **Supabase Dashboard → Authentication**
   - Monitor user logins and sessions
   - Check for unauthorized access attempts

3. **Backend Logs**
   - Look for database permission errors
   - Check API logs for unauthorized requests

---

## Troubleshooting RLS Issues

### Issue: "new row violates row-level security policy"

**Cause**: Trying to insert data with wrong user_id  
**Solution**: Ensure `user_id` matches the authenticated user's id

### Issue: "SELECT violates row-level security policy"

**Cause**: User doesn't have permission to view data  
**Solution**: Only authenticated users can query; check role in profile

### Issue: Admin can't see admin-only data

**Cause**: User profile doesn't have `role = 'admin'`  
**Solution**: Update user's profile role: 
```sql
UPDATE profiles SET role = 'admin' WHERE email = 'admin@example.com';
```

### Issue: Profile not created on signup

**Cause**: Trigger didn't fire  
**Solution**: 
1. Check trigger exists: `on_auth_user_created`
2. Manually create profile:
   ```sql
   INSERT INTO profiles (id, email, role)
   VALUES (user_uuid, 'user@example.com', 'user');
   ```

---

## RLS Best Practices Checklist

- [ ] RLS is enabled on all tables
- [ ] Policies exist for SELECT, INSERT, UPDATE, DELETE
- [ ] User data is scoped to `auth.uid()`
- [ ] Admin access is explicitly defined
- [ ] Service role key is only used on backend
- [ ] Anon key is used on frontend (RLS enforced)
- [ ] Profiles table has triggers for timestamps
- [ ] Audit logs record all admin actions
- [ ] RLS policies are tested regularly
- [ ] No hardcoded user IDs in queries

---

**Last Updated**: 2026-08-30  
**Status**: All RLS policies implemented and tested
