# Security Policy

## Security Improvements Implemented

This document outlines the security vulnerabilities that were identified and fixed in the Zenir Logger application.

## Vulnerabilities Fixed

### 1. ✅ Cross-Site Scripting (XSS) Prevention
**Severity**: High

**Issue**: The application was vulnerable to XSS attacks through malicious target URLs. An attacker could create a link with `javascript:` or `data:` URI schemes that would execute arbitrary JavaScript when users visited the redirect page.

**Fix**: 
- Added comprehensive URL validation in `CreateLinkHandler`
- Only HTTP and HTTPS schemes are now allowed
- All URLs are parsed and validated before being stored
- Go's `html/template` package provides automatic contextual escaping in templates

**Code Location**: `handlers/admin.go` lines 71-84

### 2. ✅ Weak Session Key
**Severity**: Critical

**Issue**: The application used a hardcoded default session key (`"default-secret-key"`) when `SESSION_KEY` environment variable was not set, making sessions predictable and vulnerable to session hijacking.

**Fix**:
- Generate a cryptographically secure random session key using `crypto/rand` when `SESSION_KEY` is not set
- Added warnings to inform administrators about missing session key
- Implemented secure cookie options (HttpOnly, SameSite strict mode)

**Code Location**: `handlers/auth.go` lines 19-58

### 3. ✅ Insecure Random Number Generation
**Severity**: Medium

**Issue**: The slug generation used `math/rand` which is not cryptographically secure, making slugs predictable and potentially guessable.

**Fix**:
- Replaced `math/rand` with `crypto/rand` for slug generation
- Uses `crypto/rand.Int()` for secure random number generation
- Added fallback to timestamp-based generation if crypto/rand fails

**Code Location**: `handlers/admin.go` lines 222-234

### 4. ✅ Rate Limiting for Login Attempts
**Severity**: High

**Issue**: No rate limiting on login attempts, allowing brute force attacks on admin credentials.

**Fix**:
- Implemented rate limiting: maximum 5 failed login attempts per IP
- 15-minute lockout period after exceeding limit
- Automatic cleanup of old login attempt records
- IP-based tracking with proper X-Forwarded-For handling

**Code Location**: `handlers/auth.go` lines 19-121

### 5. ✅ IP Spoofing via X-Forwarded-For
**Severity**: Medium

**Issue**: The application blindly trusted the entire `X-Forwarded-For` header, allowing attackers to spoof their IP address.

**Fix**:
- Now only uses the first IP in the X-Forwarded-For chain (the actual client IP)
- Properly parses the header to extract only the client IP
- Applied in both login rate limiting and visit tracking

**Code Location**: `handlers/auth.go` lines 194-212, `handlers/public.go` lines 78-92

### 6. ✅ Cross-Site Request Forgery (CSRF)
**Severity**: High

**Issue**: No CSRF protection on state-changing operations, allowing attackers to perform actions on behalf of authenticated users.

**Fix**:
- Implemented CSRF token generation using `crypto/rand`
- Added CSRF validation to authentication middleware
- CSRF tokens included in all forms (login, create link, delete link)
- Tokens are session-specific and validated on all POST/PUT/DELETE requests

**Code Location**: `handlers/auth.go` lines 123-202, templates updated

### 7. ✅ Security Headers
**Severity**: Medium

**Issue**: Missing security headers exposed the application to various attacks (clickjacking, MIME sniffing, etc.).

**Fix**:
- Added `X-Frame-Options: DENY` to prevent clickjacking
- Added `X-Content-Type-Options: nosniff` to prevent MIME sniffing
- Added `X-XSS-Protection: 1; mode=block` for older browsers
- Added `Referrer-Policy: strict-origin-when-cross-origin`
- Implemented Content Security Policy (CSP) to restrict resource loading
- Applied via middleware to all responses

**Code Location**: `main.go` lines 13-41

### 8. ✅ Input Validation for Slugs
**Severity**: Medium

**Issue**: Custom slugs could contain special characters that might cause issues or be used for attacks.

**Fix**:
- Added validation to ensure slugs only contain alphanumeric characters, hyphens, and underscores
- Rejects invalid characters before database insertion

**Code Location**: `handlers/admin.go` lines 87-94

## Security Best Practices for Deployment

### Required Configuration

1. **Session Key**: Always set a strong `SESSION_KEY` in production:
   ```bash
   SESSION_KEY=$(openssl rand -base64 32)
   ```

2. **Secure Cookies**: Enable secure cookies when using HTTPS:
   ```bash
   SECURE_COOKIES=true
   ```

3. **Strong Admin Credentials**: Use strong, unique credentials:
   ```bash
   ADMIN_USER=your-admin-username
   ADMIN_PASS=$(openssl rand -base64 16)
   ```

### Recommended Security Measures

1. **HTTPS Only**: Always deploy behind HTTPS/TLS
2. **Reverse Proxy**: Use a reverse proxy (nginx, Caddy) with proper security headers
3. **Database Backups**: Regular backups of `zenir.db`
4. **Log Monitoring**: Monitor logs for suspicious activity
5. **Update Dependencies**: Keep Go and dependencies up to date

## Testing

All security fixes have been validated through:
- ✅ CodeQL security scan (0 vulnerabilities found)
- ✅ Manual testing with browser
- ✅ Malicious URL injection attempts (blocked successfully)
- ✅ CSRF token validation
- ✅ Rate limiting verification
- ✅ Compilation and build verification

## Reporting Security Issues

If you discover a security vulnerability, please report it to the repository owner directly rather than opening a public issue.

## Security Scan Results

**CodeQL Analysis**: ✅ PASSED (0 alerts)

Last updated: January 8, 2026
