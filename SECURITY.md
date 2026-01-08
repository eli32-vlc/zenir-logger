# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Security Features

This application includes the following security measures:

### Authentication & Authorization
- ✅ Session-based authentication with secure cookies
- ✅ Rate limiting on login endpoint (5 attempts/minute per IP)
- ✅ HttpOnly and SameSite cookie flags
- ✅ Secure session key generation

### Input Validation
- ✅ URL validation (only http/https schemes allowed)
- ✅ SQL injection protection via parameterized queries
- ✅ XSS protection via Go template auto-escaping
- ✅ CSRF protection on all state-changing operations

### Security Headers
- ✅ X-Frame-Options: DENY
- ✅ X-Content-Type-Options: nosniff
- ✅ X-XSS-Protection: 1; mode=block
- ✅ Referrer-Policy: strict-origin-when-cross-origin
- ✅ Content-Security-Policy

### Cryptography
- ✅ Cryptographically secure random number generation (crypto/rand)
- ✅ SHA-256 hashing for fingerprints
- ✅ Proof-of-Work challenge for tracking endpoint

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email the maintainer directly (check repository for contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

You can expect:
- Initial response within 48 hours
- Regular updates on progress
- Credit in security advisory (unless you prefer anonymity)

## Security Best Practices for Deployment

### Required
1. Set a strong `SESSION_KEY` environment variable (32+ random bytes)
2. Use HTTPS in production
3. Set `Secure: true` for cookies when using HTTPS
4. Keep dependencies updated (`go get -u`)
5. Use a reverse proxy (nginx/caddy) with rate limiting

### Recommended
6. Restrict admin panel to specific IP ranges
7. Use a Web Application Firewall (WAF)
8. Enable audit logging
9. Implement backup strategy for database
10. Regular security updates

### Optional
11. Enable two-factor authentication (requires code changes)
12. Implement IP-based geographic restrictions
13. Add intrusion detection system (IDS)

## Security Audit

A comprehensive security audit was performed on January 8, 2026. See [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md) for details.

### Vulnerabilities Fixed
- Open Redirect (HIGH) - Fixed in v2.0
- CSRF (HIGH) - Fixed in v2.0
- Rate Limiting (MEDIUM) - Fixed in v2.0
- Weak Random Generation (MEDIUM) - Fixed in v2.0
- Missing Security Headers (MEDIUM) - Fixed in v2.0
- Weak Session Key (LOW) - Fixed in v2.0

## Known Limitations

1. **No built-in 2FA**: Admin accounts rely on password-only authentication
2. **No account lockout**: After rate limit expires, attempts can continue
3. **No IP blacklist**: Persistent attackers can continue after cooldown
4. **SQLite limitations**: No built-in encryption at rest

## Security Contact

For security concerns, contact the repository maintainer through GitHub.
