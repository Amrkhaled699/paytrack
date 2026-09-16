# PayTrack Security Notes — v3.0

Implemented: PBKDF2 password hashing, random bearer sessions, session TTL refresh, login rate limiting, company-scoped authorization, server-side employee limits, audit logging, rolling backups, sanitized User role data, and owner-only platform APIs.

Before real commercial deployment: use managed PostgreSQL, HTTPS-only hosting, strict CORS, CSRF protection, real TOTP/2FA, account recovery, email verification/invitations, secrets management, off-site encrypted backups, monitoring/alerting, and a professional privacy/tax/legal compliance review.

Do not keep demo credentials in a production deployment. Change the bootstrap Owner and Admin passwords immediately.


## Owner controls added in v4 hardening
- Two separately named Owner accounts: Amr and Mohamed Khaled.
- Production owner credentials come from deployment secrets, not source code.
- Any legacy generic Owner account is disabled when the two configured owners are present.
- Every company activation requires an explicit Owner action. Paid activation and complimentary activation are separate actions.
- Payment status cannot silently activate a company.
- Owner-sensitive changes require recent re-authentication.
- Auth sessions use HttpOnly cookies rather than browser localStorage tokens.
- Cookies use SameSite=Strict and Secure in production.
- 8-hour absolute sessions and 30-minute idle timeout.
- PBKDF2-HMAC-SHA-256 uses 600,000 iterations with a unique salt.
- Same-origin protection is applied to state-changing requests.
- Security headers include HSTS in production, clickjacking protection, MIME sniffing protection, referrer policy, permissions policy, and CSP.
- Login throttling remains enabled and failures are audited.

No software can honestly be guaranteed to be impossible to hack. The goal is defense in depth, rapid detection, least privilege, and minimizing the impact of any compromise. For a real commercial launch, add phishing-resistant MFA/passkeys for both Owners, managed PostgreSQL, a managed identity/session service or Redis-backed sessions, encrypted off-site backups, centralized security monitoring, dependency scanning, penetration testing, incident response, and regular independent security review.


## Production security gate
The application intentionally fails closed in production unless exactly two Owner accounts are configured with strong passwords and TOTP MFA secrets. Default Owner credentials are development-only and are never accepted as a production fallback.

Company access is also fail-closed: a submitted request is not an active company. Only an authenticated Owner can approve it. Paid approval requires a recorded paid status; complimentary approval is a separate explicit Owner action.

The project uses security headers, strict SameSite/HttpOnly session cookies, server-side authorization, session expiry/idle timeout, login/request throttling, re-authentication for sensitive Owner actions, audit logging, and tenant-scoped data access.

No security control can guarantee that a system is impossible to hack. The production gate therefore also requires managed infrastructure, secure secrets, monitoring, off-site backups, independent penetration testing, and ongoing patching.

## AI security

PayTrack AI is server-routed so provider credentials are never placed in the browser. The AI receives the authenticated role and is instructed to stay within that role. AI-generated website code is available only to Owner/Admin sessions. Keep `PAYTRACK_AI_API_KEY` in the hosting provider's secret environment settings; never commit it to GitHub.
