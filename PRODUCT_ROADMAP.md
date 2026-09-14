# PayTrack Product Roadmap — v3.0

## Implemented in this build
- Multi-company tenant isolation
- Owner Control Center with requests, companies, subscriptions, trials, billing controls, support, audit/security and platform settings
- Standard / Professional / Enterprise plans with employee limits
- 14-day trial support and subscription expiry enforcement
- Manual payment confirmation with renewal tracking
- Customer support ticket system
- Company customization: currency, tax rate, timezone, language and brand color
- Full-app localization framework with 14 languages and RTL Arabic
- HR leave/vacation records
- Employee shifts and schedules
- Payslip generator
- Employee self-service summary
- Notification center
- Existing analytics, reports, exports, global search, audit log and backups
- Password show/hide controls on password fields
- AI assistant and AI code workspace foundation

## Production integrations still requiring external credentials/infrastructure
1. Connect a payment provider and signed webhooks
2. Move the data store to managed PostgreSQL
3. Add email invitations, verification and password recovery
4. Add real 2FA/TOTP enrollment and recovery codes
5. Add CSRF protection and strict production CORS policy
6. Add off-site encrypted backups and monitoring
7. Add invoices, tax documents and automated billing emails
8. Add custom domains and per-company branding assets
9. Add formal privacy policy, terms, retention and compliance workflows


## Security completion gate
- Two production Owner accounts required; no default production Owner.
- Owner TOTP MFA required in production.
- Every company request remains pending until an Owner explicitly approves it.
- Paid approval requires paymentStatus=paid. Complimentary approval explicitly waives payment.
- Production startup fails closed if Owner secrets are missing.
- Rate limiting and strict security headers enabled.

## Still required before commercial launch
- Managed PostgreSQL or equivalent production database.
- External secret manager and key rotation.
- Passkeys/WebAuthn for Owner accounts.
- Centralized monitoring and alerting.
- Encrypted off-site backups and restore drills.
- Independent penetration test and ASVS verification.
- Privacy policy, terms, retention, and payroll/tax compliance review.
