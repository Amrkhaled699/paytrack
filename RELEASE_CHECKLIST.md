# PayTrack 4.2 Secure Release Checklist

## Owner accounts
Production requires exactly two Owner accounts configured through environment variables:
- `PAYTRACK_OWNER_1_USERNAME`
- `PAYTRACK_OWNER_1_PASSWORD`
- `PAYTRACK_OWNER_1_TOTP_SECRET`
- `PAYTRACK_OWNER_1_DISPLAY_NAME`
- `PAYTRACK_OWNER_2_USERNAME`
- `PAYTRACK_OWNER_2_PASSWORD`
- `PAYTRACK_OWNER_2_TOTP_SECRET`
- `PAYTRACK_OWNER_2_DISPLAY_NAME`

Never put passwords or TOTP secrets in HTML, JavaScript, GitHub, screenshots, or support tickets.

## Company activation rule
Every public company request begins as `pending`.
- Paid activation requires the Owner to explicitly mark payment as received and then approve.
- Complimentary activation is a separate explicit Owner action.
- Only Owner sessions can approve, reject, suspend, activate, or change plans.
- Payment alone never activates a company.

## Before accepting real customers
- Use HTTPS.
- Configure a correct `PAYTRACK_ORIGIN`.
- Configure both Owner TOTP secrets.
- Use long unique Owner passwords stored in the hosting provider's secret manager.
- Prefer passkeys/security keys for privileged accounts when WebAuthn is integrated.
- Move production persistence to a managed PostgreSQL database.
- Enable encrypted off-site backups and monitoring.
- Run dependency/security scanning and an independent penetration test.
- Publish privacy, terms, retention, and incident-response policies appropriate to the countries served.
