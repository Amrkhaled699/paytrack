# PayTrack — Multi-Company Online Pro

**Owned by Amr & Mohamed Khaled**

PayTrack is a modern payroll and attendance platform that can be operated as a hosted service for multiple independent companies.

## What is included

- Payroll dashboard with customizable tables and dynamic formula columns
- Attendance and overtime portal
- Admin and attendance-only User roles
- Password visibility buttons on every password field
- Server-side PBKDF2 password hashing and server sessions
- Cross-device synchronization
- Employee history, analytics, reports/CSV export, notifications, audit log and backups
- AI assistant and existing code workspace
- Multi-company workspaces with server-side company scoping
- Owner Control Center for PayTrack owners
- Public company access request workflow
- Manual payment confirmation before company activation
- Company activation/suspension
- Public About & Contact section
- Contact messages visible to the PayTrack Owner Control Center
- Rolling server backups
- Render deployment configuration

## Ownership / roles

There are three platform roles:

1. **Owner** — Amr & Mohamed Khaled's PayTrack platform control account. It manages customer-company requests, activation, suspension, contact messages and platform audit logs.
2. **Company Admin** — manages only the approved company's employees, payroll, attendance, tables and users.
3. **User** — attendance/overtime access only for the user's company.

A company cannot select another company in the browser to access its data. The server derives the company workspace from the authenticated session.

## Selling / activation workflow

The current version intentionally uses a manual payment workflow:

1. A prospective company clicks **Request company access**.
2. They submit company and contact details.
3. The request appears in the Owner Control Center.
4. The owner reviews it and confirms payment manually.
5. The owner clicks **Approve & activate**.
6. PayTrack creates an isolated company workspace and a company Admin account.
7. A temporary Admin password is displayed once to the owner. Share it securely and have the company administrator change it immediately.
8. The company Admin can then create attendance User accounts for that company.

A real payment provider can be connected later. Do not treat a user-submitted claim of payment as proof of payment.

## Bootstrap owner account

For first-run setup only:

- Owner username: `owner`
- Production Owner accounts: **Amr** and **Mohamed Khaled**. Their usernames are configured as `amr` and `mohamed.khaled`; their passwords are supplied through Render environment secrets and are never stored in the repository.
- The legacy single `owner` account is disabled automatically when the two production owner accounts are configured.
- Never commit owner passwords, session secrets, database files, or `.env` files to GitHub.

The older prototype Admin account is still recognized when an existing database is upgraded; existing single-company data is migrated into a private **Main Company** workspace. New customer companies do not receive automatic browser-data migration.

## Local test

1. Install Node.js 18+.
2. Open this folder after extracting it from the ZIP.
3. Run `Start_PayTrack.bat` or `npm start`.
4. Open `http://localhost:3000`.
5. Sign in as Owner with the bootstrap credentials above, or use the company Admin/User accounts.

## Deploying online

The included `render.yaml` is configured for a Render Web Service.

1. Upload the **contents** of this folder to your GitHub `PayTrack` repository.
2. In Render, create a Web Service from that repository.
3. Use the included settings:
   - Build: `npm install`
   - Start: `npm start`
   - Health check: `/api/health`
4. Keep persistent storage mounted at `/var/data`, or later replace the file store with a managed database.
5. Open the deployed HTTPS address from any location.

## Data and backups

Customer payroll and attendance data is stored per company on the server. Updating the application code should not intentionally delete the database. The server also keeps a rolling set of JSON backups. For serious production use, migrate to a managed database with tested off-site backups and a formal restore procedure.

## Contact

The public app includes an About & Contact section. Contact messages are stored for the PayTrack owners to review in the Owner Control Center.

Owner branding: **Amr & Mohamed Khaled**

Add real owner contact emails only when you are ready to publish them.

## Production security note

This is a strong prototype/deployment foundation, but payroll software handling real businesses should receive a proper production security review. Recommended future upgrades include a managed database, secure secret management, stronger session infrastructure, CSRF protection, stricter CORS policy, email/account recovery, verified payment webhooks, automated off-site backups, monitoring, privacy/compliance review and legal terms for customer companies.

## v3.0 Business Suite
This build adds a broader SaaS operating layer: Owner Command Center, plans and employee limits, trials/expiry, subscription controls, support tickets, company customization, 14-language localization with RTL Arabic, leave/vacation records, shifts/schedules, payslip generation, employee self-service summaries, notification center, and expanded security/audit views.

### Current commercial workflow
1. A prospect requests company access.
2. The Owner reviews the request.
3. The Owner marks payment as received manually.
4. The Owner approves/activates the company.
5. PayTrack creates an isolated company workspace and an initial company-admin credential.
6. The company admin signs in, changes the temporary password, and manages its own employees/payroll.

Automatic card payments, signed payment webhooks, email invitations, and managed PostgreSQL are intentionally integration points rather than pretending they are already connected without merchant/database credentials.


## Owner approval policy
Every company request requires an explicit Owner action. Payment alone never activates a company. An Owner can: mark paid, approve paid, approve complimentary (payment waived), reject, suspend, or reactivate. Company Admins and Users cannot approve or activate their own company.

## Owner security
Production owner actions use server-side sessions in HttpOnly/Secure/SameSite cookies, idle and absolute session expiry, login throttling, re-authentication for sensitive Owner changes, strict same-origin checks, security headers, audit logging, and strong PBKDF2 password hashing. Set `PAYTRACK_ORIGIN` to the exact HTTPS origin of the deployed PayTrack site. OWASP guidance recommends MFA for privileged accounts; the next production step is to connect the Owner accounts to a phishing-resistant MFA/passkey provider rather than relying on passwords alone.

### Render secrets
Set these as secret environment variables in Render: `PAYTRACK_OWNER_1_PASSWORD`, `PAYTRACK_OWNER_2_PASSWORD`, and `PAYTRACK_ORIGIN`. Use long, unique passphrases (15+ characters). Do not put the passwords in `render.yaml` or GitHub.

## PayTrack AI 4.3

The built-in AI gateway now supports multilingual natural-language operation. The assistant receives the current UI language, company state, available PayTrack capabilities, and the signed-in role. It can answer in the user's language and map natural-language requests to PayTrack actions.

For production AI, configure these server environment variables (never commit the API key):
- `PAYTRACK_AI_API_KEY` — secret AI provider key.
- `PAYTRACK_AI_MODEL` — defaults to `gpt-5.6-sol`.
- `PAYTRACK_AI_API_URL` — defaults to the OpenAI Responses endpoint.

The AI is designed as a general operator rather than a finite keyword command list, but it still respects PayTrack role permissions. Website code generation is restricted to Owner/Admin sessions. Destructive or high-impact behavior should still be reviewed as part of normal production operations.
