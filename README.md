# ShadowGuard AI
AI/SaaS security governance MVP: shadow application discovery, explainable risk scoring, simulated privacy-policy IDP, incident tracking, and approval-gated remediation recommendations.

## Stack
Next.js 15 + TypeScript + Tailwind + Recharts; FastAPI + Pydantic + Psycopg; Neon PostgreSQL; Vercel.

## Run locally
1. Create a PostgreSQL database and run `psql "$DATABASE_URL" -f database/schema.sql` then `psql "$DATABASE_URL" -f database/seed_data.sql`.
2. Copy `.env.example` to `.env`; set `DATABASE_URL` and a strong random `SHADOWGUARD_API_KEY`.
3. `pip install -r requirements.txt && uvicorn backend.app.main:app --reload`
4. In `frontend/`, copy `.env.local.example` to `.env.local`, set API URL and key, then `npm install && npm run dev`.

## Vercel
Deploy two projects from the same repository. API project root is `.`; set `DATABASE_URL` (Neon pooled URL), `SHADOWGUARD_API_KEY`, `CORS_ORIGINS`, `ENVIRONMENT=production`, `DISABLE_DOCS=true`. Frontend project root is `frontend`; set `SHADOWGUARD_API_URL` and `SHADOWGUARD_SERVICE_KEY`. The Next.js server-side proxy keeps the service key out of browser code. Vercel Python functions are under root `api/`. See https://vercel.com/docs/functions/runtimes/python and https://neon.com/docs/connect/connection-pooling.

## API
GET `/api/v1/health`, `/api/v1/dashboard`, `/api/v1/apps`, `/api/v1/incidents`; POST `/api/v1/telemetry/ingest`, `/api/v1/policies/analyze`, `/api/v1/incidents/{id}/remediate`. All except health require `X-API-Key`.

## Security controls
- SQL Injection: Psycopg `%s` placeholders for all values; no user-input SQL concatenation.
- Access control: constant-time API-key comparison protects service-to-service calls. This is not end-user authentication; add OIDC, RBAC, tenant scoping and object-level checks before production.
- Cryptography: TLS at Vercel/Neon; secrets in environment variables, not source control; rotate secrets.
- Insecure design: risk scores are explainable heuristics; remediation is only a recommendation with approval state, never an external destructive action.
- Validation: strict Pydantic models, enums, field bounds and hostname validation; CORS allow-list and security headers.

## Production checklist
- [ ] SSO/OIDC, RBAC, tenant isolation and short-lived sessions.
- [ ] Rate limiting/WAF, request-size limits, idempotency and replay protection.
- [ ] Managed secret rotation and audit-log integrity.
- [ ] Isolated PDF/OCR processing, malware scanning and secure object storage.
- [ ] Queue-based ingestion and durable event processing.
- [ ] SIEM/EDR/proxy integrations, observability, alerting and backups.
- [ ] SAST, dependency scanning, DAST and independent penetration test.
- [ ] Privacy impact assessment, employee notice, data minimization and retention policy.

## Limitations
This is an MVP foundation, not a certified production security product. Seed data is synthetic. Policy analysis is keyword simulation, not an LLM or legal advice. No endpoint agent, browser extension, SIEM integration, live traffic blocking, continuous worker, or third-party remediation execution is included. Vercel functions are request-driven, not always-on SOC agents.
