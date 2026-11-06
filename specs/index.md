# Specs Index

Use this index to track active and historical specs.

| Spec | Status | Area | Last Updated |
| --- | --- | --- | --- |
| [Authlib FastAPI Adapter](contracts/authlib-adapter.md) | draft | OAuth/OIDC | 2026-05-13 |
| [Database Contract](contracts/database.md) | draft | Persistence | 2026-05-16 |
| [Runtime Configuration Contract](contracts/runtime-config.md) | draft | Runtime/Configuration | 2026-05-16 |
| [Security And Session Contract](contracts/security-session.md) | draft | Auth/Security | 2026-05-13 |
| [Permission Requests](features/permission-requests/spec.md) | implemented | Auth/UI/Admin | 2026-05-13 |
| [Email Verification And Account Recovery](features/email-verification/spec.md) | draft | Auth/Security | 2026-05-16 |
| [Public Route Boundary Hardening](features/public-route-boundary/spec.md) | draft | Auth/Security | 2026-05-16 |
| [External OIDC Signing Backend](features/external-signing-backend/spec.md) | draft | OAuth/OIDC Security | 2026-05-16 |
| [Route Service Extraction](features/route-service-extraction/spec.md) | draft | Auth/UI/Persistence | 2026-05-16 |
| [Operational Observability Baseline](features/operational-observability/spec.md) | draft | Operations/Security | 2026-05-16 |
| [Automated Testing Baseline](features/quality-testing/spec.md) | draft | Testing/Quality | 2026-05-16 |
| [Pytest And Test Extensions](features/quality-testing/pytest-extensions.md) | draft | Testing/Quality | 2026-05-16 |
| [Hypothesis Property Tests](features/quality-testing/hypothesis-property.md) | draft | Testing/Quality | 2026-05-16 |
| [Tavern API Security Tests](features/quality-testing/tavern-api-security.md) | draft | Testing/Security | 2026-05-16 |
| [Playwright UI Tests](features/quality-testing/playwright-ui.md) | draft | Testing/UI | 2026-05-16 |
| [Locust Load Tests](features/quality-testing/locust-load.md) | draft | Testing/Performance | 2026-05-16 |
| [Testcontainers Integration Tests](features/quality-testing/testcontainers-integration.md) | draft | Testing/Integration | 2026-05-16 |
| [OIDC Key Rotation](features/oidc-key-rotation/spec.md) | implemented | OAuth/OIDC Security | 2026-05-16 |
| [OIDC Contract](contracts/oidc.md) | draft | OAuth/OIDC | 2026-05-06 |
| [Authorization Code Flow](flows/authorization-code.md) | implemented | OAuth/OIDC | 2026-05-15 |
| [OAuth Client Registration Flow](flows/client-registration.md) | implemented | OAuth/UI | 2026-05-15 |
| [Deployment Flow](flows/deployment.md) | draft | Operations | 2026-05-16 |
| [Login Flow](flows/login.md) | draft | Auth/UI | 2026-05-06 |
| [Registration Flow](flows/registration.md) | draft | Auth/UI | 2026-05-08 |
| [Page Security Flow](flows/page-security.md) | draft | Auth/UI | 2026-05-08 |
| [Home And Client Console Flow](flows/home-and-client-console.md) | draft | Auth/UI | 2026-05-13 |
| [Profile Flow](flows/profile.md) | implemented | Auth/UI | 2026-05-15 |
| [LNURL-auth Flow](flows/lnurl-auth.md) | draft | LNURL/Auth | 2026-05-06 |
| [Nostr Login](features/nostr-login/spec.md) | review | Auth/Nostr/Security | 2026-11-06 |
| [Nostr Auth Flow](flows/nostr-auth.md) | review | Nostr/Auth | 2026-11-06 |
| [Relying-Party Example Flows](flows/relying-party-examples.md) | draft | Examples/OIDC | 2026-05-13 |
| [Setup Wizard Flow](flows/setup-wizard.md) | draft | Bootstrap/Auth/UI | 2026-05-13 |
| [OAuth Token Lifecycle Flow](flows/token-lifecycle.md) | draft | OAuth/OIDC | 2026-05-13 |

## Status Values

- `draft`: being shaped; not ready for implementation.
- `review`: ready for product/engineering review.
- `approved`: ready for implementation.
- `implemented`: code and tests satisfy the spec.
- `superseded`: replaced by another spec or decision.
