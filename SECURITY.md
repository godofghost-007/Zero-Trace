# Security policy

## Supported versions

ZeroTrace is pre-1.0. Security fixes are applied to the current `main` branch and
the latest tagged self-hosted release. There is no hosted service or bug bounty
program in v1.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it privately to
the maintainers using the security contact configured for the repository
(GitHub private vulnerability reporting is preferred). Include:

- affected version or commit;
- deployment shape (local demo or self-hosted production);
- reproduction steps and impact;
- whether any secret, target, or user data was exposed.

Do not test against systems you do not own or have explicit permission to test.
ZeroTrace's scanning boundary does not authorize third-party targets.

## Security boundaries

- The engine API key and provider keys are server-side secrets. Never expose them
  to the browser or commit them.
- The engine binds to loopback. The BFF is the only public application.
- Guard is inspect-only by default. The optional upstream gateway must use an
  allowlisted OpenAI-compatible base URL.
- Scanning is limited to approved, time-bounded scopes. High/Deep profiles
  require DNS TXT ownership verification. No exploitation, brute force, NSE
  scripts, or automatic remediation is supported.
- Production startup fails closed when the secret key, PostgreSQL URL, secure
  cookies, MFA key, schema auto-creation, demo mode, or OIDC configuration is
  unsafe.

## Dependency and release hygiene

- CI runs Python, BFF, frontend, migration, and container checks.
- CodeQL runs for Python and JavaScript/TypeScript.
- Apache-2.0 is the project license. Third-party notices belong in `NOTICE` or
  the dependency manifest.
