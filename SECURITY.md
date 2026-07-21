# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `1.0.0-rc.x` | Yes — Release Candidate, security fixes via point releases |
| `< 1.0.0-rc.1` | No — pre-release builds, please upgrade |

Once `1.0.0` ships, the support window becomes "current minor" plus
"current minor − 1" with critical-only fixes for the previous minor.

## Scope and current posture

sfs has **not** had an independent cryptographic or security audit. It is a
developer preview and is **not intended for third-party data** until such an
audit and field operating time exist. `docs/SECURITY-MODEL.md` records the
threat model, per-component maturity, and the accepted at-rest limits.

The high-severity findings from internal review are fixed (test-key-gated
first-run path, header MAC, context-bound GCM nonces, iterative trie DoS guard,
metadata GCM). Documented, accepted preview limits include: a concurrent FUSE +
kernel mount on one image is unsupported (self-inflicted corruption, not
enforced); insider `sign_mode` downgrade is an at-rest limit of the same class
as LUKS/dm-crypt; key zeroization is partial.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via one of:

- **GitHub Security Advisory** —
  <https://github.com/zero-objects/sfs/security/advisories/new>
  (preferred; private until coordinated disclosure)
- **Email** — `security@zero-objects.dev`

Please include:

- Affected crate(s) / component(s) and version(s)
- Reproduction steps or a proof-of-concept
- A CVSS 3.1 vector if you can compute one

We aim to acknowledge within a few business days and to coordinate a disclosure
timeline with you.
