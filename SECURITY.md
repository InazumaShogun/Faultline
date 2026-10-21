# Security policy

Faultline is a local, single-user dependency triage workbench. Version 1.x is the current development line. No support-response SLA is promised.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** channel if enabled for this repository. Otherwise open an issue requesting a private reporting channel, without including sensitive inventory, credentials, exploit details, or private advisory data. Do not test against other people's systems.

Include the affected version/commit, a minimal synthetic reproduction, expected versus actual behavior, and relevant environment details. Redact private package names, tokens and hostnames.

## Intended use and trust boundaries

- Bind to loopback. Do not expose the server on an untrusted network; it has no authentication or multi-tenant isolation.
- Live queries disclose package names and versions to OSV and CVE IDs to FIRST. They require opt-in. `--offline` blocks live collection.
- Imported evidence is structurally validated, not authenticated. Hashes identify content and do not sign it.
- A gate pass covers queried components only. Missing PURLs, unsupported ecosystems, incomplete SBOMs and runtime configuration remain analyst responsibilities.
- Advisory links open external sites. No advisory text, package code or SBOM commands are executed.
- Reports and capsules can reveal inventory. Store and share them according to your environment's requirements.

See `docs/ARCHITECTURE.md` for the full trust model and resource limits.
