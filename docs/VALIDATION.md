# Validation record

Initial validation: **21 October 2026**, Windows host, Node.js 24.19.0, TypeScript 5.9.3.

This is a record of exercised behavior, not an independent security certification.

## Automated verification

The initial suite contains 21 passing tests. It covers:

- Equivalent CycloneDX/SPDX component inventories and graph edge counts.
- Malformed JSON, unsupported formats, duplicate identifiers, inconsistent versions, opaque relationships and dangling edges.
- Package URL scopes, Maven mapping, PyPI normalization, percent encoding and unsupported ecosystems.
- Shortest dependency paths, cycles, upstream traversal and transitive alias merging.
- CVSS 3.x reference vectors, zero impact, unsupported vectors and fixed-endpoint filtering.
- Deterministic evidence hashes, withdrawn records, merged aliases and traceable original IDs.
- Missing query coverage, missing details, provider failures, stale/future evidence and demo gate behavior.
- Successful empty queries versus unqueried packages; EPSS probability threshold versus percentile; context elevation.
- Package-scoped fixed candidates and the internal baseline comparison utility.
- Markdown escaping, SARIF record preservation, safe reference URLs and malformed snapshots.
- Fixed provider hosts, redirect rejection, per-query OSV pagination, detail retrieval and transient HTTP retries.
- HTTP Host/Origin enforcement, cross-origin preflight rejection, required request headers, malformed input, offline mode, successful snapshot analysis and response security headers.

TypeScript strict checks and the production build pass. The development install reported zero known vulnerabilities at initial installation. There are no runtime package dependencies.

### Windows startup follow-up

Launching a second copy while Faultline already occupied port 4317 reproduced an `EADDRINUSE` failure; the original batch file immediately closed and hid the error. The updated launcher verifies and reuses an existing Faultline instance, opens its browser address, selects a free fallback port when another application occupies the default, and preserves failures at a pause prompt. Four additional launcher tests cover reuse, another service's port, invalid configuration and incomplete ZIP extraction. Windows-specific batch checks are skipped on other platforms.

## Live-provider check

An explicit live query used only the public synthetic sample's package/version strings. On **2026-10-21 at 13:47 UTC**, the run returned:

| Measure                                     | Observed                          |
| ------------------------------------------- | --------------------------------- |
| Total sample components                     | 18                                |
| Supported, queryable components             | 17                                |
| Successfully queried                        | 17                                |
| Skipped                                     | 1 root application without a PURL |
| Vulnerability instances after alias merging | 61                                |
| P0 / P1 / P2 / P3                           | 4 / 8 / 22 / 27                   |
| KEV / EPSS collection                       | Both successful                   |
| Report completeness                         | Complete for queryable inventory  |
| `--fail-on P1` result                       | Exit 1, as expected               |

Counts and priorities will change with upstream intelligence. The live capsule is not bundled as a permanent threat database. The repository demonstration uses separately labeled illustrative fixtures.

## Browser verification

The desktop interface was opened in the in-app browser. The rendered overview, interactive graph, finding rationale, fixed candidate notes, component-focused ledger and search behavior were inspected. Responsive layout, import controls and export controls were reviewed separately during final QA. Screenshots in this repository show the actual application, not a mockup.

The browser automation file chooser was slow during QA. HTTP integration tests independently verify that the sample inventory and its evidence capsule can be analyzed successfully. Browser-specific picker behavior is not a correctness guarantee for every OS/browser combination.

## Not established by these checks

- No independent penetration test, formal audit, full standard-schema certification, or large-fleet benchmark has been performed.
- Docker build/runtime and macOS launch behavior were not exercised on the initial Windows host.
- SARIF output is structured as 2.1.0; acceptance by every third-party security platform has not been established.
- Priority thresholds have not been calibrated against operational loss or remediation outcomes.
- Declared paths are not code reachability, and fixed candidates are not compatibility-tested upgrades.
- GitHub-hosted CI results are separate from local validation and should be inspected for each commit. The initial clean-checkout run caught missing demo-asset staging in the test command; the command was corrected to prepare those assets before running tests.
