# Methodology

## Why this project exists

An inventory is not a remediation decision. A CVSS-only list ranks technical severity, while a defender must also consider exploitation signals, deployment exposure, missing data, and the scope of a package's presence. Faultline brings those inputs together in an investigation that can be inspected and replayed.

The design considered a generic network scanner, a lightweight SIEM, and a dependency triage workbench. The workbench was selected because it supports a concrete workflow without target scanning, privileged agents, sensitive event ingestion, or a large deployment. It complements existing scanners rather than reimplementing their ecosystem-aware version matching.

Primary sources considered:

- [CISA SBOM resources and consumption guidance](https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary).
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- [FIRST EPSS purpose and interpretation](https://www.first.org/epss/) and [API](https://api.first.org/epss/).
- [OSV batch query semantics and pagination](https://google.github.io/osv.dev/post-v1-querybatch/).
- [CycloneDX dependency completeness semantics](https://cyclonedx.org/use-cases/software-dependencies/).
- [SPDX 2.3 relationship definitions](https://spdx.github.io/spdx-spec/v2.3.1/relationships-between-SPDX-elements/).
- [CVSS v3.1 base score and Roundup specification](https://www.first.org/cvss/v3.1/specification-document).

These sources justify useful input signals and data semantics; they do not validate Faultline's custom priority thresholds or endorse the project.

## Matching and identity

Faultline delegates affected-version matching to OSV. It parses supported versioned PURLs into ecosystem/name/version queries, with Maven group/artifact mapping and PyPI name normalization. Queries do not combine a versioned PURL with a second explicit version. Qualifiers/subpaths remain inventory context and are not sent to OSV.

Within a component, advisory IDs and aliases form an equivalence graph. Transitive connected groups become one finding, preserving all original advisory IDs. The same vulnerability on two components remains two instances. Alias data is taken as supplied by the provider; incorrect upstream aliasing can affect grouping.

Withdrawn advisories do not produce findings. A missing advisory record is a coverage error, not an empty match. An unsuccessful query is different from a successful query that returned zero advisories.

## Review priorities

The first applicable rule wins:

| Priority | Rule                                                                          | Intended action                                               |
| -------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------- |
| P0       | Any CVE alias appears in available KEV evidence                               | Immediate review of applicability, mitigation and remediation |
| P1       | EPSS probability ≥ 0.10                                                       | Expedited review                                              |
| P1       | Advisory severity is CRITICAL                                                 | Expedited review                                              |
| P1       | HIGH severity and analyst says internet exposure or critical business context | Expedited review                                              |
| P2       | Remaining HIGH severity or UNKNOWN severity                                   | Prioritized manual review                                     |
| P3       | Remaining lower-severity findings                                             | Routine review, retaining uncertainty                         |

The 10% threshold is a transparent default chosen for this workbench, not a universal recommendation. There is no claim that P3 is harmless or that every P0 instance is exploitable in its local deployment. Context is analyst-declared and applies to the imported inventory as a whole.

EPSS probabilities and percentiles are displayed separately. Percentile does not control priority. A missing EPSS row is unknown, not 0%. A missing KEV match means only that there was no match in the available catalog snapshot.

## Ordering within a priority

```
sorting points = KEV * 60 + EPSS_probability * 20 + severity_points + context_points

severity_points = CVSS_v3_base * 1.5, if calculated
otherwise: LOW 3.75, MEDIUM 7.5, HIGH 11.25, CRITICAL 15, UNKNOWN 0

context_points = 3 if internet-facing + 2 if business-critical
```

The rounded points are a queue ordering heuristic, not an expected-loss estimate, application risk probability, CVSS score, or industry standard. Unknown severity still receives P2 unless another rule raises it. Stable finding keys break ties. Repair work groups findings by component and sorts by highest priority, then total sorting points.

## Severity and fixes

The adapter calculates only CVSS v3.0/v3.1 **base** scores using FIRST's formula and integer Roundup. If no supported vector is supplied, provider severity labels are used. Other vector versions do not get guessed values. When several merged records describe a finding, the highest available severity is used, with deterministic tie-breaking.

Fixed candidates are non-GIT OSV `fixed` events restricted to matching package identity. They may span multiple maintenance branches. A candidate for one advisory may remain vulnerable to another advisory. Faultline does not solve ecosystem constraints, compute a safe minimum upgrade, apply patches, or promise compatibility.

## Graph semantics

Edges follow CycloneDX `dependsOn` or SPDX `DEPENDS_ON` / `DEPENDENCY_OF`. Application roots come from declared CycloneDX metadata or SPDX description relationships. Breadth-first search returns a deterministic shortest declared path and terminates on cycles. No root means no inferred application path. Reverse traversal counts distinct upstream components while excluding the target itself.

**There is no call-graph or symbol reachability analysis.** A dependency graph does not prove execution, internet exposure, exploitability, or an attack chain. Missing graph declarations are disclosed as unknown.

## Freshness and gates

Evidence older than 48 hours or more than five minutes in the future is incomplete for gating. EPSS rows older than 72 hours also make the report incomplete. These are local operational defaults, not provider service guarantees. Demo capsules always make gates indeterminate even if their timestamp is recent.

Provider failures, failed package queries, absent query coverage, missing advisory details and no queryable packages cannot produce a gate pass. Skipped components are disclosed separately: a pass applies only to the queried inventory, not the whole application. This distinction matters for root application components and unsupported package ecosystems.

A valid imported snapshot can assert “live” status. The application checks its structure and freshness; it cannot attest that a third party truly obtained the data from the named providers. Use trusted capsules when making decisions.

## Evidence identity

The original SBOM gets a SHA-256 hash of its exact UTF-8 text. A capsule gets a SHA-256 hash of canonical JSON with recursively sorted object keys. Arrays preserve order. The canonical representation is specific to Faultline v1; it is not a claim of RFC 8785 compliance. Hashes provide reproducibility and content identity, not signatures or authenticity.
