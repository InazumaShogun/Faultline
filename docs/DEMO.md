# A five-minute review walkthrough

## 1. Frame the problem — 30 seconds

“A scan can return many advisories. Faultline helps an analyst decide what to investigate first, while preserving the evidence behind the ordering. It is a local triage workbench built around existing public intelligence, not a new vulnerability database.”

Open the workbench. Point out the demonstration banner and the coverage line. The sample contains deliberately old version strings; it does not install vulnerable software. Demonstration EPSS/KEV metadata is illustrative and clearly labeled.

## 2. Follow the strongest signal — one minute

Open **Inspect finding**. Show the KEV match, separate EPSS probability/percentile, source references, and exact reasons for priority. Explain that known exploitation at the CVE level is not proof of exploitation of this deployment.

Show the declared dependency path. Explain the distinction between a package dependency and executable-code reachability. This distinction is deliberate and tested.

## 3. Turn a finding into work — one minute

Choose **All component findings**, then open **Repair plan**. Multiple advisories on `log4j-core` form one component work item. Fixed versions are per-advisory branch candidates, not a blindly selected “safe upgrade.”

Search for `snakeyaml`, filter priorities, and inspect its transitive path. Select a graph node to move directly to its component ledger.

## 4. Show provenance and portability — one minute

Open **Evidence**. Show queried versus skipped coverage, acquisition time, normalized evidence hash, and warnings. Export the Markdown brief and evidence capsule.

Open **New investigation**, select the sample SBOM, choose **Saved evidence**, and import the exported capsule. This workflow runs without provider access. The historical demo remains indeterminate for gating.

## 5. Show the real engine — one minute

Run a live sample query or show the live validation record. The validated run on 21 October 2026 queried 17 supported package instances and returned 61 vulnerability instances with successful KEV and EPSS enrichment. Counts will change as intelligence changes.

```sh
node dist/src/cli.js analyze examples/harbor.cdx.json --live --fail-on P1
```

Explain the exit codes, then show `npm test`. The tests include incomplete provider data, OSV per-query pagination, cycles, alias deduplication, safe output, stale evidence and HTTP boundary checks.

## Questions to be ready for

**Why not just use OSV-Scanner?** Use it to generate robust ecosystem-aware scans. Faultline focuses on analyst-facing evidence, deployment context, prioritization, graph inspection and portable handoffs. It delegates affected-version matching to OSV.

**Is this a risk prediction model?** No. EPSS is an upstream predictive signal. Faultline's P0–P3 policy and sorting points are explicit operational heuristics.

**What would come next?** Authenticated/signed evidence inputs, broader SBOM conformance tests, real VEX review with expiring attestations, ecosystem-aware upgrade planning, and calibrated policy evaluation against operational outcomes. These are future work, not current features.

**Is it production proven?** It has unit tests, HTTP integration tests, live-provider verification and browser QA. It has not undergone an independent penetration test, large-fleet trial, formal verification or performance certification. See `VALIDATION.md` for the exact boundaries.
