# Contributing

Use Node.js 24+, install with `npm ci`, then run `npm run check`, `npm test`, and `npm run build`. Tests must not contact real intelligence providers; inject a fetcher and use deterministic fixtures. Live checks are opt-in and are documented separately.

Keep parser/provider boundaries validated at runtime, and preserve the distinction between absent, unknown and failed data. Do not turn missing data into zero risk. New policy behavior needs a rationale and a meaningful test. Never infer code reachability from SBOM edges or label a fixed candidate as universally safe.

UI changes should preserve keyboard access, readable contrast, responsive behavior, local assets and the strict CSP. Include before/after screenshots for visible changes. Avoid adding runtime dependencies unless the benefit and new trust surface are documented.

Open a focused pull request describing the problem, behavior change, verification, and limitations. Synthetic SBOM examples are welcome; do not include private inventories or live credentials.
