# Third-party software and data

Faultline application source is MIT licensed. No third-party application source, fonts, icons, or scripts are vendored into the runtime. Icons, brand artwork and layout are repository-native SVG/CSS.

Development dependencies, recorded with integrity hashes in `package-lock.json`:

| Package      | License    | Role                                 |
| ------------ | ---------- | ------------------------------------ |
| TypeScript   | Apache-2.0 | Build-time compiler                  |
| @types/node  | MIT        | Build-time Node.js type declarations |
| Prettier     | MIT        | Development-only source formatting   |
| undici-types | MIT        | Transitive type declarations         |

Their licenses remain available in the installed package distributions. The Docker image uses the official Node.js Debian-based distribution, whose upstream notices and licenses remain applicable.

Live data comes from OSV and its upstream advisory sources, CISA KEV, and FIRST EPSS. Upstream data terms and attribution requirements apply to those records. Faultline is not affiliated with or endorsed by those providers.

The bundled demonstration contains original curated advisory summaries, historical version strings and explicitly illustrative enrichment metadata. It is not a current or complete vulnerability database. It installs no vulnerable packages. Use original advisory references and live intelligence for operational decisions.
