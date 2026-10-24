# Contributing

In the spirit of Open Source Software, everyone is very welcome to contribute to this repository. Feel free to [raise issues](https://github.com/willfarrell/sast-json-schema/issues) or to [submit Pull Requests](https://github.com/willfarrell/sast-json-schema/pulls).

## Development Setup

```bash
git clone https://github.com/willfarrell/sast-json-schema.git
cd sast-json-schema
npm install
npm test
```

The per-draft meta-schemas at the repo root (`2020-12.json`, `2019-09.json`, etc.) are generated from `src/$defs.json` + `src/<draft>.json` by `bin/build.js`. `npm test` runs `npm run build` first via the `pretest` hook, but if you invoke tests directly (e.g. `npm run test:unit` or `node --test tests/cli.test.js`), run `npm run build` first after editing anything under `src/` (`npm install` builds them once via the `prepare` hook). `npm run test:bench` uses the experimental `node:bench` module and needs Node.js 26.9 or later.

`npm test` also runs the SAST suite, which needs these tools on your `PATH` (they are not npm dependencies): [actionlint](https://github.com/rhysd/actionlint), [gitleaks](https://github.com/gitleaks/gitleaks), [semgrep](https://semgrep.dev), [trivy](https://trivy.dev), [trufflehog](https://github.com/trufflesecurity/trufflehog) and [zizmor](https://github.com/zizmorcore/zizmor). Without them, run `npm run test:lint && npm run test:unit`, which is what the release workflow runs (the pre-commit hook only lints staged files).

The maintainer release scripts (`release:staged`, `release:approve`) also need `jq` and an `xargs` that supports `-o` (BSD or GNU findutils 4.7+).

## Committing

Ensure git commits meet the following FLOSS Best Practices:

- Message follows [Conventional Commits](https://www.conventionalcommits.org/) pattern. This is automatically enforced using `@commitlint/cli`.
- Message includes sign off for [Developer Certificate of Origin (DCO)](https://developercertificate.org/) compliance. This is automatically enforced using GitHub Actions on Pull-Requests.
  1. `git config --global user.name "Your Name"` and `git config --global user.email username@example.org` setup with `--signoff` flag on `git commit`
  2. Or, `Signed-off-by: username <email address>` as the last line of a commit, when a change is made through GitHub
- Commit is cryptographically signed and can be verified. This is automatically enforced by GitHub security configuration. [GitHub Docs: About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)

## Code Style

Code is formatted and linted using [Biome](https://biomejs.dev).

## Licence

Licensed under [MIT Licence](LICENSE).
