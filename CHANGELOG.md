# Changelog

All notable changes to this project will be documented in this file.

<!-- version list -->

## v1.13.0-beta.1 (2026-07-13)

### Bug Fixes

- Accept presence status enum in hub ingest and render unknown statuses safely
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Add docs Astro build as PR gate + hold @astrojs/starlight <0.40
  ([#501](https://github.com/n24q02m/skret/pull/501),
  [`1e46eb2`](https://github.com/n24q02m/skret/commit/1e46eb284bd20ccf0e75799dc0d27b4131a784ec))

- Add PSR changelog insertion marker so releases populate CHANGELOG.md
  ([`17caaef`](https://github.com/n24q02m/skret/commit/17caaef960e10597c0dd625c74f17b403609243b))

- Align troubleshooting exit codes with corrected error-code mappings
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Allow data: images in the hub CSP so the favicon actually loads
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Capture os.Stdout in the completion-script regression test
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Classify a dotenv sync write failure as ExitGenericError, not ExitNetworkError
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Classify delete/rollback not-found errors as ExitNotFoundError with actionable hints
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Correct false claims and stale docs across README and docs site
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Correct mention gate expression (balanced parens + precedence)
  ([#546](https://github.com/n24q02m/skret/pull/546),
  [`c725502`](https://github.com/n24q02m/skret/commit/c725502e86f88bde19faa3e805e20a00a7a37c6f))

- Correct oversized-value exit-code claim and make FAQ recipe self-contained
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Correct phantom features, AWS tier claim, and broken FAQ recipe in docs
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Count legacy manifest statuses in the summary breakdown as other
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Dedupe --version prefix, omit empty env fields on init, error on unknown completion shell
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Document that a pages target warns on every hub push
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Document the changelog insertion marker in the release process guide
  ([`5a4efe7`](https://github.com/n24q02m/skret/commit/5a4efe7314d5b917962fdb4a2baa51c7a6fa101e))

- Document the live presence model for hub push ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Drop bot-attribution comments and the contradictory .jules ignore
  ([#531](https://github.com/n24q02m/skret/pull/531),
  [`8b0b001`](https://github.com/n24q02m/skret/commit/8b0b001a28b62f1987fe3dfde942a78fca9731f4))

- Drop dead completion stdout-redirect wrapper left in root.go
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- First-run defaults, --path mangling guard, and error classification (Wave 2)
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Fix dead link, agents.md gaps, Windows troubleshooting, and sidebar order
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Fix release-process workflow name and refresh stale docs
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Gate oc mention job on comment author write access
  ([#546](https://github.com/n24q02m/skret/pull/546),
  [`c725502`](https://github.com/n24q02m/skret/commit/c725502e86f88bde19faa3e805e20a00a7a37c6f))

- Harden hub presence tests against ambient GITHUB_TOKEN and add value-leak guard
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Hide contextual keybinds in TUI when list is empty
  ([#495](https://github.com/n24q02m/skret/pull/495),
  [`dc335a0`](https://github.com/n24q02m/skret/commit/dc335a027f3df41444866c0556ded3968d73cf10))

- Hide up/down keybind hint in browse empty state
  ([#507](https://github.com/n24q02m/skret/pull/507),
  [`596de3d`](https://github.com/n24q02m/skret/commit/596de3d456e07eb4770685163e3051cf4ccf7906))

- Note get-path exit-code deviation in error-codes table
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Print empty-state message when diff has nothing to compare
  ([#524](https://github.com/n24q02m/skret/pull/524),
  [`56b1829`](https://github.com/n24q02m/skret/commit/56b1829e490f70dd59916f7002cd6db825831c5f))

- Record KeyToEnvName single-pass rewrite as terminal state in bolt ledger
  ([#530](https://github.com/n24q02m/skret/pull/530),
  [`4251b0c`](https://github.com/n24q02m/skret/commit/4251b0c84120be39612e4166fede7be0008dfa56))

- Remove unverifiable coverage claim and reconcile Doppler pricing in README
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Report every missing sync --to=github requirement in one error
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Revert @astrojs/starlight to ^0.39.0 (0.41.0 pulls @astrojs/mdx@7 needing astro 7, breaks docs
  build on main)
  ([`dc440f8`](https://github.com/n24q02m/skret/commit/dc440f82efddda7aaf23bc73a7705f9188cad06c))

- Scope config validation to the resolved env and stop init from wiping good prod defaults
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Strict config parsing, indexed syncer errors, coverage-doc consistency
  ([#516](https://github.com/n24q02m/skret/pull/516),
  [`5b5fc24`](https://github.com/n24q02m/skret/commit/5b5fc24bf587c95952e2b00fa9e1d3d17d698b9b))

- Suggest 'skret set' when get finds no secret ([#527](https://github.com/n24q02m/skret/pull/527),
  [`ef8562c`](https://github.com/n24q02m/skret/commit/ef8562c268913ae756c4c972c0dfdd577293e8f2))

- Use real v1.12.0 release output in version example
  ([#542](https://github.com/n24q02m/skret/pull/542),
  [`5551a28`](https://github.com/n24q02m/skret/commit/5551a280447b4024bc52420d8666472ebe9e62e9))

- Warn instead of silently querying the wrong prefix on a shell-mangled --path
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- Wire setup --yes to a real non-interactive guard before the auth step
  ([#545](https://github.com/n24q02m/skret/pull/545),
  [`e031684`](https://github.com/n24q02m/skret/commit/e031684bc2957e2bb056bd45cb9153c2d3703e9c))

- 🛡️ sentinel: add path traversal defense to sync state file paths
  ([#496](https://github.com/n24q02m/skret/pull/496),
  [`a4412ca`](https://github.com/n24q02m/skret/commit/a4412cadffd3a51bcf4fce6c6e863b11da0188c9))

- **deps**: Update @astrojs/starlight to ^0.41.0 ([#500](https://github.com/n24q02m/skret/pull/500),
  [`5f301c1`](https://github.com/n24q02m/skret/commit/5f301c10b59d7469f3b8a6f2e8c6f31dfb080ef8))

- **deps**: Update aws-actions/configure-aws-credentials digest to 517a711
  ([#528](https://github.com/n24q02m/skret/pull/528),
  [`8222d96`](https://github.com/n24q02m/skret/commit/8222d9608ea22184a300f702f15be72fb6c3cf96))

- **deps**: Update aws-sdk-go-v2 monorepo ([#532](https://github.com/n24q02m/skret/pull/532),
  [`d941f42`](https://github.com/n24q02m/skret/commit/d941f424e4820d07764a717a236e2a42ad3d04fe))

- **deps**: Update aws-sdk-go-v2 monorepo ([#505](https://github.com/n24q02m/skret/pull/505),
  [`541e967`](https://github.com/n24q02m/skret/commit/541e967e56647429687c391a96d97f042efe2aa8))

- **deps**: Update aws-sdk-go-v2 monorepo ([#499](https://github.com/n24q02m/skret/pull/499),
  [`005d621`](https://github.com/n24q02m/skret/commit/005d621d8e376354c87fd3c6b6e7f03e4623b994))

- **deps**: Update docker/login-action digest to af1e73f
  ([#510](https://github.com/n24q02m/skret/pull/510),
  [`289dac8`](https://github.com/n24q02m/skret/commit/289dac8338db2716da58e3b9697ebac6f7f2b66d))

- **deps**: Update github/codeql-action digest to 99df26d
  ([#519](https://github.com/n24q02m/skret/pull/519),
  [`7ba81fc`](https://github.com/n24q02m/skret/commit/7ba81fcf1ac08d3a312dec661ee52b54027a3bbd))

- **deps**: Update go to v1.26.5 ([#533](https://github.com/n24q02m/skret/pull/533),
  [`31a3df5`](https://github.com/n24q02m/skret/commit/31a3df5c82b7f01da7198b39a9dd9b6ba027f84a))

- **deps**: Update goreleaser/goreleaser-action digest to f06c13b
  ([#497](https://github.com/n24q02m/skret/pull/497),
  [`f37a084`](https://github.com/n24q02m/skret/commit/f37a08422e774640201fabfdc241529d5811d54e))

- **deps**: Update module github.com/aws/smithy-go to v1.27.3
  ([#502](https://github.com/n24q02m/skret/pull/502),
  [`921a316`](https://github.com/n24q02m/skret/commit/921a3160c29be4e5e5d0647ccd78bdcef30e6df1))

- **deps**: Update pnpm/action-setup digest to 0ebf471
  ([#498](https://github.com/n24q02m/skret/pull/498),
  [`7141444`](https://github.com/n24q02m/skret/commit/71414442e7b78a118da8e38452e991362f162e83))

- **deps**: Update python-semantic-release/publish-action digest to 5a5718c
  ([#520](https://github.com/n24q02m/skret/pull/520),
  [`1f8acbd`](https://github.com/n24q02m/skret/commit/1f8acbd5bd6eb7670313c96dc2e779167b75658e))

- **deps**: Update python-semantic-release/python-semantic-release digest to 39dd205
  ([#522](https://github.com/n24q02m/skret/pull/522),
  [`bcc09c6`](https://github.com/n24q02m/skret/commit/bcc09c658022d61ddfcf7de5e960408b67c0f150))

- **deps**: Update sharp to ^0.35.0 ([#506](https://github.com/n24q02m/skret/pull/506),
  [`a4d331a`](https://github.com/n24q02m/skret/commit/a4d331a8a8a9f897c85ebb53f24ece8443da2264))

- **deps**: Update step-security/harden-runner digest to bf7454d
  ([#529](https://github.com/n24q02m/skret/pull/529),
  [`8eaf64f`](https://github.com/n24q02m/skret/commit/8eaf64f44b88f88d830c14cd6200905ffe0ab9a4))

### Features

- Add login a11y, logout control, and shared security headers
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Add opencode bot workflow ([#541](https://github.com/n24q02m/skret/pull/541),
  [`05e41c2`](https://github.com/n24q02m/skret/commit/05e41c2472a8f9ea14afc9cce5531a0e44b130b1))

- Add per-card summary counts, fix contrast, implement table overflow
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Add vault dashboard hub worker (read-only, 0-value)
  ([#513](https://github.com/n24q02m/skret/pull/513),
  [`74b5b0a`](https://github.com/n24q02m/skret/commit/74b5b0ab3b9806857e01b39d4baf253507d0c5b9))

- B2 CF sync worker (cron container SSM->targets)
  ([#517](https://github.com/n24q02m/skret/pull/517),
  [`d34132c`](https://github.com/n24q02m/skret/commit/d34132c8fbb73bb9fb7602997eba0e7ea6920590))

- Docs/agent-UX overhaul — rich --help, agent guide, llms.txt
  ([#512](https://github.com/n24q02m/skret/pull/512),
  [`5d47ff8`](https://github.com/n24q02m/skret/commit/5d47ff8cadb039077863e283d572d1ce5a8c0998))

- Multi-namespace sync with per-target no-overwrite and dry-run
  ([#534](https://github.com/n24q02m/skret/pull/534),
  [`74e5ab8`](https://github.com/n24q02m/skret/commit/74e5ab8f86774c545f1ec6475d881073c00f504c))

- Render generated_at with relative time and stale >48h badge
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Replace manifest drift status with per-target presence-by-name
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Rewire hub push to live presence-by-name lookup
  ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))

- Sync fabric — pluggable targets, cloudflare syncer, hub push
  ([#509](https://github.com/n24q02m/skret/pull/509),
  [`3f65085`](https://github.com/n24q02m/skret/commit/3f6508556f0a7ca986069994c59f6b05b5485508))

- Value-fidelity audit + fix set --from-stdin multi-line truncation
  ([#511](https://github.com/n24q02m/skret/pull/511),
  [`93dc852`](https://github.com/n24q02m/skret/commit/93dc852d142198689f64c1c85b187f1df33eaf8f))

- Vault presence-by-name + dashboard UX fixes ([#547](https://github.com/n24q02m/skret/pull/547),
  [`c0439de`](https://github.com/n24q02m/skret/commit/c0439de7e1d6926c0fccd2a1ecd60892380c8f57))
