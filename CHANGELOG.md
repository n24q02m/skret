# Changelog

All notable changes to this project will be documented in this file.

<!-- version list -->

## v1.19.2-beta.2 (2026-09-04)

### Bug Fixes

- Isolate Home state migration ([#737](https://github.com/n24q02m/skret/pull/737),
  [`401b0f7`](https://github.com/n24q02m/skret/commit/401b0f7bc6aa9ddb8ef7e0c83e7ff466e2720a42))

- Resample executor authority clock ([#736](https://github.com/n24q02m/skret/pull/736),
  [`834ec98`](https://github.com/n24q02m/skret/commit/834ec988829554c12d76a7d5131d5c1e706d8f57))

- **hub**: Bind executor clients to role authorities
  ([#736](https://github.com/n24q02m/skret/pull/736),
  [`834ec98`](https://github.com/n24q02m/skret/commit/834ec988829554c12d76a7d5131d5c1e706d8f57))

- **release**: Recheck Home state manifest files ([#738](https://github.com/n24q02m/skret/pull/738),
  [`8500a38`](https://github.com/n24q02m/skret/commit/8500a387a52718edfc58ddce555b3d0f2b4899dc))

- **release**: Reject Home dot-segment paths ([#739](https://github.com/n24q02m/skret/pull/739),
  [`ca8fb56`](https://github.com/n24q02m/skret/commit/ca8fb569e9652dac2837542838994a7f8b6998b6))


## v1.19.2-beta.1 (2026-09-04)

### Bug Fixes

- **release**: Cut pinned G1 tuple to generation 4 (v1.6.0-beta.10)
  ([#735](https://github.com/n24q02m/skret/pull/735),
  [`caacb01`](https://github.com/n24q02m/skret/commit/caacb01a67da22ddd5b3320c580163760eaf5013))


## v1.19.1 (2026-09-03)

### Bug Fixes

- **ci**: Drop target_commitish assert in release readback
  ([#731](https://github.com/n24q02m/skret/pull/731),
  [`31fa1e5`](https://github.com/n24q02m/skret/commit/31fa1e5f2ef06f2989ec3f1a68b2bc8917d88540))


## v1.19.0 (2026-09-02)

### Bug Fixes

- Satisfy gofumpt lint ([#721](https://github.com/n24q02m/skret/pull/721),
  [`92934ac`](https://github.com/n24q02m/skret/commit/92934ac8418620054509d2013b358eada3f06fac))

- Satisfy gofumpt lint ([#716](https://github.com/n24q02m/skret/pull/716),
  [`4afc8d7`](https://github.com/n24q02m/skret/commit/4afc8d71cd386d308d5e7701393a7426b0b934ee))

- Satisfy syncer lint checks ([#721](https://github.com/n24q02m/skret/pull/721),
  [`92934ac`](https://github.com/n24q02m/skret/commit/92934ac8418620054509d2013b358eada3f06fac))

- Satisfy syncer lint checks ([#716](https://github.com/n24q02m/skret/pull/716),
  [`4afc8d7`](https://github.com/n24q02m/skret/commit/4afc8d71cd386d308d5e7701393a7426b0b934ee))

- **ci**: Install cosign for on-demand installer smoke
  ([#721](https://github.com/n24q02m/skret/pull/721),
  [`92934ac`](https://github.com/n24q02m/skret/commit/92934ac8418620054509d2013b358eada3f06fac))

- **ci**: Install cosign for on-demand installer smoke
  ([#716](https://github.com/n24q02m/skret/pull/716),
  [`4afc8d7`](https://github.com/n24q02m/skret/commit/4afc8d71cd386d308d5e7701393a7426b0b934ee))

- **ci**: Stabilize Linux coverage gate ([#721](https://github.com/n24q02m/skret/pull/721),
  [`92934ac`](https://github.com/n24q02m/skret/commit/92934ac8418620054509d2013b358eada3f06fac))

- **ci**: Stabilize Linux coverage gate ([#716](https://github.com/n24q02m/skret/pull/716),
  [`4afc8d7`](https://github.com/n24q02m/skret/commit/4afc8d71cd386d308d5e7701393a7426b0b934ee))

- **ci**: Verify installer Cosign version ([#721](https://github.com/n24q02m/skret/pull/721),
  [`92934ac`](https://github.com/n24q02m/skret/commit/92934ac8418620054509d2013b358eada3f06fac))

- **ci**: Verify installer Cosign version ([#716](https://github.com/n24q02m/skret/pull/716),
  [`4afc8d7`](https://github.com/n24q02m/skret/commit/4afc8d71cd386d308d5e7701393a7426b0b934ee))

- **release**: Bind Skret candidate to signed G1 ([#723](https://github.com/n24q02m/skret/pull/723),
  [`979dc0e`](https://github.com/n24q02m/skret/commit/979dc0e0b40d09d77577372ba66be05fa0aca1ff))

- **skret**: Repair Wave 1 live contract barriers
  ([#726](https://github.com/n24q02m/skret/pull/726),
  [`2060db4`](https://github.com/n24q02m/skret/commit/2060db41935fb9fb9f515b60219e735aa3522261))

- **syncer**: WalkDir callback must return nil not continue for reserved transport names
  ([#727](https://github.com/n24q02m/skret/pull/727),
  [`8bdfb4d`](https://github.com/n24q02m/skret/commit/8bdfb4d64226cd113e4650ebf13f518e9b93a347))

### Features

- **candidate**: Add bounded Git control executor
  ([#721](https://github.com/n24q02m/skret/pull/721),
  [`92934ac`](https://github.com/n24q02m/skret/commit/92934ac8418620054509d2013b358eada3f06fac))

### Testing

- **hub**: Stabilize signed manifest timestamps ([#723](https://github.com/n24q02m/skret/pull/723),
  [`979dc0e`](https://github.com/n24q02m/skret/commit/979dc0e0b40d09d77577372ba66be05fa0aca1ff))

- **provider**: Cover partial commit diagnostics ([#721](https://github.com/n24q02m/skret/pull/721),
  [`92934ac`](https://github.com/n24q02m/skret/commit/92934ac8418620054509d2013b358eada3f06fac))

- **provider**: Cover partial commit diagnostics ([#716](https://github.com/n24q02m/skret/pull/716),
  [`4afc8d7`](https://github.com/n24q02m/skret/commit/4afc8d71cd386d308d5e7701393a7426b0b934ee))


## v1.18.1-beta.1 (2026-08-30)

### Bug Fixes

- **ci**: Add cosign-installer to installer-smoke job in cd.yml
  ([`a152a5b`](https://github.com/n24q02m/skret/commit/a152a5bb43baae4a630dcf6e453d195ddbb54929))


## v1.18.0 (2026-08-29)

### Bug Fixes

- Align semantic release beta pin
  ([`c3ea2e7`](https://github.com/n24q02m/skret/commit/c3ea2e744ab419ba0231269f3d6eb10cc5a32ba2))

- Pass required Home migration identity flags ([#707](https://github.com/n24q02m/skret/pull/707),
  [`ea5cb3a`](https://github.com/n24q02m/skret/commit/ea5cb3a6193200780ff63a46aa08bc61bafca5a4))

- Reject aliased Home state roles ([#707](https://github.com/n24q02m/skret/pull/707),
  [`ea5cb3a`](https://github.com/n24q02m/skret/commit/ea5cb3a6193200780ff63a46aa08bc61bafca5a4))

- Remove Home sandbox slice
  ([`23dea61`](https://github.com/n24q02m/skret/commit/23dea61d153c7f544cdaf974cc99821d6226861b))

- Resolve target lock, generation drift, and AWS ambiguous put edge cases
  ([`e901297`](https://github.com/n24q02m/skret/commit/e9012974ab34e5055f8c98d087af4a0b61d0bee2))

- **cd**: Isolate release dispatch by skipping docs, hub, and secret sync
  ([`8a6d7d4`](https://github.com/n24q02m/skret/commit/8a6d7d4a266e38fa46379694c49f7075d1a658af))

- **hub**: Watchdog provider operations and bind readback OIDs
  ([`6c7f942`](https://github.com/n24q02m/skret/commit/6c7f942659ab466c26cfdb9fbd8a0e9109a504e1))

- **provider**: Fence ambiguous AWS parameter writes
  ([`ea59849`](https://github.com/n24q02m/skret/commit/ea59849b18ced2465b19da1277030a9ebb6a193b))

- **provider**: Surface partial metadata commits
  ([`b42c814`](https://github.com/n24q02m/skret/commit/b42c81450d7b643244e2bb20c1e9a19ab91df590))

- **release**: Scope homebrew cask and scoop bucket to cli archive
  ([`2cc3589`](https://github.com/n24q02m/skret/commit/2cc3589c2f9839d65f4127287fecdb4dee76097f))

- **secretlaunch**: Own child wait and surface kill failures
  ([`e5efac1`](https://github.com/n24q02m/skret/commit/e5efac19aeba605da352853038462c619ef78580))

- **secretlaunch**: Reconcile older owned generations
  ([`6dd0ac7`](https://github.com/n24q02m/skret/commit/6dd0ac77173dfbdce62a4118b09784d36cdff8d5))

- **secretlaunch**: Separate heartbeat protocol from health cadence
  ([`9536883`](https://github.com/n24q02m/skret/commit/9536883a61eb32dd0061ef04ce033d7c7ce48a36))

- **secretlaunch**: Use signed heartbeat timeout
  ([`93c8fb3`](https://github.com/n24q02m/skret/commit/93c8fb31bfa299a888adde444b8a3a85effd5bed))

- **sync**: Bind journals to targets and reject name collisions
  ([`1c0dbc0`](https://github.com/n24q02m/skret/commit/1c0dbc0649099bd22400a188a67d295412af7e8b))

- **sync**: Durably replace state journals
  ([`17b41f6`](https://github.com/n24q02m/skret/commit/17b41f64be6215704a9232687a187b5d7004943e))

- **sync**: Fence ambiguous provider mutations
  ([`3dbbd57`](https://github.com/n24q02m/skret/commit/3dbbd573e3014716eb9cc0631a352c8ea7704121))

- **sync**: Hold target lock across journal transaction
  ([`2ea0849`](https://github.com/n24q02m/skret/commit/2ea084965790b4fd0a6db27ecce69327b41c80c6))

- **sync**: Recover acknowledged operation before retry
  ([`a82e756`](https://github.com/n24q02m/skret/commit/a82e7565b96cf74498141d895839f5b8dcbecbf2))

- **update**: Integrate isolated Home sandbox follow-up
  ([#707](https://github.com/n24q02m/skret/pull/707),
  [`ea5cb3a`](https://github.com/n24q02m/skret/commit/ea5cb3a6193200780ff63a46aa08bc61bafca5a4))

### Chores

- Bump better-semantic-release to v1.4.0 ([#701](https://github.com/n24q02m/skret/pull/701),
  [`3d0783f`](https://github.com/n24q02m/skret/commit/3d0783fa5396a9928fb4a219208dab0174aa45e1))

- **skret**: Curate coherent runtime security slice
  ([`d7a5821`](https://github.com/n24q02m/skret/commit/d7a58215ab38a32d6b0520e828b965c1dd9f46d9))

### Features

- Restore Home sandbox slice
  ([`a337ffa`](https://github.com/n24q02m/skret/commit/a337ffa8d5d4e563526292a0a07e8b68c261ada8))

- **skret**: Isolate Home synthetic state root ([#707](https://github.com/n24q02m/skret/pull/707),
  [`ea5cb3a`](https://github.com/n24q02m/skret/commit/ea5cb3a6193200780ff63a46aa08bc61bafca5a4))

- **update**: Add isolated Home sandbox harness ([#707](https://github.com/n24q02m/skret/pull/707),
  [`ea5cb3a`](https://github.com/n24q02m/skret/commit/ea5cb3a6193200780ff63a46aa08bc61bafca5a4))

### Testing

- **sync**: Use canonical state path fixture
  ([`a024f14`](https://github.com/n24q02m/skret/commit/a024f14b79e33ab3ab66aa77f8a3358a77ecad52))


## v1.17.1 (2026-08-09)


## v1.17.1-beta.2 (2026-08-09)

### Bug Fixes

- Publish each tag from exactly one CD run ([#667](https://github.com/n24q02m/skret/pull/667),
  [`d6e0948`](https://github.com/n24q02m/skret/commit/d6e0948c7b813e36bd8bf03e1a6fb45276865b95))


## v1.17.1-beta.1 (2026-08-09)

### Bug Fixes

- Nothing checks the installers when a release actually happens
  ([#666](https://github.com/n24q02m/skret/pull/666),
  [`f9265df`](https://github.com/n24q02m/skret/commit/f9265df4e1fd5acaf6330e9acaee3bba3a3778bc))


## v1.17.0 (2026-08-09)


## v1.17.0-beta.1 (2026-08-09)

### Bug Fixes

- A failed signature check warns and installs anyway
  ([#658](https://github.com/n24q02m/skret/pull/658),
  [`7e32f7b`](https://github.com/n24q02m/skret/commit/7e32f7b5cbe67c713954f609247b59ef0190f829))

- Brew install fails because the cask asks for an unsupported shell
  ([#649](https://github.com/n24q02m/skret/pull/649),
  [`39dee33`](https://github.com/n24q02m/skret/commit/39dee33e248f0ab15c0739202b37c9c704825986))

- Browse screen stacks two keybind lines ([#651](https://github.com/n24q02m/skret/pull/651),
  [`ac7327a`](https://github.com/n24q02m/skret/commit/ac7327a8d9e31a5b8ea6e5c2a0fd7c07a50f1aff))

- Count login attempts in a durable object, the binding does not hold
  ([#664](https://github.com/n24q02m/skret/pull/664),
  [`2b7f53d`](https://github.com/n24q02m/skret/commit/2b7f53d3d0fc80d983061e8b038f227071eb98bc))

- Demo.gif PRs open with a token that cannot trigger CI
  ([#656](https://github.com/n24q02m/skret/pull/656),
  [`a21e119`](https://github.com/n24q02m/skret/commit/a21e1191240bdf4da820b94b8ffc71924197c519))

- Drop the no-op alias that opens the demo GIF ([#648](https://github.com/n24q02m/skret/pull/648),
  [`e6d2465`](https://github.com/n24q02m/skret/commit/e6d2465c798cd5181ec5ed73815ad4190658cc97))

- Gate coverage per package, not just on the average
  ([#661](https://github.com/n24q02m/skret/pull/661),
  [`a1f531a`](https://github.com/n24q02m/skret/commit/a1f531a462644628e9e14946fd6949bbb795ce6b))

- Healthz reports healthy while the KV the dashboard needs is down
  ([#657](https://github.com/n24q02m/skret/pull/657),
  [`0177aff`](https://github.com/n24q02m/skret/commit/0177aff415df7a64a7875070a09fc9c332bc4b3f))

- Make install.sh executable so a checkout can run it
  ([#647](https://github.com/n24q02m/skret/pull/647),
  [`0e49ffe`](https://github.com/n24q02m/skret/commit/0e49ffe96122fe44a13486e7093f9df178ccba9f))

- Migrate the release image to dockers_v2 and stop betas taking :latest
  ([#665](https://github.com/n24q02m/skret/pull/665),
  [`6eac456`](https://github.com/n24q02m/skret/commit/6eac456448a21602d4a50bebb56164ecabe541a6))

- Nothing asserted the two headers #597 was opened to add
  ([#653](https://github.com/n24q02m/skret/pull/653),
  [`f1c549d`](https://github.com/n24q02m/skret/commit/f1c549dd2bed2a6b6fe5cb49a2f1373d4ced92e6))

- Re-render the demo when the demo changes, not when the workflow does
  ([#662](https://github.com/n24q02m/skret/pull/662),
  [`56779b4`](https://github.com/n24q02m/skret/commit/56779b49479ff2d9e7683e1bbce83c765229702a))

- Release verification is broken on every install path
  ([#646](https://github.com/n24q02m/skret/pull/646),
  [`a28e58f`](https://github.com/n24q02m/skret/commit/a28e58fec3afd75ac7f902e933daedbc7a6693b7))

- Restore Direct binary row into the README install table
  ([#646](https://github.com/n24q02m/skret/pull/646),
  [`a28e58f`](https://github.com/n24q02m/skret/commit/a28e58fec3afd75ac7f902e933daedbc7a6693b7))

- Scope the empty-input guard entry to the function it was measured on
  ([#663](https://github.com/n24q02m/skret/pull/663),
  [`393a2cd`](https://github.com/n24q02m/skret/commit/393a2cd96309cdd4a6e567da63717635b49a31ac))

- Verify releases against checksums.txt.bundle, not absent .pem/.sig
  ([#646](https://github.com/n24q02m/skret/pull/646),
  [`a28e58f`](https://github.com/n24q02m/skret/commit/a28e58fec3afd75ac7f902e933daedbc7a6693b7))

- Windows installer picks the checksum row by position, not by name
  ([#652](https://github.com/n24q02m/skret/pull/652),
  [`cc65fdf`](https://github.com/n24q02m/skret/commit/cc65fdf7d72347e8bc36aeef7bd90d644c377bbf))

### Features

- Rate limit the two routes a stranger can reach ([#660](https://github.com/n24q02m/skret/pull/660),
  [`463b7e0`](https://github.com/n24q02m/skret/commit/463b7e023673aae49fc535ac664a63ea9346d3e6))

- Regenerate demo.gif ([#650](https://github.com/n24q02m/skret/pull/650),
  [`f52d25e`](https://github.com/n24q02m/skret/commit/f52d25ea6069dd3097e368807557cd0e773633e9))


## v1.16.0 (2026-08-08)


## v1.16.0-beta.2 (2026-08-08)

### Bug Fixes

- Add dashboard security headers
  ([`39a35f5`](https://github.com/n24q02m/skret/commit/39a35f590ba95ad08e6beb9e95d088bffb8be03d))

- Add local README sync release gate
  ([`5c9c70c`](https://github.com/n24q02m/skret/commit/5c9c70cb8a398936e7798a52fef8f59e8e3a852e))

- Align Vitest 4 worker test configuration
  ([`5657ab4`](https://github.com/n24q02m/skret/commit/5657ab49225b99d35a29889801fd35d88b96f9be))

- Clear all 22 npm advisories in docs and hub ([#644](https://github.com/n24q02m/skret/pull/644),
  [`7717c2f`](https://github.com/n24q02m/skret/commit/7717c2f1954f2d87fa55d3f4d4b8f215acabbe42))

- Close bot PRs that re-file an already-declined change
  ([#642](https://github.com/n24q02m/skret/pull/642),
  [`5f56090`](https://github.com/n24q02m/skret/commit/5f56090acba25eb609300999cfc7df7b9b9f082e))

- Correct palette learning date
  ([`d6b86a7`](https://github.com/n24q02m/skret/commit/d6b86a7c03991f3f2143821957dc44605267208c))

- Hash inputs before constant-time comparison to remove length oracle
  ([`769a4a5`](https://github.com/n24q02m/skret/commit/769a4a551997cba3c87050bfea3cc8dc239cb733))

- Normalize baseline EOF files
  ([`5c9c70c`](https://github.com/n24q02m/skret/commit/5c9c70cb8a398936e7798a52fef8f59e8e3a852e))

- Pin sync image bases by digest and drop two stray permissions
  ([#645](https://github.com/n24q02m/skret/pull/645),
  [`29ff572`](https://github.com/n24q02m/skret/commit/29ff572cd6bdd12d5230ba97aaa0822917f4d4eb))

- Raise hub devDependencies past three npm advisories
  ([#644](https://github.com/n24q02m/skret/pull/644),
  [`7717c2f`](https://github.com/n24q02m/skret/commit/7717c2f1954f2d87fa55d3f4d4b8f215acabbe42))

- Record the demo from an empty directory ([#643](https://github.com/n24q02m/skret/pull/643),
  [`f671706`](https://github.com/n24q02m/skret/commit/f671706a8db310c44852158111230b219d15851c))

- Reduce HTML escaping allocations
  ([`a2309a1`](https://github.com/n24q02m/skret/commit/a2309a1891bcaf75a4df9f59e76f04ffcf0caebd))

- Skip allocations in DetectEnvNameCollisions for empty secrets
  ([`be5d2f1`](https://github.com/n24q02m/skret/commit/be5d2f137621374ad2cdeee7ec73483d76f44135))

- Update AWS credentials action pin
  ([`e49807b`](https://github.com/n24q02m/skret/commit/e49807b17c203847e71d13c2f7aa156158207323))

- Update better semantic release action pin
  ([`68b3133`](https://github.com/n24q02m/skret/commit/68b31330354414be58b0063c341ac741338969fd))

- Update CodeQL action pin
  ([`2931250`](https://github.com/n24q02m/skret/commit/2931250e0630129325430ca3203d4abbc51da7c1))

- Update pnpm action pin
  ([`27627bc`](https://github.com/n24q02m/skret/commit/27627bcbdb74b8d119a0794d411b5996e2fca7a9))

- Update scorecard action pin
  ([`724ce27`](https://github.com/n24q02m/skret/commit/724ce27490e7249f16b2d09fdb2c6bf5dae40295))

- Update smithy-go dependency
  ([`49ba1d2`](https://github.com/n24q02m/skret/commit/49ba1d2b68d35e2955085a35ca779f49f2ef919e))

- Upgrade docs to astro 7 and lift the renovate holds behind it
  ([#644](https://github.com/n24q02m/skret/pull/644),
  [`7717c2f`](https://github.com/n24q02m/skret/commit/7717c2f1954f2d87fa55d3f4d4b8f215acabbe42))

- **deps**: Update actions/checkout action to v6.1.0
  ([`5054fc2`](https://github.com/n24q02m/skret/commit/5054fc23fe73d27cc8556c9e84ad2af49cc52342))

- **deps**: Update aws-sdk-go-v2 monorepo
  ([`e54c015`](https://github.com/n24q02m/skret/commit/e54c015aed0c63b6bb285aa0a80ea999149af947))

- **deps**: Update github/codeql-action action to v4.37.6
  ([`b2ea287`](https://github.com/n24q02m/skret/commit/b2ea2873594612fca666a0b6d9702d55a5f80dbc))

### Features

- Expose login form error state in document title
  ([`3bae474`](https://github.com/n24q02m/skret/commit/3bae47437dcb396b62f304307d0a1c2881cead90))

- Namespace empty state + close re-filed bot PRs ([#642](https://github.com/n24q02m/skret/pull/642),
  [`5f56090`](https://github.com/n24q02m/skret/commit/5f56090acba25eb609300999cfc7df7b9b9f082e))

- Regenerate demo.gif ([#641](https://github.com/n24q02m/skret/pull/641),
  [`b635899`](https://github.com/n24q02m/skret/commit/b635899ea342e95395e68c70ecd96ec5845f0d37))

- Render an empty-state row for namespaces with no keys
  ([#642](https://github.com/n24q02m/skret/pull/642),
  [`5f56090`](https://github.com/n24q02m/skret/commit/5f56090acba25eb609300999cfc7df7b9b9f082e))

- Use semantic time elements in dashboard
  ([`bd28fe0`](https://github.com/n24q02m/skret/commit/bd28fe043201c76c7205f67c094e781ba2b04a71))

### Performance Improvements

- ⚡ bolt: Add early return to DetectEnvNameCollisions for empty secrets
  ([`be5d2f1`](https://github.com/n24q02m/skret/commit/be5d2f137621374ad2cdeee7ec73483d76f44135))


## v1.16.0-beta.1 (2026-08-04)

### Bug Fixes

- Enforce bot governance review findings ([#619](https://github.com/n24q02m/skret/pull/619),
  [`e47b2fa`](https://github.com/n24q02m/skret/commit/e47b2fa87e8e9f41b1af00d4c2fb088b72292267))

- Make bot governance labels reliable ([#619](https://github.com/n24q02m/skret/pull/619),
  [`e47b2fa`](https://github.com/n24q02m/skret/commit/e47b2fa87e8e9f41b1af00d4c2fb088b72292267))

- Move this repo to Apache-2.0 ([#612](https://github.com/n24q02m/skret/pull/612),
  [`80e75fd`](https://github.com/n24q02m/skret/commit/80e75fd1e339a97f6ed7284a6d34be9de542a3f5))

- Stabilize env provider list error test ([#619](https://github.com/n24q02m/skret/pull/619),
  [`e47b2fa`](https://github.com/n24q02m/skret/commit/e47b2fa87e8e9f41b1af00d4c2fb088b72292267))

### Features

- Add bot PR governance workflow ([#619](https://github.com/n24q02m/skret/pull/619),
  [`e47b2fa`](https://github.com/n24q02m/skret/commit/e47b2fa87e8e9f41b1af00d4c2fb088b72292267))

- Add skret manifest and bot PR governance ([#619](https://github.com/n24q02m/skret/pull/619),
  [`e47b2fa`](https://github.com/n24q02m/skret/commit/e47b2fa87e8e9f41b1af00d4c2fb088b72292267))

- Add skret repository configuration ([#619](https://github.com/n24q02m/skret/pull/619),
  [`e47b2fa`](https://github.com/n24q02m/skret/commit/e47b2fa87e8e9f41b1af00d4c2fb088b72292267))

- Sync cross-promo section ([#600](https://github.com/n24q02m/skret/pull/600),
  [`96610ac`](https://github.com/n24q02m/skret/commit/96610acf54a4beb0d06bde33809bad5c93f8443c))


## v1.15.1 (2026-07-25)

### Bug Fixes

- Keep generating shell completions in the homebrew cask
  ([`23f73ed`](https://github.com/n24q02m/skret/commit/23f73ed091d3d37bea22a680d3b549061822c68b))

- Keep prereleases out of the scoop, brew and Latest channels
  ([`503b847`](https://github.com/n24q02m/skret/commit/503b84749dfe9fa537079191a89a70d3d725408a))

- Pin the completion shells the cask generates
  ([`02af452`](https://github.com/n24q02m/skret/commit/02af45279355e580bbb84ce24cb4cf7024a8f71f))

- Publish the homebrew tap as a cask and drop the deprecated archive format keys
  ([`09dc29b`](https://github.com/n24q02m/skret/commit/09dc29ba808eca21af7e490cc1fd35b654075a17))

- Scope table headers and structure the vault empty state
  ([`9636485`](https://github.com/n24q02m/skret/commit/9636485c821fd571e3544bf2bcdd58640b1f02ef))

- Smoke test the brew and scoop channels, not just the install scripts
  ([`454e81d`](https://github.com/n24q02m/skret/commit/454e81d3995aa568ae55cc9a0018c80281ef7cd9))


## v1.15.0 (2026-07-25)


## v1.15.0-beta.2 (2026-07-25)

### Features

- Json error envelope and json output for the write path
  ([`e39e2b7`](https://github.com/n24q02m/skret/commit/e39e2b7151c20c6db7e65bddb6fa6395c5563d4f))


## v1.15.0-beta.1 (2026-07-24)

### Bug Fixes

- Add focus-visible styles and a main landmark to the hub UI
  ([`db5be8e`](https://github.com/n24q02m/skret/commit/db5be8e85f5b13eb7fe618f178be51327910c72b))

- Adopt better-semantic-release for built-in release guards
  ([`c83239f`](https://github.com/n24q02m/skret/commit/c83239f19fe1f5abacbc4df3b1c74625638f6f2e))

- Build provider and hub API URLs with url.JoinPath to prevent malformed URLs
  ([`9a955f3`](https://github.com/n24q02m/skret/commit/9a955f30c53ad9667e89a7bc81dba9f0d9727f5d))

- Consolidate dependency automation onto renovate
  ([`1b82b03`](https://github.com/n24q02m/skret/commit/1b82b03f4db4df2e1fa3f7b520820e44137d4b74))

- Improve hub login form accessibility (labels, focus, validation)
  ([`7ee9d26`](https://github.com/n24q02m/skret/commit/7ee9d268a638f7faa2db460e2aee84d12bbe43c6))

- Pin GitHub Action references to commit SHAs ([#569](https://github.com/n24q02m/skret/pull/569),
  [`f6f22d4`](https://github.com/n24q02m/skret/commit/f6f22d4c39b76e284601c3a96b7baa169ef4d5ff))

- Replace existing release artifacts on goreleaser rerun
  ([#562](https://github.com/n24q02m/skret/pull/562),
  [`761564b`](https://github.com/n24q02m/skret/commit/761564bfca35fc38bc6fa4510be7de60202cd2bc))

- Stop browser-open tests from launching a real browser
  ([`630b6e0`](https://github.com/n24q02m/skret/commit/630b6e0e21e18cc2b647af8bdd3d6106c8ffa392))

- **deps**: Update actions/checkout action to v4.4.0
  ([#576](https://github.com/n24q02m/skret/pull/576),
  [`86ba656`](https://github.com/n24q02m/skret/commit/86ba65666bc9ff1ea062f07fa731f3c4643351d3))

- **deps**: Update github/codeql-action digest to 7188fc3
  ([#563](https://github.com/n24q02m/skret/pull/563),
  [`fe01c3e`](https://github.com/n24q02m/skret/commit/fe01c3ede12595b8086af6c26fff7f5a90a5bc30))

- **deps**: Update module github.com/aws/smithy-go to v1.27.4
  ([#564](https://github.com/n24q02m/skret/pull/564),
  [`1750994`](https://github.com/n24q02m/skret/commit/17509945ec1d17055f5e810264135ed1be16373d))

- **deps**: Update module golang.org/x/crypto to v0.54.0
  ([#570](https://github.com/n24q02m/skret/pull/570),
  [`329824b`](https://github.com/n24q02m/skret/commit/329824beaae11cce7aa5a985b5be8c36006fed74))

### Features

- Add actionable empty-state messages to run and template commands
  ([`ea0423a`](https://github.com/n24q02m/skret/commit/ea0423a582ffe835dea5e11c2905eb054edfdb89))


## v1.14.0 (2026-07-17)

### Bug Fixes

- Add command-reference docs for core commands ([#561](https://github.com/n24q02m/skret/pull/561),
  [`caa34b5`](https://github.com/n24q02m/skret/commit/caa34b5081d7061a87f1f21a9de16a952f94b095))

- Dotenv syncer writes invalid variable names for nested provider keys
  ([#560](https://github.com/n24q02m/skret/pull/560),
  [`d7ab5fe`](https://github.com/n24q02m/skret/commit/d7ab5fe2f8a42d5730d429a87f3fa37ff23d4abb))

- Expand literal date placeholder in palette ledger entry
  ([#557](https://github.com/n24q02m/skret/pull/557),
  [`9f56eab`](https://github.com/n24q02m/skret/commit/9f56eabe8a9b65e33168e89d2402a234c73ce06a))

- **deps**: Update actions/setup-node digest to 2499707
  ([#555](https://github.com/n24q02m/skret/pull/555),
  [`44b3261`](https://github.com/n24q02m/skret/commit/44b3261bcad2fdee25c6ec7e073eb0a10d625d0c))

- **deps**: Update alpine Docker tag to v3.24 ([#559](https://github.com/n24q02m/skret/pull/559),
  [`80f2dff`](https://github.com/n24q02m/skret/commit/80f2dff34053e9e73f3d05f7deda06a549358907))

- **deps**: Update aws-sdk-go-v2 monorepo ([#556](https://github.com/n24q02m/skret/pull/556),
  [`a2342ec`](https://github.com/n24q02m/skret/commit/a2342ec05a64858ad9fce658592982992d896fb4))

### Features

- Palette: add keybind hints for filtering state ([#557](https://github.com/n24q02m/skret/pull/557),
  [`9f56eab`](https://github.com/n24q02m/skret/commit/9f56eabe8a9b65e33168e89d2402a234c73ce06a))

- 🎨 palette: add keybind hints for filtering state
  ([#557](https://github.com/n24q02m/skret/pull/557),
  [`9f56eab`](https://github.com/n24q02m/skret/commit/9f56eabe8a9b65e33168e89d2402a234c73ce06a))

### Performance Improvements

- Replace strings.SplitN with strings.Cut ([#558](https://github.com/n24q02m/skret/pull/558),
  [`c0b4b61`](https://github.com/n24q02m/skret/commit/c0b4b61a9d2fec1f6673fa73b7fd63b42b3d2548))

- ⚡ bolt: bypass string allocation in splitOwnerRepo
  ([#554](https://github.com/n24q02m/skret/pull/554),
  [`215a6ad`](https://github.com/n24q02m/skret/commit/215a6ad4f1c3eee375385b2b8896cdbc9904197b))


## v1.13.0 (2026-07-14)


## v1.13.0-beta.2 (2026-07-14)

### Bug Fixes

- Say byte-exact secret reads, not injection, in the agent-ready copy
  ([#549](https://github.com/n24q02m/skret/pull/549),
  [`5722e9c`](https://github.com/n24q02m/skret/commit/5722e9c5280ed087d668efbb22339fd9fc68ca7f))

- **deps**: Update pnpm to v10.34.5 ([#538](https://github.com/n24q02m/skret/pull/538),
  [`448bee3`](https://github.com/n24q02m/skret/commit/448bee3c52ae52d3a5cb0fcf8fdf333be81c9aa2))

- **deps**: Update vitest to v3.2.7 ([#539](https://github.com/n24q02m/skret/pull/539),
  [`111e31e`](https://github.com/n24q02m/skret/commit/111e31e36b8f1b4685299fcabc063408ea4aed23))

### Features

- Add browse and sync dry-run scenes to demo.tape
  ([#549](https://github.com/n24q02m/skret/pull/549),
  [`5722e9c`](https://github.com/n24q02m/skret/commit/5722e9c5280ed087d668efbb22339fd9fc68ca7f))

- Add vault dashboard screenshot to README and hub guide
  ([#549](https://github.com/n24q02m/skret/pull/549),
  [`5722e9c`](https://github.com/n24q02m/skret/commit/5722e9c5280ed087d668efbb22339fd9fc68ca7f))

- Print an empty-state hint when scan finds no secrets
  ([#553](https://github.com/n24q02m/skret/pull/553),
  [`fccbc89`](https://github.com/n24q02m/skret/commit/fccbc8900ff1ed3fd7cfd62798d5f998bf40b9e7))

- Regenerate demo.gif with browse and sync dry-run scenes
  ([#549](https://github.com/n24q02m/skret/pull/549),
  [`5722e9c`](https://github.com/n24q02m/skret/commit/5722e9c5280ed087d668efbb22339fd9fc68ca7f))

- Surface agent-ready differentiator, add chamber comparison row, prune badges
  ([#549](https://github.com/n24q02m/skret/pull/549),
  [`5722e9c`](https://github.com/n24q02m/skret/commit/5722e9c5280ed087d668efbb22339fd9fc68ca7f))

- Surface hub dashboard, agent-ready differentiator, and demo scenes (Wave 4)
  ([#549](https://github.com/n24q02m/skret/pull/549),
  [`5722e9c`](https://github.com/n24q02m/skret/commit/5722e9c5280ed087d668efbb22339fd9fc68ca7f))


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
