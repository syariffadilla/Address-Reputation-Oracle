# Portal submission DRAFT — Address Reputation Oracle

> Prepared 25 Nov 2026 by Muse for the parent agent. Contract built
> and verified (87 stub + 10 GenVM direct tests, all run twice green;
> glsim live consensus 5/5, twice). NOT yet deployed to Studio, NOT
> yet pushed to GitHub, NOT yet submitted. The parent fills in the
> Studio deploy address, the repo URL, and the live-run tx hashes
> below, then submits via
> https://portal.genlayer.foundation/submit-contribution (Builder →
> Intelligent Contracts).

## Submission fields

- **Category:** Builder → Intelligent Contracts
- **Title:** Address Reputation Oracle: consensus-checked address safety verdicts
- **Description** (final text below; count verified with python at
  998 chars with a 42-char Studio address in place of the
  placeholder — the limit is 1000, so do NOT add words when filling
  in the real address; no em-dash anywhere):

> Address Reputation Oracle is a GenLayer Intelligent Contract that answers a simple question before anyone sends money to an unfamiliar address: is this address safe to deal with? Anyone can submit an address and chain. Validators fetch the address security record from GoPlus on their own and check the same flags (sanctioned, phishing, stealing, mixer, honeypot related, malicious contracts created). A FLAGGED, CAUTION or NO_FLAGS_FOUND verdict is only written when all validators agree. If they disagree or the fetch fails, nothing is written, so no address is ever marked clean by mistake. The rule is fixed, not an LLM call, and anyone can re-derive the verdict from the stored evidence. NO_FLAGS_FOUND only means GoPlus reported no known indicators at check time, not proof an address is safe. Live on stable Studionet (0xff7351a3d6EEBb852dA72f27BFC6c4b6fD6079F8): fake USDC creator FLAGGED, Ronin exploiter FLAGGED, Vitalik NO_FLAGS_FOUND. 97 tests pass (87 stub, 10 real GenVM direct-mode).

- **How to verify (if the form asks):** call `check_address` on the
  deployed contract, then read `get_verdict`: chain 56 fake-USDC
  creator `0xe8e0960da069c336852246a5bedf18ad05ea25e7` → flagged;
  chain 1 Ronin exploiter `0x098b716b8aaf21512996dc57eb0615e2383e2f96`
  → flagged; chain 1 Vitalik
  `0xd8da6bf26964af9d7eed9e03e53415d37aa96045` → no_flags_found;
  chain 56 Vitalik → no_flags_found.

## Evidence to attach

- GitHub repo URL: https://github.com/syariffadilla/Address-Reputation-Oracle (created 25 Nov, added to the Muse GitHub App installation; push pending, commit TBD).
- Files reviewers should read, in order: `README.md`, `DESIGN.md`,
  `TEST_LOG.md`, then `contracts/address_reputation_oracle.py`.
- Contract file for Studio: `contracts/address_reputation_oracle.py`
  (header already pins the stable runner `py-genlayer:1jb45aa8…`
  v0.2.5).
- Deployed address: `0xff7351a3d6EEBb852dA72f27BFC6c4b6fD6079F8` (stable Studionet chain 61999). Deploy tx `0x26a8a53c78b6b0c676c3113860ec2b5fe09f4bbc12072589b04a59072eb1aefb` FINALIZED. Deploying account `0x01ED7Ae5A842895C7E05a3CE5587d8DC67a6102F` (Studio local account, same as SafeLink / Token Safety / Pool). Explorer: https://explorer-studio.genlayer.com/address/0xff7351a3d6EEBb852dA72f27BFC6c4b6fD6079F8
- **REQUIRED Portal evidence: the Studionet explorer contract URL
  for the deployed address** — the form errors "Missing required
  evidence. Provide a URL for each of: (genlayer-explorer-contract)"
  without it. Add via "+ Add Evidence". Do NOT reuse a URL already
  submitted as evidence in any other submission.
- Live-run (all FINALIZED, check_address + get_verdict): chain 56 fake-USDC creator FLAGGED, tx `0xf256394f625ff7b9253738ad4e9ab35e27741f330156be7e4ca6d434eb280ff3`; chain 1 Ronin exploiter FLAGGED, tx `0xf4c0fd3c38cfd4c5a36dfc33c1c9501124af8425f1505445bb916aba4e558a6a`; chain 1 Vitalik NO_FLAGS_FOUND, tx `0x3b42b566939ce5c1082314969a9d5e2e55217d68f3276fc3d2cf416592ac9e30`; chain 56 Vitalik NO_FLAGS_FOUND, tx `0x062ecd65e19ba89f0e51fa3812cd7e23f73a0dd1a9a96c1ad2c2435ecba2b324`.
- glsim live consensus 5/5 twice (leader + 5 validators fetching real
  GoPlus) — see `scripts/glsim_live_result.json` in the repo.

## What this is NOT (say it plainly in the submission if asked)

- Not a full app — no frontend. A frontend would belong under
  Projects, not Intelligent Contracts.
- Not a price oracle and not a liquidity oracle — it checks address
  security flags only; it says nothing about price, depth, or future
  actions by the address owner.
- Not an LLM product — no LLM is called. The GenLayer value is
  independent re-fetching + exact agreement before a shared verdict
  is written.
- Not an update to the Token Safety Oracle — a new standalone
  primitive. It checks addresses, not token contracts. Only the
  consensus pattern was reused.
- Not a credit score. No number, no ranking. NO_FLAGS_FOUND means
  "no flags found at check time", never "proven safe".

## Checklist before submitting

- [x] Contract built, 87 stub + 10 direct tests pass (each run twice
  green, verified by Muse).
- [x] glsim live consensus 5/5, twice, on two fresh servers.
- [x] Anti-E018 design: every TreeMap keyed by str only; sync test
  scans for non-str TreeMap keys.
- [ ] Deploy in GenLayer Studio to stable Studionet; address + deploy
  tx recorded.
- [ ] Live-run in Studio: all verdict branches proven live (FLAGGED
  x2, NO_FLAGS_FOUND x2). CAUTION has no live demo address; do NOT
  claim a live CAUTION run.
- [ ] GitHub repo created by Syarif + added to the Muse GitHub App
  installation; files pushed.
- [ ] Submit via https://portal.genlayer.foundation/submit-contribution
  (Builder → Intelligent Contracts), 1 of the 2 weekly slots.
- [ ] Do NOT claim a point score anywhere in the submission.
  SafeLink IC received 100 Builder points in Season 1; Season 2
  points are awarded more selectively and no score is promised.
- [ ] Watch for the steward verdict; do NOT reuse the repo URL or the
  contract explorer URL as evidence in any other submission
  (duplicate-URL trap).
