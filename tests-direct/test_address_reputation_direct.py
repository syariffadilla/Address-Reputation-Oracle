"""Direct-mode tests: the REAL Address Reputation Oracle contract
executed by the GenVM direct engine (gltest).

Run from the address-reputation-oracle/ directory with SafeLink's venv
(it already has genlayer-test 0.29.2 + the cached v0.2.16 GenVM
tarball):
    ../../genlayer-intelligent-contracts-submission/safelink/.venv/bin/gltest tests-direct -q

These tests live OUTSIDE tests/ on purpose: plain `pytest` cannot run
them (they need the gltest direct fixtures), and the stub suite in
tests/ cannot run under gltest's direct plugin. See TEST_LOG.md.

Web in gltest direct mode is ALWAYS mocked (unmocked fetches raise
MockNotFoundError — there is no live fallthrough). So every demo uses
REAL GoPlus response bytes, fetched live 25 Nov 2026 by curl and saved
at tests-direct/fixtures/goplus-*.json:
* Fake-USDC creator (BSC) — honeypot_related_address=1 and one
  malicious contract created, FLAGGED.
* Vitalik (Ethereum + BSC) — every flag "0", NO_FLAGS_FOUND.
* Ronin exploiter (Ethereum) — sanctioned=1, stealing_attack=1,
  blacklist_doubt=1, FLAGGED. (DESIGN.md claimed all zeros; that was
  measured against a typo'd 41-char address. Corrected 25 Nov 2026.)
* CAUTION has NO live demo address (four plausible candidates all
  returned all zeros, 25 Nov 2026), so the CAUTION direct test uses a
  synthetic body built from the real Vitalik bytes with mixer flipped
  to "1" — the branch, not the demo, is what it proves.
The contract parses genuine GoPlus data under the real engine.
"""

import json
from pathlib import Path

import pytest

# Pin the GenVM release explicitly: the loader's "latest" resolution
# currently points at v0.3.0-rc7, whose genvm-universal.tar.xz asset
# 404s (see SafeLink TEST_LOG.md). v0.2.16 is the release GrantFlow's
# direct tests pinned in Oct 2026.
SDK_VERSION = "v0.2.16"

HERE = Path(__file__).resolve().parent
CONTRACT = str(HERE.parent / "contracts" / "address_reputation_oracle.py")
FIXTURES = HERE / "fixtures"

FLAGGED_CREATOR = "0xe8e0960da069c336852246a5bedf18ad05ea25e7"
FLAGGED_CREATOR_CHAIN = 56
VITALIK = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
VITALIK_CHAIN = 1
VITALIK_BSC_CHAIN = 56
RONIN = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
RONIN_CHAIN = 1
DEAD = "0x0000000000000000000000000000000000000001"

FLAGGED_BODY = (FIXTURES / "goplus-flagged-56.json").read_text()
VITALIK_BODY = (FIXTURES / "goplus-vitalik-1.json").read_text()
VITALIK_BSC_BODY = (FIXTURES / "goplus-vitalik-56.json").read_text()
RONIN_BODY = (FIXTURES / "goplus-ronin-1.json").read_text()


def _deploy(direct_deploy):
    return direct_deploy(CONTRACT, sdk_version=SDK_VERSION)


def _mock_goplus(direct_vm, body):
    direct_vm.mock_web(
        r"api\.gopluslabs\.io",
        {"method": "GET", "status": 200, "body": body},
    )


def test_deploy_defaults(direct_deploy, direct_owner):
    oracle = _deploy(direct_deploy)
    stats = oracle.get_stats()
    assert stats["total_entries"] == 0
    assert stats["check_count"] == 0
    assert stats["flagged"] == 0
    assert stats["caution"] == 0
    assert stats["no_flags_found"] == 0
    assert stats["ttl_checks"] == 1000
    assert stats["admin"].lower() == "0x" + direct_owner.hex()
    assert oracle.list_chains()["chains"] == [1, 56, 8453]


def test_vitalik_real_body_no_flags_and_validator_agrees(
    direct_deploy, direct_vm
):
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, VITALIK_BODY)
    result = oracle.check_address(VITALIK_CHAIN, VITALIK)
    assert result["verdict"] == "no_flags_found"
    assert result["triggered_flags"] == ""
    assert result["flag_count"] == 0
    assert result["status_code"] == 200
    assert direct_vm.run_validator() is True
    assert oracle.get_stats()["no_flags_found"] == 1
    assert oracle.is_safe(VITALIK_CHAIN, VITALIK) is True


def test_vitalik_bsc_real_body_no_flags(direct_deploy, direct_vm):
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, VITALIK_BSC_BODY)
    result = oracle.check_address(VITALIK_BSC_CHAIN, VITALIK)
    assert result["verdict"] == "no_flags_found"
    assert direct_vm.run_validator() is True


def test_flagged_real_body_flagged_and_validator_agrees(
    direct_deploy, direct_vm
):
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, FLAGGED_BODY)
    result = oracle.check_address(FLAGGED_CREATOR_CHAIN, FLAGGED_CREATOR)
    assert result["verdict"] == "flagged"
    assert result["honeypot_related_address"] == "1"
    assert result["number_of_malicious_contracts_created"] == "1"
    assert result["triggered_flags"] == (
        "honeypot_related_address,"
        "number_of_malicious_contracts_created"
    )
    assert result["flag_count"] == 2
    assert direct_vm.run_validator() is True
    assert oracle.get_stats()["flagged"] == 1
    assert oracle.is_safe(FLAGGED_CREATOR_CHAIN, FLAGGED_CREATOR) is False


def test_ronin_real_body_flagged(direct_deploy, direct_vm):
    # CORRECTION 25 Nov 2026: the real Ronin exploiter address IS
    # flagged by GoPlus (sanctioned + stealing_attack + blacklist_doubt).
    # DESIGN.md's all-zeros claim came from a typo'd 41-char address.
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, RONIN_BODY)
    result = oracle.check_address(RONIN_CHAIN, RONIN)
    assert result["verdict"] == "flagged"
    assert result["sanctioned"] == "1"
    assert result["stealing_attack"] == "1"
    assert result["blacklist_doubt"] == "1"
    assert result["triggered_flags"] == (
        "sanctioned,stealing_attack,blacklist_doubt"
    )
    assert direct_vm.run_validator() is True
    assert oracle.get_stats()["flagged"] == 1


def test_caution_synthetic_body_and_validator_agrees(
    direct_deploy, direct_vm
):
    # No live CAUTION demo exists (see module docstring). The body is
    # the real Vitalik record with exactly one field changed.
    caution = json.loads(VITALIK_BODY)
    caution["result"]["mixer"] = "1"
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, json.dumps(caution))
    result = oracle.check_address(VITALIK_CHAIN, VITALIK)
    assert result["verdict"] == "caution"
    assert result["mixer"] == "1"
    assert result["triggered_flags"] == "mixer"
    assert direct_vm.run_validator() is True
    assert oracle.get_stats()["caution"] == 1


def test_missing_flag_writes_nothing(direct_deploy, direct_vm):
    broken = json.loads(VITALIK_BODY)
    del broken["result"]["mixer"]
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, json.dumps(broken))
    with pytest.raises(Exception):
        oracle.check_address(VITALIK_CHAIN, VITALIK)
    assert oracle.get_stats()["total_entries"] == 0
    assert oracle.get_stats()["check_count"] == 0
    assert oracle.get_verdict(VITALIK_CHAIN, VITALIK)["verdict"] == "unchecked"


def test_validator_disagrees_when_body_changes(direct_deploy, direct_vm):
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, VITALIK_BODY)
    result = oracle.check_address(VITALIK_CHAIN, VITALIK)
    assert result["verdict"] == "no_flags_found"
    # The validator re-fetches and now sees the same address with one
    # flag flipped (mixer) — the record still parses, but the signals
    # disagree.
    flipped = json.loads(VITALIK_BODY)
    flipped["result"]["mixer"] = "1"
    direct_vm.clear_mocks()
    _mock_goplus(direct_vm, json.dumps(flipped))
    assert direct_vm.run_validator() is False


def test_fetch_failure_writes_nothing(direct_deploy, direct_vm):
    oracle = _deploy(direct_deploy)
    direct_vm.mock_web(
        r"api\.gopluslabs\.io",
        {"method": "GET", "status": 404, "body": "not found"},
    )
    with pytest.raises(Exception):
        oracle.check_address(VITALIK_CHAIN, VITALIK)
    assert oracle.get_stats()["total_entries"] == 0
    assert oracle.get_stats()["check_count"] == 0


def test_unknown_chain_rejected(direct_deploy, direct_vm):
    oracle = _deploy(direct_deploy)
    _mock_goplus(direct_vm, VITALIK_BODY)
    with pytest.raises(Exception):
        oracle.check_address(137, VITALIK)
