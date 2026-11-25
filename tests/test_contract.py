"""Contract end-to-end tests with the fake genlayer stub (conftest.py)."""

import json

import pytest

from conftest import (
    ADMIN,
    DEAD,
    FLAGGED_CREATOR,
    FLAGGED_CREATOR_CHAIN,
    OTHER,
    RONIN,
    RONIN_CHAIN,
    VITALIK,
    VITALIK_BSC_CHAIN,
    VITALIK_CHAIN,
    WEB_CALLS,
    WEB_RESPONSES,
    bad_count_json,
    caution_json,
    count_only_json,
    empty_result_json,
    flagged_json,
    goplus_url,
    load_contract,
    malformed_flag_json,
    missing_flag_json,
    reset_web,
    ronin_json,
    set_sender,
    system_error_json,
    vitalik_json,
)


@pytest.fixture
def oracle():
    reset_web()
    module, fake = load_contract()
    contract = module.AddressReputationOracle()
    set_sender(fake, ADMIN)
    return contract, fake


def _seed(contract, chain, address, body):
    WEB_RESPONSES[goplus_url(chain, address)] = (200, body)


# -- admin: chains ----------------------------------------------------------


def test_deploy_defaults(oracle):
    contract, _ = oracle
    stats = contract.get_stats()
    assert stats["total_entries"] == 0
    assert stats["check_count"] == 0
    assert stats["flagged"] == 0
    assert stats["caution"] == 0
    assert stats["no_flags_found"] == 0
    assert stats["ttl_checks"] == 1000
    assert contract.list_chains()["chains"] == [1, 56, 8453]


def test_add_and_remove_chain(oracle):
    contract, _ = oracle
    contract.add_chain(137)
    assert 137 in contract.list_chains()["chains"]
    contract.remove_chain(137)
    assert 137 not in contract.list_chains()["chains"]
    with pytest.raises(Exception):
        contract.check_address(137, VITALIK)


def test_add_chain_duplicate_and_bad_rejected(oracle):
    contract, _ = oracle
    with pytest.raises(Exception):
        contract.add_chain(56)
    with pytest.raises(Exception):
        contract.add_chain(0)
    with pytest.raises(Exception):
        contract.remove_chain(137)


def test_admin_guards(oracle):
    contract, fake = oracle
    set_sender(fake, OTHER)
    with pytest.raises(fake.UserError):
        contract.add_chain(137)
    with pytest.raises(fake.UserError):
        contract.remove_chain(56)
    with pytest.raises(fake.UserError):
        contract.set_ttl_checks(10)


def test_set_ttl_checks(oracle):
    contract, _ = oracle
    assert contract.set_ttl_checks(5) == {"ttl_checks": 5}
    with pytest.raises(Exception):
        contract.set_ttl_checks(0)


# -- checking: NO_FLAGS_FOUND -----------------------------------------------


def test_check_vitalik_no_flags(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, vitalik_json())
    result = contract.check_address(VITALIK_CHAIN, VITALIK)
    assert result["verdict"] == "no_flags_found"
    assert result["triggered_flags"] == ""
    assert result["flag_count"] == 0
    assert result["cached"] is False
    assert goplus_url(VITALIK_CHAIN, VITALIK) in WEB_CALLS
    # is_safe means "no flags found at check time", not "proven safe".
    assert contract.is_safe(VITALIK_CHAIN, VITALIK) is True


def test_check_vitalik_bsc_no_flags(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_BSC_CHAIN, VITALIK, vitalik_json())
    result = contract.check_address(VITALIK_BSC_CHAIN, VITALIK)
    assert result["verdict"] == "no_flags_found"


def test_check_uppercase_address_normalized(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, vitalik_json())
    result = contract.check_address(VITALIK_CHAIN, VITALIK.upper())
    assert result["address"] == VITALIK
    assert result["verdict"] == "no_flags_found"


def test_check_bad_address_and_chain_rejected(oracle):
    contract, _ = oracle
    with pytest.raises(Exception):
        contract.check_address(56, "not-an-address")
    with pytest.raises(Exception):
        contract.check_address(137, VITALIK)


# -- checking: FLAGGED / CAUTION --------------------------------------------


def test_check_flagged_creator(oracle):
    contract, _ = oracle
    _seed(contract, FLAGGED_CREATOR_CHAIN, FLAGGED_CREATOR, flagged_json())
    result = contract.check_address(FLAGGED_CREATOR_CHAIN, FLAGGED_CREATOR)
    assert result["verdict"] == "flagged"
    assert result["honeypot_related_address"] == "1"
    assert result["number_of_malicious_contracts_created"] == "1"
    assert result["triggered_flags"] == (
        "honeypot_related_address,"
        "number_of_malicious_contracts_created"
    )
    assert result["flag_count"] == 2
    assert result["data_source"] == "GoPlus"
    assert contract.is_safe(FLAGGED_CREATOR_CHAIN, FLAGGED_CREATOR) is False


def test_check_caution_synthetic(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, caution_json())
    result = contract.check_address(VITALIK_CHAIN, VITALIK)
    assert result["verdict"] == "caution"
    assert result["mixer"] == "1"
    assert result["triggered_flags"] == "mixer"
    assert contract.is_safe(VITALIK_CHAIN, VITALIK) is False


def test_check_count_only_flagged(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, count_only_json())
    result = contract.check_address(VITALIK_CHAIN, VITALIK)
    assert result["verdict"] == "flagged"
    assert result["number_of_malicious_contracts_created"] == "3"


def test_check_ronin_flagged(oracle):
    # Second live FLAGGED demo: the real Ronin exploiter address is
    # sanctioned + stealing_attack + blacklist_doubt in GoPlus.
    # (DESIGN.md's all-zeros claim was measured against a typo'd
    # 41-char address and is wrong — see conftest.)
    contract, _ = oracle
    _seed(contract, RONIN_CHAIN, RONIN, ronin_json())
    result = contract.check_address(RONIN_CHAIN, RONIN)
    assert result["verdict"] == "flagged"
    assert result["sanctioned"] == "1"
    assert result["stealing_attack"] == "1"
    assert result["blacklist_doubt"] == "1"
    assert result["triggered_flags"] == (
        "sanctioned,stealing_attack,blacklist_doubt"
    )
    assert result["flag_count"] == 3
    assert result["data_source"] == "SlowMist,BlockSec"
    assert contract.is_safe(RONIN_CHAIN, RONIN) is False


# -- caching, disputes, failures --------------------------------------------


def test_fresh_entry_is_cached_no_refetch(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, vitalik_json())
    contract.check_address(VITALIK_CHAIN, VITALIK)
    calls_before = len(WEB_CALLS)
    result = contract.check_address(VITALIK_CHAIN, VITALIK)
    assert result["cached"] is True
    assert len(WEB_CALLS) == calls_before


def test_dispute_forces_recheck(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, vitalik_json())
    contract.check_address(VITALIK_CHAIN, VITALIK)
    disputed = contract.dispute_address(VITALIK_CHAIN, VITALIK, "wrong verdict?")
    assert disputed["disputed"] is True
    assert disputed["disputes"] == 1
    calls_before = len(WEB_CALLS)
    result = contract.check_address(VITALIK_CHAIN, VITALIK)
    assert result["cached"] is False
    assert len(WEB_CALLS) > calls_before


def test_request_recheck_marks_disputed(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, vitalik_json())
    contract.check_address(VITALIK_CHAIN, VITALIK)
    result = contract.request_recheck(VITALIK_CHAIN, VITALIK)
    assert result["disputed"] is True
    assert result["last_dispute_reason"] == "recheck requested"


def test_dispute_unknown_check_rejected(oracle):
    contract, _ = oracle
    with pytest.raises(Exception):
        contract.dispute_address(VITALIK_CHAIN, VITALIK, "nothing here")


def test_empty_result_writes_nothing(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, DEAD, empty_result_json())
    with pytest.raises(Exception):
        contract.check_address(VITALIK_CHAIN, DEAD)
    view = contract.get_verdict(VITALIK_CHAIN, DEAD)
    assert view["verdict"] == "unchecked"
    assert contract.get_stats()["check_count"] == 0


def test_system_error_code_writes_nothing(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, system_error_json())
    with pytest.raises(Exception):
        contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["check_count"] == 0


def test_fetch_404_writes_nothing(oracle):
    contract, _ = oracle
    WEB_RESPONSES[goplus_url(VITALIK_CHAIN, VITALIK)] = (404, "not found")
    with pytest.raises(Exception):
        contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["check_count"] == 0


def test_unparseable_body_writes_nothing(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, "{not json")
    with pytest.raises(Exception):
        contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["check_count"] == 0


def test_missing_flag_writes_nothing(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, missing_flag_json())
    with pytest.raises(Exception):
        contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["check_count"] == 0


def test_malformed_flag_writes_nothing(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, malformed_flag_json())
    with pytest.raises(Exception):
        contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["check_count"] == 0


def test_bad_count_writes_nothing(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, bad_count_json())
    with pytest.raises(Exception):
        contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["check_count"] == 0


def test_validator_disagreement_writes_nothing(oracle):
    contract, _ = oracle
    # Leader sees the clean Vitalik record; the validator's re-fetch
    # sees the same address with one flag flipped (mixer) — the record
    # still parses, but the signals disagree, so nothing is written.
    vitalik_caution = json.loads(vitalik_json())
    vitalik_caution["result"]["mixer"] = "1"
    WEB_RESPONSES[goplus_url(VITALIK_CHAIN, VITALIK)] = [
        (200, vitalik_json()),
        (200, json.dumps(vitalik_caution)),
    ]
    with pytest.raises(RuntimeError):
        contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["check_count"] == 0
    assert contract.get_verdict(VITALIK_CHAIN, VITALIK)["verdict"] == "unchecked"


# -- views / stats ----------------------------------------------------------


def test_stats_counters_and_list_entries(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, vitalik_json())
    _seed(contract, FLAGGED_CREATOR_CHAIN, FLAGGED_CREATOR, flagged_json())
    assert contract.is_safe(VITALIK_CHAIN, VITALIK) is False
    contract.check_address(VITALIK_CHAIN, VITALIK)
    contract.check_address(FLAGGED_CREATOR_CHAIN, FLAGGED_CREATOR)
    assert contract.is_safe(VITALIK_CHAIN, VITALIK) is True
    stats = contract.get_stats()
    assert stats["no_flags_found"] == 1
    assert stats["flagged"] == 1
    assert stats["caution"] == 0
    assert stats["check_count"] == 2
    entries = contract.list_entries(0, 10)
    assert entries["total"] == 2
    # Newest first.
    assert entries["entries"][0]["address"] == FLAGGED_CREATOR
    assert entries["entries"][1]["address"] == VITALIK


def test_recheck_updates_counters(oracle):
    contract, _ = oracle
    _seed(contract, VITALIK_CHAIN, VITALIK, vitalik_json())
    contract.check_address(VITALIK_CHAIN, VITALIK)
    assert contract.get_stats()["no_flags_found"] == 1
    contract.dispute_address(VITALIK_CHAIN, VITALIK, "recheck")
    # The validator now sees the same address with a CAUTION flag.
    WEB_RESPONSES[goplus_url(VITALIK_CHAIN, VITALIK)] = (
        200,
        caution_json(),
    )
    result = contract.check_address(VITALIK_CHAIN, VITALIK)
    assert result["verdict"] == "caution"
    stats = contract.get_stats()
    assert stats["no_flags_found"] == 0
    assert stats["caution"] == 1
    assert stats["check_count"] == 2
