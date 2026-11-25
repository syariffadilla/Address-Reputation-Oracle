"""Pure-logic tests: no GenLayer stub needed, plain pytest."""

import json

import pytest

from address_reputation_logic import (
    derive_signals,
    normalize_address,
    render_source_url,
    triggered_flags,
    validate_chain_id,
    verdict_from_signals,
)
from conftest import (
    DEAD,
    FLAGGED_CREATOR,
    RONIN,
    VITALIK,
    bad_count_json,
    caution_json,
    count_only_json,
    empty_result_json,
    flagged_json,
    malformed_flag_json,
    missing_flag_json,
    ronin_json,
    system_error_json,
    vitalik_json,
)


# -- normalize_address ------------------------------------------------------


def test_normalize_address_lowercases_and_accepts():
    assert (
        normalize_address("0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045")
        == VITALIK
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "0x123",
        "d8da6bf26964af9d7eed9e03e53415d37aa96045",
        "0x" + "zz" * 20,
        "0x" + "ab" * 19,
        "0x" + "ab" * 21,
        123,
    ],
)
def test_normalize_address_rejects(bad):
    with pytest.raises(ValueError):
        normalize_address(bad)


# -- validate_chain_id ------------------------------------------------------


def test_validate_chain_id_allowlists():
    assert validate_chain_id(1) == 1
    assert validate_chain_id(56) == 56
    assert validate_chain_id(8453) == 8453


@pytest.mark.parametrize("bad", [0, 137, 42161, -1, "56", 56.0, True, None])
def test_validate_chain_id_rejects(bad):
    with pytest.raises(ValueError):
        validate_chain_id(bad)


# -- render_source_url ------------------------------------------------------


def test_render_source_url():
    assert render_source_url(56, FLAGGED_CREATOR) == (
        "https://api.gopluslabs.io/api/v1/address_security/"
        + FLAGGED_CREATOR
        + "?chain_id=56"
    )
    assert render_source_url(1, VITALIK.upper()) == (
        "https://api.gopluslabs.io/api/v1/address_security/"
        + VITALIK
        + "?chain_id=1"
    )


def test_render_source_url_rejects_bad_chain_and_address():
    with pytest.raises(ValueError):
        render_source_url(137, VITALIK)
    with pytest.raises(ValueError):
        render_source_url(56, "not-an-address")


# -- derive_signals / verdict ---------------------------------------------


def _signals(**overrides):
    base = {
        "chain_id": "56",
        "address": FLAGGED_CREATOR,
        "sanctioned": "0",
        "money_laundering": "0",
        "cybercrime": "0",
        "phishing_activities": "0",
        "stealing_attack": "0",
        "financial_crime": "0",
        "honeypot_related_address": "0",
        "number_of_malicious_contracts_created": "0",
        "mixer": "0",
        "gas_abuse": "0",
        "darkweb_transactions": "0",
        "blacklist_doubt": "0",
        "fake_kyc": "0",
        "fake_standard_interface": "0",
        "fake_token": "0",
        "blackmail_activities": "0",
        "malicious_mining_activities": "0",
        "reinit": "0",
        "status_code": "200",
        "source_url": "https://example.com/",
        "parse_ok": True,
    }
    base.update(overrides)
    return base


def test_verdict_no_flags_shape():
    assert verdict_from_signals(_signals()) == "no_flags_found"


@pytest.mark.parametrize(
    "flag",
    [
        {"sanctioned": "1"},
        {"money_laundering": "1"},
        {"cybercrime": "1"},
        {"phishing_activities": "1"},
        {"stealing_attack": "1"},
        {"financial_crime": "1"},
        {"honeypot_related_address": "1"},
    ],
)
def test_verdict_flagged_single_critical(flag):
    assert verdict_from_signals(_signals(**flag)) == "flagged"


def test_verdict_flagged_count_only():
    assert (
        verdict_from_signals(
            _signals(number_of_malicious_contracts_created="1")
        )
        == "flagged"
    )
    assert (
        verdict_from_signals(
            _signals(number_of_malicious_contracts_created="12")
        )
        == "flagged"
    )
    # Count "0" is not a finding.
    assert verdict_from_signals(_signals()) == "no_flags_found"


def test_verdict_flagged_beats_caution():
    # A critical flag wins even when a contextual flag is also set.
    assert (
        verdict_from_signals(
            _signals(mixer="1", honeypot_related_address="1")
        )
        == "flagged"
    )


@pytest.mark.parametrize(
    "flag",
    [
        {"mixer": "1"},
        {"gas_abuse": "1"},
        {"darkweb_transactions": "1"},
        {"blacklist_doubt": "1"},
        {"fake_kyc": "1"},
        {"fake_standard_interface": "1"},
        {"fake_token": "1"},
        {"blackmail_activities": "1"},
        {"malicious_mining_activities": "1"},
        {"reinit": "1"},
    ],
)
def test_verdict_caution_single_contextual(flag):
    assert verdict_from_signals(_signals(**flag)) == "caution"


def test_verdict_unchecked_when_unparsed():
    assert (
        verdict_from_signals(_signals(parse_ok=False)) == "unchecked"
    )


def test_triggered_flags_lists_all_positive_in_order():
    signals = _signals(
        mixer="1",
        honeypot_related_address="1",
        number_of_malicious_contracts_created="2",
    )
    assert triggered_flags(signals) == [
        "honeypot_related_address",
        "number_of_malicious_contracts_created",
        "mixer",
    ]
    assert triggered_flags(_signals()) == []


def test_derive_flagged_creator():
    signals = derive_signals(
        56,
        FLAGGED_CREATOR,
        "https://api.gopluslabs.io/api/v1/address_security/"
        + FLAGGED_CREATOR
        + "?chain_id=56",
        200,
        flagged_json(),
    )
    assert signals["parse_ok"] is True
    assert signals["chain_id"] == "56"
    assert signals["honeypot_related_address"] == "1"
    assert signals["number_of_malicious_contracts_created"] == "1"
    assert signals["data_source"] == "GoPlus"
    assert signals["triggered_flags"] == (
        "honeypot_related_address,"
        "number_of_malicious_contracts_created"
    )
    assert signals["flag_count"] == 2
    assert verdict_from_signals(signals) == "flagged"


def test_derive_vitalik_no_flags():
    signals = derive_signals(
        1, VITALIK, "https://example.com/", 200, vitalik_json()
    )
    assert signals["parse_ok"] is True
    assert signals["sanctioned"] == "0"
    assert signals["mixer"] == "0"
    assert signals["triggered_flags"] == ""
    assert signals["flag_count"] == 0
    assert verdict_from_signals(signals) == "no_flags_found"


def test_derive_ronin_flagged():
    # CORRECTION 25 Nov 2026: DESIGN.md claimed GoPlus returns all
    # zeros for the Ronin exploiter. That was measured against a
    # typo'd 41-char address. The real address is flagged on three
    # indicators, so the "dataset gap" example in DESIGN.md is wrong
    # and must not be repeated in the README or submission.
    signals = derive_signals(
        1, RONIN, "https://example.com/", 200, ronin_json()
    )
    assert signals["parse_ok"] is True
    assert signals["sanctioned"] == "1"
    assert signals["stealing_attack"] == "1"
    assert signals["blacklist_doubt"] == "1"
    assert signals["data_source"] == "SlowMist,BlockSec"
    assert signals["triggered_flags"] == (
        "sanctioned,stealing_attack,blacklist_doubt"
    )
    assert signals["flag_count"] == 3
    assert verdict_from_signals(signals) == "flagged"


def test_derive_caution_synthetic():
    signals = derive_signals(
        1, VITALIK, "https://example.com/", 200, caution_json()
    )
    assert signals["parse_ok"] is True
    assert signals["mixer"] == "1"
    assert signals["triggered_flags"] == "mixer"
    assert signals["flag_count"] == 1
    assert verdict_from_signals(signals) == "caution"


def test_derive_count_only_flagged():
    signals = derive_signals(
        1, VITALIK, "https://example.com/", 200, count_only_json()
    )
    assert signals["parse_ok"] is True
    assert signals["number_of_malicious_contracts_created"] == "3"
    assert verdict_from_signals(signals) == "flagged"


def test_derive_missing_flag_is_unchecked():
    signals = derive_signals(
        1, VITALIK, "https://example.com/", 200, missing_flag_json()
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_malformed_flag_is_unchecked():
    signals = derive_signals(
        1, VITALIK, "https://example.com/", 200, malformed_flag_json()
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_bad_count_is_unchecked():
    signals = derive_signals(
        1, VITALIK, "https://example.com/", 200, bad_count_json()
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_empty_result_is_unchecked():
    signals = derive_signals(
        56, DEAD, "https://example.com/", 200, empty_result_json()
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_system_error_code_is_unchecked():
    signals = derive_signals(
        56, VITALIK, "https://example.com/", 200, system_error_json()
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_non_200_is_unchecked():
    signals = derive_signals(
        56, VITALIK, "https://example.com/", 404, ""
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_malformed_json_is_unchecked():
    signals = derive_signals(
        56, VITALIK, "https://example.com/", 200, "{not json"
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_result_not_a_dict_is_unchecked():
    signals = derive_signals(
        56,
        VITALIK,
        "https://example.com/",
        200,
        json.dumps({"code": 1, "result": []}),
    )
    assert signals["parse_ok"] is False
    assert verdict_from_signals(signals) == "unchecked"


def test_derive_wrong_code_is_unchecked():
    signals = derive_signals(
        56,
        VITALIK,
        "https://example.com/",
        200,
        json.dumps({"code": 0, "result": {}}),
    )
    assert signals["parse_ok"] is False
