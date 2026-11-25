"""Sync guard: the pure functions in contracts/address_reputation_oracle.py
must stay byte-identical (AST-identical) to
contracts/address_reputation_logic.py.

The contract is self-contained because a single-file GenLayer contract
cannot import a sibling module on-chain, so the logic is duplicated.
If this test fails, copy the changed function from
address_reputation_logic.py into address_reputation_oracle.py (or vice
versa) and re-run.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOGIC = ROOT / "contracts" / "address_reputation_logic.py"
CONTRACT = ROOT / "contracts" / "address_reputation_oracle.py"

PURE_FUNCTIONS = [
    "normalize_address",
    "validate_chain_id",
    "render_source_url",
    "_parse_count",
    "_flag_value",
    "_flags_well_formed",
    "derive_signals",
    "triggered_flags",
    "verdict_from_signals",
]


def _functions(path):
    tree = ast.parse(path.read_text())
    return {
        node.name: ast.dump(node)
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def test_pure_functions_in_sync():
    logic_fns = _functions(LOGIC)
    contract_fns = _functions(CONTRACT)
    for name in PURE_FUNCTIONS:
        assert name in logic_fns, f"{name} missing from address_reputation_logic.py"
        assert (
            name in contract_fns
        ), f"{name} missing from address_reputation_oracle.py"
        assert logic_fns[name] == contract_fns[name], (
            f"{name} drifted between address_reputation_logic.py and "
            "address_reputation_oracle.py — copy the change across and re-run"
        )


def test_contract_header_pins_stable_runner():
    first_line = CONTRACT.read_text().splitlines()[0]
    assert first_line == (
        '# { "Depends": "py-genlayer:'
        "1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6"
        '" }'
    )
    assert "py-genlayer:test" not in CONTRACT.read_text()
    assert "py-genlayer:latest" not in CONTRACT.read_text()


def test_no_llm_calls_in_contract():
    text = CONTRACT.read_text()
    assert "exec_prompt" not in text
    assert "nondet.llm" not in text


def test_no_bare_gl_user_error():
    # 15 Nov 2026 (Oracle): gl.UserError does not exist in SDK
    # v0.2.5/v0.2.16 — it lives in genlayer.gl.vm only. The contract
    # must import UserError from there, never use gl.UserError.
    text = CONTRACT.read_text()
    assert "gl.UserError" not in text
    assert "from genlayer.gl.vm import UserError" in text


def test_no_int_treemap_keys():
    # The Token Safety Oracle v1 submission was REJECTED with E018
    # because its chains map used u64 as a TreeMap key. Every TreeMap
    # in this contract must be keyed by str. This test scans the
    # storage annotations for any int-typed TreeMap key.
    import re

    text = CONTRACT.read_text()
    for match in re.finditer(r"TreeMap\[([^\]]+)\]", text):
        key_type = match.group(1).split(",")[0].strip()
        assert key_type == "str", (
            f"TreeMap key type {key_type!r} is not str — "
            "GenVM lint (E018) rejects non-str TreeMap keys"
        )
