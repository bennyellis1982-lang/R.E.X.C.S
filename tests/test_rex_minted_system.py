from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools import rex_minted_system as rms


class AmountTests(unittest.TestCase):
    def test_six_decimal_fixed_point(self) -> None:
        self.assertEqual(rms.parse_amount("1"), 1_000_000)
        self.assertEqual(rms.parse_amount("1.2"), 1_200_000)
        self.assertEqual(rms.parse_amount("0.000001"), 1)
        self.assertEqual(rms.format_amount(1), "0.000001")
        self.assertEqual(rms.format_amount(1_000_000), "1.000000")

    def test_rejects_rounding_and_ambiguous_money_formats(self) -> None:
        for value in ("0.0000001", "-1", "+1", "1,000", "$1", "1e6", "01"):
            with self.subTest(value=value):
                with self.assertRaises(rms.MintedSystemError):
                    rms.parse_amount(value)


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        rms.init_state(
            self.state,
            name="REX Minted Unit",
            symbol="REXM",
            issuer="REX-OPERATOR",
            max_supply="2.000000",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mint(self, *, amount: str = "1.000000", key: str = "mint-test-0001"):
        return rms.append_mint(
            self.state,
            amount=amount,
            recipient_id="INV-001",
            idempotency_key=key,
            authorization_ref="AUTH-001",
            authorized_by="OPERATOR-001",
            reason="Approved offline test allocation",
            authorize=True,
        )

    def test_mint_verifies_and_replays_idempotently(self) -> None:
        first_event, first_summary, first_replay = self.mint()
        second_event, second_summary, second_replay = self.mint()

        self.assertFalse(first_replay)
        self.assertTrue(second_replay)
        self.assertEqual(first_event["entry_hash"], second_event["entry_hash"])
        self.assertEqual(first_summary.total_minted, "1.000000")
        self.assertEqual(second_summary.ledger_entry_count, 2)
        self.assertEqual(second_summary.remaining_supply, "1.000000")

    def test_idempotency_key_cannot_be_reused_for_different_payload(self) -> None:
        self.mint()
        with self.assertRaisesRegex(rms.MintedSystemError, "different mint payload"):
            self.mint(amount="0.500000")

    def test_requires_authorization_and_enforces_supply_cap(self) -> None:
        with self.assertRaises(rms.MintedSystemError):
            rms.append_mint(
                self.state,
                amount="1.000000",
                recipient_id="INV-001",
                idempotency_key="mint-test-0002",
                authorization_ref="AUTH-001",
                authorized_by="OPERATOR-001",
                reason="Unapproved request must fail",
                authorize=False,
            )
        self.mint(amount="2.000000", key="mint-test-0003")
        with self.assertRaises(rms.MintedSystemError):
            self.mint(amount="0.000001", key="mint-test-0004")

    def test_tampering_is_detected(self) -> None:
        self.mint()
        ledger_path = self.state / "ledger.jsonl"
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["amount"] = "1.500000"
        lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(rms.MintedSystemError, "hash mismatch"):
            rms.verify_state(self.state)

    def test_rehashed_entry_cannot_switch_policy(self) -> None:
        self.mint()
        ledger_path = self.state / "ledger.jsonl"
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        changed = json.loads(lines[1])
        changed["policy_id"] = "f" * 64
        changed["entry_hash"] = rms.entry_hash(changed)
        lines[1] = rms.canonical_json(changed)
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(rms.MintedSystemError, "policy mismatch"):
            rms.verify_state(self.state)

    def test_policy_tampering_and_reinitialization_are_blocked(self) -> None:
        policy_path = self.state / "policy.json"
        original = policy_path.read_text(encoding="utf-8")
        with self.assertRaisesRegex(rms.MintedSystemError, "never overwrites"):
            rms.init_state(
                self.state,
                name="Replacement",
                symbol="NEW",
                issuer="OTHER-OPERATOR",
                max_supply="999.000000",
            )
        self.assertEqual(policy_path.read_text(encoding="utf-8"), original)

        changed = json.loads(original)
        changed["max_supply"] = "999.000000"
        policy_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(rms.MintedSystemError, "policy hash mismatch"):
            rms.verify_state(self.state)

    def test_investor_pack_is_prepare_only_and_source_controlled(self) -> None:
        self.mint()
        output = self.root / "investor-pack"
        first_read = rms.build_investor_pack(self.state, output)

        rendered = first_read.read_text(encoding="utf-8")
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        allocation = (output / "allocation_register.csv").read_text(encoding="utf-8")
        source_log = (output / "source_log.json").read_text(encoding="utf-8")

        self.assertIn("PREPARE ONLY", rendered)
        self.assertIn("NOT PROVIDED", rendered)
        self.assertIn("1.000000", rendered)
        self.assertIn("................................................................", rendered)
        self.assertIn("asic.gov.au", rendered)
        self.assertIn("austrac.gov.au", rendered)
        self.assertIn("ato.gov.au", rendered)
        self.assertEqual(manifest["status"], "working_draft")
        self.assertEqual(manifest["first_read"]["format"], "html")
        self.assertIn("INV-001,1.000000,1000000,50.0000%", allocation)
        self.assertNotIn(str(self.root), source_log)


if __name__ == "__main__":
    unittest.main()
