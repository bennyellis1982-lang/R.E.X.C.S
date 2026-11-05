import json
import tempfile
import unittest
from pathlib import Path

from tools.rexfort_black import (
    activate,
    canonical_bytes,
    sha256_bytes,
    validate_source,
    verify,
)


SOURCE = Path("docs/records/REXFORT_BLACK_CROSS_KEY.json")


class RexfortBlackTests(unittest.TestCase):
    def test_activate_and_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            source_copy = directory_path / "source.json"
            source_copy.write_bytes(SOURCE.read_bytes())
            packet_path = directory_path / "activation.json"
            packet = activate(source_copy, packet_path)
            self.assertEqual(packet["status"], "ACTIVE_LOCAL_POLICY")
            self.assertTrue(packet["controls"]["deny_secret_answer_recording"])
            self.assertEqual(packet["source_record"]["path"], "source.json")
            self.assertEqual(verify(packet_path), (True, []))

    def test_tampering_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            packet_path = Path(directory) / "activation.json"
            activate(SOURCE, packet_path)
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            packet["status"] = "DISABLED"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            valid, errors = verify(packet_path)
            self.assertFalse(valid)
            self.assertIn("packet SHA-256 mismatch", errors)

    def test_secret_answer_fields_are_rejected(self):
        source = json.loads(SOURCE.read_text(encoding="utf-8"))
        source["answers"] = ["must never be persisted"]
        with self.assertRaisesRegex(ValueError, "forbidden challenge-answer fields"):
            validate_source(source)

    def test_malformed_packet_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            packet_path = Path(directory) / "activation.json"
            packet_path.write_text("not json", encoding="utf-8")
            valid, errors = verify(packet_path)
            self.assertFalse(valid)
            self.assertIn("activation packet unreadable", errors[0])

    def test_source_override_supports_separate_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            packet_path = directory_path / "activation.json"
            activate(SOURCE, packet_path)
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            packet["source_record"]["path"] = "missing.json"
            unsigned = dict(packet)
            unsigned.pop("packet_sha256")
            packet["packet_sha256"] = sha256_bytes(canonical_bytes(unsigned))
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            self.assertEqual(verify(packet_path, SOURCE), (True, []))


if __name__ == "__main__":
    unittest.main()
