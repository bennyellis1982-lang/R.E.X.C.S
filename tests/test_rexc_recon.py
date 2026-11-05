import json
import tempfile
import unittest
from pathlib import Path

from rexc_recon import run


class RexReconTests(unittest.TestCase):
    def test_baseline_detects_modification_and_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            output = root / "output"
            evidence.mkdir()
            first = evidence / "first.txt"
            second = evidence / "second.txt"
            first.write_text("original", encoding="utf-8")
            second.write_text("preserve", encoding="utf-8")
            baseline = root / "baseline.json"

            self.assertEqual(run([
                str(evidence), "--output-dir", str(output),
                "--baseline", str(baseline), "--update-baseline",
            ]), 0)
            first.write_text("changed", encoding="utf-8")
            second.unlink()
            self.assertEqual(run([
                str(evidence), "--output-dir", str(output),
                "--baseline", str(baseline), "--fail-on-drift",
            ]), 2)
            summaries = sorted(output.glob("*.summary.json"))
            summary = json.loads(summaries[-1].read_text(encoding="utf-8"))
            self.assertEqual(summary["status_counts"]["modified_since_baseline"], 1)
            self.assertEqual(summary["missing_since_baseline"], ["second.txt"])

    def test_pattern_and_content_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            output = root / "output"
            evidence.mkdir()
            (evidence / "keep.log").write_text("three_and_six", encoding="utf-8")
            (evidence / "ignore.txt").write_text("three_and_six", encoding="utf-8")
            explicit = root / "records.jsonl"
            self.assertEqual(run([
                str(evidence), "--pattern", r"\.log$", "--content", "three_and_six",
                "--output", str(explicit), "--output-dir", str(output),
            ]), 0)
            records = [json.loads(line) for line in explicit.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertTrue(records[0]["content_match"])

    def test_nested_output_tree_is_not_reingested(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            output = evidence / "recon-output"
            (evidence / "source.txt").write_text("source", encoding="utf-8")
            output.mkdir()
            (output / "old.jsonl").write_text("generated", encoding="utf-8")
            explicit = evidence.parent / f"{evidence.name}-records.jsonl"
            self.assertEqual(run([
                str(evidence), "--output", str(explicit),
                "--output-dir", str(output),
            ]), 0)
            records = [json.loads(line) for line in explicit.read_text().splitlines()]
            self.assertEqual([record["relative_path"] for record in records], ["source.txt"])


if __name__ == "__main__":
    unittest.main()
