#!/usr/bin/env python3
"""Offline checks: TMPDIR=/path/to/scratch python3 -I tools/perf-bench/test_bench.py."""

import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("bench.py")
spec = importlib.util.spec_from_file_location("bench", SCRIPT)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchTests(unittest.TestCase):
    def invoke(self, *args, env=None):
        return subprocess.run(
            ["python3", "-I", str(SCRIPT), "--ward", "/usr/bin/true", *args],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_tmpdir_is_required(self):
        for value in (None, ""):
            env = dict(os.environ)
            env.pop("TMPDIR", None)
            if value is not None:
                env["TMPDIR"] = value
            result = self.invoke(env=env)
            self.assertEqual(result.returncode, 2)
            self.assertIn("TMPDIR must name", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_invalid_repetitions_fail_before_creating_scratch(self):
        with tempfile.TemporaryDirectory() as root:
            env = dict(os.environ, TMPDIR=root)
            for args in (("--reps", "0"), ("--reps", "-1"), ("--add-reps", "-1")):
                result = self.invoke(*args, env=env)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(list(Path(root).iterdir()), [])

    def test_cleanup_handles_readonly_stores_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            outside = root / "outside"
            outside.mkdir()
            marker = outside / "keep"
            marker.write_text("keep")
            marker.chmod(0o444)
            scratch = root / "scratch"
            store = scratch / "objects"
            store.mkdir(parents=True)
            (store / "object").write_text("immutable")
            (store / "object").chmod(0o444)
            (store / "link").symlink_to(outside, target_is_directory=True)
            store.chmod(0o555)
            bench.make_writable_and_remove(scratch)
            self.assertFalse(scratch.exists())
            self.assertEqual(marker.read_text(), "keep")
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o444)

    def test_cleanup_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as scratch:
            error = subprocess.CalledProcessError(1, "chmod")
            with patch.object(bench.subprocess, "run", side_effect=error):
                with self.assertRaises(subprocess.CalledProcessError):
                    bench.make_writable_and_remove(Path(scratch))

    def test_failed_version_probe_still_cleans_up(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.invoke("--ward", "/usr/bin/false", env=dict(os.environ, TMPDIR=root))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_p1_copy_is_hash_pinned_without_changing_the_acceptance_fixture(self):
        source = bench.FIXTURES["P1 proj-poly"][0]
        before = (source / "requirements.txt").read_bytes()
        with tempfile.TemporaryDirectory() as root:
            project = bench.copy_fixture(source, Path(root) / "project")
            pins = (project / "requirements.txt").read_text()
            self.assertIn("six==1.17.0 --hash=sha256:", pins)
            self.assertTrue((project / "package-lock.json").is_file())
        self.assertEqual((source / "requirements.txt").read_bytes(), before)

    def test_medians_use_all_samples_and_convert_seconds_to_milliseconds(self):
        for samples, expected in (([0.009, 0.001, 0.003], 3), ([0.009, 0.001, 0.003, 0.005], 4)):
            with patch.object(bench, "run", side_effect=[(value, 0) for value in samples]):
                self.assertAlmostEqual(
                    bench.median_ms(None, [], None, None, len(samples)), expected
                )

    def test_json_run_cleans_up_and_keeps_progress_off_stdout(self):
        # true stands in for ward so the harness orchestration is exercised
        # without downloading runtimes or resolving packages.
        with tempfile.TemporaryDirectory() as root:
            env = dict(os.environ, TMPDIR=os.path.relpath(root))
            result = self.invoke("--json", "--reps", "2", "--add-reps", "0", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data["reps"], 2)
            self.assertEqual(len(data["rows"]), 20)
            self.assertEqual({row["unit"] for row in data["rows"]}, {"s", "ms"})
            self.assertIn("scratch:", result.stderr)
            self.assertEqual(list(Path(root).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
