#!/usr/bin/env python3
"""Offline trust-boundary controls; never invoke dependency setup or network."""
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

SCRIPT = runpy.run_path(str(Path(__file__).with_name("install-wire-tools.py")))


class WireDependencyTrustTests(unittest.TestCase):
    def test_known_index_and_package_bytes_require_hash_and_size(self):
        # Given a signed-index expectation, when index or package bytes change,
        # then exact digest/size validation must reject them before installation.
        body = b"known package or signed index bytes"
        expected = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        for name in ["Packages.xz", "tshark.deb"]:
            SCRIPT["verify_blob"](body, expected, name)
            with self.assertRaises(RuntimeError):
                SCRIPT["verify_blob"](body[:-1], expected, name)
            with self.assertRaises(RuntimeError):
                SCRIPT["verify_blob"](b"X" + body[1:], expected, name)

    def test_wrong_or_additional_primary_fingerprint_is_rejected(self):
        # Given the exact trust anchor, when a downloaded key has a different
        # primary fingerprint or an additional primary key, then reject it.
        expected = "A2E402B85A4B70CD78D8A3D9D875551314ECA0F0"
        pub = "pub:::::::::\n"
        fpr = "fpr:::::::::" + expected + ":\n"
        SCRIPT["verify_primary_key"](pub + fpr, expected)
        # Signing subkeys do not replace the primary key's trust identity.
        SCRIPT["verify_primary_key"](pub + fpr + "sub:::::::::\n" + "fpr:::::::::OTHER:\n", expected)
        for bad in ["", pub + fpr.replace(expected, "OTHER"), pub + fpr + pub + fpr]:
            with self.assertRaises(RuntimeError):
                SCRIPT["verify_primary_key"](bad, expected)


class WireAPTStagingTests(unittest.TestCase):
    def fixture_package(self, evidence, body=b"known verified synthetic package bytes"):
        name = "tshark_test_amd64.deb"
        (evidence / name).write_bytes(body)
        return {"Filename": "pool/main/w/wireshark/" + name, "Size": str(len(body)),
                "SHA256": hashlib.sha256(body).hexdigest()}

    def test_private_evidence_uses_public_owned_stage_and_cleans_only_it(self):
        # Given private evidence and an unrelated temporary directory, when
        # verified packages are staged, then APT gets public exact copies and
        # cleanup removes only that stage without changing private parents.
        with tempfile.TemporaryDirectory(dir="/tmp") as evidence_name, tempfile.TemporaryDirectory(prefix="kaferry-lab-unrelated-", dir="/tmp") as unrelated_name:
            evidence, unrelated = Path(evidence_name), Path(unrelated_name)
            evidence.chmod(0o700)
            package = self.fixture_package(evidence)
            sentinel = unrelated / "keep"
            sentinel.write_text("unrelated")
            with SCRIPT["verified_apt_stage"](evidence, [package], "m2-staging-test") as specs:
                staged = Path(specs[0])
                directory = staged.parent
                self.assertTrue(directory.name.startswith("kaferry-lab-m2-staging-test-wire-"))
                self.assertNotEqual(directory, evidence)
                self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
                self.assertEqual(staged.stat().st_mode & 0o777, 0o644)
                self.assertEqual(staged.read_bytes(), (evidence / staged.name).read_bytes())
                SCRIPT["verify_apt_stage_path"](directory)
                receipt = json.loads((evidence / "apt-staging.json").read_text())
                self.assertEqual(receipt["run_id"], "m2-staging-test")
                self.assertEqual(receipt["packages"][0]["sha256"], package["SHA256"])
                self.assertFalse(receipt["cleaned"])
            self.assertFalse(directory.exists())
            self.assertTrue(json.loads((evidence / "apt-staging.json").read_text())["cleaned"])
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
            self.assertEqual(sentinel.read_text(), "unrelated")

    def test_failed_install_body_still_cleans_stage_and_retains_receipt(self):
        # Given a verified stage, when the install body fails, then the same
        # error survives and the owned staging directory is removed in finally.
        with tempfile.TemporaryDirectory(dir="/tmp") as evidence_name:
            evidence = Path(evidence_name)
            package = self.fixture_package(evidence)
            with self.assertRaisesRegex(RuntimeError, "synthetic install failure"):
                with SCRIPT["verified_apt_stage"](evidence, [package], "m2-staging-test") as specs:
                    directory = Path(specs[0]).parent
                    raise RuntimeError("synthetic install failure")
            self.assertFalse(directory.exists())
            self.assertTrue(json.loads((evidence / "apt-staging.json").read_text())["cleaned"])

    def test_changed_package_never_reaches_install_and_stage_is_cleaned(self):
        # Given bytes changed after their package pin was selected, when staging
        # begins, then verification rejects them before yielding any APT paths.
        with tempfile.TemporaryDirectory(dir="/tmp") as evidence_name:
            evidence = Path(evidence_name)
            package = self.fixture_package(evidence)
            (evidence / Path(package["Filename"]).name).write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "hash/size mismatch"):
                with SCRIPT["verified_apt_stage"](evidence, [package], "m2-staging-test"):
                    self.fail("unverified package reached the install body")
            receipt = json.loads((evidence / "apt-staging.json").read_text())
            self.assertFalse(Path(receipt["directory"]).exists())
            self.assertTrue(receipt["cleaned"])

    def test_missing_or_invalid_run_identity_is_rejected_before_staging(self):
        # Given no valid fixture run label, when setup requests a stage, then no
        # staging receipt or package path is created.
        with tempfile.TemporaryDirectory(dir="/tmp") as evidence_name:
            evidence = Path(evidence_name)
            for invalid in ["", "abc", "../another-run", "UPPER", "m2-test;command", "m" * 50]:
                with self.assertRaisesRegex(RuntimeError, "LAB_RUN_ID"):
                    with SCRIPT["verified_apt_stage"](evidence, [], invalid):
                        self.fail("invalid ownership reached staging")
                self.assertFalse((evidence / "apt-staging.json").exists())

    def test_actual_private_apt_path_still_fails_traversal_guard(self):
        # Given a private actual APT input directory, when its path is checked,
        # then the original traversal requirement still fails without chmod.
        with tempfile.TemporaryDirectory(dir="/tmp") as directory_name:
            directory = Path(directory_name).resolve()
            directory.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "traversable by _apt"):
                SCRIPT["verify_apt_stage_path"](directory)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
