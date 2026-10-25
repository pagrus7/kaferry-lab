#!/usr/bin/env python3
"""Offline trust-boundary controls; never invoke dependency setup or network."""
import hashlib
from pathlib import Path
import runpy
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


if __name__ == "__main__":
    unittest.main()
