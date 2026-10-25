#!/usr/bin/env python3
"""Install the frozen standard dissector on a disposable Ubuntu 24.04 CI runner.

The receipt is dependency evidence, never a claim that packet observation works.
No capture privileges or host packet/offload settings are changed here.
"""

from contextlib import contextmanager
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile


BASE = "https://ppa.launchpadcontent.net/wireshark-dev/stable/ubuntu/"
PINS = Path(__file__).with_suffix(".pins.json")


def verify_blob(body, expected, name):
    if len(body) != int(expected["size"]) or hashlib.sha256(body).hexdigest() != expected["sha256"]:
        raise RuntimeError("frozen dependency hash/size mismatch: " + name)


def verify_primary_key(shown, expected):
    primary = []
    want_primary = False
    for line in shown.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            want_primary = True
        elif fields[0] == "fpr" and want_primary:
            primary.append(fields[9])
            want_primary = False
    if primary != [expected]:
        raise RuntimeError("PPA signing key fingerprint mismatch")


def require_run_id(value):
    if not re.fullmatch(r"[a-z][a-z0-9-]{3,48}", value):
        raise RuntimeError("LAB_RUN_ID must match [a-z][a-z0-9-]{3,48}")
    return value


def verify_apt_stage_path(directory):
    # Check only the actual public APT input path. Private evidence/workspace
    # parents do not need to be readable by APT and are never modified.
    for parent in [directory, *directory.parents]:
        if parent.stat().st_mode & 0o001 == 0:
            raise RuntimeError("APT staging parents must be traversable by _apt")


@contextmanager
def verified_apt_stage(evidence, packages, run_id):
    require_run_id(run_id)
    receipt_path = evidence / "apt-staging.json"
    # Reserve the receipt before creating another resource; one installation
    # attempt owns one staging directory and may not replace a prior receipt.
    with receipt_path.open("x") as receipt_file:
        receipt_file.write("{}\n")
    directory = Path(tempfile.mkdtemp(prefix="kaferry-lab-" + run_id + "-wire-", dir="/tmp")).resolve()
    identity = directory.stat()
    receipt = {"schema": 1, "run_id": run_id, "directory": str(directory), "owner_uid": identity.st_uid,
               "device": identity.st_dev, "inode": identity.st_ino, "packages": [], "cleaned": False}
    try:
        # Only this newly reserved directory and its public package files change
        # mode. Do not chmod runner HOME, workspace parents, /tmp or APT settings.
        directory.chmod(0o755)
        verify_apt_stage_path(directory)
        specs = []
        for package in packages:
            name = Path(package["Filename"]).name
            expected = {"size": package["Size"], "sha256": package["SHA256"]}
            # A bounded verified snapshot prevents a changed source from growing
            # an unbounded copy. Verify the destination again before invoking APT.
            with (evidence / name).open("rb") as source:
                body = source.read(int(expected["size"]) + 1)
            verify_blob(body, expected, name)
            destination = directory / name
            with destination.open("xb") as output:
                output.write(body)
            destination.chmod(0o644)
            verify_blob(destination.read_bytes(), expected, name)
            receipt["packages"].append({"path": str(destination), "size": len(body), "sha256": expected["sha256"]})
            specs.append(str(destination))
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        yield specs
    finally:
        # Never glob or delete by a label alone. Clean the one retained inode
        # created above; replacement or missing ownership leaves cleanup failed.
        current = directory.lstat()
        if (current.st_dev, current.st_ino, current.st_uid) != (identity.st_dev, identity.st_ino, identity.st_uid):
            raise RuntimeError("APT staging directory ownership changed; cleanup unconfirmed")
        shutil.rmtree(directory)
        receipt["cleaned"] = True
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: install-wire-tools.py NEW_EVIDENCE_DIRECTORY")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if (platform.system(), platform.machine(), release.get("ID", "").strip('"'), release.get("VERSION_ID", "").strip('"')) != ("Linux", "x86_64", "ubuntu", "24.04") or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("requires a disposable native Ubuntu 24.04 AMD64 GitHub Actions runner")
    run_id = require_run_id(os.environ.get("LAB_RUN_ID", ""))
    pins = json.loads(PINS.read_text())
    root = Path(sys.argv[1]).resolve()
    root.mkdir(mode=0o700)  # reserve private evidence; never mix attempts
    shutil.copyfile(PINS, root / PINS.name)
    (root / "gnupg").mkdir(mode=0o700)
    counter = 0

    def run(argv, *, data=None, timeout=180):
        nonlocal counter
        counter += 1
        prefix = root / f"command-{counter:02d}"
        prefix.with_suffix(".json").write_text(json.dumps(argv) + "\n")
        # subprocess.run kills and reaps a timed-out direct child. Commands here
        # do not invoke background daemons; APT's own lock/budget is also bounded.
        with prefix.with_suffix(".stdout").open("wb") as out, prefix.with_suffix(".stderr").open("wb") as err:
            subprocess.run(argv, input=data, stdout=out, stderr=err, timeout=timeout, check=True)
        return prefix.with_suffix(".stdout").read_bytes()

    def fetch(url, path, expected=None):
        run(["curl", "--proto", "=https", "--tlsv1.2", "--connect-timeout", "10", "--max-time", "90", "--max-filesize", "67108864", "--fail", "--silent", "--show-error", "--output", str(path), url], timeout=100)
        path.chmod(0o644)
        body = path.read_bytes()
        if expected:
            verify_blob(body, expected, path.name)
        return body

    key = root / "signing-key.asc"
    fetch("https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x" + pins["fingerprint"], key)
    gpg = ["gpg", "--batch", "--homedir", str(root / "gnupg")]
    shown = run(gpg + ["--with-colons", "--show-keys", str(key)]).decode()
    verify_primary_key(shown, pins["fingerprint"])
    ring = root / "signing-key.gpg"
    run(gpg + ["--output", str(ring), "--dearmor", str(key)])
    fetch(BASE + "dists/noble/InRelease", root / "InRelease", pins["metadata"]["InRelease"])
    run(["gpgv", "--keyring", str(ring), "--output", str(root / "Release"), str(root / "InRelease")])
    signed = (root / "Release").read_text()
    sha_section = signed.split("SHA256:\n", 1)[1]
    for compressed, plain, index in [("Packages.xz", "Packages", "main/binary-amd64"), ("Sources.xz", "Sources", "main/source")]:
        for name in [compressed, plain]:
            pin = pins["metadata"][name]
            if not any(line.split() == [pin["sha256"], str(pin["size"]), index + "/" + name] for line in sha_section.splitlines()):
                raise RuntimeError("index pin absent from verified Release: " + name)
        data = fetch(BASE + "dists/noble/" + index + "/by-hash/SHA256/" + pins["metadata"][compressed]["sha256"], root / compressed, pins["metadata"][compressed])
        data = lzma.decompress(data)
        (root / plain).write_bytes(data)
        verify_blob(data, pins["metadata"][plain], plain)
    paragraphs = []
    for paragraph in (root / "Packages").read_text().strip().split("\n\n"):
        paragraphs.append(dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" ")))
    for package in pins["packages"]:
        matches = [p for p in paragraphs if all(p.get(k) == v for k, v in package.items())]
        if len(matches) != 1:
            raise RuntimeError("package pin absent/ambiguous in verified index")
        fetch(BASE + package["Filename"], root / Path(package["Filename"]).name, {"size": package["Size"], "sha256": package["SHA256"]})
    # Keep the exact source and distribution patch for later field/schema review;
    # no source is compiled or used as an oracle for Kafka record expectations.
    source = (root / "Sources").read_text()
    for item in pins["source_files"]:
        if not any(line.split() == [item["sha256"], str(item["size"]), item["name"]] for line in source.splitlines()):
            raise RuntimeError("source pin absent from verified Sources")
        fetch(BASE + "pool/main/w/wireshark/" + item["name"], root / item["name"], item)
    original = next(p for p in pins["source_files"] if ".orig." in p["name"])
    with tarfile.open(root / original["name"], "r:bz2") as archive:
        members = [m for m in archive.getmembers() if m.name.endswith("/epan/dissectors/packet-kafka.c") and m.isfile()]
        if len(members) != 1 or members[0].size > 2 << 20:
            raise RuntimeError("unrecognized dissector source member")
        (root / "packet-kafka.c").write_bytes(archive.extractfile(members[0]).read())
    # Install only signed-index/hash-verified local package bytes. Ordinary
    # authenticated Ubuntu sources supply dependencies; no PPA configuration
    # or capture privilege changes are needed.
    with verified_apt_stage(root, pins["packages"], run_id) as specs:
        run(["sudo", "-n", "apt-get", "-o", "DPkg::Lock::Timeout=30", "update"], timeout=240)
        run(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=30", "install", "-y", "--reinstall", "--no-install-recommends", *specs], timeout=300)
    run(["apt-cache", "policy", *[p["Package"] for p in pins["packages"]]])
    installed = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"]).decode()
    for p in pins["packages"]:
        if f'{p["Package"]}\t{p["Version"]}\t{p["Architecture"]}\n' not in installed:
            raise RuntimeError("installed dependency revision mismatch")
    run(["tshark", "--version"])
    run(["tshark", "-G", "fields"])
    run(["tshark", "-G", "currentprefs"])
    tools = {}
    for name in ["tshark", "dumpcap"]:
        path = Path(shutil.which(name)).resolve()
        tools[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    receipt = {"schema": 1, "pins_sha256": hashlib.sha256(PINS.read_bytes()).hexdigest(), "platform": "linux-amd64/ubuntu-24.04", "tools": tools, "version": pins["version"], "capture_capability_measured": False, "produce11_capability_measured": False}
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (root / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in sorted(root.iterdir()) if p.is_file()))


if __name__ == "__main__":
    main()
