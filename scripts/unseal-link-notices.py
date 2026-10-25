#!/usr/bin/env python3
"""Offline PRIVATE recovery; trusted API ZIP digest is an external prerequisite.

Caller must obtain it from authenticated GitHub metadata bound to the expected
trusted repository/workflow/run/head/job/attempt/artifact ID. An adjacent self
hash is NOT trusted. CBC supplies no sender authenticity. No network or upload.
"""
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tarfile
import zipfile

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("link_notice_seal", Path(__file__).with_name("seal-link-notices.py"))
s = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s)


def verified_member(artifact, trusted_zip_sha256):
    # Before ZIP parsing AND before all OpenSSL invocations.
    if not isinstance(trusted_zip_sha256, str) or not s.SHA.fullmatch(trusted_zip_sha256):
        raise s.Rejected("externally trusted artifact ZIP SHA256 required")
    body = s.read_regular(artifact, s.MAX_ZIP)
    if s.digest(body) != trusted_zip_sha256:
        raise s.Rejected("artifact ZIP digest mismatch before parsing or decryption")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            members = archive.infolist()
            if len(members) != 1:
                raise s.Rejected("artifact must contain exactly one CMS member")
            entry = members[0]
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if (entry.filename != "notice.cms" or entry.is_dir() or kind not in (0, stat.S_IFREG)
                    or entry.external_attr & 0x10 or entry.flag_bits & 1
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or not 0 < entry.file_size <= s.MAX_CMS or entry.compress_size > s.MAX_CMS):
                raise s.Rejected("artifact CMS member type, name or bound rejected")
            with archive.open(entry) as source:
                cms = source.read(s.MAX_CMS + 1)
            if len(cms) != entry.file_size:
                raise s.Rejected("artifact CMS length rejected")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
        raise s.Rejected("artifact ZIP rejected") from None
    return cms, s.digest(cms)


def unpack(clear, identity):
    if len(clear) > s.MAX_TAR:
        raise s.Rejected("recovered archive bound exceeded")
    prefix = "link-notices/" + identity["run_id"] + "/"
    payloads, manifest = {}, None
    try:
        with tarfile.open(fileobj=io.BytesIO(clear), mode="r:") as archive:
            for number, entry in enumerate(archive):
                if (number > s.MAX_FILES or entry.type != tarfile.REGTYPE or entry.pax_headers
                        or entry.mode != 0o600 or entry.uid != 0 or entry.gid != 0 or entry.mtime != 0
                        or not entry.name.startswith(prefix)):
                    raise s.Rejected("recovered archive member rejected")
                name = entry.name[len(prefix):]
                limit = s.MAX_MANIFEST if name == "MANIFEST.json" else s.MAX_FILE
                if entry.size < 0 or entry.size > limit:
                    raise s.Rejected("recovered member byte bound exceeded")
                if name != "MANIFEST.json" and (not s.safe_relative(name) or name in payloads):
                    raise s.Rejected("recovered member pathname rejected")
                with archive.extractfile(entry) as source:  # memory only; never extractall
                    body = source.read(limit + 1)
                if len(body) != entry.size:
                    raise s.Rejected("recovered member length rejected")
                if name == "MANIFEST.json":
                    if manifest is not None:
                        raise s.Rejected("duplicate inner manifest")
                    manifest = s.parse_json(body)
                else:
                    if sum(map(len, payloads.values())) + len(body) > s.MAX_PAYLOAD:
                        raise s.Rejected("recovered payload bound exceeded")
                    receipt = s.parse_json(body)
                    if not isinstance(receipt, dict) or ("RunID" in receipt and receipt["RunID"] != identity["run_id"]):
                        raise s.Rejected("recovered receipt run rejected")
                    payloads[name] = body
    except tarfile.TarError:
        raise s.Rejected("recovered archive invalid") from None
    if not payloads or manifest is None:
        raise s.Rejected("recovered manifest or receipts missing")
    marker = s.parse_json(payloads.get("PRIVATE.json", b"null"))
    if marker != {"RunID": identity["run_id"], "Classification": "PRIVATE RAW EVIDENCE", "Publication": "withhold pending explicit redaction review"}:
        raise s.Rejected("recovered private marker rejected")
    canonical, expected_manifest = s.pack(payloads, identity)
    # Fixed USTAR byte equality also rejects hidden extensions and trailing data.
    if manifest != expected_manifest or clear != canonical:
        raise s.Rejected("inner manifest identity, hashes or canonical archive rejected")
    return payloads, manifest


def unseal(base, identity, artifact, trusted_zip_sha256, key, cert):
    identity = s.identities(identity["run_id"], identity["source_head"], identity["recipient_sha256"], identity["job"], identity["attempt"])
    destination, error_fd = s.reserve_operation(Path(base) / ".cache/unsealed-link-notices", identity["run_id"])
    action = "verify trusted artifact ZIP bytes and sole CMS member"
    try:
        cms, cms_sha = verified_member(artifact, trusted_zip_sha256)
        action = "read pinned recipient certificate"
        cert_body = s.certificate(cert, identity["recipient_sha256"])
        action = "read private recipient key"
        s.read_regular(key, 16384, private=True)
        action = "write private recipient snapshot"
        s.write_private(destination / "recipient.pem", cert_body)
        action = "decrypt and retain stock command receipt"
        clear = s.openssl(["cms", "-decrypt", "-binary", "-inform", "DER", "-recip", str(destination / "recipient.pem"),
                           "-inkey", str(key)], cms, destination, "unseal", s.MAX_TAR)
        payloads, manifest = unpack(clear, identity)
        action = "persist verified recovered receipts"
        recovered = destination / "receipts"
        recovered.mkdir(mode=0o700)
        for name, body in sorted(payloads.items()):
            path = recovered / name
            for parent in reversed(path.relative_to(recovered).parents):
                if parent == Path("."):
                    continue
                try:
                    (recovered / parent).mkdir(mode=0o700)
                except FileExistsError:
                    pass
            s.write_private(path, body)
        action = "persist verified inner manifest"
        s.write_private(destination / "MANIFEST.json", s.encode(manifest))
        action = "persist complete metadata"
        s.prepare_complete(destination, s.encode(dict(identity, complete=True,
                        trusted_zip_sha256=trusted_zip_sha256, derived_cms_sha256=cms_sha,
                        files=len(payloads), total_bytes=sum(map(len, payloads.values())))))
        owned_fd, error_fd = error_fd, None
        s.close_operation(owned_fd)
        s.publish_complete(destination)
        return payloads
    except (OSError, KeyboardInterrupt, SystemExit) as error:
        if error_fd is None:
            raise s.EvidenceIncomplete("terminal sink unavailable; exact notice unavailable; evidence incomplete; stopped") from None
        s.retain_os_error(error_fd, action, error)
    finally:
        if error_fd is not None:
            owned_fd, error_fd = error_fd, None
            s.close_operation(owned_fd, sys.exc_info()[1])


def main():
    parser = s.arguments(__doc__)
    parser.add_argument("--artifact-zip", type=Path, required=True)
    parser.add_argument("--trusted-artifact-zip-sha256", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args()
    identity = s.identities(args.run_id, args.source_head, args.recipient_sha256, args.job, args.attempt)
    if args.recipient_sha256 != s.CERT_PIN:
        raise s.Rejected("reviewed recipient pin required")
    unseal(Path.cwd(), identity, args.artifact_zip, args.trusted_artifact_zip_sha256,
           args.private_key, Path(__file__).with_name("link-notices-recipient.pem"))
    print("unsealed: verified receipts retained privately")


def cli():
    previous_term = s.signal.signal(s.signal.SIGTERM, s.terminal_signal)
    try:
        main()
        return 0
    except (s.EvidenceIncomplete, KeyboardInterrupt):
        print("unsealing rejected; private evidence incomplete; stopped", file=sys.stderr)
        return 1
    except (s.Rejected, OSError, ValueError):
        print("unsealing rejected; no complete output accepted; stopped", file=sys.stderr)
        return 1
    finally:
        s.signal.signal(s.signal.SIGTERM, previous_term)


if __name__ == "__main__":
    raise SystemExit(cli())
