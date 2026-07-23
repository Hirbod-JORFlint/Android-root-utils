#!/usr/bin/env python3
"""
Keybox Generator for TrickyStore

Takes a valid hardware keybox.xml and produces N ready-to-use copies for
Strong Integrity. Cryptographic material (private keys + certificate chains)
is preserved — that is required for Google attestation to succeed. Each
output gets a unique DeviceID and normalized PEM/XML formatting.

Usage:
  python generate_keyboxes.py keybox.xml
  python generate_keyboxes.py keybox.xml -n 50 -o keyboxes.zip
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import string
import sys
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
except ImportError:
    print("Error: 'cryptography' is required. Install with: pip install cryptography")
    sys.exit(1)


GOOGLE_HW_ROOT_SN = "f92009e853b6b045"  # Google hardware attestation root
AOSP_EC_ROOT_SN = "d8a08c7ddd303ab6"    # AOSP software EC root
AOSP_RSA_ROOT_SN = "a2059ed10e435b57"   # AOSP software RSA root


@dataclass
class KeyMaterial:
    algorithm: str
    private_key_pem: str
    certificates_pem: list[str]


@dataclass
class ParsedKeybox:
    device_id: str
    keys: dict[str, KeyMaterial] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable hash of crypto material (ignores DeviceID)."""
        h = hashlib.sha256()
        for alg in sorted(self.keys):
            km = self.keys[alg]
            h.update(alg.encode())
            h.update(km.private_key_pem.encode())
            for cert in km.certificates_pem:
                h.update(cert.encode())
        return h.hexdigest()[:16]


@dataclass
class ValidationResult:
    ok: bool
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)


def _strip_pem(text: str | None) -> str:
    if not text:
        return ""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return "\n".join(lines)


def _public_key_bytes(key) -> bytes:
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _load_private_key(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def _load_certificate(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def _cert_expiry(cert: x509.Certificate) -> datetime:
    # cryptography >= 42 uses *_utc; older builds use naive datetime attrs.
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is not None:
        return expiry
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _subject_serial(cert: x509.Certificate) -> str:
    """Android attestation roots are identified by subject serialNumber DN."""
    attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)
    if attrs:
        return attrs[0].value.lower()
    return format(cert.serial_number, "x")


def _root_kind(cert: x509.Certificate) -> str:
    sn = _subject_serial(cert)
    if sn == GOOGLE_HW_ROOT_SN:
        return "Google hardware"
    if sn == AOSP_EC_ROOT_SN:
        return "AOSP software (EC)"
    if sn == AOSP_RSA_ROOT_SN:
        return "AOSP software (RSA)"
    return "Unknown"


def _verify_cert_signed_by(child: x509.Certificate, parent: x509.Certificate) -> None:
    pub = parent.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child.signature_hash_algorithm,
        )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    else:
        raise TypeError(f"Unsupported issuer key type: {type(pub)}")


def normalize_private_key_pem(pem: str) -> str:
    """Re-export private key in traditional PEM form TrickyStore expects."""
    key = _load_private_key(pem)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        ).decode()
    if isinstance(key, rsa.RSAPrivateKey):
        return key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        ).decode()
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()


def normalize_certificate_pem(pem: str) -> str:
    cert = _load_certificate(pem)
    return cert.public_bytes(Encoding.PEM).decode()


def generate_device_id(length: int = 16) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "KB-" + "".join(secrets.choice(alphabet) for _ in range(length))


def parse_keybox(path: Path) -> ParsedKeybox:
    tree = ET.parse(path)
    root = tree.getroot()

    if root.tag != "AndroidAttestation":
        raise ValueError(f"Unexpected root element: <{root.tag}>")

    keybox_elem = root.find("Keybox")
    if keybox_elem is None:
        raise ValueError("No <Keybox> element found")

    parsed = ParsedKeybox(device_id=keybox_elem.get("DeviceID", "Unknown"))

    for key_elem in keybox_elem.findall("Key"):
        algorithm = (key_elem.get("algorithm") or "").strip().lower()
        if algorithm not in {"ecdsa", "rsa"}:
            continue

        private_key_pem = _strip_pem(
            key_elem.findtext("PrivateKey")
        )
        chain_elem = key_elem.find("CertificateChain")
        certs: list[str] = []
        if chain_elem is not None:
            for cert_elem in chain_elem.findall("Certificate"):
                pem = _strip_pem(cert_elem.text)
                if pem:
                    certs.append(pem)

        if not private_key_pem or not certs:
            raise ValueError(f"Incomplete {algorithm} key material in keybox")

        parsed.keys[algorithm] = KeyMaterial(
            algorithm=algorithm,
            private_key_pem=normalize_private_key_pem(private_key_pem),
            certificates_pem=[normalize_certificate_pem(c) for c in certs],
        )

    if "ecdsa" not in parsed.keys and "rsa" not in parsed.keys:
        raise ValueError("Keybox must contain at least one of ecdsa/rsa keys")

    return parsed


def validate_keybox(parsed: ParsedKeybox) -> ValidationResult:
    result = ValidationResult(ok=True)
    now = datetime.now(timezone.utc)

    result.info.append(f"Source DeviceID: {parsed.device_id}")
    result.info.append(f"Crypto fingerprint: {parsed.fingerprint}")

    for alg, km in parsed.keys.items():
        try:
            priv = _load_private_key(km.private_key_pem)
            leaf = _load_certificate(km.certificates_pem[0])
        except Exception as exc:
            result.ok = False
            result.errors.append(f"[{alg}] Failed to parse key/cert: {exc}")
            continue

        if _public_key_bytes(priv.public_key()) != _public_key_bytes(leaf.public_key()):
            result.ok = False
            result.errors.append(
                f"[{alg}] Private key does NOT match leaf certificate "
                "(Strong Integrity would fail)"
            )
        else:
            result.info.append(f"[{alg}] Private key matches leaf certificate")

        # Chain signatures
        for i in range(len(km.certificates_pem) - 1):
            child = _load_certificate(km.certificates_pem[i])
            parent = _load_certificate(km.certificates_pem[i + 1])
            try:
                _verify_cert_signed_by(child, parent)
                result.info.append(f"[{alg}] Chain link {i} -> {i + 1} valid")
            except Exception as exc:
                result.ok = False
                result.errors.append(f"[{alg}] Chain link {i} -> {i + 1} invalid: {exc}")

        expiry = _cert_expiry(leaf)
        if expiry <= now:
            result.ok = False
            result.errors.append(f"[{alg}] Leaf certificate expired on {expiry.date()}")
        else:
            result.info.append(f"[{alg}] Leaf valid until {expiry.date()}")

        root = _load_certificate(km.certificates_pem[-1])
        kind = _root_kind(root)
        result.info.append(f"[{alg}] Root: {kind} (SN {_subject_serial(root)})")
        if "AOSP" in kind:
            result.warnings.append(
                f"[{alg}] AOSP software root detected - typically DEVICE only, not Strong"
            )
        elif kind == "Unknown":
            result.warnings.append(
                f"[{alg}] Unknown attestation root - Strong Integrity may fail"
            )

        if len(km.certificates_pem) < 2:
            result.warnings.append(f"[{alg}] Certificate chain is unusually short")

    if "ecdsa" not in parsed.keys:
        result.warnings.append("Missing ECDSA key — some apps prefer EC attestation")
    if "rsa" not in parsed.keys:
        result.warnings.append("Missing RSA key — some apps prefer RSA attestation")

    return result


def build_keybox_xml(device_id: str, keys: dict[str, KeyMaterial]) -> str:
    """Build a TrickyStore-compatible keybox.xml string."""
    # Preserve a stable algorithm order: ecdsa then rsa (common convention).
    ordered = [alg for alg in ("ecdsa", "rsa") if alg in keys]

    lines = [
        '<?xml version="1.0"?>',
        "<AndroidAttestation>",
        "<NumberOfKeyboxes>1</NumberOfKeyboxes>",
        f'<Keybox DeviceID="{_xml_escape(device_id)}">',
    ]

    for alg in ordered:
        km = keys[alg]
        lines.append(f'<Key algorithm="{alg}">')
        lines.append('<PrivateKey format="pem">')
        lines.append(km.private_key_pem.rstrip())
        lines.append("</PrivateKey>")
        lines.append("<CertificateChain>")
        lines.append(f"<NumberOfCertificates>{len(km.certificates_pem)}</NumberOfCertificates>")
        for cert_pem in km.certificates_pem:
            lines.append('<Certificate format="pem">')
            lines.append(cert_pem.rstrip())
            lines.append("</Certificate>")
        lines.append("</CertificateChain>")
        lines.append("</Key>")

    lines.append("</Keybox>")
    lines.append("</AndroidAttestation>")
    lines.append("")  # trailing newline
    return "\n".join(lines)


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def generate_outputs(
    parsed: ParsedKeybox,
    count: int,
    zip_path: Path,
    also_dir: Path | None,
) -> list[str]:
    used_ids: set[str] = set()
    filenames: list[str] = []

    if also_dir is not None:
        also_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(1, count + 1):
            device_id = generate_device_id()
            while device_id in used_ids:
                device_id = generate_device_id()
            used_ids.add(device_id)

            xml_content = build_keybox_xml(device_id, parsed.keys)
            filename = f"keybox_{i:03d}.xml"
            zf.writestr(filename, xml_content)
            filenames.append(filename)

            if also_dir is not None:
                with open(also_dir / filename, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(xml_content)

            if i % 10 == 0 or i == count:
                print(f"  [+] {i}/{count}")

    return filenames


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate N usable TrickyStore keyboxes from a valid hardware keybox.xml. "
            "Private keys and certificate chains are preserved (required for Strong Integrity); "
            "each output gets a unique DeviceID."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to source keybox.xml",
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=50,
        help="Number of keyboxes to generate (default: 50)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("keyboxes.zip"),
        help="Output ZIP path (default: keyboxes.zip)",
    )
    parser.add_argument(
        "--also-dir",
        type=Path,
        default=Path("generated_keyboxes"),
        help="Also write individual XML files to this directory "
             "(default: generated_keyboxes). Use '' to disable.",
    )
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip cryptographic validation of the source keybox",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.count < 1:
        print("Error: --count must be >= 1")
        return 1

    if not args.input.is_file():
        print(f"Error: input file not found: {args.input}")
        return 1

    also_dir: Path | None
    if str(args.also_dir) in {"", "none", "None"}:
        also_dir = None
    else:
        also_dir = args.also_dir

    print(f"[*] Parsing {args.input}")
    try:
        parsed = parse_keybox(args.input)
    except Exception as exc:
        print(f"Error: failed to parse keybox: {exc}")
        return 1

    print(f"[*] Found algorithms: {', '.join(sorted(parsed.keys))}")

    if not args.skip_validate:
        print("[*] Validating cryptographic material...")
        validation = validate_keybox(parsed)
        for line in validation.info:
            print(f"    - {line}")
        for line in validation.warnings:
            print(f"  [!] {line}")
        for line in validation.errors:
            print(f"  [x] {line}")
        if not validation.ok:
            print(
                "\nError: source keybox failed validation. "
                "Refusing to generate broken copies. "
                "Use --skip-validate to override (not recommended)."
            )
            return 1
        print("[+] Source keybox looks usable for Strong Integrity (if unrevoked)")
    else:
        print("[!] Validation skipped")

    print(f"[*] Generating {args.count} keyboxes -> {args.output}")
    generate_outputs(parsed, args.count, args.output, also_dir)

    print(f"\n[+] Done. Wrote {args.count} keyboxes to {args.output.resolve()}")
    if also_dir is not None:
        print(f"[+] Individual files in {also_dir.resolve()}")
    print(
        "[*] Note: outputs share the same attestation keys/certs as the source "
        "(required for Strong). Only DeviceID differs per file."
    )
    print(
        "[*] Revocation is enforced by Google - a revoked source keybox "
        "cannot be made valid by regenerating copies."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
