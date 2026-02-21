#!/usr/bin/env python3

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET

ALLOWED_PROVIDERS = {"proton", "airvpn", "mullvad", "ivpn"}
LEGACY_KEYS = {"provider", "enc", "iv"}


def run_adb(serial: str, package: str) -> str:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(
        [
            "exec-out",
            "run-as",
            package,
            "sh",
            "-c",
            "if [ -f shared_prefs/tunmux_secure.xml ]; then cat shared_prefs/tunmux_secure.xml; fi",
        ]
    )
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or "unknown adb error"
        raise RuntimeError(f"failed to read tunmux_secure.xml: {stderr}")
    stdout = proc.stdout or ""
    stderr = proc.stderr.strip()
    lowered = stdout.lower()
    if lowered.startswith("run-as:") or lowered.startswith("cat:"):
        raise RuntimeError(stdout.strip())
    if stderr:
        lowered_err = stderr.lower()
        if "run-as" in lowered_err or "permission denied" in lowered_err:
            raise RuntimeError(stderr)
    return proc.stdout


def parse_keys(xml_text: str) -> set[str]:
    xml_body = extract_xml_body(xml_text)
    if not xml_body:
        return set()
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError as exc:
        preview = single_line_preview(xml_text)
        raise RuntimeError(
            f"invalid shared_prefs xml: {exc}; output={preview}"
        ) from exc

    keys = set()
    for child in root:
        name = child.attrib.get("name", "").strip()
        if name:
            keys.add(name)
    return keys


def ensure_no_legacy(keys: set[str]) -> None:
    present = sorted(k for k in keys if k in LEGACY_KEYS)
    if present:
        raise RuntimeError(f"legacy keys present: {', '.join(present)}")


def ensure_shape(keys: set[str]) -> None:
    for key in sorted(keys):
        if key.startswith("enc_") or key.startswith("iv_"):
            provider = key.split("_", 1)[1]
            if provider not in ALLOWED_PROVIDERS:
                raise RuntimeError(f"unknown provider key suffix: {key}")
            continue
        raise RuntimeError(f"unexpected key format: {key}")


def has_provider_pair(keys: set[str], provider: str) -> bool:
    return f"enc_{provider}" in keys and f"iv_{provider}" in keys


def extract_xml_body(raw: str) -> str:
    text = raw.strip()
    if not text:
        return ""
    start = text.find("<?xml")
    if start == -1:
        start = text.find("<map")
    if start == -1:
        raise RuntimeError(
            "device output is not XML; this usually means run-as failed or app is not debuggable"
        )
    candidate = text[start:]
    end = candidate.rfind(">")
    if end == -1:
        raise RuntimeError("device output is truncated (missing XML end)")
    return candidate[: end + 1]


def single_line_preview(text: str) -> str:
    compact = " ".join(text.strip().split())
    if len(compact) > 160:
        return compact[:157] + "..."
    return compact or "<empty>"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Android keystore shared-pref key layout"
    )
    parser.add_argument("--package", default="net.tunmux", help="Android package name")
    parser.add_argument("--serial", default="", help="adb device serial")
    parser.add_argument(
        "--expect-provider",
        action="append",
        default=[],
        help="Provider expected to have both enc_ and iv_ keys",
    )
    parser.add_argument(
        "--expect-absent",
        action="append",
        default=[],
        help="Provider expected to have no enc_/iv_ keys",
    )
    args = parser.parse_args()

    for name in args.expect_provider + args.expect_absent:
        if name not in ALLOWED_PROVIDERS:
            print(
                f"invalid provider '{name}', allowed: {', '.join(sorted(ALLOWED_PROVIDERS))}",
                file=sys.stderr,
            )
            return 2

    try:
        xml_text = run_adb(args.serial, args.package)
        keys = parse_keys(xml_text)
        ensure_no_legacy(keys)
        if keys:
            ensure_shape(keys)

        for provider in args.expect_provider:
            if not has_provider_pair(keys, provider):
                raise RuntimeError(f"missing provider keys for {provider}")

        for provider in args.expect_absent:
            if f"enc_{provider}" in keys or f"iv_{provider}" in keys:
                raise RuntimeError(f"provider keys unexpectedly present for {provider}")

        print("PASS")
        if keys:
            print("keys:", ", ".join(sorted(keys)))
        else:
            print("keys: <none>")
        return 0
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
