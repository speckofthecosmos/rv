#!/usr/bin/env python3
"""Package RV, optionally with the signing/profile needed for Touch ID Keychain access.

Two signed paths are supported:

* Developer ID: a Developer ID Application identity plus a macOS Developer ID
  provisioning profile (runs on any Mac; the release path).
* Development: an Apple Development identity plus a macOS App Development
  profile that lists this Mac (runs only on the Macs in the profile; for a
  personal build). The packager checks that this Mac and the signing
  certificate are in the profile before signing, because a mismatch otherwise
  shows up only as the app being killed at launch.

The data protection (Touch ID) Keychain needs `keychain-access-groups`, which
macOS only honours when a provisioning profile authorises it (Apple TN3137).
"""

import argparse
import datetime
import hashlib
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile

UPSTREAM_BUNDLE_ID = "io.github.madeye.rv"


def this_mac_provisioning_udid():
    report = subprocess.check_output(["system_profiler", "SPHardwareDataType"], text=True)
    match = re.search(r"Provisioning UDID:\s*(\S+)", report)
    return match.group(1) if match else None


def identity_sha1(identity):
    """Return the SHA-1 of the code-signing certificate `identity` names (hash or name)."""
    listing = subprocess.check_output(
        ["security", "find-identity", "-v", "-p", "codesigning"], text=True
    )
    matches = []
    for line in listing.splitlines():
        found = re.match(r"\s*\d+\)\s+([0-9A-F]{40})\s+\"(.*)\"", line)
        if found and (identity.upper() == found.group(1) or identity in found.group(2)):
            matches.append(found.group(1))
    if len(matches) != 1:
        raise SystemExit(
            f"--identity {identity!r} must match exactly one valid signing identity "
            f"(matched {len(matches)})"
        )
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default="0.2.0")
    parser.add_argument("--bundle-id", default=UPSTREAM_BUNDLE_ID,
                        help="CFBundleIdentifier; must match the profile's App ID "
                             f"(default {UPSTREAM_BUNDLE_ID})")
    parser.add_argument("--identity",
                        help="Developer ID Application or Apple Development signing identity")
    parser.add_argument("--profile", type=Path,
                        help="Matching macOS Developer ID or App Development provisioning profile")
    args = parser.parse_args()
    if bool(args.identity) != bool(args.profile):
        parser.error("--identity and --profile must be supplied together")
    if not args.binary.is_file():
        parser.error("--binary must name an existing executable")
    if args.output.suffix != ".app" or args.output.exists():
        parser.error("--output must name a new .app bundle")

    bundle_id = args.bundle_id
    entitlements = None
    development = False
    if args.profile:
        profile = plistlib.loads(subprocess.check_output([
            "security", "cms", "-D", "-i", str(args.profile)
        ]))
        allowed = profile["Entitlements"]
        app_id = allowed.get("com.apple.application-identifier")
        if not app_id or "OSX" not in profile.get("Platform", []):
            parser.error("a macOS provisioning profile is required (this one is not for macOS)")
        if app_id.split(".", 1)[1] != bundle_id:
            parser.error(f"the profile is for {app_id}, not {bundle_id}; pass --bundle-id")
        if profile["ExpirationDate"] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
            parser.error("the provisioning profile has expired")
        if profile.get("ProvisionsAllDevices"):
            pass  # Developer ID profile
        elif "ProvisionedDevices" in profile:
            development = True
            udid = this_mac_provisioning_udid()
            if not udid or udid not in profile["ProvisionedDevices"]:
                parser.error("this Mac's Provisioning UDID is not in the development profile")
        else:
            parser.error("a Developer ID or App Development macOS profile is required")
        cert_hashes = {hashlib.sha1(der).hexdigest().upper()
                       for der in profile.get("DeveloperCertificates", [])}
        if identity_sha1(args.identity) not in cert_hashes:
            parser.error("the signing identity's certificate is not in the profile")
        groups = allowed.get("keychain-access-groups", [])
        if not any(app_id == group or (group.endswith(".*") and app_id.startswith(group[:-1])) for group in groups):
            parser.error("the profile does not allow the app's Keychain access group")
        entitlements = {
            "com.apple.application-identifier": app_id,
            "com.apple.developer.team-identifier": allowed["com.apple.developer.team-identifier"],
            "keychain-access-groups": [app_id],
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rv-package-", dir=args.output.parent) as work:
        app = Path(work) / "RV.app"
        contents = app / "Contents"
        (contents / "MacOS").mkdir(parents=True)
        (contents / "Resources").mkdir()
        shutil.copy2(args.binary, contents / "MacOS/rv")
        assets = Path(__file__).resolve().parent.parent / "assets"
        shutil.copy2(assets / "app-icon.icns", contents / "Resources/app-icon.icns")
        info = {
            "CFBundleName": "RV", "CFBundleDisplayName": "RV",
            "CFBundleIdentifier": bundle_id, "CFBundleExecutable": "rv",
            "CFBundleIconFile": "app-icon.icns", "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": args.version, "CFBundleVersion": args.version,
            "LSMinimumSystemVersion": "12.0", "NSHighResolutionCapable": True,
            "NSSupportsAutomaticGraphicsSwitching": True,
        }
        with (contents / "Info.plist").open("wb") as file:
            plistlib.dump(info, file)
        command = ["codesign", "--force", "--sign", args.identity or "-"]
        if entitlements:
            shutil.copy2(args.profile, contents / "embedded.provisionprofile")
            entitlement_file = Path(work) / "entitlements.plist"
            with entitlement_file.open("wb") as file:
                plistlib.dump(entitlements, file)
            # A development build is for this Mac only: no secure timestamp
            # (which contacts Apple), since it is never notarized.
            timestamp = "--timestamp=none" if development else "--timestamp"
            command += ["--options", "runtime", timestamp, "--entitlements", str(entitlement_file)]
        subprocess.run(command + [str(app)], check=True)
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True)
        shutil.move(str(app), args.output)
    print(f"Packaged {args.output}" + (" (development profile)" if development else ""))


if __name__ == "__main__":
    main()
