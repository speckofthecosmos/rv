#!/bin/sh
# Build RV and the Keychain round-trip check, signed with an Apple Development
# identity and a macOS App Development provisioning profile, so a personal
# build can use the Touch ID (data protection) Keychain on the Macs the
# profile lists. Nothing is installed or sent to Apple.
#
#   RV_PROVISION_PROFILE=~/path/RV_Dev.provisionprofile \
#   RV_BUNDLE_ID=com.example.rv scripts/build-touchid-local.sh
#
# Optional: RV_SIGN_IDENTITY (default "Apple Development"; a SHA-1 from
# `security find-identity -v -p codesigning` also works).
# Output: target/touchid/RV.app and target/touchid/KeychainCheck.app.
# Keep the profile outside the repository: it lists device identifiers.
set -eu

: "${RV_PROVISION_PROFILE:?set RV_PROVISION_PROFILE to the downloaded .provisionprofile}"
: "${RV_BUNDLE_ID:?set RV_BUNDLE_ID to the App ID the profile was made for}"
identity=${RV_SIGN_IDENTITY:-Apple Development}
# Homebrew's rustup keeps its cargo proxy off the default PATH.
command -v cargo >/dev/null 2>&1 || PATH="/opt/homebrew/opt/rustup/bin:$PATH"

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/target/touchid"
cd "$root"

cargo build --release -p rv-app --locked
cargo build --release -p rv-core --example keychain_roundtrip --locked

rm -rf "$out/RV.app" "$out/KeychainCheck.app"
for pair in "target/release/rv:RV.app" "target/release/examples/keychain_roundtrip:KeychainCheck.app"; do
  python3 scripts/package-macos.py \
    --binary "${pair%%:*}" --output "$out/${pair#*:}" \
    --bundle-id "$RV_BUNDLE_ID" \
    --identity "$identity" --profile "$RV_PROVISION_PROFILE"
done

echo
echo "Check the protected Keychain (needs a Touch ID press):"
echo "  $out/KeychainCheck.app/Contents/MacOS/rv"
echo "It must print 'Protected Keychain create, update, and authenticated read passed.'"
