#!/bin/bash
set -euo pipefail

zsign="${1:-./bin/zsign}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj "/CN=zsign-entitlements-test" \
	-keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
mkdir "$tmp/app"

make_profile()
{
	local name="$1"
	local key="$2"
	local value="$3"
	cat >"$tmp/$name.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>TeamIdentifier</key>
	<array><string>TESTTEAM</string></array>
	<key>Entitlements</key>
	<dict>
		<key>application-identifier</key>
		<string>TESTTEAM.com.example.app</string>
		<key>$key</key>
		$value
	</dict>
</dict>
</plist>
EOF
	openssl cms -sign -binary -nodetach -outform DER \
		-in "$tmp/$name.plist" -signer "$tmp/cert.pem" -inkey "$tmp/key.pem" \
		-out "$tmp/$name.mobileprovision"
}

assert_requires_explicit_entitlements()
{
	local name="$1"
	local key="$2"
	local value="$3"
	make_profile "$name" "$key" "$value"
	if "$zsign" -f -k "$tmp/missing.p12" -p test -m "$tmp/$name.mobileprovision" "$tmp/app" >"$tmp/$name.out" 2>&1; then
		echo "$name: profile-derived unsafe iCloud entitlements unexpectedly succeeded" >&2
		exit 1
	fi
	if ! grep -Fq "$key is an allowlist value; use -e" "$tmp/$name.out"; then
		echo "$name: expected explicit-entitlements error was not reported" >&2
		cat "$tmp/$name.out" >&2
		exit 1
	fi
}

assert_requires_explicit_entitlements \
	"development-containers" \
	"com.apple.developer.icloud-container-development-container-identifiers" \
	"<array><string>iCloud.com.example.app</string></array>"
assert_requires_explicit_entitlements \
	"wildcard-services" \
	"com.apple.developer.icloud-services" \
	"<array><string>*</string></array>"
assert_requires_explicit_entitlements \
	"wildcard-kvstore" \
	"com.apple.developer.ubiquity-kvstore-identifier" \
	"<string>TESTTEAM.*</string>"
assert_requires_explicit_entitlements \
	"development-environment" \
	"com.apple.developer.icloud-container-environment" \
	"<array><string>Development</string><string>Production</string></array>"

cat >"$tmp/explicit.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.developer.icloud-services</key>
	<array><string>CloudKit</string></array>
</dict>
</plist>
EOF
if "$zsign" -f -k "$tmp/missing.p12" -p test \
	-m "$tmp/wildcard-services.mobileprovision" -e "$tmp/explicit.plist" \
	"$tmp/app" >"$tmp/explicit.out" 2>&1; then
	echo "explicit entitlements unexpectedly completed with a missing p12" >&2
	exit 1
fi
if grep -Fq "is an allowlist value; use -e" "$tmp/explicit.out"; then
	echo "explicit entitlements did not bypass the profile fallback guard" >&2
	cat "$tmp/explicit.out" >&2
	exit 1
fi

echo "Profile iCloud entitlement checks passed."
