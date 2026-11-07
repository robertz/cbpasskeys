#!/usr/bin/env bash
# Runs the specs on every engine in test-harness/server-*.json; exits non-zero on any failure.
#   bash scripts/test.sh            all engines
#   bash scripts/test.sh lucee@6    one engine
set -euo pipefail
cd "$(dirname "$0")/../test-harness"

if [ ! -f lib/derby.jar ]; then
	echo "test-harness/lib/derby.jar is missing: put an Apache Derby 10.15+ embedded jar there (see README)." >&2
	exit 1
fi
[ -d coldbox ] || box install

status=0
for config in server-${1:-*}.json; do
	name=$(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' "$config" | head -1)
	port=$(sed -n 's/.*"port":[[:space:]]*\([0-9]*\).*/\1/p' "$config" | head -1)
	echo "== $config"
	box server stop serverConfigFile="$config" >/dev/null 2>&1 || true
	box server start serverConfigFile="$config" >/dev/null
	if curl -sf -m 600 "http://127.0.0.1:$port/tests/runner.cfm?reporter=text" > "/tmp/cbpasskeys-$name.txt"; then
		grep -E "Bundles/Suites/Specs" "/tmp/cbpasskeys-$name.txt" | sed "s/<[^>]*>//g"
	else
		cat "/tmp/cbpasskeys-$name.txt" | sed 's/<[^>]*>//g' | grep -E "\( (X|!!) \)|Error|Failure" | head -40
		status=1
	fi
	box server stop serverConfigFile="$config" >/dev/null 2>&1 || true
done
exit $status
