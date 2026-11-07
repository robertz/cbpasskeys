#!/usr/bin/env bash
# Line coverage of the module's code from Lucee's execution log; exits non-zero on any
# uncovered line. Turns the log on for the Lucee 6 server, runs the specs, then turns it off.
#   bash scripts/coverage.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/test-harness"
config=server-lucee@6.json
port=$(sed -n 's/.*"port":[[:space:]]*\([0-9]*\).*/\1/p' "$config" | head -1)
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT

[ -d coldbox ] || box install
box server stop serverConfigFile="$config" >/dev/null 2>&1 || true
box server start serverConfigFile="$config" >/dev/null
box server stop serverConfigFile="$config" >/dev/null

cfconfig=$(find .engine/lucee6 -path "*lucee-server/context/.CFConfig.json" | head -1)
toggle() {
	python3 - "$cfconfig" "$1" "$logs" <<'PY'
import json, sys
path, mode, logs = sys.argv[1:]
d = json.load(open(path))
if mode == "on":
    d["executionLog"] = {"enabled": True, "class": "lucee.runtime.engine.ResourceExecutionLog",
                         "arguments": {"directory": logs, "unit": "nano", "min-time-nano": "0"}}
else:
    d.pop("executionLog", None)
json.dump(d, open(path, "w"), indent=2)
PY
	# templates are instrumented when they compile, so drop compiled classes both ways
	find .engine/lucee6 -type d -name cfclasses -prune -exec rm -rf {} +
}

toggle on
box server start serverConfigFile="$config" >/dev/null
curl -sf -m 600 "http://127.0.0.1:$port/tests/runner.cfm?reporter=text" | grep -E "Bundles/Suites/Specs" | sed 's/<[^>]*>//g' || echo "specs failed"
box server stop serverConfigFile="$config" >/dev/null
toggle off

python3 "$root/scripts/coverage.py" "$logs" \
	cbpasskeys/ModuleConfig.cfc models/RelyingParty.cfc models/Cbor.cfc models/CoseKey.cfc \
	models/TableCredentialStore.cfc models/MemoryCredentialStore.cfc
