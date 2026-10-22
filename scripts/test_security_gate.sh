#!/usr/bin/env sh
set -eu

report="trivy-policy-test.json"
rm -f "$report"

trivy config --quiet --format json --severity HIGH,CRITICAL \
  --exit-code 0 --output "$report" tests/fixtures/insecure

finding_count="$(jq '[.. | objects | select(.Severity? == "HIGH" or .Severity? == "CRITICAL")] | length' "$report")"
if [ "$finding_count" -lt 1 ]; then
  echo "ERROR: negative Terraform fixture did not produce a HIGH/CRITICAL finding" >&2
  exit 1
fi

echo "Security-gate negative test passed: $finding_count blocking finding(s) detected."
