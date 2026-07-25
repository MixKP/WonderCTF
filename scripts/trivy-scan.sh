#!/usr/bin/env bash
# Trivy scan for every image this repo builds, plus a config/IaC scan of the
# Dockerfiles and k8s manifests. Used by `make scan` and CI.
#
# Policy:
#   - Gated images (everything except a06) must have zero HIGH/CRITICAL
#     vulnerabilities *with an available fix* (--ignore-unfixed — failing a
#     build over a CVE nobody can patch yet isn't actionable). A failure here
#     is real, actionable signal: bump the base image or the dependency.
#   - challenges/a06-vulnerable-components is scanned but never gates the
#     build — it exists specifically to carry a large, deliberately outdated
#     dependency surface (see .trivyignore for why an exhaustive ignore list
#     isn't the right tool here).
#   - `trivy config` scans every Dockerfile and the k8s manifests for
#     misconfigurations (missing USER, privileged containers, etc.) and is
#     gated the same way as the application images.
set -uo pipefail
cd "$(dirname "$0")/.."

SEVERITY="HIGH,CRITICAL"
IGNOREFILE=".trivyignore"
FAILED=0

GATED_IMAGES=(
  "ctf/platform:local"
  "ctf/frontend:local"
  "ctf/a01-broken-access-control:local"
  "ctf/a02-crypto-failures:local"
  "ctf/a03-injection:local"
  "ctf/a04-insecure-design:local"
  "ctf/a05-security-misconfig:local"
  "ctf/a07-auth-failures:local"
  "ctf/a08-integrity-failures:local"
  "ctf/a09-logging-failures:local"
  "ctf/a10-ssrf:local"
)

echo "=== Gated image scans (severity: $SEVERITY, ignore-unfixed) ==="
for image in "${GATED_IMAGES[@]}"; do
  echo "--- $image ---"
  if ! trivy image \
      --severity "$SEVERITY" \
      --ignore-unfixed \
      --ignorefile "$IGNOREFILE" \
      --exit-code 1 \
      "$image"; then
    echo "FAILED: $image has HIGH/CRITICAL vulnerabilities with an available fix"
    FAILED=1
  fi
done

echo "=== Report-only scan: challenges/a06-vulnerable-components (never gates the build) ==="
trivy image \
  --severity "$SEVERITY" \
  --ignore-unfixed \
  --ignorefile "$IGNOREFILE" \
  --show-suppressed \
  "ctf/a06-vulnerable-components:local" || true

echo "=== IaC / config scan: Dockerfiles + k8s manifests ==="
if ! trivy config \
    --severity "$SEVERITY" \
    --exit-code 1 \
    --ignorefile "$IGNOREFILE" \
    --skip-dirs "**/node_modules" \
    .; then
  echo "FAILED: config scan found HIGH/CRITICAL misconfigurations"
  FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  echo
  echo "Trivy scan FAILED — see findings above."
  exit 1
fi

echo
echo "Trivy scan passed."
