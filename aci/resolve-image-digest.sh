#!/bin/sh
# Resolves the currently-published aci-session-worker image to a
# registry+digest reference, e.g.
#   ghcr.io/directionallyai/aci-worker/aci-session-worker@sha256:...
#
# Assumes GitHub Packages (GHCR) as the publish target, published as a
# public package (nothing in this image is secret -- worker.py/storage.py
# are the same files anyone can already read in this repo, and Azure
# needs to pull this image into the container group it launches without
# this repo handing out a registry credential to do it). GHCR container
# package visibility can't be flipped by a workflow's own GITHUB_TOKEN
# (needs a PAT with repo + write:packages scope, or the GitHub UI) --
# set to public once, manually, after aci-session-worker-build.yml's
# first successful push.
#
# Never resolves to a tag -- see arm-template.json's own comment for why
# the CCE policy has to be generated against the same immutable digest
# that actually gets deployed, not a tag that could move out from under
# either one independently.
#
# Usage: ./resolve-image-digest.sh [org] [package] [tag]
#   org     defaults to directionallyai
#   package defaults to aci-worker/aci-session-worker
#           (GHCR package name, i.e. everything after ghcr.io/<org>/ --
#           GitHub Packages allows the "/" in a container package name)
#   tag     defaults to dev (aci-session-worker-build.yml's own
#           convention, matching backend's lambda-executor-build.yml: a
#           floating :dev tag alongside an immutable :<git-sha> one)
set -eu

ORG="${1:-directionallyai}"
PACKAGE="${2:-aci-worker/aci-session-worker}"
TAG="${3:-dev}"

# GitHub's REST API path-encodes "/" in the package name as %2F -- gh api
# does not do this for us.
ENCODED_PACKAGE=$(printf '%s' "$PACKAGE" | sed 's#/#%2F#g')

VERSIONS_JSON=$(gh api "orgs/${ORG}/packages/container/${ENCODED_PACKAGE}/versions" --paginate)

DIGEST=$(printf '%s' "$VERSIONS_JSON" | python3 -c '
import json, sys

tag = sys.argv[1]
versions = json.load(sys.stdin)
for version in versions:
    tags = version.get("metadata", {}).get("container", {}).get("tags", [])
    if tag in tags:
        print(version["name"])  # the manifest digest, e.g. "sha256:..."
        break
else:
    sys.exit(f"no published version of this package is tagged {tag!r}")
' "$TAG")

if [ -z "$DIGEST" ]; then
    echo "resolve-image-digest.sh: could not resolve a digest for ${PACKAGE}:${TAG}" >&2
    exit 1
fi

echo "ghcr.io/${ORG}/${PACKAGE}@${DIGEST}"
