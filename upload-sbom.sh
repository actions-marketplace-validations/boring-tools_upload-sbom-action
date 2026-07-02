#!/usr/bin/env bash
set -euo pipefail

api_url="${BORING_TOOLS_API_URL:-https://api.boring.tools}"
api_key="${BORING_TOOLS_API_KEY:-}"
project_id="${BORING_TOOLS_PROJECT_ID:-}"
sbom_file="${BORING_TOOLS_SBOM_FILE:-}"
source_metadata="${BORING_TOOLS_SOURCE_METADATA:-true}"
source_metadata="${source_metadata,,}"

if [ -z "$api_key" ]; then
  echo "BORING_TOOLS_API_KEY is required" >&2
  exit 2
fi

if [ -z "$project_id" ]; then
  echo "BORING_TOOLS_PROJECT_ID is required" >&2
  exit 2
fi

if [ -z "$sbom_file" ]; then
  echo "BORING_TOOLS_SBOM_FILE is required" >&2
  exit 2
fi

if [ ! -f "$sbom_file" ]; then
  echo "SBOM file not found: $sbom_file" >&2
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to upload the SBOM" >&2
  exit 2
fi

# Tell GitHub Actions to mask the secret before any command can echo it.
if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  printf '::add-mask::%s\n' "$api_key"
fi

api_url="${api_url%/}"
upload_url="$api_url/v1/sboms?projectId=$project_id"
payload_file="$sbom_file"

case "$source_metadata" in
  1|true|yes)
    repository="${GITHUB_REPOSITORY:-}"
    ref="${GITHUB_REF:-}"
    branch="${GITHUB_REF_NAME:-}"
    commit_sha="${GITHUB_SHA:-}"
    run_id="${GITHUB_RUN_ID:-}"
    server_url="${GITHUB_SERVER_URL:-https://github.com}"
    run_url=""
    if [ -n "$repository" ] && [ -n "$run_id" ]; then
      run_url="$server_url/$repository/actions/runs/$run_id"
    fi

    if ! command -v jq >/dev/null 2>&1; then
      echo "jq is required to attach source metadata" >&2
      exit 2
    fi

    tmp_payload="$(mktemp)"
    trap 'rm -f "$tmp_payload"' EXIT

    jq \
      --arg repository "$repository" \
      --arg ref "$ref" \
      --arg branch "$branch" \
      --arg commitSha "$commit_sha" \
      --arg runId "$run_id" \
      --arg runUrl "$run_url" \
      '. + {
        source: {
          type: "github_action",
          repository: $repository,
          ref: $ref,
          branch: $branch,
          commitSha: $commitSha,
          runId: $runId,
          runUrl: $runUrl
        }
      }' \
      "$sbom_file" > "$tmp_payload"
    payload_file="$tmp_payload"
    ;;
  0|false|no)
    ;;
  *)
    echo "BORING_TOOLS_SOURCE_METADATA must be true or false" >&2
    exit 2
    ;;
esac

curl --fail-with-body \
  -X POST "$upload_url" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${api_key}" \
  --data-binary "@$payload_file"
