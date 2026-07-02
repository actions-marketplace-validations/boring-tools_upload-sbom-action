# Upload SBOM to boring.tools

This GitHub Action uploads an **existing CycloneDX JSON SBOM** to boring.tools so it can be stored, scanned for vulnerabilities, and shown in your project dashboard.

It intentionally does **not** generate the SBOM. Use any generator you like (Syft, Trivy, CycloneDX CLI, cdxgen, etc.) and pass the generated file to this action.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `api-url` | no | `https://api.boring.tools` | boring.tools API base URL |
| `api-key` | yes | — | boring.tools API key with SBOM upload access. Prefer a key scoped to the target project. |
| `project-id` | yes | — | boring.tools project ID |
| `sbom-file` | yes | — | Path to an existing CycloneDX JSON SBOM |
| `source-metadata` | no | `true` | Add GitHub repository/ref/commit/run metadata to the upload payload |

## Example: generate with Syft, upload with boring.tools

Store these values in your repository:

- Secret: `BORING_TOOLS_API_KEY`
- Variable: `BORING_TOOLS_PROJECT_ID`

Create the API key from **Organization settings → API Keys** and set **Project scope** to the project whose ID you store in `BORING_TOOLS_PROJECT_ID`. Project-scoped keys limit a leaked CI secret to a single project.

```yaml
name: SBOM

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Install Syft
        uses: anchore/sbom-action/download-syft@v0

      - name: Generate CycloneDX SBOM
        run: syft dir:. -o cyclonedx-json=sbom.cdx.json

      - name: Upload SBOM to boring.tools
        uses: boring-tools/upload-sbom-action@v1
        with:
          api-key: ${{ secrets.BORING_TOOLS_API_KEY }}
          project-id: ${{ vars.BORING_TOOLS_PROJECT_ID }}
          sbom-file: sbom.cdx.json
```

For a self-hosted/staging API, pass `api-url`:

```yaml
      - name: Upload SBOM to boring.tools
        uses: boring-tools/upload-sbom-action@v1
        with:
          api-url: https://api.example.com
          api-key: ${{ secrets.BORING_TOOLS_API_KEY }}
          project-id: ${{ vars.BORING_TOOLS_PROJECT_ID }}
          sbom-file: sbom.cdx.json
```

## Example: use an already generated SBOM

```yaml
- name: Upload SBOM to boring.tools
  uses: boring-tools/upload-sbom-action@v1
  with:
    api-key: ${{ secrets.BORING_TOOLS_API_KEY }}
    project-id: ${{ vars.BORING_TOOLS_PROJECT_ID }}
    sbom-file: path/to/bom.json
```

## What gets uploaded

The action uploads the SBOM file to the selected project with `projectId` in the request URL:

```text
POST /v1/sboms?projectId=<project-id>
```

When `source-metadata` is enabled, the action enriches the upload payload with:

- GitHub repository
- ref and branch
- commit SHA
- workflow run ID and URL

When `source-metadata` is disabled, the SBOM JSON body is sent unchanged. The original API key is masked in GitHub Actions logs.

## Troubleshooting

- `BORING_TOOLS_API_KEY is required` — add the API key as a GitHub Actions secret.
- `BORING_TOOLS_PROJECT_ID is required` — add the project ID as a GitHub Actions repository variable.
- `BORING_TOOLS_SOURCE_METADATA must be true or false` — pass `true`/`false`, `yes`/`no`, or `1`/`0` in any casing.
- `SBOM file not found` — check that your generator writes to the same path passed to `sbom-file`.
- `jq is required` — only metadata-enriched uploads need `jq`. GitHub-hosted runners include `jq` by default; install it on self-hosted runners or set `source-metadata: false` to send the SBOM JSON unchanged.
- HTTP `400` — the file is not valid CycloneDX JSON or the project ID is missing or invalid.
- HTTP `401` — the API key is missing or invalid.
- HTTP `403` — the API key is valid but lacks SBOM upload access or is scoped to a different project.
- HTTP `404` — the project ID does not belong to the API key's organization.
