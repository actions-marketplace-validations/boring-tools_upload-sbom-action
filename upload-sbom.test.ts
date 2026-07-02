import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "bt-upload-sbom-"));
});

afterEach(async () => {
  await rm(dir, { force: true, recursive: true });
});

test("upload action posts enriched CycloneDX JSON without printing the API key", async () => {
  const sbomPath = join(dir, "sbom.cdx.json");
  const capturedBodyPath = join(dir, "captured-body.json");
  const capturedArgsPath = join(dir, "captured-args.txt");
  const fakeBin = join(dir, "bin");
  await Bun.$`mkdir -p ${fakeBin}`;

  await writeFile(
    sbomPath,
    JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
      specVersion: "1.6",
    })
  );

  await writeFile(
    join(fakeBin, "curl"),
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > ${capturedArgsPath}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-binary)
      shift
      input="$1"
      cp "${"$"}{input#@}" ${capturedBodyPath}
      ;;
  esac
  shift || true
done
printf '{"success":true}\n'
`
  );
  await Bun.$`chmod +x ${join(fakeBin, "curl")}`;

  const proc = Bun.spawn({
    cmd: ["bash", "upload-sbom.sh"],
    cwd: process.cwd(),
    env: {
      ...process.env,
      BORING_TOOLS_API_KEY: "bt_secret_test_key",
      BORING_TOOLS_API_URL: "https://api.example.test",
      BORING_TOOLS_PROJECT_ID: "11111111-1111-4111-8111-111111111111",
      BORING_TOOLS_SBOM_FILE: sbomPath,
      BORING_TOOLS_SOURCE_METADATA: "true",
      GITHUB_ACTIONS: "true",
      GITHUB_REF: "refs/heads/main",
      GITHUB_REF_NAME: "main",
      GITHUB_REPOSITORY: "acme/widgets",
      GITHUB_RUN_ID: "98765",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_SHA: "abcdef123456",
      PATH: `${fakeBin}:${process.env.PATH}`,
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  expect(exitCode).toBe(0);
  expect(stderr).not.toContain("bt_secret_test_key");
  expect(stdout).toContain("::add-mask::bt_secret_test_key");

  const capturedArgs = await readFile(capturedArgsPath, "utf8");
  expect(capturedArgs).toContain(
    "https://api.example.test/v1/sboms?projectId=11111111-1111-4111-8111-111111111111"
  );
  expect(capturedArgs).toContain("x-api-key: bt_secret_test_key");

  const capturedBody = JSON.parse(await readFile(capturedBodyPath, "utf8"));
  expect(capturedBody.projectId).toBeUndefined();
  expect(capturedBody.bomFormat).toBe("CycloneDX");
  expect(capturedBody.source).toEqual({
    branch: "main",
    commitSha: "abcdef123456",
    ref: "refs/heads/main",
    repository: "acme/widgets",
    runId: "98765",
    runUrl: "https://github.com/acme/widgets/actions/runs/98765",
    type: "github_action",
  });
});

test("upload action does not print the local API key outside GitHub Actions", async () => {
  const sbomPath = join(dir, "sbom.cdx.json");
  const fakeBin = join(dir, "bin");
  await Bun.$`mkdir -p ${fakeBin}`;

  await writeFile(
    sbomPath,
    JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
      specVersion: "1.6",
    })
  );

  await writeFile(
    join(fakeBin, "curl"),
    `#!/usr/bin/env bash
set -euo pipefail
exit 0
`
  );
  await Bun.$`chmod +x ${join(fakeBin, "curl")}`;

  const proc = Bun.spawn({
    cmd: ["bash", "upload-sbom.sh"],
    cwd: process.cwd(),
    env: {
      ...process.env,
      BORING_TOOLS_API_KEY: "bt_secret_local_key",
      BORING_TOOLS_PROJECT_ID: "44444444-4444-4444-8444-444444444444",
      BORING_TOOLS_SBOM_FILE: sbomPath,
      BORING_TOOLS_SOURCE_METADATA: "false",
      GITHUB_ACTIONS: "",
      PATH: `${fakeBin}:${process.env.PATH}`,
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  expect(exitCode).toBe(0);
  expect(stdout).not.toContain("bt_secret_local_key");
  expect(stderr).not.toContain("bt_secret_local_key");
  expect(stdout).not.toContain("::add-mask::");
});

test("upload action preserves the SBOM body when source metadata is disabled", async () => {
  const sbomPath = join(dir, "sbom.cdx.json");
  const capturedBodyPath = join(dir, "captured-body.json");
  const capturedArgsPath = join(dir, "captured-args.txt");
  const fakeBin = join(dir, "bin");
  await Bun.$`mkdir -p ${fakeBin}`;

  await writeFile(
    sbomPath,
    JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
      specVersion: "1.6",
    })
  );

  await writeFile(
    join(fakeBin, "curl"),
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > ${capturedArgsPath}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-binary)
      shift
      cp "${"$"}{1#@}" ${capturedBodyPath}
      ;;
  esac
  shift || true
done
`
  );
  await Bun.$`chmod +x ${join(fakeBin, "curl")}`;

  const proc = Bun.spawn({
    cmd: ["bash", "upload-sbom.sh"],
    cwd: process.cwd(),
    env: {
      ...process.env,
      BORING_TOOLS_API_KEY: "bt_secret_test_key",
      BORING_TOOLS_PROJECT_ID: "22222222-2222-4222-8222-222222222222",
      BORING_TOOLS_SBOM_FILE: sbomPath,
      BORING_TOOLS_SOURCE_METADATA: "false",
      PATH: `${fakeBin}:${process.env.PATH}`,
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  expect(await proc.exited).toBe(0);

  const capturedArgs = await readFile(capturedArgsPath, "utf8");
  expect(capturedArgs).toContain(
    "https://api.boring.tools/v1/sboms?projectId=22222222-2222-4222-8222-222222222222"
  );

  const capturedBody = JSON.parse(await readFile(capturedBodyPath, "utf8"));
  expect(capturedBody).toEqual({
    bomFormat: "CycloneDX",
    components: [],
    specVersion: "1.6",
  });
});

test("upload action does not require jq when source metadata is disabled", async () => {
  const sbomPath = join(dir, "sbom.cdx.json");
  const capturedBodyPath = join(dir, "captured-body.json");
  const fakeBin = join(dir, "bin");
  await Bun.$`mkdir -p ${fakeBin}`;

  await writeFile(
    sbomPath,
    JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
      specVersion: "1.6",
    })
  );

  await writeFile(
    join(fakeBin, "curl"),
    `#!/usr/bin/bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-binary)
      shift
      /bin/cp "${"$"}{1#@}" ${capturedBodyPath}
      ;;
  esac
  shift || true
done
`
  );
  await Bun.$`chmod +x ${join(fakeBin, "curl")}`;

  const proc = Bun.spawn({
    cmd: ["/usr/bin/bash", "upload-sbom.sh"],
    cwd: process.cwd(),
    env: {
      BORING_TOOLS_API_KEY: "bt_secret_test_key",
      BORING_TOOLS_PROJECT_ID: "33333333-3333-4333-8333-333333333333",
      BORING_TOOLS_SBOM_FILE: sbomPath,
      BORING_TOOLS_SOURCE_METADATA: "false",
      PATH: `${fakeBin}:/usr/local/bin`,
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  const [stderr, exitCode] = await Promise.all([
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  expect(exitCode).toBe(0);
  expect(stderr).not.toContain("jq is required");

  const capturedBody = JSON.parse(await readFile(capturedBodyPath, "utf8"));
  expect(capturedBody).toEqual({
    bomFormat: "CycloneDX",
    components: [],
    specVersion: "1.6",
  });
});

test("upload action accepts mixed-case source metadata values", async () => {
  const sbomPath = join(dir, "sbom.cdx.json");
  const capturedBodyPath = join(dir, "captured-body.json");
  const fakeBin = join(dir, "bin");
  await Bun.$`mkdir -p ${fakeBin}`;

  await writeFile(
    sbomPath,
    JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
      specVersion: "1.6",
    })
  );

  await writeFile(
    join(fakeBin, "curl"),
    `#!/usr/bin/env bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-binary)
      shift
      cp "${"$"}{1#@}" ${capturedBodyPath}
      ;;
  esac
  shift || true
done
`
  );
  await Bun.$`chmod +x ${join(fakeBin, "curl")}`;

  const proc = Bun.spawn({
    cmd: ["bash", "upload-sbom.sh"],
    cwd: process.cwd(),
    env: {
      ...process.env,
      BORING_TOOLS_API_KEY: "bt_secret_test_key",
      BORING_TOOLS_PROJECT_ID: "66666666-6666-4666-8666-666666666666",
      BORING_TOOLS_SBOM_FILE: sbomPath,
      BORING_TOOLS_SOURCE_METADATA: "False",
      PATH: `${fakeBin}:${process.env.PATH}`,
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  const [stderr, exitCode] = await Promise.all([
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  expect(exitCode).toBe(0);
  expect(stderr).not.toContain("BORING_TOOLS_SOURCE_METADATA must be true or false");

  const capturedBody = JSON.parse(await readFile(capturedBodyPath, "utf8"));
  expect(capturedBody).toEqual({
    bomFormat: "CycloneDX",
    components: [],
    specVersion: "1.6",
  });
});

test("upload action rejects invalid source metadata values", async () => {
  const sbomPath = join(dir, "sbom.cdx.json");
  const fakeBin = join(dir, "bin");
  await Bun.$`mkdir -p ${fakeBin}`;

  await writeFile(
    sbomPath,
    JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
      specVersion: "1.6",
    })
  );

  await writeFile(
    join(fakeBin, "curl"),
    `#!/usr/bin/env bash
set -euo pipefail
echo "curl should not be called" >&2
exit 99
`
  );
  await Bun.$`chmod +x ${join(fakeBin, "curl")}`;

  const proc = Bun.spawn({
    cmd: ["bash", "upload-sbom.sh"],
    cwd: process.cwd(),
    env: {
      ...process.env,
      BORING_TOOLS_API_KEY: "bt_secret_test_key",
      BORING_TOOLS_PROJECT_ID: "55555555-5555-4555-8555-555555555555",
      BORING_TOOLS_SBOM_FILE: sbomPath,
      BORING_TOOLS_SOURCE_METADATA: "maybe",
      PATH: `${fakeBin}:${process.env.PATH}`,
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  const [stderr, exitCode] = await Promise.all([
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  expect(exitCode).toBe(2);
  expect(stderr).toContain(
    "BORING_TOOLS_SOURCE_METADATA must be true or false"
  );
  expect(stderr).not.toContain("curl should not be called");
});
