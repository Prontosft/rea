#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { parseEvidence } from "../dist/domain/evidence.js";

const execute = promisify(execFile);
const root = await PrivateRuntimeRoot.create({ prefix: "rea-bun-verifier-" });
const run = (command, args) =>
  execute(command, args, { timeout: 120_000, maxBuffer: 16 * 1024 * 1024 });
try {
  const source = join(root.path, "hello.ts");
  await writeFile(source, 'console.log("REA_BUN_VERIFICATION");\n');
  const docker = process.argv.includes("--docker");
  const binary = join(root.path, "hello");
  const compiler = docker
    ? "oven/bun:1.4.0"
    : (await run("bun", ["--version"])).stdout.trim();
  if (docker) {
    await run("docker", [
      "run",
      "--rm",
      "--network=none",
      "-v",
      `${root.path}:/work`,
      "-w",
      "/work",
      "oven/bun:1.4.0",
      "build",
      "--compile",
      "hello.ts",
      "--outfile",
      "hello",
    ]);
  } else {
    await run("bun", ["build", "--compile", source, "--outfile", binary]);
  }
  const cli = async (command) =>
    JSON.parse(
      (
        await execute(
          process.execPath,
          ["scripts/rea.mjs", command, binary, "--json"],
          {
            timeout: 120_000,
            maxBuffer: 16 * 1024 * 1024,
            env: {
              ...process.env,
              TMPDIR: root.path,
              TMP: root.path,
              TEMP: root.path,
            },
          },
        )
      ).stdout,
    );
  const inspected = parseEvidence(
    await cli("inspect-artifact"),
  ).normalized_result;
  const graph = inspected.substeps[0].evidence.normalized_result;
  assert.equal(graph.manifest.root_format, "bun-standalone");
  const module = graph.occurrences.find(
    (row) =>
      row.format_metadata?.kind === "bun-standalone-entry" &&
      row.format_metadata.region === "contents" &&
      row.format_metadata.entry_point,
  );
  assert.ok(module);
  const extracted = parseEvidence(
    await cli("extract-artifact"),
  ).normalized_result;
  assert.equal(extracted.containment_verified, true);
  assert.match(
    await readFile(join(extracted.output_root, module.logical_path), "utf8"),
    /REA_BUN_VERIFICATION/u,
  );
  console.log(
    JSON.stringify(
      {
        compiler,
        host: `${process.platform}-${process.arch}`,
        docker,
        root_format: graph.manifest.root_format,
        entry_point: module.logical_path,
        sha256: graph.nodes.find(
          (node) => node.artifact_id === module.artifact_id,
        )?.sha256,
        extraction_verified: true,
        target_executed: false,
      },
      null,
      2,
    ),
  );
} finally {
  await root.close();
}
