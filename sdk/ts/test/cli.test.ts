import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { RemitMcp } from "../src/mcp.ts";

test("remit-mcp initializes legacy clients and advertises modern discovery", async () => {
  const mcp = new RemitMcp();
  const initialize = await mcp.handle({ id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });
  assert.equal(initialize.result.protocolVersion, "2025-11-25");
  const discovery = await mcp.handle({ id: 2, method: "server/discover" });
  assert.equal(discovery.result.resultType, "complete");
  assert.deepEqual(discovery.result.supportedVersions, ["2026-07-28", "2025-11-25"]);
});

test("remit-ts builds a TypeScript kernel in a CommonJS project", () => {
  const dir = mkdtempSync(join(tmpdir(), "remit-ts-"));
  try {
    writeFileSync(join(dir, "package.json"), '{"type":"commonjs"}');
    writeFileSync(join(dir, "count.ts"), `
      export const remit = {
        reads: { q: { sql: "SELECT 1 AS n", max_rows: 1 } },
        returns: { int: { min: 0, max: 2 } },
      };
      export default function main(): number { return 1; }
    `);
    const cli = fileURLToPath(new URL("../bin/remit-ts.ts", import.meta.url));
    const run = spawnSync(process.execPath, [cli, "build", "count.ts"], { cwd: dir, encoding: "utf8", timeout: 20_000 });
    assert.equal(run.status, 0, run.stderr);
    const program = JSON.parse(readFileSync(join(dir, "count.remit.json"), "utf8"));
    assert.equal(program.reads.q.max_rows, 1);
    assert.match(program.code.source, /return 1;/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
