import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";

let tmpDir;

beforeEach(() => {
  vi.resetModules();
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ait-test-"));
  process.env.VLI_TRUST_DATA_DIR = tmpDir;
});

afterEach(async () => {
  // Close the DB held by this test's module instance before unlinking files
  // (Windows holds locks on open SQLite files).
  try {
    const { close } = await import("../src/lib/store.js");
    close();
  } catch {
    // module may not have been imported in this test
  }
  vi.restoreAllMocks();
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // best-effort; OS will reap the temp dir
  }
});

// Helper: create a session row so sealEvent's FK constraint passes.
async function startSession(sessionId) {
  const { getDb } = await import("../src/lib/store.js");
  const db = getDb();
  db.prepare(
    `INSERT INTO sessions (session_id, agent_id, started_at) VALUES (?, ?, ?)`
  ).run(sessionId, "test-agent", new Date().toISOString());
}

describe("submitAnchor", () => {
  it("skips when VLI_API_KEY is unset", async () => {
    delete process.env.VLI_API_KEY;
    process.env.VLI_VAV_URL = "https://example.test";

    await startSession("ses-x");
    const { submitAnchor, sealEvent, createAnchorBatch } = await import("../src/lib/proof-chain.js");

    sealEvent("ses-x", "ai.test", { x: 1 });
    const batch = createAnchorBatch();
    const result = await submitAnchor(batch.batch_id);
    expect(result.status).toBe("skipped");
    expect(result.reason).toMatch(/no.?key|VLI_API_KEY/i);
  });

  it("posts to VAV /api/anchor with bearer auth and merkle_root", async () => {
    process.env.VLI_API_KEY = "user-key-abc";
    process.env.VLI_VAV_URL = "https://example.test";

    await startSession("ses-y");
    const { submitAnchor, sealEvent, createAnchorBatch } = await import("../src/lib/proof-chain.js");

    sealEvent("ses-y", "ai.test", { x: 2 });
    const batch = createAnchorBatch();

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ anchored: true, entry: { leaf_index: 7 }, usage: { remaining: 4 } }),
    });
    global.fetch = fetchMock;

    const result = await submitAnchor(batch.batch_id);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("https://example.test/api/anchor");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Authorization"]).toBe("Bearer user-key-abc");
    expect(opts.headers["Content-Type"]).toBe("application/json");

    const body = JSON.parse(opts.body);
    expect(body.merkle_root).toBe(batch.merkle_root);
    expect(body.batch_id).toBe(batch.batch_id);
    expect(body.event_count).toBe(batch.event_count);
    expect(body.source).toBe("mcp-ai-trust");

    expect(result.status).toBe("anchored");
    expect(result.registry.entry.leaf_index).toBe(7);
  });

  it("returns failed status with limit message on 429", async () => {
    process.env.VLI_API_KEY = "user-key-abc";
    process.env.VLI_VAV_URL = "https://example.test";

    await startSession("ses-z");
    const { submitAnchor, sealEvent, createAnchorBatch } = await import("../src/lib/proof-chain.js");
    sealEvent("ses-z", "ai.test", { x: 3 });
    const batch = createAnchorBatch();

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      json: async () => ({ error: "anchor_limit_reached", message: "5/5 used", upgrade_url: "/vault#upgrade" }),
    });

    const result = await submitAnchor(batch.batch_id);
    expect(result.status).toBe("failed");
    expect(result.http_status).toBe(429);
    expect(result.error).toBe("5/5 used");
  });
});
