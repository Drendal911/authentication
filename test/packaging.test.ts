import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(__dirname, "..");
type NpmOptions = { cwd: string; stdio?: "pipe"; encoding?: "utf8" };

/** Runs npm without shell: true (DEP0190). Prefers the npm CLI that launched the tests. */
function npm(args: string[], options: NpmOptions): string {
  const cli = process.env.npm_execpath;
  if (cli && /\.c?js$/.test(cli)) {
    return execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", ...options });
  }
  if (process.platform === "win32") {
    return execFileSync(process.env.ComSpec ?? "cmd.exe", ["/d", "/c", "npm", ...args], { encoding: "utf8", ...options });
  }
  return execFileSync("npm", args, { encoding: "utf8", ...options });
}

describe("packaging", () => {
  it(
    "ships only the allowed files with no runtime dependencies, and ESM and CJS both resolve",
    () => {
      npm(["run", "build"], { cwd: root, stdio: "pipe" });

      const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
        dependencies?: Record<string, string>;
      };
      expect(manifest.dependencies ?? {}).toEqual({});

      const dry = npm(["pack", "--dry-run", "--json"], { cwd: root });
      const [info] = JSON.parse(dry) as [{ files: { path: string }[] }];
      const allowed = /^(dist\/.+|README\.md|SECURITY\.md|LICENSE|package\.json)$/;
      for (const file of info.files) {
        expect(file.path, file.path).toMatch(allowed);
      }

      const work = mkdtempSync(join(tmpdir(), "auth-pack-"));
      try {
        const tarball = npm(["pack", "--json", "--pack-destination", work], { cwd: root });
        const [packed] = JSON.parse(tarball) as [{ filename: string }];
        const consumer = join(work, "consumer");
        mkdirSync(consumer);
        writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
        // Peers are not auto-resolved so the install never queries the ambient registry (which may be GitHub Packages during publish).
        const installArgs = ["install", join(work, packed.filename), "--no-save", "--legacy-peer-deps", "--ignore-scripts", "--no-audit", "--no-fund"];
        npm(installArgs, { cwd: consumer, stdio: "pipe" });

        const installed = JSON.parse(readFileSync(join(consumer, "node_modules", "@drendal911", "authentication", "package.json"), "utf8")) as {
          dependencies?: Record<string, string>;
        };
        expect(installed.dependencies ?? {}).toEqual({});

        writeFileSync(
          join(consumer, "esm.mjs"),
          'import { createAuth, createSessionToken } from "@drendal911/authentication"; if (typeof createAuth !== "function" || typeof createSessionToken !== "function") throw new Error("esm");',
        );
        writeFileSync(
          join(consumer, "cjs.cjs"),
          'const m = require("@drendal911/authentication"); if (typeof m.createAuth !== "function") throw new Error("cjs");',
        );
        execFileSync(process.execPath, [join(consumer, "esm.mjs")], { cwd: consumer, stdio: "pipe" });
        execFileSync(process.execPath, [join(consumer, "cjs.cjs")], { cwd: consumer, stdio: "pipe" });
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    },
    180_000,
  );
});
