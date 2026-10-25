import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm", "cjs"],
  dts: true,
  target: "node22",
  platform: "node",
  clean: true,
  sourcemap: false,
  splitting: false,
});
