#!/usr/bin/env node
/**
 * Clear .next when app/ routes changed (e.g. migration into route groups) or when
 * the dev CSS bundle is missing while server output still exists (stale hybrid cache).
 * npm run dev runs this via the predev hook before starting Next.js.
 */
import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const appDir = join(root, "app");
const nextDir = join(root, ".next");
const serverApp = join(nextDir, "server", "app");
const devLayoutCss = join(nextDir, "static", "css", "app", "layout.css");

function walk(dir, out = []) {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, name.name);
    if (name.isDirectory()) walk(path, out);
    else if (name.isFile() && name.name === "page.tsx") out.push(path);
  }
  return out;
}

function routesStale() {
  if (!existsSync(appDir) || !existsSync(serverApp)) return false;
  for (const pageTsx of walk(appDir)) {
    const rel = pageTsx.slice(appDir.length + 1).replace(/page\.tsx$/, "page.js");
    if (!existsSync(join(serverApp, rel))) return true;
  }
  return false;
}

/** True when .next has server output but dev-mode layout.css is absent. */
function devCssStale() {
  const serverDir = join(nextDir, "server");
  if (!existsSync(serverDir) || !statSync(serverDir).isDirectory()) return false;
  if (existsSync(devLayoutCss)) return false;
  // Server artifacts without dev CSS → unstyled pages (Times New Roman, no Tailwind).
  return true;
}

function clearNext(reason) {
  console.log(reason);
  rmSync(nextDir, { recursive: true, force: true });
}

if (routesStale()) {
  clearNext("Clearing stale .next cache (app routes changed)…");
} else if (devCssStale()) {
  clearNext("Clearing stale .next cache (dev CSS missing)…");
}
