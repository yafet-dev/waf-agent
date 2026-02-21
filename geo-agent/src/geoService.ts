import { exec } from "child_process";
import { promises as fs } from "fs";
import * as path from "path";

// ─── Paths ──────────────────────────────────────────────────────────────────
const GEO_LISTS_DIR = "/etc/nginx/waf/geo-lists";
const GEO_SERVERS_DIR = "/etc/nginx/waf/geo-servers";

export const ALLOW_LIST_PATH = path.join(GEO_LISTS_DIR, "waf.zergaw.et.allow");
export const DENY_LIST_PATH = path.join(GEO_LISTS_DIR, "waf.zergaw.et.deny");
export const ACTIVE_CONF_PATH = path.join(
  GEO_SERVERS_DIR,
  "waf.zergaw.et.active.conf"
);

const ALLOW_ONLY_CONF = path.join(
  GEO_SERVERS_DIR,
  "waf.zergaw.et.allow_only.conf"
);
const DENY_ONLY_CONF = path.join(
  GEO_SERVERS_DIR,
  "waf.zergaw.et.deny_only.conf"
);

// ─── Constants ──────────────────────────────────────────────────────────────
export const COUNTRY_RE = /^[A-Z]{2}$/;
const CMD_TIMEOUT = 10_000; // 10 s

// ─── Internal helper ────────────────────────────────────────────────────────
function run(cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: CMD_TIMEOUT }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr?.trim() || err.message));
      resolve(stdout);
    });
  });
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Read a geo-list file and return the set of country codes.
 * File format: one entry per line "XX 1;"
 */
export async function readList(filePath: string): Promise<Set<string>> {
  const codes = new Set<string>();
  try {
    const data = await fs.readFile(filePath, "utf-8");
    for (const line of data.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const m = t.match(/^([A-Z]{2})\s+1;$/);
      if (m) codes.add(m[1]);
    }
  } catch (err: any) {
    if (err.code === "ENOENT") return codes; // file doesn't exist yet
    throw err;
  }
  return codes;
}

/**
 * Atomically write a geo-list file, validate nginx, and reload.
 * Rolls back on nginx -t failure.
 */
export async function writeListAtomic(
  filePath: string,
  codes: Set<string>
): Promise<void> {
  const content =
    [...codes]
      .sort()
      .map((c) => `${c} 1;`)
      .join("\n") + (codes.size > 0 ? "\n" : "");

  // Save original for rollback
  let backup: string | null = null;
  try {
    backup = await fs.readFile(filePath, "utf-8");
  } catch {
    /* file may not exist yet */
  }

  const tmp = `${filePath}.tmp`;
  await fs.writeFile(tmp, content, "utf-8");
  await fs.rename(tmp, filePath); // atomic move

  try {
    await validateAndReloadNginx();
    console.log(`[geo] wrote ${filePath} (${codes.size} entries)`);
  } catch (err) {
    // Rollback
    if (backup !== null) {
      await fs.writeFile(filePath, backup, "utf-8");
    } else {
      await fs.unlink(filePath).catch(() => {});
    }
    throw err;
  }
}

/**
 * Atomically switch the active enforcement mode, validate, and reload.
 * Rolls back on nginx -t failure.
 */
export async function setModeAtomic(
  mode: "allow_only" | "deny_only"
): Promise<void> {
  const includeLine =
    mode === "allow_only"
      ? `include ${ALLOW_ONLY_CONF};`
      : `include ${DENY_ONLY_CONF};`;

  let backup: string | null = null;
  try {
    backup = await fs.readFile(ACTIVE_CONF_PATH, "utf-8");
  } catch {
    /* may not exist */
  }

  const tmp = `${ACTIVE_CONF_PATH}.tmp`;
  await fs.writeFile(tmp, includeLine + "\n", "utf-8");
  await fs.rename(tmp, ACTIVE_CONF_PATH);

  try {
    await validateAndReloadNginx();
    console.log(`[geo] mode set to ${mode}`);
  } catch (err) {
    // Rollback
    if (backup !== null) {
      await fs.writeFile(ACTIVE_CONF_PATH, backup, "utf-8");
    }
    throw err;
  }
}

/**
 * Run `nginx -t` then `systemctl reload nginx`.
 * Throws on failure.
 */
export async function validateAndReloadNginx(): Promise<void> {
  await run("nginx -t");
  await run("systemctl reload nginx");
}

/**
 * Determine current mode by reading active.conf.
 */
export async function getCurrentMode(): Promise<
  "allow_only" | "deny_only" | "unknown"
> {
  try {
    const data = await fs.readFile(ACTIVE_CONF_PATH, "utf-8");
    if (data.includes("allow_only.conf")) return "allow_only";
    if (data.includes("deny_only.conf")) return "deny_only";
    return "unknown";
  } catch {
    return "unknown";
  }
}
