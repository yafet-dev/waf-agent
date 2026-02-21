import { Router, Request, Response } from "express";
import {
  readList,
  writeListAtomic,
  setModeAtomic,
  getCurrentMode,
  ALLOW_LIST_PATH,
  DENY_LIST_PATH,
  COUNTRY_RE,
} from "./geoService";

const router = Router();

// ─── POST /v1/geo/mode ─────────────────────────────────────────────────────
router.post("/mode", async (req: Request, res: Response) => {
  try {
    const { mode, force } = req.body;

    if (mode !== "allow_only" && mode !== "deny_only") {
      return res
        .status(400)
        .json({ error: 'mode must be "allow_only" or "deny_only"' });
    }

    // Safety: switching to allow_only with empty allow list blocks everyone
    if (mode === "allow_only") {
      const allow = await readList(ALLOW_LIST_PATH);
      if (allow.size === 0 && !force) {
        return res.status(400).json({
          error:
            "Allow list is empty. This would block all traffic. Send force=true to override.",
        });
      }
    }

    await setModeAtomic(mode);
    return res.json({ ok: true, mode });
  } catch (err: any) {
    console.error("[geo] POST /mode error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /v1/geo/allow ────────────────────────────────────────────────────
router.post("/allow", async (req: Request, res: Response) => {
  try {
    const { country } = req.body;

    if (!country || !COUNTRY_RE.test(country)) {
      return res.status(400).json({
        error:
          'Invalid country code. Must be uppercase ISO-3166-1 alpha-2 (e.g. "ET").',
      });
    }

    const list = await readList(ALLOW_LIST_PATH);
    if (list.has(country)) {
      return res.json({ ok: true, message: "Already in allow list" });
    }

    list.add(country);
    await writeListAtomic(ALLOW_LIST_PATH, list);
    return res.json({ ok: true, added: country });
  } catch (err: any) {
    console.error("[geo] POST /allow error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ─── DELETE /v1/geo/allow/:country ──────────────────────────────────────────
router.delete("/allow/:country", async (req: Request, res: Response) => {
  try {
    const { country } = req.params;

    if (!COUNTRY_RE.test(country)) {
      return res.status(400).json({ error: "Invalid country code." });
    }

    const list = await readList(ALLOW_LIST_PATH);
    if (!list.has(country)) {
      return res.json({ ok: true, message: "Not in allow list" });
    }

    // Safety: removing last entry while in allow_only mode blocks everyone
    if (list.size === 1) {
      const mode = await getCurrentMode();
      if (mode === "allow_only" && req.query.force !== "true") {
        return res.status(400).json({
          error:
            "Removing the last country from the allow list in allow_only mode would block all traffic. Add ?force=true to override.",
        });
      }
    }

    list.delete(country);
    await writeListAtomic(ALLOW_LIST_PATH, list);
    return res.json({ ok: true, removed: country });
  } catch (err: any) {
    console.error("[geo] DELETE /allow error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /v1/geo/deny ─────────────────────────────────────────────────────
router.post("/deny", async (req: Request, res: Response) => {
  try {
    const { country } = req.body;

    if (!country || !COUNTRY_RE.test(country)) {
      return res.status(400).json({
        error:
          'Invalid country code. Must be uppercase ISO-3166-1 alpha-2 (e.g. "CN").',
      });
    }

    const list = await readList(DENY_LIST_PATH);
    if (list.has(country)) {
      return res.json({ ok: true, message: "Already in deny list" });
    }

    list.add(country);
    await writeListAtomic(DENY_LIST_PATH, list);
    return res.json({ ok: true, added: country });
  } catch (err: any) {
    console.error("[geo] POST /deny error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ─── DELETE /v1/geo/deny/:country ───────────────────────────────────────────
router.delete("/deny/:country", async (req: Request, res: Response) => {
  try {
    const { country } = req.params;

    if (!COUNTRY_RE.test(country)) {
      return res.status(400).json({ error: "Invalid country code." });
    }

    const list = await readList(DENY_LIST_PATH);
    if (!list.has(country)) {
      return res.json({ ok: true, message: "Not in deny list" });
    }

    list.delete(country);
    await writeListAtomic(DENY_LIST_PATH, list);
    return res.json({ ok: true, removed: country });
  } catch (err: any) {
    console.error("[geo] DELETE /deny error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /v1/geo/status ────────────────────────────────────────────────────
router.get("/status", async (_req: Request, res: Response) => {
  try {
    const [mode, allow, deny] = await Promise.all([
      getCurrentMode(),
      readList(ALLOW_LIST_PATH),
      readList(DENY_LIST_PATH),
    ]);

    return res.json({
      mode,
      allow: [...allow].sort(),
      deny: [...deny].sort(),
    });
  } catch (err: any) {
    console.error("[geo] GET /status error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

export { router as geoRoutes };
