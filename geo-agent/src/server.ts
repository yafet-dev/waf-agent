import express from "express";
import { geoRoutes } from "./geoRoutes";

const app = express();
const PORT = process.env.GEO_AGENT_PORT || 8081;

app.use(express.json());

// Mount routes
app.use("/v1/geo", geoRoutes);

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "geo-agent", timestamp: new Date().toISOString() });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("[geo] unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`🌍 Geo Agent listening on http://0.0.0.0:${PORT}`);
});

export default app;
