import express from "express";
import auth from "@acme/auth-client";
import audit from "@acme/audit-events";

const app = express();
app.get("/healthz", (_req, res) => {
  audit.record("healthcheck", auth.subject());
  res.send("ok");
});
