import { Worker } from "bullmq";
import Redis from "ioredis";
import pino from "pino";
import { z } from "zod";

const log = pino();
const payload = z.object({ id: z.string() });
const connection = new Redis(process.env.REDIS_URL || "redis://localhost:6379");
new Worker("jobs", async job => log.info(payload.parse(job.data)), { connection });
