import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";

export const env = createEnv({
  server: {
    DATABASE_URL: z.string().url(),
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
    BETTER_AUTH_SECRET: z.string().min(32),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    GITHUB_CLIENT_SECRET: z.string().optional(),
    DISCORD_CLIENT_SECRET: z.string().optional(),
    STRIPE_SECRET_KEY: z.string().startsWith("sk_"),
    STRIPE_WEBHOOK_SECRET: z.string().startsWith("whsec_"),
    RESEND_API_KEY: z.string().startsWith("re_"),
    REDIS_URL: z.string().url().optional(),
    CLICKHOUSE_URL: z.string().url().optional(),
    CLICKHOUSE_USERNAME: z.string().optional(),
    CLICKHOUSE_PASSWORD: z.string().optional(),
    GATEWAY_GRPC_URL: z
      .string()
      .url()
      .optional()
      .default("http://localhost:9090"),
  },
  clientPrefix: "PUBLIC_",
  client: {
    PUBLIC_APP_URL: z.string().url().default("http://localhost:3000"),
    PUBLIC_STRIPE_PUBLISHABLE_KEY: z.string().startsWith("pk_"),
    PUBLIC_GOOGLE_CLIENT_ID: z.string().optional(),
    PUBLIC_GITHUB_CLIENT_ID: z.string().optional(),
    PUBLIC_DISCORD_CLIENT_ID: z.string().optional(),
  },
  runtimeEnv: process.env,
  skipValidation: !!process.env.SKIP_ENV_VALIDATION,
  emptyStringAsUndefined: true,
});
