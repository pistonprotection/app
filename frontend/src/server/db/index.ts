import { drizzle } from "drizzle-orm/node-postgres";
import { env } from "@/env";
import * as authSchema from "./auth-schema";
import * as appSchema from "./schema";

export const db = drizzle({
  connection: env.DATABASE_URL,
  schema: {
    ...authSchema,
    ...appSchema,
  },
});
