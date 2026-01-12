import { adminRouter } from "./routers/admin";
import { analyticsRouter } from "./routers/analytics";
import { backendsRouter } from "./routers/backends";
import { billingRouter } from "./routers/billing";
import { filtersRouter } from "./routers/filters";
import { createTRPCRouter } from "./trpc";

/**
 * This is the primary router for your server.
 *
 * All routers added in /api/routers should be manually added here.
 */
export const appRouter = createTRPCRouter({
  backends: backendsRouter,
  filters: filtersRouter,
  analytics: analyticsRouter,
  billing: billingRouter,
  admin: adminRouter,
});

// Export type definition of API
export type AppRouter = typeof appRouter;
