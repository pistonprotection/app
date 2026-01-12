import { createTRPCRouter } from "./trpc";
import { backendsRouter } from "./routers/backends";
import { filtersRouter } from "./routers/filters";
import { analyticsRouter } from "./routers/analytics";
import { billingRouter } from "./routers/billing";
import { adminRouter } from "./routers/admin";

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
