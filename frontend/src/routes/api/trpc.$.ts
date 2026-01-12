import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { createAPIFileRoute } from "@tanstack/react-start/api";
import { appRouter } from "@/server/api/root";
import { createTRPCContext } from "@/server/api/trpc";

export const APIRoute = createAPIFileRoute("/api/trpc/$")({
  GET: async ({ request }) => {
    return fetchRequestHandler({
      endpoint: "/api/trpc",
      req: request,
      router: appRouter,
      createContext: () => createTRPCContext({ headers: request.headers }),
      onError:
        process.env.NODE_ENV === "development"
          ? ({ path, error }) => {
              console.error(`tRPC failed on ${path ?? "<no-path>"}: ${error.message}`);
            }
          : undefined,
    });
  },
  POST: async ({ request }) => {
    return fetchRequestHandler({
      endpoint: "/api/trpc",
      req: request,
      router: appRouter,
      createContext: () => createTRPCContext({ headers: request.headers }),
      onError:
        process.env.NODE_ENV === "development"
          ? ({ path, error }) => {
              console.error(`tRPC failed on ${path ?? "<no-path>"}: ${error.message}`);
            }
          : undefined,
    });
  },
});
