import {
  defaultShouldDehydrateQuery,
  QueryClient,
} from "@tanstack/react-query";
import { isTRPCClientError } from "@trpc/client";
import SuperJSON from "superjson";

export const createQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: {
        // With SSR, we usually want to set some default staleTime
        // above 0 to avoid refetching immediately on the client
        staleTime: 30 * 1000,
        retry: (count, error) => {
          const toAttempt = typeof window === "undefined" ? 0 : 3;

          if (!isTRPCClientError(error) || !error.data) {
            return count < toAttempt;
          }

          const errorData = error.data as {
            httpStatus: number;
          };
          // Don't retry on 4xx errors
          if (errorData.httpStatus >= 400 && errorData.httpStatus < 500) {
            return false;
          }

          return count < toAttempt;
        },
      },
      dehydrate: {
        serializeData: SuperJSON.serialize,
        shouldDehydrateQuery: (query) =>
          defaultShouldDehydrateQuery(query) ||
          query.state.status === "pending",
      },
      hydrate: {
        deserializeData: SuperJSON.deserialize,
      },
    },
  });
