import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import { ZodError, z } from "zod";
import { auth, type Organization, type Session } from "@/server/auth";
import { db } from "@/server/db";
import {
  getProtectionOrganizationById,
  getRoleOfUserInOrg,
  hasActiveSubscription,
} from "@/server/server-utils";

/**
 * Context creation for tRPC procedures
 */
export const createTRPCContext = async (opts: { headers: Headers }) => {
  const session = await auth.api.getSession({ headers: opts.headers });
  return {
    db,
    session,
    ...opts,
  };
};

/**
 * Initialize tRPC with context and transformer
 */
const t = initTRPC.context<typeof createTRPCContext>().create({
  transformer: superjson,
  errorFormatter({ shape, error }) {
    return {
      ...shape,
      data: {
        ...shape.data,
        zodError:
          error.cause instanceof ZodError ? error.cause.flatten() : null,
      },
    };
  },
});

export const createTRPCRouter = t.router;

/**
 * Timing middleware for development
 */
const timingMiddleware = t.middleware(async ({ next, path }) => {
  const start = Date.now();

  if (t._config.isDev) {
    const waitMs = Math.floor(Math.random() * 100) + 50;
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }

  const result = await next();

  const end = Date.now();
  console.log(`[TRPC] ${path} took ${end - start}ms`);

  return result;
});

/**
 * Public procedure - no authentication required
 */
export const publicProcedure = t.procedure.use(timingMiddleware);

/**
 * Protected procedure - requires authenticated user
 */
const enforceUserIsAuthed = t.middleware(({ ctx, next }) => {
  if (!ctx.session?.user) {
    throw new TRPCError({ code: "UNAUTHORIZED" });
  }
  return next({
    ctx: {
      session: { ...ctx.session, user: ctx.session.user },
    },
  });
});

export const protectedProcedure = t.procedure
  .use(timingMiddleware)
  .use(enforceUserIsAuthed);

/**
 * Platform admin procedure - requires admin role
 */
const enforceUserIsPlatformAdmin = enforceUserIsAuthed.unstable_pipe(
  ({ ctx, next }) => {
    if (ctx.session.user.role !== "admin") {
      throw new TRPCError({ code: "FORBIDDEN" });
    }
    return next({ ctx });
  },
);

export const adminProcedure = t.procedure
  .use(timingMiddleware)
  .use(enforceUserIsPlatformAdmin);

/**
 * Organization procedure - requires organization context
 */
export const organizationProcedure = protectedProcedure
  .input(z.object({ organizationId: z.string().uuid() }))
  .use(async ({ ctx, input, next }) => {
    const organization = await auth.api.getFullOrganization({
      headers: ctx.headers,
      query: {
        organizationId: input.organizationId,
      },
    });

    if (!organization) {
      throw new TRPCError({
        code: "NOT_FOUND",
        message: "Organization not found",
      });
    }

    return next({
      ctx: {
        ...ctx,
        organization,
      },
    });
  });

/**
 * Organization owner procedure - requires owner role
 */
export const organizationOwnerProcedure = organizationProcedure.use(
  async ({ ctx, input, next }) => {
    const role = await getRoleOfUserInOrg(
      ctx.session.user.id,
      input.organizationId,
    );

    if (role !== "owner") {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: "You must be an organization owner to perform this action",
      });
    }

    return next({ ctx });
  },
);

/**
 * Organization admin procedure - requires admin or owner role
 */
export const organizationAdminProcedure = organizationProcedure.use(
  async ({ ctx, input, next }) => {
    const role = await getRoleOfUserInOrg(
      ctx.session.user.id,
      input.organizationId,
    );

    if (role !== "owner" && role !== "admin") {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: "You must be an organization admin to perform this action",
      });
    }

    return next({ ctx });
  },
);

/**
 * Organization with subscription procedure - requires active subscription
 */
export const organizationWithSubscriptionProcedure = organizationProcedure.use(
  async ({ ctx, input, next }) => {
    const hasSubscription = await hasActiveSubscription(input.organizationId);

    if (!hasSubscription) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: "Active subscription required to access this feature",
      });
    }

    const protectionOrg = await getProtectionOrganizationById(
      input.organizationId,
    );

    return next({
      ctx: {
        ...ctx,
        protectionOrganization: protectionOrg,
      },
    });
  },
);

// Type exports for use in routers
export type Context = Awaited<ReturnType<typeof createTRPCContext>>;
export type ProtectedContext = Context & { session: Session };
export type OrganizationContext = ProtectedContext & {
  organization: Organization;
};
