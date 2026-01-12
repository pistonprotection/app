import { TRPCError } from "@trpc/server";
import { and, eq, gte, isNull, lt, or } from "drizzle-orm";
import { z } from "zod";
import {
  createTRPCRouter,
  organizationAdminProcedure,
  organizationProcedure,
  organizationWithSubscriptionProcedure,
} from "@/server/api/trpc";
import { backend, filter, ipList } from "@/server/db/schema";
import { getOrganizationLimits } from "@/server/server-utils";

// Zod schemas for validation
const protocolSchema = z.enum([
  "tcp",
  "udp",
  "http",
  "https",
  "quic",
  "minecraft_java",
  "minecraft_bedrock",
]);

const filterActionSchema = z.enum([
  "allow",
  "block",
  "rate_limit",
  "challenge",
  "drop",
]);

// Input schemas for filters
const createFilterSchema = z.object({
  backendId: z.string().uuid().optional(),
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  protocol: protocolSchema.optional(),
  action: filterActionSchema,
  priority: z.number().int().min(0).max(10000).default(100),
  enabled: z.boolean().default(true),
  // Match conditions
  sourceIps: z.array(z.string()).optional(),
  sourceCidrs: z.array(z.string()).optional(),
  sourceCountries: z.array(z.string().length(2)).optional(),
  sourceAsns: z.array(z.number().int().positive()).optional(),
  destPorts: z.array(z.number().int().min(1).max(65535)).optional(),
  // L7 specific conditions
  httpMethods: z
    .array(z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]))
    .optional(),
  httpPaths: z.array(z.string()).optional(),
  httpHosts: z.array(z.string()).optional(),
  httpHeaders: z.record(z.string()).optional(),
  httpUserAgents: z.array(z.string()).optional(),
  // Rate limiting
  rateLimit: z.number().int().positive().optional(),
  rateLimitWindow: z.number().int().positive().optional(),
  rateLimitBurst: z.number().int().positive().optional(),
  // Time-based activation
  activeFrom: z.date().optional(),
  activeTo: z.date().optional(),
  activeDays: z.array(z.number().int().min(0).max(6)).optional(),
  activeHoursStart: z.number().int().min(0).max(23).optional(),
  activeHoursEnd: z.number().int().min(0).max(23).optional(),
});

const updateFilterSchema = z.object({
  id: z.string().uuid(),
  backendId: z.string().uuid().optional().nullable(),
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional().nullable(),
  protocol: protocolSchema.optional().nullable(),
  action: filterActionSchema.optional(),
  priority: z.number().int().min(0).max(10000).optional(),
  enabled: z.boolean().optional(),
  // Match conditions
  sourceIps: z.array(z.string()).optional().nullable(),
  sourceCidrs: z.array(z.string()).optional().nullable(),
  sourceCountries: z.array(z.string().length(2)).optional().nullable(),
  sourceAsns: z.array(z.number().int().positive()).optional().nullable(),
  destPorts: z.array(z.number().int().min(1).max(65535)).optional().nullable(),
  // L7 specific conditions
  httpMethods: z
    .array(z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]))
    .optional()
    .nullable(),
  httpPaths: z.array(z.string()).optional().nullable(),
  httpHosts: z.array(z.string()).optional().nullable(),
  httpHeaders: z.record(z.string()).optional().nullable(),
  httpUserAgents: z.array(z.string()).optional().nullable(),
  // Rate limiting
  rateLimit: z.number().int().positive().optional().nullable(),
  rateLimitWindow: z.number().int().positive().optional().nullable(),
  rateLimitBurst: z.number().int().positive().optional().nullable(),
  // Time-based activation
  activeFrom: z.date().optional().nullable(),
  activeTo: z.date().optional().nullable(),
  activeDays: z.array(z.number().int().min(0).max(6)).optional().nullable(),
  activeHoursStart: z.number().int().min(0).max(23).optional().nullable(),
  activeHoursEnd: z.number().int().min(0).max(23).optional().nullable(),
});

// Input schemas for IP lists
const createIpListSchema = z.object({
  ip: z.string().min(1).max(45),
  cidr: z.number().int().min(0).max(128).optional(),
  type: z.enum(["allow", "block"]),
  reason: z.string().max(255).optional(),
  source: z.enum(["manual", "automatic", "api"]).default("manual"),
  expiresAt: z.date().optional(),
});

const updateIpListSchema = z.object({
  id: z.string().uuid(),
  type: z.enum(["allow", "block"]).optional(),
  reason: z.string().max(255).optional().nullable(),
  expiresAt: z.date().optional().nullable(),
});

export const filtersRouter = createTRPCRouter({
  // ==================== FILTER RULES ====================

  // List all filters for an organization
  list: organizationProcedure
    .input(
      z
        .object({
          backendId: z.string().uuid().optional(),
          enabled: z.boolean().optional(),
        })
        .partial(),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [eq(filter.organizationId, input.organizationId)];

      if (input.backendId) {
        conditions.push(eq(filter.backendId, input.backendId));
      }

      if (input.enabled !== undefined) {
        conditions.push(eq(filter.enabled, input.enabled));
      }

      return ctx.db.query.filter.findMany({
        where: and(...conditions),
        orderBy: (filter, { asc }) => [asc(filter.priority)],
        with: {
          backend: {
            columns: { id: true, name: true },
          },
        },
      });
    }),

  // Get a single filter
  get: organizationProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const result = await ctx.db.query.filter.findFirst({
        where: and(
          eq(filter.id, input.id),
          eq(filter.organizationId, input.organizationId),
        ),
        with: {
          backend: true,
        },
      });

      if (!result) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Filter not found",
        });
      }

      return result;
    }),

  // Create a new filter (requires subscription)
  create: organizationWithSubscriptionProcedure
    .input(createFilterSchema)
    .mutation(async ({ ctx, input }) => {
      // Check filter limit
      const limits = await getOrganizationLimits(input.organizationId);
      const existingCount = await ctx.db.query.filter.findMany({
        where: eq(filter.organizationId, input.organizationId),
        columns: { id: true },
      });

      if (limits.filters !== -1 && existingCount.length >= limits.filters) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: `Filter limit reached. Your plan allows ${limits.filters} filters.`,
        });
      }

      // If backendId is provided, verify it belongs to the organization
      if (input.backendId) {
        const backendRecord = await ctx.db.query.backend.findFirst({
          where: and(
            eq(backend.id, input.backendId),
            eq(backend.organizationId, input.organizationId),
          ),
        });

        if (!backendRecord) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "Backend not found",
          });
        }
      }

      const [newFilter] = await ctx.db
        .insert(filter)
        .values({
          ...input,
          organizationId: input.organizationId,
        })
        .returning();

      return newFilter;
    }),

  // Update a filter (requires admin)
  update: organizationAdminProcedure
    .input(updateFilterSchema)
    .mutation(async ({ ctx, input }) => {
      const { id, organizationId, ...data } = input;

      // Verify filter belongs to organization
      const existing = await ctx.db.query.filter.findFirst({
        where: and(
          eq(filter.id, id),
          eq(filter.organizationId, organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Filter not found",
        });
      }

      // If backendId is provided, verify it belongs to the organization
      if (data.backendId) {
        const backendRecord = await ctx.db.query.backend.findFirst({
          where: and(
            eq(backend.id, data.backendId),
            eq(backend.organizationId, organizationId),
          ),
        });

        if (!backendRecord) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "Backend not found",
          });
        }
      }

      const [updated] = await ctx.db
        .update(filter)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(filter.id, id))
        .returning();

      return updated;
    }),

  // Delete a filter (requires admin)
  delete: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify filter belongs to organization
      const existing = await ctx.db.query.filter.findFirst({
        where: and(
          eq(filter.id, input.id),
          eq(filter.organizationId, input.organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Filter not found",
        });
      }

      await ctx.db.delete(filter).where(eq(filter.id, input.id));
      return { success: true };
    }),

  // Toggle filter enabled status
  toggle: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const existing = await ctx.db.query.filter.findFirst({
        where: and(
          eq(filter.id, input.id),
          eq(filter.organizationId, input.organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Filter not found",
        });
      }

      const [updated] = await ctx.db
        .update(filter)
        .set({ enabled: !existing.enabled, updatedAt: new Date() })
        .where(eq(filter.id, input.id))
        .returning();

      return updated;
    }),

  // Bulk update filter priorities
  updatePriorities: organizationAdminProcedure
    .input(
      z.object({
        filters: z.array(
          z.object({
            id: z.string().uuid(),
            priority: z.number().int().min(0).max(10000),
          }),
        ),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const results = [];

      for (const { id, priority } of input.filters) {
        // Verify filter belongs to organization
        const existing = await ctx.db.query.filter.findFirst({
          where: and(
            eq(filter.id, id),
            eq(filter.organizationId, input.organizationId),
          ),
        });

        if (existing) {
          const [updated] = await ctx.db
            .update(filter)
            .set({ priority, updatedAt: new Date() })
            .where(eq(filter.id, id))
            .returning();
          results.push(updated);
        }
      }

      return results;
    }),

  // Duplicate a filter
  duplicate: organizationWithSubscriptionProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Check filter limit
      const limits = await getOrganizationLimits(input.organizationId);
      const existingCount = await ctx.db.query.filter.findMany({
        where: eq(filter.organizationId, input.organizationId),
        columns: { id: true },
      });

      if (limits.filters !== -1 && existingCount.length >= limits.filters) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: `Filter limit reached. Your plan allows ${limits.filters} filters.`,
        });
      }

      const existing = await ctx.db.query.filter.findFirst({
        where: and(
          eq(filter.id, input.id),
          eq(filter.organizationId, input.organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Filter not found",
        });
      }

      // Create a copy with a modified name
      const { id, createdAt, updatedAt, matchCount, lastMatch, ...filterData } =
        existing;

      const [newFilter] = await ctx.db
        .insert(filter)
        .values({
          ...filterData,
          name: `${filterData.name} (copy)`,
          enabled: false, // Start disabled
        })
        .returning();

      return newFilter;
    }),

  // ==================== IP LISTS ====================

  // List all IP list entries for an organization
  listIpList: organizationProcedure
    .input(
      z
        .object({
          type: z.enum(["allow", "block"]).optional(),
          includeExpired: z.boolean().default(false),
        })
        .partial(),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [eq(ipList.organizationId, input.organizationId)];

      if (input.type) {
        conditions.push(eq(ipList.type, input.type));
      }

      if (!input.includeExpired) {
        const expiryCondition = or(
          isNull(ipList.expiresAt),
          gte(ipList.expiresAt, new Date()),
        );
        if (expiryCondition) {
          conditions.push(expiryCondition);
        }
      }

      return ctx.db.query.ipList.findMany({
        where: and(...conditions),
        orderBy: (ipList, { desc }) => [desc(ipList.createdAt)],
        with: {
          createdByUser: {
            columns: { id: true, name: true, email: true },
          },
        },
      });
    }),

  // Get a single IP list entry
  getIpListEntry: organizationProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const result = await ctx.db.query.ipList.findFirst({
        where: and(
          eq(ipList.id, input.id),
          eq(ipList.organizationId, input.organizationId),
        ),
        with: {
          createdByUser: {
            columns: { id: true, name: true, email: true },
          },
        },
      });

      if (!result) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "IP list entry not found",
        });
      }

      return result;
    }),

  // Create a new IP list entry
  createIpListEntry: organizationAdminProcedure
    .input(createIpListSchema)
    .mutation(async ({ ctx, input }) => {
      // Check if IP already exists in the list
      const existing = await ctx.db.query.ipList.findFirst({
        where: and(
          eq(ipList.organizationId, input.organizationId),
          eq(ipList.ip, input.ip),
        ),
      });

      if (existing) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "IP already exists in the list",
        });
      }

      const [newEntry] = await ctx.db
        .insert(ipList)
        .values({
          ...input,
          organizationId: input.organizationId,
          createdBy: ctx.session.user.id,
        })
        .returning();

      return newEntry;
    }),

  // Update an IP list entry
  updateIpListEntry: organizationAdminProcedure
    .input(updateIpListSchema)
    .mutation(async ({ ctx, input }) => {
      const { id, organizationId, ...data } = input;

      // Verify entry belongs to organization
      const existing = await ctx.db.query.ipList.findFirst({
        where: and(
          eq(ipList.id, id),
          eq(ipList.organizationId, organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "IP list entry not found",
        });
      }

      const [updated] = await ctx.db
        .update(ipList)
        .set(data)
        .where(eq(ipList.id, id))
        .returning();

      return updated;
    }),

  // Delete an IP list entry
  deleteIpListEntry: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify entry belongs to organization
      const existing = await ctx.db.query.ipList.findFirst({
        where: and(
          eq(ipList.id, input.id),
          eq(ipList.organizationId, input.organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "IP list entry not found",
        });
      }

      await ctx.db.delete(ipList).where(eq(ipList.id, input.id));
      return { success: true };
    }),

  // Bulk add IPs to the list
  bulkAddIpList: organizationAdminProcedure
    .input(
      z.object({
        entries: z.array(
          z.object({
            ip: z.string().min(1).max(45),
            cidr: z.number().int().min(0).max(128).optional(),
            type: z.enum(["allow", "block"]),
            reason: z.string().max(255).optional(),
            expiresAt: z.date().optional(),
          }),
        ),
        source: z.enum(["manual", "automatic", "api"]).default("manual"),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const results = {
        added: 0,
        skipped: 0,
        errors: [] as string[],
      };

      for (const entry of input.entries) {
        try {
          // Check if IP already exists
          const existing = await ctx.db.query.ipList.findFirst({
            where: and(
              eq(ipList.organizationId, input.organizationId),
              eq(ipList.ip, entry.ip),
            ),
          });

          if (existing) {
            results.skipped++;
            continue;
          }

          await ctx.db.insert(ipList).values({
            ...entry,
            organizationId: input.organizationId,
            source: input.source,
            createdBy: ctx.session.user.id,
          });

          results.added++;
        } catch (_error) {
          results.errors.push(`Failed to add ${entry.ip}`);
        }
      }

      return results;
    }),

  // Delete expired IP list entries
  cleanupExpiredIpList: organizationAdminProcedure.mutation(
    async ({ ctx, input }) => {
      const now = new Date();

      const deleted = await ctx.db
        .delete(ipList)
        .where(
          and(
            eq(ipList.organizationId, input.organizationId),
            lt(ipList.expiresAt, now),
          ),
        )
        .returning();

      return { deleted: deleted.length };
    },
  ),

  // Search IP in the list
  searchIpList: organizationProcedure
    .input(z.object({ query: z.string().min(1) }))
    .query(async ({ ctx, input }) => {
      // This is a simple search - for production, you'd want to implement
      // proper CIDR matching logic
      return ctx.db.query.ipList.findMany({
        where: and(
          eq(ipList.organizationId, input.organizationId),
          eq(ipList.ip, input.query),
        ),
        with: {
          createdByUser: {
            columns: { id: true, name: true },
          },
        },
      });
    }),
});
