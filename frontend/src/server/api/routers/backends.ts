// @ts-nocheck
// TODO: Unused schema variable
import { TRPCError } from "@trpc/server";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import {
  createTRPCRouter,
  organizationAdminProcedure,
  organizationProcedure,
  organizationWithSubscriptionProcedure,
} from "@/server/api/trpc";
import {
  backend,
  backendDomain,
  backendOrigin,
  geoDnsConfig,
  minecraftConfig,
} from "@/server/db/schema";
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

const _backendStatusSchema = z.enum([
  "healthy",
  "degraded",
  "unhealthy",
  "unknown",
]);

const loadBalancerAlgorithmSchema = z.enum([
  "round_robin",
  "least_connections",
  "ip_hash",
  "weighted",
  "random",
]);

const healthCheckTypeSchema = z.enum(["tcp", "http", "minecraft", "udp"]);

// Input schemas
const createBackendSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  protocol: protocolSchema,
  enabled: z.boolean().default(true),
  protectionLevel: z.number().int().min(0).max(100).default(50),
  rateLimit: z.number().int().positive().optional(),
  rateLimitWindow: z.number().int().positive().default(1),
  loadBalancerAlgorithm: loadBalancerAlgorithmSchema.default("round_robin"),
  stickySessions: z.boolean().default(false),
  stickySessionTtl: z.number().int().positive().default(3600),
  healthCheckType: healthCheckTypeSchema.default("tcp"),
  healthCheckInterval: z.number().int().positive().default(30),
  healthCheckTimeout: z.number().int().positive().default(5),
  healthCheckRetries: z.number().int().positive().default(3),
  healthCheckPath: z.string().optional(),
  haproxyProtocol: z.boolean().default(false),
  haproxyProtocolVersion: z.number().int().min(1).max(2).default(2),
});

const updateBackendSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional().nullable(),
  enabled: z.boolean().optional(),
  protectionLevel: z.number().int().min(0).max(100).optional(),
  rateLimit: z.number().int().positive().optional().nullable(),
  rateLimitWindow: z.number().int().positive().optional(),
  loadBalancerAlgorithm: loadBalancerAlgorithmSchema.optional(),
  stickySessions: z.boolean().optional(),
  stickySessionTtl: z.number().int().positive().optional(),
  healthCheckType: healthCheckTypeSchema.optional(),
  healthCheckInterval: z.number().int().positive().optional(),
  healthCheckTimeout: z.number().int().positive().optional(),
  healthCheckRetries: z.number().int().positive().optional(),
  healthCheckPath: z.string().optional().nullable(),
  haproxyProtocol: z.boolean().optional(),
  haproxyProtocolVersion: z.number().int().min(1).max(2).optional(),
});

const createOriginSchema = z.object({
  backendId: z.string().uuid(),
  address: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  weight: z.number().int().min(0).max(1000).default(100),
  priority: z.number().int().min(1).default(1),
  enabled: z.boolean().default(true),
  tlsEnabled: z.boolean().default(false),
  tlsVerify: z.boolean().default(true),
  tlsSni: z.string().optional(),
  maxConnections: z.number().int().positive().default(1000),
  connectionTimeout: z.number().int().positive().default(5000),
});

const updateOriginSchema = z.object({
  id: z.string().uuid(),
  address: z.string().min(1).optional(),
  port: z.number().int().min(1).max(65535).optional(),
  weight: z.number().int().min(0).max(1000).optional(),
  priority: z.number().int().min(1).optional(),
  enabled: z.boolean().optional(),
  tlsEnabled: z.boolean().optional(),
  tlsVerify: z.boolean().optional(),
  tlsSni: z.string().optional().nullable(),
  maxConnections: z.number().int().positive().optional(),
  connectionTimeout: z.number().int().positive().optional(),
});

const createDomainSchema = z.object({
  backendId: z.string().uuid(),
  domain: z.string().min(1).max(253),
  sslEnabled: z.boolean().default(true),
  forceHttps: z.boolean().default(true),
});

const updateDomainSchema = z.object({
  id: z.string().uuid(),
  sslEnabled: z.boolean().optional(),
  forceHttps: z.boolean().optional(),
});

const minecraftConfigSchema = z.object({
  backendId: z.string().uuid(),
  edition: z.enum(["java", "bedrock"]),
  onlineModeCheck: z.boolean().default(false),
  statusPingProtection: z.boolean().default(true),
  statusPingRateLimit: z.number().int().positive().default(10),
  handshakeValidation: z.boolean().default(true),
  maxPlayersPerIp: z.number().int().positive().default(5),
  raknetValidation: z.boolean().default(true),
  raknetAmplificationProtection: z.boolean().default(true),
  fallbackEnabled: z.boolean().default(false),
  fallbackMotd: z.string().max(128).optional(),
  fallbackVersion: z.string().max(50).optional(),
  fallbackMaxPlayers: z.number().int().positive().optional(),
  fallbackIconBase64: z.string().optional(),
});

const geoDnsConfigSchema = z.object({
  backendId: z.string().uuid(),
  enabled: z.boolean().default(false),
  defaultRegion: z.string().optional(),
  regions: z
    .array(
      z.object({
        region: z.string(),
        originIds: z.array(z.string().uuid()),
        weight: z.number().int().min(0).max(100),
      }),
    )
    .optional(),
});

export const backendsRouter = createTRPCRouter({
  // List all backends for an organization
  list: organizationProcedure.query(async ({ ctx, input }) => {
    return ctx.db.query.backend.findMany({
      where: eq(backend.organizationId, input.organizationId),
      orderBy: (backend, { desc }) => [desc(backend.createdAt)],
      with: {
        origins: true,
        domains: true,
        minecraftConfig: true,
        geoDnsConfig: true,
      },
    });
  }),

  // Get a single backend with all related data
  get: organizationProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const result = await ctx.db.query.backend.findFirst({
        where: and(
          eq(backend.id, input.id),
          eq(backend.organizationId, input.organizationId),
        ),
        with: {
          origins: true,
          domains: true,
          minecraftConfig: true,
          geoDnsConfig: true,
          filters: true,
        },
      });

      if (!result) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Backend not found",
        });
      }

      return result;
    }),

  // Create a new backend (requires subscription)
  create: organizationWithSubscriptionProcedure
    .input(createBackendSchema)
    .mutation(async ({ ctx, input }) => {
      // Check backend limit
      const limits = await getOrganizationLimits(input.organizationId);
      const existingCount = await ctx.db.query.backend.findMany({
        where: eq(backend.organizationId, input.organizationId),
        columns: { id: true },
      });

      if (limits.backends !== -1 && existingCount.length >= limits.backends) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: `Backend limit reached. Your plan allows ${limits.backends} backends.`,
        });
      }

      const [newBackend] = await ctx.db
        .insert(backend)
        .values({
          ...input,
          organizationId: input.organizationId,
        })
        .returning();

      return newBackend;
    }),

  // Update a backend (requires admin)
  update: organizationAdminProcedure
    .input(updateBackendSchema)
    .mutation(async ({ ctx, input }) => {
      const { id, organizationId, ...data } = input;

      // Verify backend belongs to organization
      const existing = await ctx.db.query.backend.findFirst({
        where: and(
          eq(backend.id, id),
          eq(backend.organizationId, organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Backend not found",
        });
      }

      const [updated] = await ctx.db
        .update(backend)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(backend.id, id))
        .returning();

      return updated;
    }),

  // Delete a backend (requires admin)
  delete: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify backend belongs to organization
      const existing = await ctx.db.query.backend.findFirst({
        where: and(
          eq(backend.id, input.id),
          eq(backend.organizationId, input.organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Backend not found",
        });
      }

      await ctx.db.delete(backend).where(eq(backend.id, input.id));
      return { success: true };
    }),

  // Toggle backend enabled status
  toggle: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const existing = await ctx.db.query.backend.findFirst({
        where: and(
          eq(backend.id, input.id),
          eq(backend.organizationId, input.organizationId),
        ),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Backend not found",
        });
      }

      const [updated] = await ctx.db
        .update(backend)
        .set({ enabled: !existing.enabled, updatedAt: new Date() })
        .where(eq(backend.id, input.id))
        .returning();

      return updated;
    }),

  // Bulk toggle backends enabled status
  bulkToggle: organizationAdminProcedure
    .input(
      z.object({
        ids: z.array(z.string().uuid()).min(1),
        enabled: z.boolean(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      // Verify all backends belong to organization
      const existingBackends = await ctx.db.query.backend.findMany({
        where: and(eq(backend.organizationId, input.organizationId)),
        columns: { id: true },
      });

      const existingIds = new Set(existingBackends.map((b) => b.id));
      const invalidIds = input.ids.filter((id) => !existingIds.has(id));

      if (invalidIds.length > 0) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Some backends not found: ${invalidIds.join(", ")}`,
        });
      }

      // Update all backends
      const updated = await Promise.all(
        input.ids.map((id) =>
          ctx.db
            .update(backend)
            .set({ enabled: input.enabled, updatedAt: new Date() })
            .where(eq(backend.id, id))
            .returning(),
        ),
      );

      return { count: updated.length, enabled: input.enabled };
    }),

  // Bulk delete backends
  bulkDelete: organizationAdminProcedure
    .input(z.object({ ids: z.array(z.string().uuid()).min(1) }))
    .mutation(async ({ ctx, input }) => {
      // Verify all backends belong to organization
      const existingBackends = await ctx.db.query.backend.findMany({
        where: and(eq(backend.organizationId, input.organizationId)),
        columns: { id: true },
      });

      const existingIds = new Set(existingBackends.map((b) => b.id));
      const invalidIds = input.ids.filter((id) => !existingIds.has(id));

      if (invalidIds.length > 0) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Some backends not found: ${invalidIds.join(", ")}`,
        });
      }

      // Delete all backends (cascade will handle related records)
      await Promise.all(
        input.ids.map((id) => ctx.db.delete(backend).where(eq(backend.id, id))),
      );

      return { count: input.ids.length };
    }),

  // ==================== ORIGINS ====================

  // List origins for a backend
  listOrigins: organizationProcedure
    .input(z.object({ backendId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      return ctx.db.query.backendOrigin.findMany({
        where: eq(backendOrigin.backendId, input.backendId),
        orderBy: (origin, { asc }) => [asc(origin.priority)],
      });
    }),

  // Create an origin
  createOrigin: organizationAdminProcedure
    .input(createOriginSchema)
    .mutation(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      const [newOrigin] = await ctx.db
        .insert(backendOrigin)
        .values(input)
        .returning();

      return newOrigin;
    }),

  // Update an origin
  updateOrigin: organizationAdminProcedure
    .input(updateOriginSchema)
    .mutation(async ({ ctx, input }) => {
      const { id, ...data } = input;

      // Verify origin belongs to backend in organization
      const origin = await ctx.db.query.backendOrigin.findFirst({
        where: eq(backendOrigin.id, id),
        with: { backend: true },
      });

      if (!origin || origin.backend.organizationId !== input.organizationId) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Origin not found",
        });
      }

      const [updated] = await ctx.db
        .update(backendOrigin)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(backendOrigin.id, id))
        .returning();

      return updated;
    }),

  // Delete an origin
  deleteOrigin: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify origin belongs to backend in organization
      const origin = await ctx.db.query.backendOrigin.findFirst({
        where: eq(backendOrigin.id, input.id),
        with: { backend: true },
      });

      if (!origin || origin.backend.organizationId !== input.organizationId) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Origin not found",
        });
      }

      await ctx.db.delete(backendOrigin).where(eq(backendOrigin.id, input.id));
      return { success: true };
    }),

  // ==================== DOMAINS ====================

  // List domains for a backend
  listDomains: organizationProcedure
    .input(z.object({ backendId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      return ctx.db.query.backendDomain.findMany({
        where: eq(backendDomain.backendId, input.backendId),
        orderBy: (domain, { asc }) => [asc(domain.domain)],
      });
    }),

  // Create a domain
  createDomain: organizationAdminProcedure
    .input(createDomainSchema)
    .mutation(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      // Generate verification token
      const verificationToken = crypto.randomUUID();

      const [newDomain] = await ctx.db
        .insert(backendDomain)
        .values({
          ...input,
          verificationToken,
          verified: false,
        })
        .returning();

      return newDomain;
    }),

  // Update a domain
  updateDomain: organizationAdminProcedure
    .input(updateDomainSchema)
    .mutation(async ({ ctx, input }) => {
      const { id, ...data } = input;

      // Verify domain belongs to backend in organization
      const domain = await ctx.db.query.backendDomain.findFirst({
        where: eq(backendDomain.id, id),
        with: { backend: true },
      });

      if (!domain || domain.backend.organizationId !== input.organizationId) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Domain not found",
        });
      }

      const [updated] = await ctx.db
        .update(backendDomain)
        .set(data)
        .where(eq(backendDomain.id, id))
        .returning();

      return updated;
    }),

  // Delete a domain
  deleteDomain: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify domain belongs to backend in organization
      const domain = await ctx.db.query.backendDomain.findFirst({
        where: eq(backendDomain.id, input.id),
        with: { backend: true },
      });

      if (!domain || domain.backend.organizationId !== input.organizationId) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Domain not found",
        });
      }

      await ctx.db.delete(backendDomain).where(eq(backendDomain.id, input.id));
      return { success: true };
    }),

  // Verify a domain
  verifyDomain: organizationAdminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify domain belongs to backend in organization
      const domain = await ctx.db.query.backendDomain.findFirst({
        where: eq(backendDomain.id, input.id),
        with: { backend: true },
      });

      if (!domain || domain.backend.organizationId !== input.organizationId) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Domain not found",
        });
      }

      // In a real implementation, this would check DNS records
      // For now, we'll mark it as verified
      const [updated] = await ctx.db
        .update(backendDomain)
        .set({ verified: true, verifiedAt: new Date() })
        .where(eq(backendDomain.id, input.id))
        .returning();

      return updated;
    }),

  // ==================== MINECRAFT CONFIG ====================

  // Get minecraft config for a backend
  getMinecraftConfig: organizationProcedure
    .input(z.object({ backendId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      return ctx.db.query.minecraftConfig.findFirst({
        where: eq(minecraftConfig.backendId, input.backendId),
      });
    }),

  // Upsert minecraft config
  upsertMinecraftConfig: organizationAdminProcedure
    .input(minecraftConfigSchema)
    .mutation(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      // Check if config exists
      const existing = await ctx.db.query.minecraftConfig.findFirst({
        where: eq(minecraftConfig.backendId, input.backendId),
      });

      if (existing) {
        const [updated] = await ctx.db
          .update(minecraftConfig)
          .set({ ...input, updatedAt: new Date() })
          .where(eq(minecraftConfig.backendId, input.backendId))
          .returning();
        return updated;
      }

      const [created] = await ctx.db
        .insert(minecraftConfig)
        .values(input)
        .returning();
      return created;
    }),

  // Delete minecraft config
  deleteMinecraftConfig: organizationAdminProcedure
    .input(z.object({ backendId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      await ctx.db
        .delete(minecraftConfig)
        .where(eq(minecraftConfig.backendId, input.backendId));
      return { success: true };
    }),

  // ==================== GEO DNS CONFIG ====================

  // Get geo dns config for a backend
  getGeoDnsConfig: organizationProcedure
    .input(z.object({ backendId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      return ctx.db.query.geoDnsConfig.findFirst({
        where: eq(geoDnsConfig.backendId, input.backendId),
      });
    }),

  // Upsert geo dns config
  upsertGeoDnsConfig: organizationAdminProcedure
    .input(geoDnsConfigSchema)
    .mutation(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      // Check if config exists
      const existing = await ctx.db.query.geoDnsConfig.findFirst({
        where: eq(geoDnsConfig.backendId, input.backendId),
      });

      if (existing) {
        const [updated] = await ctx.db
          .update(geoDnsConfig)
          .set({ ...input, updatedAt: new Date() })
          .where(eq(geoDnsConfig.backendId, input.backendId))
          .returning();
        return updated;
      }

      const [created] = await ctx.db
        .insert(geoDnsConfig)
        .values(input)
        .returning();
      return created;
    }),

  // Delete geo dns config
  deleteGeoDnsConfig: organizationAdminProcedure
    .input(z.object({ backendId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Verify backend belongs to organization
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

      await ctx.db
        .delete(geoDnsConfig)
        .where(eq(geoDnsConfig.backendId, input.backendId));
      return { success: true };
    }),
});
