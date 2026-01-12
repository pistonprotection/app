import { TRPCError } from "@trpc/server";
import { and, desc, eq, gte, like, lte, or, sql } from "drizzle-orm";
import { z } from "zod";
import { adminProcedure, createTRPCRouter } from "@/server/api/trpc";
import { organization, subscription, user } from "@/server/db/auth-schema";
import {
  attackEvent,
  auditLog,
  backend,
  filter,
  ipScore,
  protectionOrganization,
  trafficMetric,
} from "@/server/db/schema";

export const adminRouter = createTRPCRouter({
  // ==================== USER MANAGEMENT ====================

  // List all users with pagination and search
  listUsers: adminProcedure
    .input(
      z.object({
        search: z.string().optional(),
        role: z.enum(["user", "admin"]).optional(),
        banned: z.boolean().optional(),
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
      }),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [];

      if (input.search) {
        conditions.push(
          or(
            like(user.email, `%${input.search}%`),
            like(user.name, `%${input.search}%`),
            like(user.username, `%${input.search}%`),
          ),
        );
      }

      if (input.role) {
        conditions.push(eq(user.role, input.role));
      }

      if (input.banned !== undefined) {
        conditions.push(eq(user.banned, input.banned));
      }

      const users = await ctx.db.query.user.findMany({
        where: conditions.length > 0 ? and(...conditions) : undefined,
        orderBy: [desc(user.createdAt)],
        limit: input.limit,
        offset: input.offset,
        columns: {
          id: true,
          name: true,
          email: true,
          emailVerified: true,
          username: true,
          role: true,
          banned: true,
          banReason: true,
          banExpires: true,
          createdAt: true,
          twoFactorEnabled: true,
        },
      });

      const countResult = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(user)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      return {
        users,
        total: countResult[0]?.count ?? 0,
      };
    }),

  // Get a single user with their organizations
  getUser: adminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const result = await ctx.db.query.user.findFirst({
        where: eq(user.id, input.id),
        columns: {
          id: true,
          name: true,
          email: true,
          emailVerified: true,
          username: true,
          role: true,
          banned: true,
          banReason: true,
          banExpires: true,
          createdAt: true,
          updatedAt: true,
          twoFactorEnabled: true,
          image: true,
        },
        with: {
          members: {
            with: {
              organization: true,
            },
          },
        },
      });

      if (!result) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "User not found",
        });
      }

      return result;
    }),

  // Update user role
  updateUserRole: adminProcedure
    .input(
      z.object({
        userId: z.string().uuid(),
        role: z.enum(["user", "admin"]),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      // Prevent admin from changing their own role
      if (input.userId === ctx.session.user.id) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Cannot change your own role",
        });
      }

      const [updated] = await ctx.db
        .update(user)
        .set({ role: input.role, updatedAt: new Date() })
        .where(eq(user.id, input.userId))
        .returning();

      return updated;
    }),

  // Ban user
  banUser: adminProcedure
    .input(
      z.object({
        userId: z.string().uuid(),
        reason: z.string().min(1).max(500),
        expiresAt: z.date().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      // Prevent admin from banning themselves
      if (input.userId === ctx.session.user.id) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Cannot ban yourself",
        });
      }

      const [updated] = await ctx.db
        .update(user)
        .set({
          banned: true,
          banReason: input.reason,
          banExpires: input.expiresAt,
          updatedAt: new Date(),
        })
        .where(eq(user.id, input.userId))
        .returning();

      return updated;
    }),

  // Unban user
  unbanUser: adminProcedure
    .input(z.object({ userId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const [updated] = await ctx.db
        .update(user)
        .set({
          banned: false,
          banReason: null,
          banExpires: null,
          updatedAt: new Date(),
        })
        .where(eq(user.id, input.userId))
        .returning();

      return updated;
    }),

  // Delete user (soft delete - sets banned)
  deleteUser: adminProcedure
    .input(z.object({ userId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      if (input.userId === ctx.session.user.id) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Cannot delete yourself",
        });
      }

      // Delete user - this will cascade to sessions, accounts, etc.
      await ctx.db.delete(user).where(eq(user.id, input.userId));

      return { success: true };
    }),

  // ==================== ORGANIZATION MANAGEMENT ====================

  // List all organizations
  listOrganizations: adminProcedure
    .input(
      z.object({
        search: z.string().optional(),
        status: z
          .enum(["pre-onboarding", "active", "suspended", "cancelled"])
          .optional(),
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
      }),
    )
    .query(async ({ ctx, input }) => {
      const orgs = await ctx.db.query.organization.findMany({
        where: input.search
          ? or(
              like(organization.name, `%${input.search}%`),
              like(organization.slug, `%${input.search}%`),
            )
          : undefined,
        orderBy: [desc(organization.createdAt)],
        limit: input.limit,
        offset: input.offset,
        with: {
          members: {
            columns: { id: true },
          },
        },
      });

      // Get protection org data and subscriptions for each org
      const orgsWithData = await Promise.all(
        orgs.map(async (org) => {
          const protOrg = await ctx.db.query.protectionOrganization.findFirst({
            where: eq(protectionOrganization.organizationId, org.id),
          });

          const sub = await ctx.db.query.subscription.findFirst({
            where: eq(subscription.referenceId, org.id),
          });

          return {
            ...org,
            memberCount: org.members.length,
            status: protOrg?.status ?? "pre-onboarding",
            subscription: sub
              ? { plan: sub.plan, status: sub.status }
              : { plan: "free", status: "active" },
          };
        }),
      );

      const countResult = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(organization);

      return {
        organizations: orgsWithData,
        total: countResult[0]?.count ?? 0,
      };
    }),

  // Get a single organization with details
  getOrganization: adminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const org = await ctx.db.query.organization.findFirst({
        where: eq(organization.id, input.id),
        with: {
          members: {
            with: {
              user: {
                columns: { id: true, name: true, email: true },
              },
            },
          },
        },
      });

      if (!org) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Organization not found",
        });
      }

      const protOrg = await ctx.db.query.protectionOrganization.findFirst({
        where: eq(protectionOrganization.organizationId, input.id),
      });

      const sub = await ctx.db.query.subscription.findFirst({
        where: eq(subscription.referenceId, input.id),
      });

      // Get resource counts
      const backendCount = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(backend)
        .where(eq(backend.organizationId, input.id));

      const filterCount = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(filter)
        .where(eq(filter.organizationId, input.id));

      return {
        ...org,
        protectionOrganization: protOrg,
        subscription: sub,
        stats: {
          backends: backendCount[0]?.count ?? 0,
          filters: filterCount[0]?.count ?? 0,
        },
      };
    }),

  // Update organization status
  updateOrganizationStatus: adminProcedure
    .input(
      z.object({
        organizationId: z.string().uuid(),
        status: z.enum(["pre-onboarding", "active", "suspended", "cancelled"]),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      // Ensure protection organization exists
      const existing = await ctx.db.query.protectionOrganization.findFirst({
        where: eq(protectionOrganization.organizationId, input.organizationId),
      });

      if (existing) {
        await ctx.db
          .update(protectionOrganization)
          .set({ status: input.status })
          .where(
            eq(protectionOrganization.organizationId, input.organizationId),
          );
      } else {
        await ctx.db.insert(protectionOrganization).values({
          organizationId: input.organizationId,
          status: input.status,
        });
      }

      return { success: true };
    }),

  // Update organization limits
  updateOrganizationLimits: adminProcedure
    .input(
      z.object({
        organizationId: z.string().uuid(),
        bandwidthLimit: z.number().int().optional(),
        backendsLimit: z.number().int().optional(),
        filtersLimit: z.number().int().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const { organizationId, ...limits } = input;

      const existing = await ctx.db.query.protectionOrganization.findFirst({
        where: eq(protectionOrganization.organizationId, organizationId),
      });

      if (existing) {
        await ctx.db
          .update(protectionOrganization)
          .set(limits)
          .where(eq(protectionOrganization.organizationId, organizationId));
      } else {
        await ctx.db.insert(protectionOrganization).values({
          organizationId,
          ...limits,
        });
      }

      return { success: true };
    }),

  // Delete organization
  deleteOrganization: adminProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db.delete(organization).where(eq(organization.id, input.id));
      return { success: true };
    }),

  // ==================== GLOBAL IP SCORES ====================

  // List IP scores with filtering
  listIpScores: adminProcedure
    .input(
      z.object({
        search: z.string().optional(),
        maxScore: z.number().int().min(0).max(100).optional(),
        isProxy: z.boolean().optional(),
        isVpn: z.boolean().optional(),
        isTor: z.boolean().optional(),
        isDatacenter: z.boolean().optional(),
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
      }),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [];

      if (input.search) {
        conditions.push(like(ipScore.ip, `%${input.search}%`));
      }

      if (input.maxScore !== undefined) {
        conditions.push(lte(ipScore.score, input.maxScore));
      }

      if (input.isProxy !== undefined) {
        conditions.push(eq(ipScore.isProxy, input.isProxy));
      }

      if (input.isVpn !== undefined) {
        conditions.push(eq(ipScore.isVpn, input.isVpn));
      }

      if (input.isTor !== undefined) {
        conditions.push(eq(ipScore.isTor, input.isTor));
      }

      if (input.isDatacenter !== undefined) {
        conditions.push(eq(ipScore.isDatacenter, input.isDatacenter));
      }

      const scores = await ctx.db.query.ipScore.findMany({
        where: conditions.length > 0 ? and(...conditions) : undefined,
        orderBy: [desc(ipScore.lastSeen)],
        limit: input.limit,
        offset: input.offset,
      });

      const countResult = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(ipScore)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      return {
        scores,
        total: countResult[0]?.count ?? 0,
      };
    }),

  // Get a single IP score
  getIpScore: adminProcedure
    .input(z.object({ ip: z.string() }))
    .query(async ({ ctx, input }) => {
      const result = await ctx.db.query.ipScore.findFirst({
        where: eq(ipScore.ip, input.ip),
      });

      if (!result) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "IP score not found",
        });
      }

      return result;
    }),

  // Update IP score
  updateIpScore: adminProcedure
    .input(
      z.object({
        ip: z.string(),
        score: z.number().int().min(0).max(100).optional(),
        isProxy: z.boolean().optional(),
        isVpn: z.boolean().optional(),
        isTor: z.boolean().optional(),
        isDatacenter: z.boolean().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const { ip, ...data } = input;

      const existing = await ctx.db.query.ipScore.findFirst({
        where: eq(ipScore.ip, ip),
      });

      if (!existing) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "IP score not found",
        });
      }

      const [updated] = await ctx.db
        .update(ipScore)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(ipScore.ip, ip))
        .returning();

      return updated;
    }),

  // Create IP score entry
  createIpScore: adminProcedure
    .input(
      z.object({
        ip: z.string(),
        score: z.number().int().min(0).max(100).default(100),
        country: z.string().length(2).optional(),
        asn: z.number().int().positive().optional(),
        asnName: z.string().optional(),
        isProxy: z.boolean().default(false),
        isVpn: z.boolean().default(false),
        isTor: z.boolean().default(false),
        isDatacenter: z.boolean().default(false),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const existing = await ctx.db.query.ipScore.findFirst({
        where: eq(ipScore.ip, input.ip),
      });

      if (existing) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "IP score already exists",
        });
      }

      const [created] = await ctx.db.insert(ipScore).values(input).returning();

      return created;
    }),

  // Delete IP score
  deleteIpScore: adminProcedure
    .input(z.object({ ip: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db.delete(ipScore).where(eq(ipScore.ip, input.ip));
      return { success: true };
    }),

  // Bulk update IP scores
  bulkUpdateIpScores: adminProcedure
    .input(
      z.object({
        ips: z.array(z.string()),
        score: z.number().int().min(0).max(100).optional(),
        isProxy: z.boolean().optional(),
        isVpn: z.boolean().optional(),
        isTor: z.boolean().optional(),
        isDatacenter: z.boolean().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const { ips, ...data } = input;

      let updated = 0;
      for (const ip of ips) {
        const result = await ctx.db
          .update(ipScore)
          .set({ ...data, updatedAt: new Date() })
          .where(eq(ipScore.ip, ip));
        if (result.rowCount && result.rowCount > 0) {
          updated++;
        }
      }

      return { updated };
    }),

  // ==================== PLATFORM STATISTICS ====================

  // Get platform-wide statistics
  getPlatformStats: adminProcedure.query(async ({ ctx }) => {
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    // User stats
    const userStats = await ctx.db
      .select({
        total: sql<number>`count(*)`,
        activeToday: sql<number>`count(*) filter (where ${user.updatedAt} >= ${last24h})`,
        admins: sql<number>`count(*) filter (where ${user.role} = 'admin')`,
        banned: sql<number>`count(*) filter (where ${user.banned} = true)`,
      })
      .from(user);

    // Organization stats
    const orgStats = await ctx.db
      .select({
        total: sql<number>`count(*)`,
      })
      .from(organization);

    // Backend stats
    const backendStats = await ctx.db
      .select({
        total: sql<number>`count(*)`,
        healthy: sql<number>`count(*) filter (where ${backend.status} = 'healthy')`,
        unhealthy: sql<number>`count(*) filter (where ${backend.status} = 'unhealthy')`,
      })
      .from(backend);

    // Attack stats
    const attackStats = await ctx.db
      .select({
        totalLast24h: sql<number>`count(*) filter (where ${attackEvent.startedAt} >= ${last24h})`,
        totalLast7d: sql<number>`count(*) filter (where ${attackEvent.startedAt} >= ${last7d})`,
        ongoing: sql<number>`count(*) filter (where ${attackEvent.endedAt} is null)`,
      })
      .from(attackEvent);

    // Traffic stats
    const trafficStats = await ctx.db
      .select({
        requestsLast24h: sql<number>`coalesce(sum(${trafficMetric.requestsTotal}), 0)`,
        bytesLast24h: sql<number>`coalesce(sum(${trafficMetric.bytesIn} + ${trafficMetric.bytesOut}), 0)`,
        blockedLast24h: sql<number>`coalesce(sum(${trafficMetric.requestsBlocked}), 0)`,
      })
      .from(trafficMetric)
      .where(gte(trafficMetric.timestamp, last24h));

    // Subscription stats
    const subStats = await ctx.db
      .select({
        total: sql<number>`count(*)`,
        active: sql<number>`count(*) filter (where ${subscription.status} = 'active')`,
        trialing: sql<number>`count(*) filter (where ${subscription.status} = 'trialing')`,
      })
      .from(subscription);

    return {
      users: userStats[0] ?? { total: 0, activeToday: 0, admins: 0, banned: 0 },
      organizations: orgStats[0] ?? { total: 0 },
      backends: backendStats[0] ?? { total: 0, healthy: 0, unhealthy: 0 },
      attacks: attackStats[0] ?? {
        totalLast24h: 0,
        totalLast7d: 0,
        ongoing: 0,
      },
      traffic: trafficStats[0] ?? {
        requestsLast24h: 0,
        bytesLast24h: 0,
        blockedLast24h: 0,
      },
      subscriptions: subStats[0] ?? { total: 0, active: 0, trialing: 0 },
    };
  }),

  // ==================== AUDIT LOG ====================

  // List audit log entries
  listAuditLog: adminProcedure
    .input(
      z.object({
        organizationId: z.string().uuid().optional(),
        userId: z.string().uuid().optional(),
        action: z.string().optional(),
        resource: z.string().optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
      }),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [];

      if (input.organizationId) {
        conditions.push(eq(auditLog.organizationId, input.organizationId));
      }

      if (input.userId) {
        conditions.push(eq(auditLog.userId, input.userId));
      }

      if (input.action) {
        conditions.push(eq(auditLog.action, input.action));
      }

      if (input.resource) {
        conditions.push(eq(auditLog.resource, input.resource));
      }

      if (input.startDate) {
        conditions.push(gte(auditLog.timestamp, input.startDate));
      }

      if (input.endDate) {
        conditions.push(lte(auditLog.timestamp, input.endDate));
      }

      const logs = await ctx.db.query.auditLog.findMany({
        where: conditions.length > 0 ? and(...conditions) : undefined,
        orderBy: [desc(auditLog.timestamp)],
        limit: input.limit,
        offset: input.offset,
        with: {
          user: {
            columns: { id: true, name: true, email: true },
          },
          organization: {
            columns: { id: true, name: true },
          },
        },
      });

      const countResult = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(auditLog)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      return {
        logs,
        total: countResult[0]?.count ?? 0,
      };
    }),

  // Get unique actions/resources for filtering
  getAuditLogFilters: adminProcedure.query(async ({ ctx }) => {
    const actions = await ctx.db
      .selectDistinct({ action: auditLog.action })
      .from(auditLog);

    const resources = await ctx.db
      .selectDistinct({ resource: auditLog.resource })
      .from(auditLog);

    return {
      actions: actions.map((a) => a.action),
      resources: resources.map((r) => r.resource),
    };
  }),
});
