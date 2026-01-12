import { TRPCError } from "@trpc/server";
import { and, asc, desc, eq, gte, lte, sql } from "drizzle-orm";
import { z } from "zod";
import {
  createTRPCRouter,
  organizationProcedure,
  protectedProcedure,
} from "@/server/api/trpc";
import {
  attackEvent,
  backend,
  connectionAttempt,
  filter,
  ipScore,
  trafficMetric,
} from "@/server/db/schema";

// Zod schemas for validation
const severitySchema = z.enum(["low", "medium", "high", "critical"]);

const _timeRangeSchema = z.object({
  startDate: z.date(),
  endDate: z.date(),
});

export const analyticsRouter = createTRPCRouter({
  // ==================== TRAFFIC METRICS ====================

  // Get traffic metrics for an organization
  getTrafficMetrics: organizationProcedure
    .input(
      z.object({
        backendId: z.string().uuid().optional(),
        startDate: z.date(),
        endDate: z.date(),
        interval: z.enum(["minute", "hour", "day"]).default("hour"),
      }),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [
        eq(trafficMetric.organizationId, input.organizationId),
        gte(trafficMetric.timestamp, input.startDate),
        lte(trafficMetric.timestamp, input.endDate),
      ];

      if (input.backendId) {
        conditions.push(eq(trafficMetric.backendId, input.backendId));
      }

      return ctx.db.query.trafficMetric.findMany({
        where: and(...conditions),
        orderBy: [asc(trafficMetric.timestamp)],
        with: {
          backend: {
            columns: { id: true, name: true },
          },
        },
      });
    }),

  // Get aggregated traffic stats
  getTrafficStats: organizationProcedure
    .input(
      z.object({
        backendId: z.string().uuid().optional(),
        hours: z.number().int().min(1).max(720).default(24), // Max 30 days
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      const conditions = [
        eq(trafficMetric.organizationId, input.organizationId),
        gte(trafficMetric.timestamp, startDate),
      ];

      if (input.backendId) {
        conditions.push(eq(trafficMetric.backendId, input.backendId));
      }

      const metrics = await ctx.db
        .select({
          totalRequests: sql<number>`coalesce(sum(${trafficMetric.requestsTotal}), 0)`,
          allowedRequests: sql<number>`coalesce(sum(${trafficMetric.requestsAllowed}), 0)`,
          blockedRequests: sql<number>`coalesce(sum(${trafficMetric.requestsBlocked}), 0)`,
          challengedRequests: sql<number>`coalesce(sum(${trafficMetric.requestsChallenged}), 0)`,
          bytesIn: sql<number>`coalesce(sum(${trafficMetric.bytesIn}), 0)`,
          bytesOut: sql<number>`coalesce(sum(${trafficMetric.bytesOut}), 0)`,
          avgLatency: sql<number>`coalesce(avg(${trafficMetric.avgLatencyMs}), 0)`,
          p95Latency: sql<number>`coalesce(max(${trafficMetric.p95LatencyMs}), 0)`,
          p99Latency: sql<number>`coalesce(max(${trafficMetric.p99LatencyMs}), 0)`,
          uniqueIps: sql<number>`coalesce(sum(${trafficMetric.uniqueIps}), 0)`,
          errorCount: sql<number>`coalesce(sum(${trafficMetric.errorCount}), 0)`,
        })
        .from(trafficMetric)
        .where(and(...conditions));

      return (
        metrics[0] ?? {
          totalRequests: 0,
          allowedRequests: 0,
          blockedRequests: 0,
          challengedRequests: 0,
          bytesIn: 0,
          bytesOut: 0,
          avgLatency: 0,
          p95Latency: 0,
          p99Latency: 0,
          uniqueIps: 0,
          errorCount: 0,
        }
      );
    }),

  // Get real-time stats (last 5 minutes)
  getRealtimeStats: organizationProcedure.query(async ({ ctx, input }) => {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);

    const metrics = await ctx.db
      .select({
        requestsPerSecond: sql<number>`coalesce(sum(${trafficMetric.requestsTotal}) / 300.0, 0)`,
        bytesPerSecond: sql<number>`coalesce(sum(${trafficMetric.bytesIn} + ${trafficMetric.bytesOut}) / 300.0, 0)`,
        blockedPerSecond: sql<number>`coalesce(sum(${trafficMetric.requestsBlocked}) / 300.0, 0)`,
        activeConnections: sql<number>`coalesce(sum(${trafficMetric.uniqueIps}), 0)`,
      })
      .from(trafficMetric)
      .where(
        and(
          eq(trafficMetric.organizationId, input.organizationId),
          gte(trafficMetric.timestamp, fiveMinutesAgo),
        ),
      );

    return (
      metrics[0] ?? {
        requestsPerSecond: 0,
        bytesPerSecond: 0,
        blockedPerSecond: 0,
        activeConnections: 0,
      }
    );
  }),

  // Get traffic by backend
  getTrafficByBackend: organizationProcedure
    .input(
      z.object({
        hours: z.number().int().min(1).max(720).default(24),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      return ctx.db
        .select({
          backendId: trafficMetric.backendId,
          backendName: backend.name,
          totalRequests: sql<number>`coalesce(sum(${trafficMetric.requestsTotal}), 0)`,
          blockedRequests: sql<number>`coalesce(sum(${trafficMetric.requestsBlocked}), 0)`,
          bytesTotal: sql<number>`coalesce(sum(${trafficMetric.bytesIn} + ${trafficMetric.bytesOut}), 0)`,
        })
        .from(trafficMetric)
        .leftJoin(backend, eq(trafficMetric.backendId, backend.id))
        .where(
          and(
            eq(trafficMetric.organizationId, input.organizationId),
            gte(trafficMetric.timestamp, startDate),
          ),
        )
        .groupBy(trafficMetric.backendId, backend.name)
        .orderBy(sql`sum(${trafficMetric.requestsTotal}) desc`);
    }),

  // ==================== ATTACK EVENTS ====================

  // List attack events
  getAttackEvents: organizationProcedure
    .input(
      z.object({
        backendId: z.string().uuid().optional(),
        severity: severitySchema.optional(),
        type: z.string().optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
      }),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [eq(attackEvent.organizationId, input.organizationId)];

      if (input.backendId) {
        conditions.push(eq(attackEvent.backendId, input.backendId));
      }

      if (input.severity) {
        conditions.push(eq(attackEvent.severity, input.severity));
      }

      if (input.type) {
        conditions.push(eq(attackEvent.type, input.type));
      }

      if (input.startDate) {
        conditions.push(gte(attackEvent.startedAt, input.startDate));
      }

      if (input.endDate) {
        conditions.push(lte(attackEvent.startedAt, input.endDate));
      }

      const events = await ctx.db.query.attackEvent.findMany({
        where: and(...conditions),
        orderBy: [desc(attackEvent.startedAt)],
        limit: input.limit,
        offset: input.offset,
        with: {
          backend: {
            columns: { id: true, name: true },
          },
        },
      });

      // Get total count for pagination
      const countResult = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(attackEvent)
        .where(and(...conditions));

      return {
        events,
        total: countResult[0]?.count ?? 0,
      };
    }),

  // Get a single attack event
  getAttackEvent: organizationProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const result = await ctx.db.query.attackEvent.findFirst({
        where: and(
          eq(attackEvent.id, input.id),
          eq(attackEvent.organizationId, input.organizationId),
        ),
        with: {
          backend: true,
        },
      });

      if (!result) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Attack event not found",
        });
      }

      return result;
    }),

  // Get attack statistics
  getAttackStats: organizationProcedure
    .input(
      z.object({
        hours: z.number().int().min(1).max(720).default(24),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      const stats = await ctx.db
        .select({
          total: sql<number>`count(*)`,
          critical: sql<number>`count(*) filter (where ${attackEvent.severity} = 'critical')`,
          high: sql<number>`count(*) filter (where ${attackEvent.severity} = 'high')`,
          medium: sql<number>`count(*) filter (where ${attackEvent.severity} = 'medium')`,
          low: sql<number>`count(*) filter (where ${attackEvent.severity} = 'low')`,
          mitigated: sql<number>`count(*) filter (where ${attackEvent.mitigatedAt} is not null)`,
          ongoing: sql<number>`count(*) filter (where ${attackEvent.endedAt} is null)`,
        })
        .from(attackEvent)
        .where(
          and(
            eq(attackEvent.organizationId, input.organizationId),
            gte(attackEvent.startedAt, startDate),
          ),
        );

      return (
        stats[0] ?? {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          mitigated: 0,
          ongoing: 0,
        }
      );
    }),

  // Get attack types distribution
  getAttackTypes: organizationProcedure
    .input(
      z.object({
        hours: z.number().int().min(1).max(720).default(24),
        limit: z.number().int().min(1).max(20).default(10),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      return ctx.db
        .select({
          type: attackEvent.type,
          count: sql<number>`count(*)`,
          totalBytes: sql<number>`coalesce(sum(${attackEvent.totalBytes}), 0)`,
          avgPacketsPerSecond: sql<number>`coalesce(avg(${attackEvent.packetsPerSecond}), 0)`,
        })
        .from(attackEvent)
        .where(
          and(
            eq(attackEvent.organizationId, input.organizationId),
            gte(attackEvent.startedAt, startDate),
          ),
        )
        .groupBy(attackEvent.type)
        .orderBy(sql`count(*) desc`)
        .limit(input.limit);
    }),

  // ==================== CONNECTION ATTEMPTS ====================

  // List recent connection attempts
  getConnectionAttempts: organizationProcedure
    .input(
      z.object({
        backendId: z.string().uuid().optional(),
        sourceIp: z.string().optional(),
        success: z.boolean().optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
      }),
    )
    .query(async ({ ctx, input }) => {
      const conditions = [
        eq(connectionAttempt.organizationId, input.organizationId),
      ];

      if (input.backendId) {
        conditions.push(eq(connectionAttempt.backendId, input.backendId));
      }

      if (input.sourceIp) {
        conditions.push(eq(connectionAttempt.sourceIp, input.sourceIp));
      }

      if (input.success !== undefined) {
        conditions.push(eq(connectionAttempt.success, input.success));
      }

      if (input.startDate) {
        conditions.push(gte(connectionAttempt.timestamp, input.startDate));
      }

      if (input.endDate) {
        conditions.push(lte(connectionAttempt.timestamp, input.endDate));
      }

      const attempts = await ctx.db.query.connectionAttempt.findMany({
        where: and(...conditions),
        orderBy: [desc(connectionAttempt.timestamp)],
        limit: input.limit,
        offset: input.offset,
        with: {
          backend: {
            columns: { id: true, name: true },
          },
          filter: {
            columns: { id: true, name: true },
          },
        },
      });

      const countResult = await ctx.db
        .select({ count: sql<number>`count(*)` })
        .from(connectionAttempt)
        .where(and(...conditions));

      return {
        attempts,
        total: countResult[0]?.count ?? 0,
      };
    }),

  // Get connection attempts by source IP
  getConnectionsByIp: organizationProcedure
    .input(
      z.object({
        sourceIp: z.string(),
        hours: z.number().int().min(1).max(168).default(24),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      const stats = await ctx.db
        .select({
          total: sql<number>`count(*)`,
          successful: sql<number>`count(*) filter (where ${connectionAttempt.success} = true)`,
          blocked: sql<number>`count(*) filter (where ${connectionAttempt.success} = false)`,
          bytesIn: sql<number>`coalesce(sum(${connectionAttempt.bytesIn}), 0)`,
          bytesOut: sql<number>`coalesce(sum(${connectionAttempt.bytesOut}), 0)`,
          avgLatency: sql<number>`coalesce(avg(${connectionAttempt.latencyMs}), 0)`,
        })
        .from(connectionAttempt)
        .where(
          and(
            eq(connectionAttempt.organizationId, input.organizationId),
            eq(connectionAttempt.sourceIp, input.sourceIp),
            gte(connectionAttempt.timestamp, startDate),
          ),
        );

      const recentAttempts = await ctx.db.query.connectionAttempt.findMany({
        where: and(
          eq(connectionAttempt.organizationId, input.organizationId),
          eq(connectionAttempt.sourceIp, input.sourceIp),
          gte(connectionAttempt.timestamp, startDate),
        ),
        orderBy: [desc(connectionAttempt.timestamp)],
        limit: 20,
        with: {
          backend: {
            columns: { id: true, name: true },
          },
        },
      });

      return {
        stats: stats[0] ?? {
          total: 0,
          successful: 0,
          blocked: 0,
          bytesIn: 0,
          bytesOut: 0,
          avgLatency: 0,
        },
        recentAttempts,
      };
    }),

  // Get top source IPs
  getTopSourceIps: organizationProcedure
    .input(
      z.object({
        hours: z.number().int().min(1).max(168).default(24),
        limit: z.number().int().min(1).max(50).default(10),
        filter: z.enum(["all", "blocked", "allowed"]).default("all"),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      const conditions = [
        eq(connectionAttempt.organizationId, input.organizationId),
        gte(connectionAttempt.timestamp, startDate),
      ];

      if (input.filter === "blocked") {
        conditions.push(eq(connectionAttempt.success, false));
      } else if (input.filter === "allowed") {
        conditions.push(eq(connectionAttempt.success, true));
      }

      return ctx.db
        .select({
          sourceIp: connectionAttempt.sourceIp,
          count: sql<number>`count(*)`,
          successfulCount: sql<number>`count(*) filter (where ${connectionAttempt.success} = true)`,
          blockedCount: sql<number>`count(*) filter (where ${connectionAttempt.success} = false)`,
          bytesTotal: sql<number>`coalesce(sum(${connectionAttempt.bytesIn} + ${connectionAttempt.bytesOut}), 0)`,
        })
        .from(connectionAttempt)
        .where(and(...conditions))
        .groupBy(connectionAttempt.sourceIp)
        .orderBy(sql`count(*) desc`)
        .limit(input.limit);
    }),

  // ==================== IP SCORES ====================

  // Lookup IP score
  lookupIpScore: protectedProcedure
    .input(z.object({ ip: z.string() }))
    .query(async ({ ctx, input }) => {
      if (!input.ip || input.ip.length < 7) {
        return {
          ip: input.ip,
          score: 50,
          country: null,
          asn: null,
          isProxy: false,
          isVpn: false,
          isTor: false,
          isDatacenter: false,
        };
      }

      const result = await ctx.db.query.ipScore.findFirst({
        where: eq(ipScore.ip, input.ip),
      });

      if (!result) {
        return {
          ip: input.ip,
          score: 50, // Default neutral score
          country: null,
          asn: null,
          isProxy: false,
          isVpn: false,
          isTor: false,
          isDatacenter: false,
        };
      }

      return {
        ip: result.ip,
        score: result.score,
        country: result.country,
        asn: result.asn,
        isProxy: result.isProxy,
        isVpn: result.isVpn,
        isTor: result.isTor,
        isDatacenter: result.isDatacenter,
      };
    }),

  // Lookup multiple IP scores
  lookupIpScores: protectedProcedure
    .input(z.object({ ips: z.array(z.string()).max(100) }))
    .query(async ({ ctx, input }) => {
      const results = await ctx.db.query.ipScore.findMany({
        where: sql`${ipScore.ip} = any(${input.ips})`,
      });

      return results;
    }),

  // Get IP score statistics (for organization analytics)
  getIpScoreStats: organizationProcedure
    .input(
      z.object({
        hours: z.number().int().min(1).max(168).default(24),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      // Get unique IPs from connection attempts
      const uniqueIps = await ctx.db
        .selectDistinct({ ip: connectionAttempt.sourceIp })
        .from(connectionAttempt)
        .where(
          and(
            eq(connectionAttempt.organizationId, input.organizationId),
            gte(connectionAttempt.timestamp, startDate),
          ),
        );

      const ipAddresses = uniqueIps.map((r) => r.ip);

      if (ipAddresses.length === 0) {
        return {
          totalIps: 0,
          avgScore: 100,
          lowScoreCount: 0,
          proxyCount: 0,
          vpnCount: 0,
          torCount: 0,
          datacenterCount: 0,
        };
      }

      const stats = await ctx.db
        .select({
          totalIps: sql<number>`count(*)`,
          avgScore: sql<number>`coalesce(avg(${ipScore.score}), 100)`,
          lowScoreCount: sql<number>`count(*) filter (where ${ipScore.score} < 50)`,
          proxyCount: sql<number>`count(*) filter (where ${ipScore.isProxy} = true)`,
          vpnCount: sql<number>`count(*) filter (where ${ipScore.isVpn} = true)`,
          torCount: sql<number>`count(*) filter (where ${ipScore.isTor} = true)`,
          datacenterCount: sql<number>`count(*) filter (where ${ipScore.isDatacenter} = true)`,
        })
        .from(ipScore)
        .where(sql`${ipScore.ip} = any(${ipAddresses})`);

      return (
        stats[0] ?? {
          totalIps: 0,
          avgScore: 100,
          lowScoreCount: 0,
          proxyCount: 0,
          vpnCount: 0,
          torCount: 0,
          datacenterCount: 0,
        }
      );
    }),

  // ==================== DASHBOARD STATS ====================

  // Get combined dashboard stats
  getDashboardStats: organizationProcedure.query(async ({ ctx, input }) => {
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const _lastHour = new Date(now.getTime() - 60 * 60 * 1000);

    // Get traffic stats
    const trafficStats = await ctx.db
      .select({
        totalRequests: sql<number>`coalesce(sum(${trafficMetric.requestsTotal}), 0)`,
        blockedRequests: sql<number>`coalesce(sum(${trafficMetric.requestsBlocked}), 0)`,
        bytesIn: sql<number>`coalesce(sum(${trafficMetric.bytesIn}), 0)`,
        bytesOut: sql<number>`coalesce(sum(${trafficMetric.bytesOut}), 0)`,
      })
      .from(trafficMetric)
      .where(
        and(
          eq(trafficMetric.organizationId, input.organizationId),
          gte(trafficMetric.timestamp, last24h),
        ),
      );

    // Get attack count
    const attackCount = await ctx.db
      .select({ count: sql<number>`count(*)` })
      .from(attackEvent)
      .where(
        and(
          eq(attackEvent.organizationId, input.organizationId),
          gte(attackEvent.startedAt, last24h),
        ),
      );

    // Get ongoing attacks
    const ongoingAttacks = await ctx.db
      .select({ count: sql<number>`count(*)` })
      .from(attackEvent)
      .where(
        and(
          eq(attackEvent.organizationId, input.organizationId),
          sql`${attackEvent.endedAt} is null`,
        ),
      );

    // Get backend status summary
    const backendStats = await ctx.db
      .select({
        total: sql<number>`count(*)`,
        healthy: sql<number>`count(*) filter (where ${backend.status} = 'healthy')`,
        degraded: sql<number>`count(*) filter (where ${backend.status} = 'degraded')`,
        unhealthy: sql<number>`count(*) filter (where ${backend.status} = 'unhealthy')`,
      })
      .from(backend)
      .where(eq(backend.organizationId, input.organizationId));

    // Get filter stats
    const filterStats = await ctx.db
      .select({
        total: sql<number>`count(*)`,
        active: sql<number>`count(*) filter (where ${filter.enabled} = true)`,
        disabled: sql<number>`count(*) filter (where ${filter.enabled} = false)`,
      })
      .from(filter)
      .where(eq(filter.organizationId, input.organizationId));

    return {
      traffic: trafficStats[0] ?? {
        totalRequests: 0,
        blockedRequests: 0,
        bytesIn: 0,
        bytesOut: 0,
      },
      attacks: {
        total: attackCount[0]?.count ?? 0,
        ongoing: ongoingAttacks[0]?.count ?? 0,
      },
      backends: backendStats[0] ?? {
        total: 0,
        healthy: 0,
        degraded: 0,
        unhealthy: 0,
      },
      filters: filterStats[0] ?? {
        total: 0,
        active: 0,
        disabled: 0,
      },
    };
  }),

  // Get geographic distribution of traffic
  getGeoDistribution: organizationProcedure
    .input(
      z.object({
        hours: z.number().int().min(1).max(168).default(24),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      // Get unique source IPs from connection attempts
      const sourceIps = await ctx.db
        .selectDistinct({ ip: connectionAttempt.sourceIp })
        .from(connectionAttempt)
        .where(
          and(
            eq(connectionAttempt.organizationId, input.organizationId),
            gte(connectionAttempt.timestamp, startDate),
          ),
        )
        .limit(10000);

      const ipAddresses = sourceIps.map((r) => r.ip);

      if (ipAddresses.length === 0) {
        return [];
      }

      // Get country distribution from IP scores
      return ctx.db
        .select({
          country: ipScore.country,
          count: sql<number>`count(*)`,
        })
        .from(ipScore)
        .where(
          and(
            sql`${ipScore.ip} = any(${ipAddresses})`,
            sql`${ipScore.country} is not null`,
          ),
        )
        .groupBy(ipScore.country)
        .orderBy(sql`count(*) desc`)
        .limit(20);
    }),

  // Get traffic time series for charts
  getTrafficTimeSeries: organizationProcedure
    .input(
      z.object({
        hours: z.number().int().min(1).max(168).default(24),
        interval: z.enum(["minute", "hour", "day"]).default("hour"),
        backendId: z.string().uuid().optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(Date.now() - input.hours * 60 * 60 * 1000);

      const conditions = [
        eq(trafficMetric.organizationId, input.organizationId),
        gte(trafficMetric.timestamp, startDate),
      ];

      if (input.backendId) {
        conditions.push(eq(trafficMetric.backendId, input.backendId));
      }

      // Group by time interval
      const intervalTrunc =
        input.interval === "minute"
          ? sql`date_trunc('minute', ${trafficMetric.timestamp})`
          : input.interval === "hour"
            ? sql`date_trunc('hour', ${trafficMetric.timestamp})`
            : sql`date_trunc('day', ${trafficMetric.timestamp})`;

      const result = await ctx.db
        .select({
          time: intervalTrunc,
          total: sql<number>`coalesce(sum(${trafficMetric.requestsTotal}), 0)`,
          allowed: sql<number>`coalesce(sum(${trafficMetric.requestsAllowed}), 0)`,
          blocked: sql<number>`coalesce(sum(${trafficMetric.requestsBlocked}), 0)`,
          challenged: sql<number>`coalesce(sum(${trafficMetric.requestsChallenged}), 0)`,
          bytesIn: sql<number>`coalesce(sum(${trafficMetric.bytesIn}), 0)`,
          bytesOut: sql<number>`coalesce(sum(${trafficMetric.bytesOut}), 0)`,
        })
        .from(trafficMetric)
        .where(and(...conditions))
        .groupBy(intervalTrunc)
        .orderBy(asc(intervalTrunc));

      // Format the time for display
      return result.map((row) => ({
        time: new Date(row.time as string).toLocaleTimeString("en-US", {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        }),
        total: Number(row.total),
        allowed: Number(row.allowed),
        blocked: Number(row.blocked),
        challenged: Number(row.challenged),
        bytesIn: Number(row.bytesIn),
        bytesOut: Number(row.bytesOut),
      }));
    }),

  // Get recent events for activity feed
  getRecentEvents: organizationProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(100).default(10),
      }),
    )
    .query(async ({ ctx, input }) => {
      // Get recent attack events
      const attacks = await ctx.db.query.attackEvent.findMany({
        where: eq(attackEvent.organizationId, input.organizationId),
        orderBy: [desc(attackEvent.startedAt)],
        limit: input.limit,
        with: {
          backend: {
            columns: { id: true, name: true },
          },
        },
      });

      // Get recent connection attempts (blocked)
      const blockedConnections = await ctx.db.query.connectionAttempt.findMany({
        where: and(
          eq(connectionAttempt.organizationId, input.organizationId),
          eq(connectionAttempt.result, "blocked"),
        ),
        orderBy: [desc(connectionAttempt.timestamp)],
        limit: input.limit,
      });

      // Combine and format events
      const events: Array<{
        type: string;
        sourceIp: string;
        action: string;
        timestamp: Date;
        timeAgo: string;
      }> = [];

      // Add attack events
      for (const attack of attacks) {
        events.push({
          type: attack.attackType,
          sourceIp: attack.sourceIps?.[0] ?? "Unknown",
          action: attack.endedAt ? "mitigated" : "ongoing",
          timestamp: attack.startedAt,
          timeAgo: formatTimeAgo(attack.startedAt),
        });
      }

      // Add blocked connections
      for (const conn of blockedConnections) {
        events.push({
          type: conn.blockReason ?? "Connection blocked",
          sourceIp: conn.sourceIp,
          action: "blocked",
          timestamp: conn.timestamp,
          timeAgo: formatTimeAgo(conn.timestamp),
        });
      }

      // Sort by timestamp and limit
      return events
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
        .slice(0, input.limit);
    }),
});

// Helper function to format time ago
function formatTimeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) {
    return "Just now";
  }
  if (diffMins < 60) {
    return `${diffMins}m ago`;
  }
  if (diffHours < 24) {
    return `${diffHours}h ago`;
  }
  return `${diffDays}d ago`;
}
