import { z } from "zod";
import { eq, and, sql, gte } from "drizzle-orm";
import { TRPCError } from "@trpc/server";
import {
  createTRPCRouter,
  organizationProcedure,
  organizationOwnerProcedure,
  protectedProcedure,
} from "@/server/api/trpc";
import { subscription } from "@/server/db/auth-schema";
import {
  protectionOrganization,
  backend,
  filter,
  trafficMetric,
} from "@/server/db/schema";
import {
  getOrganizationLimits,
  protectionPlans,
  formatBytes,
  formatNumber,
} from "@/server/server-utils";
import { stripeClient } from "@/server/stripe";

export const billingRouter = createTRPCRouter({
  // ==================== SUBSCRIPTION INFO ====================

  // Get current subscription for an organization
  getSubscription: organizationProcedure.query(async ({ ctx, input }) => {
    const sub = await ctx.db.query.subscription.findFirst({
      where: eq(subscription.referenceId, input.organizationId),
    });

    if (!sub) {
      // Return free tier info
      return {
        plan: "free",
        status: "active" as const,
        currentPeriodEnd: null,
        cancelAtPeriodEnd: false,
        stripeSubscriptionId: null,
        stripeCustomerId: null,
        trialEnd: null,
        isTrialing: false,
      };
    }

    return {
      plan: sub.plan,
      status: sub.status as "active" | "trialing" | "past_due" | "canceled" | "incomplete",
      currentPeriodEnd: sub.periodEnd?.toISOString() ?? null,
      cancelAtPeriodEnd: sub.cancelAtPeriodEnd ?? false,
      stripeSubscriptionId: sub.stripeSubscriptionId,
      stripeCustomerId: sub.stripeCustomerId,
      trialEnd: sub.trialEnd?.toISOString() ?? null,
      isTrialing: sub.status === "trialing",
    };
  }),

  // Get subscription with full plan details
  getSubscriptionDetails: organizationProcedure.query(async ({ ctx, input }) => {
    const sub = await ctx.db.query.subscription.findFirst({
      where: eq(subscription.referenceId, input.organizationId),
    });

    const planName = sub?.plan ?? "free";
    const plan = protectionPlans.find((p) => p.name === planName);

    return {
      subscription: sub
        ? {
            plan: sub.plan,
            status: sub.status,
            periodStart: sub.periodStart?.toISOString(),
            periodEnd: sub.periodEnd?.toISOString(),
            cancelAtPeriodEnd: sub.cancelAtPeriodEnd,
            trialStart: sub.trialStart?.toISOString(),
            trialEnd: sub.trialEnd?.toISOString(),
          }
        : null,
      plan: plan
        ? {
            name: plan.name,
            limits: plan.limits,
          }
        : {
            name: "free",
            limits: { backends: 1, filters: 5, bandwidth: 1_000_000_000 },
          },
    };
  }),

  // ==================== USAGE INFO ====================

  // Get current usage for an organization
  getUsage: organizationProcedure.query(async ({ ctx, input }) => {
    // Get limits based on subscription
    const limits = await getOrganizationLimits(input.organizationId);

    // Get protection organization data
    const protOrg = await ctx.db.query.protectionOrganization.findFirst({
      where: eq(protectionOrganization.organizationId, input.organizationId),
    });

    // Count backends
    const backendCount = await ctx.db
      .select({ count: sql<number>`count(*)` })
      .from(backend)
      .where(eq(backend.organizationId, input.organizationId));

    // Count filters
    const filterCount = await ctx.db
      .select({ count: sql<number>`count(*)` })
      .from(filter)
      .where(eq(filter.organizationId, input.organizationId));

    // Get bandwidth usage (from protection org or calculate from metrics)
    const bandwidthUsed = protOrg?.bandwidthUsed ?? 0;

    return {
      backends: {
        used: backendCount[0]?.count ?? 0,
        limit: limits.backends,
        unlimited: limits.backends === -1,
      },
      filters: {
        used: filterCount[0]?.count ?? 0,
        limit: limits.filters,
        unlimited: limits.filters === -1,
      },
      bandwidth: {
        used: bandwidthUsed,
        usedFormatted: formatBytes(bandwidthUsed),
        limit: limits.bandwidth,
        limitFormatted: formatBytes(limits.bandwidth),
        unlimited: limits.bandwidth === -1,
        percentage:
          limits.bandwidth === -1
            ? 0
            : Math.min(100, (bandwidthUsed / limits.bandwidth) * 100),
      },
      lastUsageReset: protOrg?.lastUsageReset?.toISOString() ?? null,
    };
  }),

  // Get detailed bandwidth usage over time
  getBandwidthHistory: organizationProcedure
    .input(
      z.object({
        days: z.number().int().min(1).max(90).default(30),
      })
    )
    .query(async ({ ctx, input }) => {
      const startDate = new Date(
        Date.now() - input.days * 24 * 60 * 60 * 1000
      );

      const usage = await ctx.db
        .select({
          date: sql<string>`date_trunc('day', ${trafficMetric.timestamp})::date`,
          bytesIn: sql<number>`coalesce(sum(${trafficMetric.bytesIn}), 0)`,
          bytesOut: sql<number>`coalesce(sum(${trafficMetric.bytesOut}), 0)`,
          total: sql<number>`coalesce(sum(${trafficMetric.bytesIn} + ${trafficMetric.bytesOut}), 0)`,
        })
        .from(trafficMetric)
        .where(
          and(
            eq(trafficMetric.organizationId, input.organizationId),
            gte(trafficMetric.timestamp, startDate)
          )
        )
        .groupBy(sql`date_trunc('day', ${trafficMetric.timestamp})`)
        .orderBy(sql`date_trunc('day', ${trafficMetric.timestamp})`);

      return usage;
    }),

  // ==================== ORGANIZATION LIMITS ====================

  // Get organization limits
  getLimits: organizationProcedure.query(async ({ ctx, input }) => {
    const limits = await getOrganizationLimits(input.organizationId);

    return {
      backends: {
        limit: limits.backends,
        unlimited: limits.backends === -1,
        formatted: formatNumber(limits.backends),
      },
      filters: {
        limit: limits.filters,
        unlimited: limits.filters === -1,
        formatted: formatNumber(limits.filters),
      },
      bandwidth: {
        limit: limits.bandwidth,
        unlimited: limits.bandwidth === -1,
        formatted: formatBytes(limits.bandwidth),
      },
    };
  }),

  // ==================== AVAILABLE PLANS ====================

  // Get all available plans
  getPlans: protectedProcedure.query(async () => {
    return protectionPlans.map((plan) => ({
      name: plan.name,
      lookupKey: plan.lookupKey ?? null,
      annualLookupKey: plan.annualDiscountLookupKey ?? null,
      limits: {
        backends: plan.limits?.backends ?? 1,
        backendsFormatted: formatNumber(plan.limits?.backends ?? 1),
        filters: plan.limits?.filters ?? 5,
        filtersFormatted: formatNumber(plan.limits?.filters ?? 5),
        bandwidth: plan.limits?.bandwidth ?? 1_000_000_000,
        bandwidthFormatted: formatBytes(plan.limits?.bandwidth ?? 1_000_000_000),
      },
      hasFreeTrial: !!plan.freeTrial,
      freeTrialDays: plan.freeTrial?.days ?? 0,
    }));
  }),

  // ==================== STRIPE INTEGRATION ====================

  // Create checkout session to upgrade/subscribe
  createCheckoutSession: organizationOwnerProcedure
    .input(
      z.object({
        priceId: z.string(),
        annual: z.boolean().default(false),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const userId = ctx.session.user.id;
      const userEmail = ctx.session.user.email;

      // Check if organization already has an active subscription
      const existingSub = await ctx.db.query.subscription.findFirst({
        where: and(
          eq(subscription.referenceId, input.organizationId),
          sql`${subscription.status} in ('active', 'trialing')`
        ),
      });

      if (existingSub?.stripeSubscriptionId) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message:
            "Organization already has an active subscription. Use the billing portal to manage it.",
        });
      }

      const session = await stripeClient.checkout.sessions.create({
        mode: "subscription",
        payment_method_types: ["card"],
        customer_email: userEmail,
        line_items: [{ price: input.priceId, quantity: 1 }],
        success_url: `${process.env.PUBLIC_APP_URL}/dashboard/billing?success=true&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.PUBLIC_APP_URL}/dashboard/billing?canceled=true`,
        subscription_data: {
          trial_period_days: 14,
          metadata: {
            organizationId: input.organizationId,
          },
        },
        metadata: {
          userId,
          organizationId: input.organizationId,
        },
      });

      return { url: session.url, sessionId: session.id };
    }),

  // Create billing portal session
  createPortalSession: organizationOwnerProcedure.mutation(
    async ({ ctx, input }) => {
      const sub = await ctx.db.query.subscription.findFirst({
        where: eq(subscription.referenceId, input.organizationId),
      });

      if (!sub?.stripeCustomerId) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "No Stripe customer found for this organization.",
        });
      }

      const session = await stripeClient.billingPortal.sessions.create({
        customer: sub.stripeCustomerId,
        return_url: `${process.env.PUBLIC_APP_URL}/dashboard/billing`,
      });

      return { url: session.url };
    }
  ),

  // Cancel subscription at period end
  cancelSubscription: organizationOwnerProcedure.mutation(
    async ({ ctx, input }) => {
      const sub = await ctx.db.query.subscription.findFirst({
        where: eq(subscription.referenceId, input.organizationId),
      });

      if (!sub?.stripeSubscriptionId) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "No active subscription found.",
        });
      }

      await stripeClient.subscriptions.update(sub.stripeSubscriptionId, {
        cancel_at_period_end: true,
      });

      // Update local record
      await ctx.db
        .update(subscription)
        .set({ cancelAtPeriodEnd: true })
        .where(eq(subscription.id, sub.id));

      return { success: true };
    }
  ),

  // Resume canceled subscription
  resumeSubscription: organizationOwnerProcedure.mutation(
    async ({ ctx, input }) => {
      const sub = await ctx.db.query.subscription.findFirst({
        where: eq(subscription.referenceId, input.organizationId),
      });

      if (!sub?.stripeSubscriptionId) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "No subscription found.",
        });
      }

      await stripeClient.subscriptions.update(sub.stripeSubscriptionId, {
        cancel_at_period_end: false,
      });

      // Update local record
      await ctx.db
        .update(subscription)
        .set({ cancelAtPeriodEnd: false })
        .where(eq(subscription.id, sub.id));

      return { success: true };
    }
  ),

  // ==================== INVOICES ====================

  // Get invoices from Stripe
  getInvoices: organizationOwnerProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(100).default(10),
      })
    )
    .query(async ({ ctx, input }) => {
      const sub = await ctx.db.query.subscription.findFirst({
        where: eq(subscription.referenceId, input.organizationId),
      });

      if (!sub?.stripeCustomerId) {
        return [];
      }

      try {
        const invoices = await stripeClient.invoices.list({
          customer: sub.stripeCustomerId,
          limit: input.limit,
        });

        return invoices.data.map((invoice) => ({
          id: invoice.id,
          number: invoice.number,
          status: invoice.status,
          amount: invoice.amount_due / 100,
          currency: invoice.currency.toUpperCase(),
          date: invoice.created
            ? new Date(invoice.created * 1000).toISOString()
            : null,
          paidAt: invoice.status_transitions?.paid_at
            ? new Date(invoice.status_transitions.paid_at * 1000).toISOString()
            : null,
          hostedInvoiceUrl: invoice.hosted_invoice_url,
          invoicePdf: invoice.invoice_pdf,
        }));
      } catch (error) {
        console.error("Failed to fetch invoices:", error);
        return [];
      }
    }),

  // Get upcoming invoice
  getUpcomingInvoice: organizationOwnerProcedure.query(
    async ({ ctx, input }) => {
      const sub = await ctx.db.query.subscription.findFirst({
        where: eq(subscription.referenceId, input.organizationId),
      });

      if (!sub?.stripeCustomerId) {
        return null;
      }

      try {
        const upcomingInvoice = await stripeClient.invoices.retrieveUpcoming({
          customer: sub.stripeCustomerId,
        });

        return {
          amount: upcomingInvoice.amount_due / 100,
          currency: upcomingInvoice.currency.toUpperCase(),
          dueDate: upcomingInvoice.due_date
            ? new Date(upcomingInvoice.due_date * 1000).toISOString()
            : null,
          periodStart: upcomingInvoice.period_start
            ? new Date(upcomingInvoice.period_start * 1000).toISOString()
            : null,
          periodEnd: upcomingInvoice.period_end
            ? new Date(upcomingInvoice.period_end * 1000).toISOString()
            : null,
          lines: upcomingInvoice.lines.data.map((line) => ({
            description: line.description,
            amount: line.amount / 100,
            quantity: line.quantity,
          })),
        };
      } catch (error) {
        // No upcoming invoice (e.g., canceled subscription)
        return null;
      }
    }
  ),

  // ==================== PAYMENT METHODS ====================

  // Get payment methods
  getPaymentMethods: organizationOwnerProcedure.query(
    async ({ ctx, input }) => {
      const sub = await ctx.db.query.subscription.findFirst({
        where: eq(subscription.referenceId, input.organizationId),
      });

      if (!sub?.stripeCustomerId) {
        return [];
      }

      try {
        const paymentMethods = await stripeClient.paymentMethods.list({
          customer: sub.stripeCustomerId,
          type: "card",
        });

        return paymentMethods.data.map((pm) => ({
          id: pm.id,
          brand: pm.card?.brand,
          last4: pm.card?.last4,
          expMonth: pm.card?.exp_month,
          expYear: pm.card?.exp_year,
          isDefault: pm.metadata?.default === "true",
        }));
      } catch (error) {
        console.error("Failed to fetch payment methods:", error);
        return [];
      }
    }
  ),
});
