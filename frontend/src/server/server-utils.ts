import type { StripePlan } from "@better-auth/stripe";
import { and, eq } from "drizzle-orm";
import { db } from "@/server/db";
import { member } from "@/server/db/auth-schema";
import { protectionOrganization } from "@/server/db/schema";

// Extended plan interface with usage-based billing options
export interface ProtectionPlanConfig extends Record<string, unknown> {
  // Flat plan limits
  backends: number;
  filters: number;
  bandwidth: number; // in bytes
  requests: number; // max requests per month (-1 for unlimited)
  // Billing type
  billingType: "flat" | "usage" | "hybrid";
  // Usage-based pricing (in cents)
  bandwidthPricePerGb?: number; // $/GB for usage/hybrid plans
  requestsPricePerMillion?: number; // $/million requests
  basePriceMonthly?: number; // Base monthly price for hybrid plans (cents)
  // Included in hybrid plans
  includedBandwidthGb?: number;
  includedRequestsMillions?: number;
}

// Protection plan definitions for Stripe
export const protectionPlans: StripePlan[] = [
  {
    name: "free",
    limits: {
      backends: 1,
      filters: 5,
      bandwidth: 1_000_000_000, // 1GB
      requests: 100_000,
      billingType: "flat",
    } as ProtectionPlanConfig,
  },
  {
    name: "starter",
    lookupKey: "price_starter_monthly",
    annualDiscountLookupKey: "price_starter_annual",
    limits: {
      backends: 5,
      filters: 25,
      bandwidth: 100_000_000_000, // 100GB
      requests: 10_000_000, // 10M
      billingType: "flat",
    } as ProtectionPlanConfig,
    freeTrial: {
      days: 14,
      onTrialStart: async (_subscription) => {
        console.log("Starter trial started");
      },
      onTrialEnd: async ({ subscription: _subscription }, _request) => {
        console.log("Starter trial ended");
      },
      onTrialExpired: async (_subscription) => {
        console.log("Starter trial expired");
      },
    },
  },
  {
    name: "professional",
    lookupKey: "price_professional_monthly",
    annualDiscountLookupKey: "price_professional_annual",
    limits: {
      backends: 15,
      filters: 100,
      bandwidth: 1_000_000_000_000, // 1TB
      requests: 100_000_000, // 100M
      billingType: "hybrid",
      bandwidthPricePerGb: 5, // $0.05/GB overage
      requestsPricePerMillion: 50, // $0.50/million overage
      includedBandwidthGb: 1000,
      includedRequestsMillions: 100,
    } as ProtectionPlanConfig,
    freeTrial: {
      days: 14,
      onTrialStart: async (_subscription) => {
        console.log("Professional trial started");
      },
      onTrialEnd: async ({ subscription: _subscription }, _request) => {
        console.log("Professional trial ended");
      },
      onTrialExpired: async (_subscription) => {
        console.log("Professional trial expired");
      },
    },
  },
  {
    name: "enterprise",
    lookupKey: "price_enterprise_monthly",
    annualDiscountLookupKey: "price_enterprise_annual",
    limits: {
      backends: -1, // unlimited
      filters: -1,
      bandwidth: -1,
      requests: -1,
      billingType: "flat", // Custom pricing negotiated
    } as ProtectionPlanConfig,
    freeTrial: {
      days: 14,
      onTrialStart: async (_subscription) => {
        console.log("Enterprise trial started");
      },
      onTrialEnd: async ({ subscription: _subscription }, _request) => {
        console.log("Enterprise trial ended");
      },
      onTrialExpired: async (_subscription) => {
        console.log("Enterprise trial expired");
      },
    },
  },
  // Usage-based plans
  {
    name: "pay-as-you-go",
    lookupKey: "price_payg_monthly",
    limits: {
      backends: 10,
      filters: 50,
      bandwidth: -1, // unlimited, charged per use
      requests: -1,
      billingType: "usage",
      bandwidthPricePerGb: 8, // $0.08/GB
      requestsPricePerMillion: 100, // $1.00/million
    } as ProtectionPlanConfig,
  },
];

// Get a user's role in an organization
export async function getRoleOfUserInOrg(
  userId: string,
  orgId: string,
): Promise<string | null> {
  const memberRecord = await db.query.member.findFirst({
    where: and(eq(member.userId, userId), eq(member.organizationId, orgId)),
  });

  return memberRecord?.role ?? null;
}

// Check if organization has active subscription
export async function hasActiveSubscription(orgId: string): Promise<boolean> {
  const subscription = await db.query.subscription.findFirst({
    where: (sub, { eq, and, inArray }) =>
      and(
        eq(sub.referenceId, orgId),
        inArray(sub.status, ["active", "trialing"]),
      ),
  });

  return !!subscription;
}

// Get protection organization by ID
export async function getProtectionOrganizationById(orgId: string) {
  return db.query.protectionOrganization.findFirst({
    where: eq(protectionOrganization.organizationId, orgId),
  });
}

// Get plan limits for an organization
export async function getOrganizationLimits(orgId: string): Promise<{
  backends: number;
  filters: number;
  bandwidth: number;
  requests: number;
  billingType: "flat" | "usage" | "hybrid";
  bandwidthPricePerGb?: number;
  requestsPricePerMillion?: number;
}> {
  const subscription = await db.query.subscription.findFirst({
    where: (sub, { eq, and, inArray }) =>
      and(
        eq(sub.referenceId, orgId),
        inArray(sub.status, ["active", "trialing"]),
      ),
  });

  if (!subscription) {
    // Return free tier limits
    return {
      backends: 1,
      filters: 5,
      bandwidth: 1_000_000_000,
      requests: 100_000,
      billingType: "flat",
    };
  }

  const plan = protectionPlans.find((p) => p.name === subscription.plan);
  if (!plan || !plan.limits) {
    return {
      backends: 1,
      filters: 5,
      bandwidth: 1_000_000_000,
      requests: 100_000,
      billingType: "flat",
    };
  }

  const limits = plan.limits as ProtectionPlanConfig;
  return {
    backends: limits.backends ?? 1,
    filters: limits.filters ?? 5,
    bandwidth: limits.bandwidth ?? 1_000_000_000,
    requests: limits.requests ?? 100_000,
    billingType: limits.billingType ?? "flat",
    bandwidthPricePerGb: limits.bandwidthPricePerGb,
    requestsPricePerMillion: limits.requestsPricePerMillion,
  };
}

// Check if organization is approaching or over usage limits
export async function checkUsageStatus(orgId: string): Promise<{
  bandwidthUsedPercent: number;
  requestsUsedPercent: number;
  isOverBandwidthLimit: boolean;
  isOverRequestsLimit: boolean;
  needsWarning: boolean;
  estimatedOverageCost: number; // in cents
}> {
  const [protOrg, limits] = await Promise.all([
    getProtectionOrganizationById(orgId),
    getOrganizationLimits(orgId),
  ]);

  if (!protOrg) {
    return {
      bandwidthUsedPercent: 0,
      requestsUsedPercent: 0,
      isOverBandwidthLimit: false,
      isOverRequestsLimit: false,
      needsWarning: false,
      estimatedOverageCost: 0,
    };
  }

  const bandwidthUsed = protOrg.bandwidthUsed ?? 0;
  const requestsUsed = protOrg.requestsUsed ?? 0;

  // Calculate percentages (-1 means unlimited)
  const bandwidthUsedPercent =
    limits.bandwidth === -1
      ? 0
      : Math.round((bandwidthUsed / limits.bandwidth) * 100);
  const requestsUsedPercent =
    limits.requests === -1
      ? 0
      : Math.round((requestsUsed / limits.requests) * 100);

  const isOverBandwidthLimit =
    limits.bandwidth !== -1 && bandwidthUsed > limits.bandwidth;
  const isOverRequestsLimit =
    limits.requests !== -1 && requestsUsed > limits.requests;

  const warningThreshold = protOrg.usageWarningThreshold ?? 80;
  const needsWarning =
    (protOrg.usageWarningEnabled ?? true) &&
    (bandwidthUsedPercent >= warningThreshold ||
      requestsUsedPercent >= warningThreshold);

  // Calculate estimated overage cost for usage/hybrid plans
  let estimatedOverageCost = 0;
  if (limits.billingType === "usage" || limits.billingType === "hybrid") {
    if (isOverBandwidthLimit && limits.bandwidthPricePerGb) {
      const overageGb = (bandwidthUsed - limits.bandwidth) / 1_000_000_000;
      estimatedOverageCost += Math.ceil(overageGb * limits.bandwidthPricePerGb);
    }
    if (isOverRequestsLimit && limits.requestsPricePerMillion) {
      const overageMillions = (requestsUsed - limits.requests) / 1_000_000;
      estimatedOverageCost += Math.ceil(
        overageMillions * limits.requestsPricePerMillion,
      );
    }
  }

  return {
    bandwidthUsedPercent,
    requestsUsedPercent,
    isOverBandwidthLimit,
    isOverRequestsLimit,
    needsWarning,
    estimatedOverageCost,
  };
}

// Check if organization should be blocked due to hard cap
export async function shouldBlockDueToUsage(orgId: string): Promise<boolean> {
  const protOrg = await getProtectionOrganizationById(orgId);
  if (!protOrg || !protOrg.usageHardCap) {
    return false;
  }

  const usageStatus = await checkUsageStatus(orgId);
  return usageStatus.isOverBandwidthLimit || usageStatus.isOverRequestsLimit;
}

// Format bytes to human readable
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes === -1) return "Unlimited";

  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
}

// Format number with commas
export function formatNumber(num: number): string {
  if (num === -1) return "Unlimited";
  return num.toLocaleString();
}
