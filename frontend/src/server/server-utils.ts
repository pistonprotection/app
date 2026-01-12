import type { StripePlan } from "@better-auth/stripe";
import { db } from "@/server/db";
import { member } from "@/server/db/auth-schema";
import { protectionOrganization } from "@/server/db/schema";
import { eq, and } from "drizzle-orm";

// Protection plan definitions for Stripe
export const protectionPlans: StripePlan[] = [
  {
    name: "free",
    limits: {
      backends: 1,
      filters: 5,
      bandwidth: 1_000_000_000, // 1GB
    },
  },
  {
    name: "starter",
    lookupKey: "price_starter_monthly",
    annualDiscountLookupKey: "price_starter_annual",
    limits: {
      backends: 5,
      filters: 25,
      bandwidth: 100_000_000_000, // 100GB
    },
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
    },
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
    },
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
];

// Get a user's role in an organization
export async function getRoleOfUserInOrg(
  userId: string,
  orgId: string
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
        inArray(sub.status, ["active", "trialing"])
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
}> {
  const subscription = await db.query.subscription.findFirst({
    where: (sub, { eq, and, inArray }) =>
      and(
        eq(sub.referenceId, orgId),
        inArray(sub.status, ["active", "trialing"])
      ),
  });

  if (!subscription) {
    // Return free tier limits
    return {
      backends: 1,
      filters: 5,
      bandwidth: 1_000_000_000,
    };
  }

  const plan = protectionPlans.find((p) => p.name === subscription.plan);
  if (!plan || !plan.limits) {
    return {
      backends: 1,
      filters: 5,
      bandwidth: 1_000_000_000,
    };
  }

  return {
    backends: plan.limits.backends ?? 1,
    filters: plan.limits.filters ?? 5,
    bandwidth: plan.limits.bandwidth ?? 1_000_000_000,
  };
}

// Format bytes to human readable
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes === -1) return "Unlimited";

  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

// Format number with commas
export function formatNumber(num: number): string {
  if (num === -1) return "Unlimited";
  return num.toLocaleString();
}
